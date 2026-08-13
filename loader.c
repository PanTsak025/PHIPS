#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "event.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

static volatile int running = 1;

static void handle_sigint(int sig)
{
    running = 0;
}

static const char *type_name(unsigned int type)
{
    switch (type) 
    {
        case EVENT_EXEC:
            return "EXEC";
        case EVENT_CLONE:
            return "CLONE";
        case EVENT_OPEN:
            return "OPEN";
        case EVENT_CONNECT:
            return "CONNECT";
        case EVENT_EXIT:
            return "EXIT";
        default:
            return "UNKNOWN";
    }
}

static void print_json_string(const char *s)
{
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
    {
        switch (*p)
        {
        case '"':  fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\n': fputs("\\n", stdout); break;
        case '\r': fputs("\\r", stdout); break;
        case '\t': fputs("\\t", stdout); break;
        default:
            if (*p < 0x20)
                printf("\\u%04x", *p);
            else
                putchar(*p);
        }
    }
    putchar('"');
}

static void resolve_openat_path(unsigned int pid, int dfd, const char *rel,
                                 char *out, size_t out_sz)
{
    char linkpath[64];
    char base[PATH_MAX];
    ssize_t n;

    if (rel[0] == '/') 
    {
        snprintf(out, out_sz, "%s", rel);
        return;
    }

    if (dfd == AT_FDCWD) 
    {
        snprintf(linkpath, sizeof(linkpath), "/proc/%u/cwd", pid);
    } else 
    {
        snprintf(linkpath, sizeof(linkpath), "/proc/%u/fd/%d", pid, dfd);
    }

    n = readlink(linkpath, base, sizeof(base) - 1);
    if (n < 0) 
    {
        snprintf(out, out_sz, "%s", rel);
        return;
    }
    base[n] = '\0';

    snprintf(out, out_sz, "%s/%s", base, rel);
}

// This function is called for each event received from the ring buffer
// It prints the event information in JSON format
static int handle_event(void *ctx,void *data, size_t data_sz)
{
    const struct event *e = data;
    char ipstr[INET_ADDRSTRLEN] = "";
    char resolved_path[PATH_MAX];
    const char *filename_to_print = e->filename;

    if(e->type == EVENT_CONNECT && e->family == 2) // AF_INET
    {
        struct in_addr a = { .s_addr = e->remote_addr };
        inet_ntop(AF_INET, &a, ipstr, sizeof(ipstr));
    }

    if (e->type == EVENT_OPEN)
    {
        resolve_openat_path(e->pid, e->dfd, e->filename,
                             resolved_path, sizeof(resolved_path));
        filename_to_print = resolved_path;
    }

    printf("{\"type\":\"%s\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":",
        type_name(e->type), e->pid, e->ppid, e->uid);
    print_json_string(e->comm);
    printf(",\"filename\":");
    print_json_string(filename_to_print);
    printf(",\"dst_ip\":\"%s\",\"dst_port\":%u,"
        "\"ts_ns\":%llu,\"group_dead\":%s}\n",
        ipstr, e->remote_port ? ntohs(e->remote_port) : 0, e->timestamp,
        e->group_dead ? "true" : "false");
	
    fflush(stdout);
	return 0;
}

int main(void)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link_exec = NULL, *link_open = NULL, *link_connect = NULL, *link_exit = NULL, *link_clone = NULL;
    struct ring_buffer *rb = NULL;
    int map_fd, err;

    signal(SIGINT, handle_sigint);

    obj = bpf_object__open_file("probe.bpf.o", NULL);
    if(!obj)
    {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }

    	err = bpf_object__load(obj);
	if (err) 
    {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		return 1;
	}
 
	prog = bpf_object__find_program_by_name(obj, "handle_execve");
	link_exec = bpf_program__attach(prog);
	if (!link_exec) 
    {
		fprintf(stderr, "failed to attach handle_execve\n");
		return 1;
	}
 
    prog = bpf_object__find_program_by_name(obj, "handle_clone");
    link_clone = bpf_program__attach(prog);
    if (!link_clone) 
    {
        fprintf(stderr, "failed to attach handle_clone\n");
        return 1;
    }

	prog = bpf_object__find_program_by_name(obj, "handle_openat");
	link_open = bpf_program__attach(prog);
	if (!link_open) 
    {
		fprintf(stderr, "failed to attach handle_openat\n");
		return 1;
	}
 
	prog = bpf_object__find_program_by_name(obj, "handle_connect");
	link_connect = bpf_program__attach(prog);
	if (!link_connect) 
    {
		fprintf(stderr, "failed to attach handle_connect\n");
		return 1;
	}
    
    prog = bpf_object__find_program_by_name(obj, "handle_exit");
    link_exit = bpf_program__attach(prog);
    if (!link_exit) 
    {
        fprintf(stderr, "failed to attach handle_exit\n");
        return 1;
    }

	map_fd = bpf_object__find_map_fd_by_name(obj, "ring_buffer");
	rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
	if (!rb) 
    {
		fprintf(stderr, "failed to create ring buffer\n");
		return 1;
	}

    fprintf(stderr, "listening for events... Press Ctrl+C to exit.\n");

    while(running)
    {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR)
        {
            err = 0;
            break;
        }
        if (err < 0) 
        {
            fprintf(stderr, "error polling ring buffer: %d\n", err);
            break;
        }
    }

    int drop_map_fd = bpf_object__find_map_fd_by_name(obj, "drop_count");
    if (drop_map_fd >= 0) 
    {
        int ncpus = libbpf_num_possible_cpus();
        __u64 *per_cpu_vals = calloc(ncpus, sizeof(__u64));
        __u32 key = 0;
        if (per_cpu_vals &&
            bpf_map_lookup_elem(drop_map_fd, &key, per_cpu_vals) == 0) 
        {
            __u64 total = 0;
            for (int i = 0; i < ncpus; i++)
                total += per_cpu_vals[i];
            fprintf(stderr, "events dropped (ring buffer full): %llu\n",
                    (unsigned long long)total);
        }
        free(per_cpu_vals);
    }

    ring_buffer__free(rb);
    bpf_link__destroy(link_exec);
    bpf_link__destroy(link_open);
    bpf_link__destroy(link_connect);
    bpf_link__destroy(link_exit);
    bpf_link__destroy(link_clone);
    bpf_object__close(obj);

    return 0;
}