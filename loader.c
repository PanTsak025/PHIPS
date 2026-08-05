#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "event.h"
#include <errno.h>

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

// This function is called for each event received from the ring buffer
// It prints the event information in JSON format
static int handle_event(void *ctx,void *data, size_t data_sz)
{
    const struct event *e = data;
    char ipstr[INET_ADDRSTRLEN] = "";

    if(e->type == EVENT_CONNECT && e->family == 2) // AF_INET
    {
        struct in_addr a = { .s_addr = e->remote_addr };
        inet_ntop(AF_INET, &a, ipstr, sizeof(ipstr));
    }

    printf("{\"type\":\"%s\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":\"%s\","
        "\"filename\":\"%s\",\"dst_ip\":\"%s\",\"dst_port\":%u,"
        "\"ts_ns\":%llu}\n",
        type_name(e->type), e->pid, e->ppid, e->uid, e->comm, e->filename,
        ipstr, e->remote_port ? ntohs(e->remote_port) : 0, e->timestamp);
	
    fflush(stdout);
	return 0;
}

int main(void)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link_exec = NULL, *link_open = NULL, *link_connect = NULL, *link_exit = NULL;
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

    ring_buffer__free(rb);
    bpf_link__destroy(link_exec);
    bpf_link__destroy(link_open);
    bpf_link__destroy(link_connect);
    bpf_link__destroy(link_exit);
    bpf_object__close(obj);

    return 0;
}