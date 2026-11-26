// PHIPS collector, user-space side (schema v3).
//
// Loads probe.bpf.o into the kernel, receives events from the ring buffer and writes them as
// JSON lines (one event per line), either to stdout or to daily files in a directory.
//
//   sudo ./loader                       # print to stdout
//   sudo ./loader -o /var/lib/phips -z  # daily gzip files, e.g. kali-2026-11-26-091500.jsonl.gz
//   sudo ./loader -d 0                  # no de-duplication: every read/write is reported
//
// Every output file starts with:
//   1. a META line   (host, boot id, kernel, clock, settings) and
//   2. PROC lines    (a snapshot of the processes already running, so long-lived daemons such
//                     as sshd or nginx have their program path and command line in the graph)
// so each file can be loaded on its own.

#define _GNU_SOURCE // fopencookie()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <dirent.h>
#include <ctype.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <zlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "event.h"

#define PF_KTHREAD 0x00200000

static volatile sig_atomic_t running = 1;

// ---------------------------------------------------------------------------------------------
// Settings (command line)
// ---------------------------------------------------------------------------------------------
static const char *out_dir = NULL;   // -o: directory for daily files; NULL = stdout
static int use_gzip = 0;             // -z: compress the daily files
static double dedupe_sec = 60.0;     // -d: de-duplication window in seconds (0 = off)

// ---------------------------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------------------------
static FILE *out = NULL;
static char out_day[16] = "";        // UTC day of the current file, "YYYY-MM-DD"
static char hostname[256] = "";
static char boot_id[64] = "";
static struct utsname uts;
static unsigned long long events_written = 0;
static long clk_tck = 100;           // /proc start times are in these units (USER_HZ)

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

// ---------------------------------------------------------------------------------------------
// Timestamps
//
// The kernel stamps every event with CLOCK_BOOTTIME (ns since boot, counting suspend too).
// Orthrus / PIDSMaker (and any real deployment) need Unix epoch time, so events from different
// boots, hosts and days can be put on one timeline and cut into calendar days.
//
//     epoch_ns = boot_ns + offset        where   offset = CLOCK_REALTIME - CLOCK_BOOTTIME
//
// Example: the machine booted at 2026-11-26 09:00:00 UTC (epoch 1795683600 s). An event stamped
// boot_ns = 5 s is printed as ts_ns = 1795683605000000000.
//
// The offset is re-measured on every poll (every 100 ms) so it follows NTP corrections and
// manual clock changes. BOOTTIME is read just before and after REALTIME and the midpoint is used.
// ---------------------------------------------------------------------------------------------
static long long ts_to_ns(const struct timespec *t)
{
    return (long long)t->tv_sec * 1000000000LL + t->tv_nsec;
}

static long long boot_to_epoch_offset(void)
{
    struct timespec b1, rt, b2;

    clock_gettime(CLOCK_BOOTTIME, &b1);
    clock_gettime(CLOCK_REALTIME, &rt);
    clock_gettime(CLOCK_BOOTTIME, &b2);
    return ts_to_ns(&rt) - (ts_to_ns(&b1) + (ts_to_ns(&b2) - ts_to_ns(&b1)) / 2);
}

static long long epoch_offset_ns;

static long long now_epoch_ns(void)
{
    struct timespec rt;
    clock_gettime(CLOCK_REALTIME, &rt);
    return ts_to_ns(&rt);
}

// Process identity. /proc/<pid>/stat gives a process's start time in clock ticks (1/100 s);
// the kernel gives us nanoseconds. Both sides are converted to ticks the same way the kernel does
// (integer division), so a process seen in the /proc snapshot and later in kernel events gets
// exactly the same (pid, start_ticks) key.
static unsigned long long boot_ns_to_ticks(unsigned long long ns)
{
    return ns / (1000000000ULL / (unsigned long long)clk_tck);
}

// ---------------------------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------------------------
static void json_str_n(const char *s, size_t max)
{
    fputc('"', out);
    for (size_t i = 0; i < max && s[i]; i++)
    {
        unsigned char c = (unsigned char)s[i];
        switch (c)
        {
        case '"':  fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\n': fputs("\\n", out); break;
        case '\r': fputs("\\r", out); break;
        case '\t': fputs("\\t", out); break;
        default:
            if (c < 0x20 || c == 0x7f)
                fprintf(out, "\\u%04x", c);
            else
                fputc(c, out);
        }
    }
    fputc('"', out);
}

static void json_str(const char *s)
{
    json_str_n(s, (size_t)-1);
}

// argv is NUL-separated ("curl\0-s\0http://x\0"); print it space-separated.
static void json_args(const char *args, size_t len)
{
    char buf[ARGS_LEN + 1];

    if (len > ARGS_LEN)
        len = ARGS_LEN;
    memcpy(buf, args, len);
    buf[len] = '\0';
    for (size_t i = 0; i < len; i++)
        if (buf[i] == '\0')
            buf[i] = ' ';
    while (len > 0 && buf[len - 1] == ' ')
        buf[--len] = '\0';
    json_str(buf);
}

static void format_ip(unsigned short family, const unsigned char *a, char *out_s, size_t sz)
{
    static const unsigned char v4mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

    if (family == 2)
        inet_ntop(AF_INET, a, out_s, sz);
    else if (family == 10 && memcmp(a, v4mapped, 12) == 0) // ::ffff:1.2.3.4 is really IPv4
        inet_ntop(AF_INET, a + 12, out_s, sz);
    else if (family == 10)
        inet_ntop(AF_INET6, a, out_s, sz);
    else
        snprintf(out_s, sz, "?");
}

static const char *type_name(unsigned int type)
{
    switch (type)
    {
    case EVENT_EXEC:    return "EXEC";
    case EVENT_OPEN:    return "OPEN";
    case EVENT_CONNECT: return "CONNECT";
    case EVENT_EXIT:    return "EXIT";
    case EVENT_CLONE:   return "CLONE";
    case EVENT_READ:    return "READ";
    case EVENT_WRITE:   return "WRITE";
    case EVENT_ACCEPT:  return "ACCEPT";
    case EVENT_SEND:    return "SEND";
    case EVENT_RECV:    return "RECV";
    default:            return "UNKNOWN";
    }
}

static const char *proto_name(unsigned short p)
{
    return p == 6 ? "tcp" : p == 17 ? "udp" : "other";
}

static void json_object_file(const struct event *e)
{
    fputs(",\"filename\":", out);
    if (e->flags & EF_PIPE)
        fprintf(out, "\"pipe:[%llu]\"", e->ino);
    else
        json_str_n(e->filename, PATH_LEN);
    fprintf(out, ",\"kind\":\"%s\",\"dev\":%u,\"ino\":%llu,\"gen\":%u",
            (e->flags & EF_PIPE) ? "pipe" : "file", e->dev, e->ino, e->gen);
    if (e->flags & EF_PATH_TRUNCATED)
        fputs(",\"path_truncated\":true", out);
}

static void json_object_net(const struct event *e, int with_local)
{
    char r[INET6_ADDRSTRLEN], l[INET6_ADDRSTRLEN];

    format_ip(e->family, e->raddr, r, sizeof(r));
    fprintf(out, ",\"family\":\"%s\",\"proto\":\"%s\",\"raddr\":\"%s\",\"rport\":%u,\"lport\":%u",
            e->family == 2 ? "ipv4" : "ipv6", proto_name(e->protocol), r, e->rport, e->lport);
    if (with_local)
    {
        format_ip(e->family, e->laddr, l, sizeof(l));
        fprintf(out, ",\"laddr\":\"%s\"", l);
    }
}

// ---------------------------------------------------------------------------------------------
// One kernel event -> one JSON line
// ---------------------------------------------------------------------------------------------
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct event e;

    (void)ctx;
    // The kernel sends only the part of struct event this type needs (see EVENT_SIZE_* in
    // event.h). Copy it into a zeroed struct so the missing tail reads as empty.
    memset(&e, 0, sizeof(e));
    memcpy(&e, data, data_sz < sizeof(e) ? data_sz : sizeof(e));
    e.comm[sizeof(e.comm) - 1] = '\0';

    if (!out)
        return 0;

    fprintf(out, "{\"type\":\"%s\",\"ts_ns\":%lld,\"pid\":%u,\"tid\":%u,\"ppid\":%u,"
                 "\"uid\":%u,\"euid\":%u,\"comm\":",
            type_name(e.type), (long long)e.ts + epoch_offset_ns, e.pid, e.tid, e.ppid,
            e.uid, e.euid);
    json_str_n(e.comm, sizeof(e.comm));
    fprintf(out, ",\"start_ticks\":%llu", boot_ns_to_ticks(e.start_boot_ns));

    switch (e.type)
    {
    case EVENT_CLONE:
        // pid/start_ticks = the new child, ppid/parent_start_ticks = the process that created it
        fprintf(out, ",\"parent_start_ticks\":%llu", boot_ns_to_ticks(e.parent_start_boot_ns));
        break;

    case EVENT_EXEC:
        json_object_file(&e);
        fputs(",\"exec_name\":", out);
        json_str_n(e.exec_name, PATH_LEN);
        fputs(",\"args\":", out);
        json_args(e.args, e.args_len);
        if (e.flags & EF_ARGS_TRUNCATED)
            fputs(",\"args_truncated\":true", out);
        break;

    case EVENT_OPEN:
    {
        const char *access = e.fmode == 3 ? "readwrite" : e.fmode == 2 ? "write"
                           : e.fmode == 1 ? "read" : "none";
        json_object_file(&e);
        fprintf(out, ",\"access\":\"%s\",\"created\":%s,\"fd\":%d",
                access, (e.flags & EF_CREATED) ? "true" : "false", e.ret);
        break;
    }

    case EVENT_READ:
    case EVENT_WRITE:
        json_object_file(&e);
        break;

    case EVENT_CONNECT:
        json_object_net(&e, 0);
        break;

    case EVENT_ACCEPT:
    case EVENT_SEND:
    case EVENT_RECV:
        json_object_net(&e, 1);
        break;

    case EVENT_EXIT:
        // wait() status encoding: low 7 bits = killing signal, otherwise exit code in bits 8-15
        if (e.ret & 0x7f)
            fprintf(out, ",\"signal\":%d", e.ret & 0x7f);
        else
            fprintf(out, ",\"exit_code\":%d", (e.ret >> 8) & 0xff);
        break;
    }

    fputs("}\n", out);
    events_written++;
    return 0;
}

// ---------------------------------------------------------------------------------------------
// Snapshot of processes that were already running when the file starts
// ---------------------------------------------------------------------------------------------
static int read_file(const char *path, char *buf, size_t sz)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t n;

    if (fd < 0)
        return -1;
    n = read(fd, buf, sz - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return (int)n;
}

static void snapshot_one(int pid)
{
    char path[64], stat[1024], exe[PATH_MAX] = "", cmd[ARGS_LEN + 1], status[4096];
    char comm[64] = "";
    char *open_paren, *close_paren, *tok, *save = NULL;
    unsigned long long start_ticks = 0;
    unsigned long flags = 0;
    unsigned int uid = 0, euid = 0;
    int ppid = 0, field = 3, n;
    ssize_t el;

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    if (read_file(path, stat, sizeof(stat)) < 0)
        return; // exited meanwhile

    // "1234 (my prog) S 1 ..." : comm may contain spaces and ')' so cut at the LAST ')'
    open_paren = strchr(stat, '(');
    close_paren = strrchr(stat, ')');
    if (!open_paren || !close_paren || close_paren < open_paren)
        return;
    snprintf(comm, sizeof(comm), "%.*s", (int)(close_paren - open_paren - 1), open_paren + 1);

    for (tok = strtok_r(close_paren + 2, " ", &save); tok; tok = strtok_r(NULL, " ", &save), field++)
    {
        if (field == 4)
            ppid = atoi(tok);
        else if (field == 9)
            flags = strtoul(tok, NULL, 10);
        else if (field == 22)
        {
            start_ticks = strtoull(tok, NULL, 10);
            break;
        }
    }
    if (flags & PF_KTHREAD)
        return;

    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    el = readlink(path, exe, sizeof(exe) - 1);
    exe[el > 0 ? el : 0] = '\0';

    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    n = read_file(path, cmd, sizeof(cmd));

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    if (read_file(path, status, sizeof(status)) > 0)
    {
        char *u = strstr(status, "\nUid:");
        if (u)
            sscanf(u + 5, "%u %u", &uid, &euid);
    }

    fprintf(out, "{\"type\":\"PROC\",\"ts_ns\":%lld,\"pid\":%d,\"ppid\":%d,\"uid\":%u,"
                 "\"euid\":%u,\"comm\":", now_epoch_ns(), pid, ppid, uid, euid);
    json_str(comm);
    fprintf(out, ",\"start_ticks\":%llu,\"filename\":", start_ticks);
    json_str(exe);
    fputs(",\"args\":", out);
    json_args(cmd, n > 0 ? (size_t)n : 0);
    fputs("}\n", out);
}

static void snapshot_processes(void)
{
    DIR *d = opendir("/proc");
    struct dirent *de;
    int self = getpid();

    if (!d)
        return;
    while ((de = readdir(d)))
    {
        if (!isdigit((unsigned char)de->d_name[0]))
            continue;
        int pid = atoi(de->d_name);
        if (pid != self)
            snapshot_one(pid);
    }
    closedir(d);
}

// ---------------------------------------------------------------------------------------------
// Files: META header, daily rotation
// ---------------------------------------------------------------------------------------------
static void write_header(void)
{
    epoch_offset_ns = boot_to_epoch_offset();
    fprintf(out, "{\"type\":\"META\",\"schema_version\":%d,\"clock\":\"epoch_ns\",\"ts_ns\":%lld,"
                 "\"hostname\":", COLLECTOR_SCHEMA_VERSION, now_epoch_ns());
    json_str(hostname);
    fputs(",\"boot_id\":", out);
    json_str(boot_id);
    fputs(",\"kernel\":", out);
    json_str(uts.release);
    fprintf(out, ",\"arch\":\"%s\",\"clk_tck\":%ld,\"dedupe_ns\":%lld,"
                 "\"boot_to_epoch_offset_ns\":%lld}\n",
            uts.machine, clk_tck, (long long)(dedupe_sec * 1e9), epoch_offset_ns);
    snapshot_processes();
    fflush(out);
}

// gzip output, done INSIDE the loader with zlib. Running an external `gzip` would be a mistake:
// gzip is a separate process, so its reads and writes of our output would themselves become
// events, which become more output... a feedback loop (79,000 events in 3 s when measured).
// fopencookie() wraps the gzFile in a normal FILE *, so all fprintf() calls work unchanged.
static ssize_t gz_write(void *cookie, const char *buf, size_t size)
{
    return gzwrite((gzFile)cookie, buf, (unsigned)size) > 0 || size == 0 ? (ssize_t)size : -1;
}

static int gz_close(void *cookie)
{
    return gzclose((gzFile)cookie) == Z_OK ? 0 : -1;
}

static FILE *open_gzip(const char *path)
{
    cookie_io_functions_t io = {.read = NULL, .write = gz_write, .seek = NULL, .close = gz_close};
    gzFile gz = gzopen(path, "wb6");

    if (!gz)
        return NULL;
    return fopencookie(gz, "w", io);
}

static void utc_day(char *buf, size_t sz)
{
    time_t t = time(NULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(buf, sz, "%Y-%m-%d", &tm);
}

static void close_output(void)
{
    if (!out || out == stdout)
        return;
    fclose(out); // for gzip files this also finishes the gzip stream (gz_close)
    out = NULL;
}

// Open a new file in out_dir (or use stdout). Called at start and when the UTC day changes.
static int open_output(void)
{
    char path[PATH_MAX], stamp[32];
    time_t t = time(NULL);
    struct tm tm;

    if (!out_dir)
    {
        out = stdout;
        write_header();
        return 0;
    }

    close_output();
    gmtime_r(&t, &tm);
    strftime(stamp, sizeof(stamp), "%Y-%m-%d-%H%M%S", &tm);
    utc_day(out_day, sizeof(out_day));
    snprintf(path, sizeof(path), "%s/%s-%s.jsonl%s", out_dir, hostname, stamp, use_gzip ? ".gz" : "");

    out = use_gzip ? open_gzip(path) : fopen(path, "w");
    if (!out)
    {
        fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    fprintf(stderr, "writing %s\n", path);
    write_header();
    return 0;
}

// ---------------------------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------------------------
static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [-o DIR] [-z] [-d SECONDS]\n"
            "  -o DIR      write daily files into DIR instead of stdout\n"
            "  -z          gzip the daily files (needs -o)\n"
            "  -d SECONDS  report repeated read/write/send/recv/open of the same\n"
            "              (process, object) at most once per SECONDS (default 60, 0 = all)\n",
            prog);
}

static unsigned long long total_drops(int map_fd)
{
    int ncpus = libbpf_num_possible_cpus();
    unsigned long long *vals, total = 0;
    __u32 key = 0;

    if (map_fd < 0 || ncpus <= 0)
        return 0;
    vals = calloc(ncpus, sizeof(*vals));
    if (vals && bpf_map_lookup_elem(map_fd, &key, vals) == 0)
        for (int i = 0; i < ncpus; i++)
            total += vals[i];
    free(vals);
    return total;
}

// probe.bpf.o is looked up next to the loader executable, so it can be started from anywhere
// (e.g. by systemd).
static void find_bpf_object(char *buf, size_t sz)
{
    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);

    if (n > 0)
    {
        exe[n] = '\0';
        char *slash = strrchr(exe, '/');
        if (slash)
        {
            *slash = '\0';
            snprintf(buf, sz, "%s/probe.bpf.o", exe);
            if (access(buf, R_OK) == 0)
                return;
        }
    }
    snprintf(buf, sz, "probe.bpf.o");
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *links[16];
    struct ring_buffer *rb = NULL;
    struct collector_config cfg = {0};
    char obj_path[PATH_MAX];
    int nlinks = 0, err, opt, drop_fd;
    unsigned long long last_drops = 0;
    time_t last_stats = time(NULL);
    __u32 zero = 0;

    while ((opt = getopt(argc, argv, "o:zd:h")) != -1)
    {
        switch (opt)
        {
        case 'o': out_dir = optarg; break;
        case 'z': use_gzip = 1; break;
        case 'd': dedupe_sec = atof(optarg); break;
        default: usage(argv[0]); return opt == 'h' ? 0 : 1;
        }
    }
    if (use_gzip && !out_dir)
    {
        fprintf(stderr, "-z needs -o DIR\n");
        return 1;
    }
    if (out_dir)
        mkdir(out_dir, 0750);

    if (access("/sys/kernel/btf/vmlinux", R_OK) != 0)
    {
        fprintf(stderr, "this kernel has no BTF (/sys/kernel/btf/vmlinux); "
                        "a kernel >= 5.8 built with CONFIG_DEBUG_INFO_BTF=y is required\n");
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal); // systemd stops services with SIGTERM
    signal(SIGPIPE, SIG_IGN);

    clk_tck = sysconf(_SC_CLK_TCK);
    if (clk_tck <= 0)
        clk_tck = 100;
    gethostname(hostname, sizeof(hostname) - 1);
    uname(&uts);
    read_file("/proc/sys/kernel/random/boot_id", boot_id, sizeof(boot_id));
    boot_id[strcspn(boot_id, "\n")] = '\0';

    find_bpf_object(obj_path, sizeof(obj_path));
    obj = bpf_object__open_file(obj_path, NULL);
    if (!obj)
    {
        fprintf(stderr, "failed to open %s\n", obj_path);
        return 1;
    }
    err = bpf_object__load(obj);
    if (err)
    {
        fprintf(stderr, "failed to load BPF object: %d (run as root?)\n", err);
        return 1;
    }

    // Settings must be in place before the first event can fire.
    cfg.self_tgid = getpid();
    cfg.dedupe_ns = (unsigned long long)(dedupe_sec * 1e9);
    if (bpf_map_update_elem(bpf_object__find_map_fd_by_name(obj, "collector_cfg"), &zero, &cfg, 0))
    {
        fprintf(stderr, "failed to write config map\n");
        return 1;
    }

    bpf_object__for_each_program(prog, obj)
    {
        struct bpf_link *l = bpf_program__attach(prog);
        if (!l)
        {
            fprintf(stderr, "failed to attach %s\n", bpf_program__name(prog));
            return 1;
        }
        if (nlinks < (int)(sizeof(links) / sizeof(links[0])))
            links[nlinks++] = l;
    }

    rb = ring_buffer__new(bpf_object__find_map_fd_by_name(obj, "ring_buffer"), handle_event, NULL, NULL);
    if (!rb)
    {
        fprintf(stderr, "failed to create ring buffer\n");
        return 1;
    }
    drop_fd = bpf_object__find_map_fd_by_name(obj, "drop_count");

    // Probes are attached BEFORE the /proc snapshot, so a process that starts during the snapshot
    // is caught by the CLONE/EXEC events at least.
    if (open_output())
        return 1;

    fprintf(stderr, "PHIPS collector v%d running (dedupe %.0fs). Ctrl+C to stop.\n",
            COLLECTOR_SCHEMA_VERSION, dedupe_sec);

    while (running)
    {
        epoch_offset_ns = boot_to_epoch_offset(); // follow NTP / clock changes
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err == -EINTR)
            break;
        if (err < 0)
        {
            fprintf(stderr, "error polling ring buffer: %d\n", err);
            break;
        }
        if (out)
            fflush(out); // once per poll, not once per event: much faster under load

        if (out_dir)
        {
            char day[16];
            utc_day(day, sizeof(day));
            if (strcmp(day, out_day) != 0 && open_output())
                break;
        }

        if (time(NULL) - last_stats >= 60)
        {
            unsigned long long drops = total_drops(drop_fd);
            fprintf(stderr, "events written: %llu, dropped in the last minute: %llu\n",
                    events_written, drops - last_drops);
            last_drops = drops;
            last_stats = time(NULL);
        }
    }

    ring_buffer__consume(rb); // whatever is still in the buffer
    if (out)
        fflush(out);
    fprintf(stderr, "events written: %llu, dropped (ring buffer full): %llu\n",
            events_written, total_drops(drop_fd));

    close_output();
    ring_buffer__free(rb);
    for (int i = 0; i < nlinks; i++)
        bpf_link__destroy(links[i]);
    bpf_object__close(obj);
    return 0;
}
