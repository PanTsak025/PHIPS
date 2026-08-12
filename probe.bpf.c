#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "event.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif


char LICENSE[] SEC("license") = "GPL";

struct 
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} ring_buffer SEC(".maps");

static __always_inline void get_current_proc(struct event *e)  // fill the event struct with current process information
{                                                              // timestamp, pid, uid, ppid and comm are the same for all events.
    struct task_struct *task;

    __builtin_memset(e, 0, sizeof(*e)); // Initialize the event structure to zero

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32; // get the PID from the upper 32 bits
    
    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF; // get the UID from the lower 32 bits
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter* ctx) // hanlde the EXECVE event
{
    const char *filename_ptr;

    struct event *e;
    e = bpf_ringbuf_reserve(&ring_buffer, sizeof(*e), 0); //safecheck it is not NULL
    if (!e)
    {
        return 0;
    }
    get_current_proc(e);
    e->type = EVENT_EXEC;
    

    filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_clone(struct trace_event_raw_sched_process_fork *ctx) // hanlde the CLONE event
{
    struct event *e;

    e = bpf_ringbuf_reserve(&ring_buffer, sizeof(*e), 0); //safecheck it is not NULL
    if (!e)
    {
        return 0;
    }

    get_current_proc(e);
    e->type = EVENT_CLONE;

    e->pid = ctx->child_pid; // Override the PID with the child PID 
    e->ppid = ctx->parent_pid; // Override the PPID with the parent PID 
    bpf_get_current_comm(&e->comm, sizeof(e->comm)); // Override the comm with the child's comm
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) // hanlde the OPENAT
{
    struct event *e;
    const char *filename_ptr;

    e = bpf_ringbuf_reserve(&ring_buffer, sizeof(*e), 0); //safecheck it is not NULL
    if (!e)
    {
        return 0;
    }

    get_current_proc(e);
    e->type = EVENT_OPEN;

    filename_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) // hanlde the CONNECT
{
    struct event *e;
    struct sockaddr_in addr = {};
    const void *addr_ptr;

    e = bpf_ringbuf_reserve(&ring_buffer, sizeof(*e), 0); //safecheck it is not NULL
    if (!e)
    {
        return 0;
    }

    get_current_proc(e);
    e->type = EVENT_CONNECT;

    addr_ptr = (const void *)ctx->args[1];
    bpf_probe_read_user(&addr, sizeof(addr), addr_ptr); //do not know if it is IPv4 or IPv6   
    
    if (addr.sin_family == AF_INET) 
    {
        e->family = AF_INET;
        e->remote_addr = addr.sin_addr.s_addr;
        e->remote_port = addr.sin_port;
    } 
    else if (addr.sin_family == AF_INET6) 
    {
        e->family = AF_INET6;
        // not handle IPv6
    } 
    else 
    {
        // Unsupported address family
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_exit *ctx) // hanlde the EXIT
{
    struct event *e;

    e = bpf_ringbuf_reserve(&ring_buffer, sizeof(*e), 0); //safecheck it is not NULL
    if (!e)
    {
        return 0;
    }

    get_current_proc(e);
    e->type = EVENT_EXIT;
    e->group_dead = ctx->group_dead; // Set the group_dead field based on the tracepoint data   
    bpf_ringbuf_submit(e, 0);
    return 0;
}