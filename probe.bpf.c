#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "event.h"

char LICENSE[] SEC("license") = "GPL";

struct 
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} ring_buffer SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter* ctx)
{
    struct task_struct *task;
    const char *filename_ptr;

    struct event *e;
    e = bpf_ringbuf_reserve(&ring_buffer, sizeof(*e), 0); //safecheck it is not NULL
    if (!e)
        return 0;

    e->type = EVENT_EXEC;
    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;// get the PID from the upper 32 bits
   
    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF; // get the UID from the lower 32 bits
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}