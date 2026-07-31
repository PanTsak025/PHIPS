#ifndef __EVENT_H
#define __EVENT_H

#include <linux/types.h> /* __u8/__u16/__u32/__u64 - identical width on the BPF target and userspace */

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

/*
 * Explicit values: this enum crosses a boundary that can become versioned
 * over time (a BPF object pinned from an older build vs. a recompiled
 * userspace loader, or a persisted ring-buffer capture replayed later).
 * Declaration order isn't safe once anyone inserts a new kind in the
 * middle. 0 is reserved so a zeroed/uninitialized event decodes as
 * invalid rather than silently as EVENT_EXEC.
 */
enum event_type {
    EVENT_UNKNOWN = 0,
    EVENT_EXEC    = 1,
    EVENT_OPEN    = 2,
    EVENT_CONNECT = 3,
};

struct exec_data {
    __u32 ppid;
    char filename[MAX_FILENAME_LEN];
};

struct open_data {
    char filename[MAX_FILENAME_LEN];
    __u32 flags;
};

struct connect_data {
    __u32 daddr;    /* IPv4, network byte order */
    __u16 dport;    /* network byte order */
    __u16 protocol; /* IPPROTO_TCP / IPPROTO_UDP */
};

struct event {
    /*
     * __u32 rather than `enum event_type` directly: an enum's underlying
     * storage type is implementation-defined in C, and the BPF-target
     * compile and the userspace compile are two separate compilations even
     * when both use clang. A fixed-width wire field removes that variable;
     * cast to/from enum event_type wherever this field is consumed.
     */
    __u32 type;

    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    char comm[TASK_COMM_LEN];

    union {
        struct exec_data exec;
        struct open_data open;
        struct connect_data connect;
    };
};

#endif /* __EVENT_H */
