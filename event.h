#ifndef __EVENT_H
#define __EVENT_H

/*
 * Shared between the kernel side (probe.bpf.c) and user space (loader.c).
 * Only plain C types here: this file is compiled both for the BPF target and for x86_64/arm64.
 *
 * Collector schema v3. Every event says WHO did it (the process), WHAT kind of action it was,
 * and on WHICH object (a file/pipe, or a network peer).
 */

#define COLLECTOR_SCHEMA_VERSION 3

enum event_type
{
    EVENT_EXEC    = 1,  // a process successfully replaced its program (execve/execveat)
    EVENT_OPEN    = 2,  // a file/pipe was successfully opened (open, openat, openat2, creat)
    EVENT_CONNECT = 3,  // a process asked to connect a socket to a remote IPv4/IPv6 address
    EVENT_EXIT    = 4,  // the LAST thread of a process exited (whole process gone)
    EVENT_CLONE   = 5,  // a new PROCESS was created (fork/vfork/clone without CLONE_THREAD)
    EVENT_READ    = 6,  // data read from a file or pipe        (read, pread, readv, sendfile in, ...)
    EVENT_WRITE   = 7,  // data written to a file or pipe       (write, pwrite, writev, sendfile out, ...)
    EVENT_ACCEPT  = 8,  // an incoming TCP connection was accepted (accept, accept4)
    EVENT_SEND    = 9,  // data sent on an IPv4/IPv6 socket     (send*, write on a socket)
    EVENT_RECV    = 10, // data received on an IPv4/IPv6 socket (recv*, read on a socket)
};

// bits of event.flags
#define EF_PATH_TRUNCATED  0x01 // path deeper/longer than the buffer: the leading part is missing
#define EF_ARGS_TRUNCATED  0x02 // command line longer than ARGS_LEN
#define EF_PIPE            0x04 // object is an anonymous pipe (no path; printed as pipe:[ino])
#define EF_CREATED         0x08 // OPEN created the file (O_CREAT on a file that did not exist)

#define PATH_LEN 256
#define ARGS_LEN 256

struct event
{
    // ---------------- header: present in EVERY event ----------------
    unsigned int type;                    // enum event_type
    unsigned int pid;                     // process id (tgid): what `ps` shows
    unsigned int tid;                     // thread id that performed the action
    unsigned int ppid;                    // parent process id
    unsigned int uid;                     // real user id
    unsigned int euid;                    // effective user id (differs after setuid: privilege change)
    unsigned long long ts;                // CLOCK_BOOTTIME ns of the event; loader converts to epoch
    unsigned long long start_boot_ns;     // when THIS process started (CLOCK_BOOTTIME ns).
                                          // (boot_id, pid, start) identifies a process uniquely,
                                          // even when the kernel later reuses the pid number.
    unsigned long long parent_start_boot_ns; // CLONE only: start time of the parent process
    char comm[16];                        // process name (of the main thread, not of the thread)

    // file / pipe object (OPEN, READ, WRITE, EXEC)
    unsigned long long ino;               // inode number
    unsigned int dev;                     // device (filesystem) the inode lives on
    unsigned int gen;                     // inode generation: (dev, ino, gen) = one file, even
                                          // after rename/move. Survives `mv /tmp/x /usr/bin/y`.
    unsigned int fmode;                   // OPEN: kernel f_mode bits (1 = read, 2 = write)
    int ret;                              // CONNECT/OPEN/ACCEPT: syscall result; EXIT: exit code

    // network object (CONNECT, ACCEPT, SEND, RECV)
    unsigned short family;                // 2 = AF_INET (IPv4), 10 = AF_INET6 (IPv6)
    unsigned short protocol;              // 6 = TCP, 17 = UDP
    unsigned short lport;                 // local port  (host byte order)
    unsigned short rport;                 // remote port (host byte order)
    unsigned char laddr[16];              // local address  (IPv4 uses the first 4 bytes)
    unsigned char raddr[16];              // remote address (IPv4 uses the first 4 bytes)

    unsigned short args_len;              // EXEC: bytes valid in args
    unsigned char flags;                  // EF_* bits
    unsigned char _pad[5];

    // ---------------- variable tail: only sent for event types that need it ----------------
    char filename[PATH_LEN];              // OPEN/READ/WRITE/EXEC: absolute path, resolved in the kernel
    char args[ARGS_LEN];                  // EXEC: argv, NUL-separated (as in /proc/<pid>/cmdline)
    char exec_name[PATH_LEN];             // EXEC: the name exactly as passed to execve(); differs from
                                          // filename for scripts (filename = the interpreter binary)
};

// The kernel only reserves (and sends) the part of the struct an event type needs:
//   CLONE/EXIT/CONNECT/ACCEPT/SEND/RECV  -> header only
//   OPEN/READ/WRITE                      -> header + filename
//   EXEC                                 -> everything
// This keeps the ring buffer and the CPU cost low for the frequent event types.
#define EVENT_SIZE_HEADER __builtin_offsetof(struct event, filename)
#define EVENT_SIZE_FILE   __builtin_offsetof(struct event, args)
#define EVENT_SIZE_FULL   sizeof(struct event)

// Runtime settings written by the loader into the `config` map before attaching.
struct collector_config
{
    unsigned int self_tgid;               // the loader's own pid: its events are ignored
    unsigned int _pad;
    unsigned long long dedupe_ns;         // READ/WRITE/SEND/RECV/OPEN of the same (process, object)
                                          // are sent at most once per this many ns. 0 = send all.
};

#endif /* __EVENT_H */
