# PHIPS collector (schema v3)

An eBPF collector that records, for every process on a Linux host, what it **runs**, **reads**,
**writes** and **talks to**, as JSON lines ready to become a provenance graph.

```
kernel (probe.bpf.c)                         user space (loader.c)            analysis
tp_btf/sys_enter  read/write/send/recv/connect   ring buffer -> JSON lines  ->  graph_builder.py
tp_btf/sys_exit   open/openat/openat2, accept    epoch timestamps               feature_encoder.py
sched_process_fork / exec / exit                 daily gzip files, /proc        (PIDSMaker adapter)
                                                 snapshot, drop stats
```

## Requirements

- Linux >= 5.8 with BTF (`/sys/kernel/btf/vmlinux` exists): Fedora, Debian/Kali, Ubuntu 22.04+, RHEL 9.
- x86_64 or arm64. Works on kernels without kprobes or fentry: it only uses tracepoints.
- Build: `clang`, `libbpf-dev`, `zlib1g-dev` (Fedora: `libbpf-devel zlib-devel`), `pkg-config`.
- Analysis: `python3` with `networkx`.

## Use

```bash
make
sudo tests/selftest.sh                 # 9 end-to-end checks on this machine
sudo ./loader > capture.jsonl          # quick capture to stdout, Ctrl+C to stop
sudo ./loader -o /var/lib/phips -z     # daily gzip files
sudo make install && sudo systemctl enable --now phips-collector   # as a service
journalctl -u phips-collector -f       # "dropped in the last minute" should stay 0
python3 graph_builder.py /var/lib/phips/*.jsonl.gz
```

`-d SECONDS` (default 60) is the de-duplication window: repeated read/write/send/recv/open of
the same (process, object) are reported once per window. `-d 0` reports every syscall; that is
~10x the volume and ~25x the overhead, so use it only for short experiments.

## Verifying a machine before (and while) collecting

Three checks, from quick to thorough. Run all three on every new machine or kernel.

| Check | Command | What it proves |
|---|---|---|
| Self-test | `sudo tests/selftest.sh` | an attack chain, a rename, pipes, UDP and a failed exec come out right in the graph |
| Cross-check | `sudo tests/crosscheck_strace.sh` | the collector sees exactly what strace (an independent tracer) sees on a varied workload: every (process, operation, object) |
| Consistency | `python3 tests/validate_capture.py FILES...` | rules every capture must satisfy, over any amount of real data: no events after a process exits, no relative paths, no duplicates inside the de-dup window, valid addresses, no clock jumps |

The first two use controlled workloads; the third is how you check hours of real use. Run it
on the capture of every collection day; it must say `RESULT: OK`.

## What is recorded

| Event | Kernel source | Meaning |
|---|---|---|
| `CLONE` | `sched_process_fork` | a new **process** (threads are ignored) |
| `EXEC` | `sched_process_exec` | a **successful** exec, with resolved binary path and argv |
| `OPEN` | exit of open/openat/openat2/creat | a successful open, with access read/write and `created` |
| `READ` / `WRITE` | entry of read, pread64, readv, preadv(2), write, pwrite64, writev, pwritev(2), sendfile, splice, copy_file_range | data flow with a file or pipe |
| `SEND` / `RECV` | the same syscalls on a socket, plus send(to/msg/mmsg), recv(from/msg/mmsg) | data flow with an IPv4/IPv6 peer |
| `CONNECT` | entry of connect | outgoing connection attempt (including refused ones) |
| `ACCEPT` | exit of accept/accept4 | incoming TCP connection, with the client address |
| `EXIT` | `sched_process_exit` | the whole process ended, with exit code or signal |
| `PROC` | user space, `/proc` | processes already running when a file starts |
| `META` | user space | first line of every file: host, boot id, kernel, settings |

Every event carries `ts_ns` (Unix epoch ns), `pid`, `tid`, `ppid`, `uid`, `euid`, `comm` (the
main thread's name) and `start_ticks`.

### Example lines

```json
{"type":"EXEC","ts_ns":1795687966856199825,"pid":1193,"tid":1193,"ppid":1189,"uid":0,"euid":0,"comm":"curl","start_ticks":159673,"filename":"/usr/bin/curl","kind":"file","dev":266338304,"ino":181375,"gen":0,"exec_name":"/usr/bin/curl","args":"curl -s -o /tmp/phips-selftest.V6KRsx/x.sh http://127.0.0.1:18080/x.sh"}
{"type":"WRITE","ts_ns":1795687966863673755,"pid":1193,"tid":1193,"ppid":1189,"uid":0,"euid":0,"comm":"curl","start_ticks":159673,"filename":"/tmp/phips-selftest.V6KRsx/x.sh","kind":"file","dev":266338304,"ino":688985,"gen":200819403}
{"type":"ACCEPT","ts_ns":1795687966860937406,"pid":1191,"tid":1191,"ppid":1189,"uid":0,"euid":0,"comm":"python3","start_ticks":159573,"family":"ipv4","proto":"tcp","raddr":"127.0.0.1","rport":48678,"lport":18080,"laddr":"127.0.0.1"}
```

## Node identity (why the graph stays correct over days)

| Node | Key | Why |
|---|---|---|
| process | `(boot_id, pid, start_ticks)` | pids are reused; the start time is not. Same key in kernel events and in the `/proc` snapshot. |
| file / pipe | `(dev, ino, gen)` | the inode survives `mv`: download → rename → execute stays one node |
| socket | `(remote ip, service port, protocol)` | the service port is the smaller one (443, 22, 53), so we don't get one node per ephemeral port |

Paths are resolved **inside the kernel** from the kernel's own file object at the moment of the
event: always absolute, symlinks resolved, correct even if the process exits or closes the fd
right after.

## Mapping to Orthrus / PIDSMaker (`darpa_tc` schema)

| PHIPS | Orthrus `operation` | Edge direction |
|---|---|---|
| CLONE | EVENT_CLONE | parent → child |
| EXEC | EVENT_EXECUTE | file → process |
| OPEN | EVENT_OPEN | file → process |
| READ | EVENT_READ | file → process |
| WRITE | EVENT_WRITE | process → file |
| CONNECT | EVENT_CONNECT | process → netflow |
| SEND | EVENT_SENDTO | process → netflow |
| RECV | EVENT_RECVFROM | netflow → process |
| ACCEPT | (no Orthrus type) | the adapter maps it to EVENT_RECVFROM or drops it |
| EXIT, PROC, META | (not events) | node attributes |

Node labels match what Orthrus tokenises: process = path + command line, file = path,
netflow = remote IP (+ port).

## Limitations (known and accepted for now)

1. **io_uring** I/O does not go through the syscalls we trace, so it is invisible. Falco has the
   same gap. Planned: record `io_uring_setup` so its use is at least visible.
2. **Memory-mapped I/O**: reads/writes through `mmap` are not events; only the `open` is.
   Shared libraries therefore show as open + read of their header.
3. **Local IPC**: Unix-domain sockets (D-Bus, `docker.sock`) and netlink are skipped.
4. **Unconnected UDP receive**: the sender is unknown at syscall entry, so the event is dropped
   (DNS replies on connected sockets are fine).
5. **32-bit programs** on x86_64 are ignored (different syscall numbers).
6. **Paths** longer than 256 bytes or deeper than 40 levels are cut (`path_truncated: true`).
   Container processes show host paths (`/var/lib/docker/overlay2/...`).
7. **De-duplication** keeps the first occurrence per window: with `-d 60`, a process that reads
   then writes then reads the same file within a minute gives one READ and one WRITE.
8. **Not separate events yet**: ptrace/process_vm_writev (injection), setuid (visible as a new
   `euid` on later events), unlink/chmod, kernel module loading, `mmap(PROT_EXEC)`.
9. Under extreme load the ring buffer can fill; drops are counted and logged every minute.
10. A root attacker can stop the collector. Shipping events off the host closes that gap later.

The old captures `testsession.jsonl`, `testsession1.jsonl` and `overnight.jsonl` are schema v1
(time since boot, no flags, thread processes) and are rejected by `graph_builder.py`.
