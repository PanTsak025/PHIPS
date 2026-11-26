"""
Compare a strace log with a collector capture of the same workload (see crosscheck_strace.sh).

Both sides are reduced to sets of (process, TYPE, object):
    object = absolute path, pipe:[ino], "socket", or ip:port for CONNECT
Sets, not counts: the collector de-duplicates repeated identical operations on purpose.
Processes are compared by pid (tgid), because de-duplication is per process.
"""
import json
import re
import sys
from collections import defaultdict

READS = {"read", "pread64", "readv", "preadv", "preadv2", "recvfrom", "recvmsg", "recvmmsg"}
WRITES = {"write", "pwrite64", "writev", "pwritev", "pwritev2", "sendto", "sendmsg", "sendmmsg"}
OPENS = {"open", "openat", "openat2", "creat"}

LINE = re.compile(r"^(\d+)\s+(\w+)\((.*)\) += (.*)$")
FD = re.compile(r"^(-?\d+)<(.*?)>(?:,|$)")


def classify(desc):
    """strace -yy fd description -> ('file', path) | ('pipe', 'pipe:[n]') | ('net', connected) | None"""
    # -yy appends device numbers to device files: "/dev/null<char 1:3>" -> "/dev/null"
    desc = re.sub(r"<(?:char|block) \d+:\d+>?$", "", desc)
    if desc.startswith("/"):
        return ("file", desc.replace(" (deleted)", ""))
    if desc.startswith("pipe:["):
        return ("pipe", desc)
    m = re.match(r"(TCP|UDP)(v6)?:\[(.*)\]", desc)
    if m:
        return ("net", "->" in m.group(3))
    return None  # anon_inode, UNIX, NETLINK...: not recorded by the collector (by design)


def parse_strace(path):
    tgid = {}        # tid -> pid (threads map to their process)
    seen = set()
    pending = {}     # tid -> first half of an <unfinished ...> line
    lines = []
    with open(path) as f:
        for raw in f:
            raw = raw.rstrip("\n")
            m = re.match(r"^(\d+)\s+(.*) <unfinished \.\.\.>$", raw)
            if m:
                pending[m.group(1)] = m.group(2)
                continue
            m = re.match(r"^(\d+)\s+<\.\.\. \w+ resumed>(.*)$", raw)
            if m and m.group(1) in pending:
                raw = f"{m.group(1)} {pending.pop(m.group(1))}{m.group(2)}"
            lines.append(raw)

    root = None
    for raw in lines:
        m = LINE.match(raw)
        if not m:
            continue
        tid, sc, args, ret = int(m.group(1)), m.group(2), m.group(3), m.group(4)
        if root is None:
            root = tid  # the process strace started: its own creation happens before tracing
        tgid.setdefault(tid, tid)
        pid = tgid[tid]
        ok = not ret.startswith("-1") and not ret.startswith("?")

        if sc in ("clone", "clone3", "fork", "vfork") and ok:
            child = int(re.match(r"(\d+)", ret).group(1))
            if "CLONE_THREAD" in args:
                tgid[child] = pid
            else:
                tgid[child] = child
                seen.add((child, "CLONE", ""))
        elif sc in ("execve", "execveat") and ret.startswith("0"):
            name = re.match(r'^(?:\d+<.*?>, )?"(.*?)"', args)
            if name:
                seen.add((pid, "EXEC", name.group(1)))
        elif sc in OPENS and ok:
            r = re.match(r"^\d+<(.*)>$", ret)
            obj = classify(r.group(1)) if r else None
            if obj and obj[0] in ("file", "pipe"):
                seen.add((pid, "OPEN", obj[1]))
        elif sc in ("accept", "accept4") and ok:
            r = re.match(r"^\d+<(.*)>$", ret)
            obj = classify(r.group(1)) if r else None
            if obj and obj[0] == "net":
                seen.add((pid, "ACCEPT", "socket"))
        elif sc == "connect":
            mm = re.search(r'sin6?_port=htons\((\d+)\).*?(?:inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6, "([^"]+)")', args)
            if mm and FD.match(args) and classify(FD.match(args).group(2)):
                seen.add((pid, "CONNECT", f"{mm.group(2) or mm.group(3)}:{mm.group(1)}"))
        elif sc in READS | WRITES | {"sendfile", "splice", "copy_file_range"}:
            fds = []  # (fd description, is_write)
            if sc == "sendfile":
                parts = re.findall(r"-?\d+<(.*?)>", args)
                if len(parts) >= 2:
                    fds = [(parts[1], False), (parts[0], True)]
            elif sc in ("splice", "copy_file_range"):
                parts = re.findall(r"-?\d+<(.*?)>", args)
                if len(parts) >= 2:
                    fds = [(parts[0], False), (parts[1], True)]
            else:
                m2 = FD.match(args)
                if m2:
                    fds = [(m2.group(2), sc in WRITES)]
            for desc, is_write in fds:
                obj = classify(desc)
                if obj is None:
                    continue
                if obj[0] == "net":
                    connected = obj[1]
                    has_dest = "sin_port=" in args or "sin6_port=" in args
                    if not is_write and not connected:
                        continue  # unconnected UDP receive: peer unknown, skipped by design
                    if is_write and not connected and not has_dest:
                        continue
                    seen.add((pid, "SEND" if is_write else "RECV", "socket"))
                else:
                    seen.add((pid, "WRITE" if is_write else "READ", obj[1]))
    return seen, set(tgid.values()), root


def parse_capture(path, pids):
    got = set()
    with open(path) as f:
        for line in f:
            e = json.loads(line)
            t = e["type"]
            if t in ("META", "PROC") or e["pid"] not in pids:
                continue
            if t in ("OPEN", "READ", "WRITE"):
                got.add((e["pid"], t, e["filename"]))
            elif t == "EXEC":
                got.add((e["pid"], t, e["exec_name"]))
            elif t == "CLONE":
                got.add((e["pid"], t, ""))
            elif t == "CONNECT":
                got.add((e["pid"], t, f"{e['raddr']}:{e['rport']}"))
            elif t in ("SEND", "RECV", "ACCEPT"):
                got.add((e["pid"], t, "socket"))
    return got


def main():
    strace_set, pids, root = parse_strace(sys.argv[1])
    cap_set = parse_capture(sys.argv[2], pids)
    # strace cannot see the fork that created the process it starts; the collector can.
    cap_set.discard((root, "CLONE", ""))
    by_type = defaultdict(lambda: [0, [], []])
    for item in strace_set | cap_set:
        row = by_type[item[1]]
        if item in strace_set and item in cap_set:
            row[0] += 1
        elif item in strace_set:
            row[1].append(item)
        else:
            row[2].append(item)

    print(f"processes in the workload: {len(pids)}\n")
    print(f"{'type':8} {'both':>6} {'missed':>7} {'extra':>6}")
    bad = 0
    for t in sorted(by_type):
        both, missed, extra = by_type[t]
        print(f"{t:8} {both:6d} {len(missed):7d} {len(extra):6d}")
        bad += len(missed) + len(extra)
    for t in sorted(by_type):
        for label, items in (("MISSED (strace saw, collector did not)", by_type[t][1]),
                             ("EXTRA (collector saw, strace did not)", by_type[t][2])):
            for it in sorted(items, key=str)[:8]:
                print(f"  {label}: {it}")
    total = sum(r[0] + len(r[1]) for r in by_type.values())
    print(f"\nagreement: {sum(r[0] for r in by_type.values())}/{total} strace observations matched; "
          f"{bad} differences")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
