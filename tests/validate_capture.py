"""
Consistency checks for collector v3 captures: rules that every correct capture must satisfy.
Run it on any capture, however large (it streams the file):

    python3 tests/validate_capture.py /var/lib/phips/kali-2026-11-26-*.jsonl.gz

ERROR   = the collector produced something impossible (a bug, or a corrupted file)
WARNING = unusual but explainable (listed with the usual reason); look if the count is large
Exit code 1 if there is any ERROR.
"""
import gzip
import ipaddress
import json
import sys
from collections import Counter, defaultdict

FILE_TYPES = {"OPEN", "READ", "WRITE", "EXEC"}
NET_TYPES = {"CONNECT", "ACCEPT", "SEND", "RECV"}
KNOWN = FILE_TYPES | NET_TYPES | {"CLONE", "EXIT", "PROC", "META"}
COMMON = ["ts_ns", "pid", "tid", "ppid", "uid", "euid", "comm", "start_ticks"]
REQUIRED = {
    "CLONE": ["parent_start_ticks"],
    "EXEC": ["filename", "dev", "ino", "gen", "exec_name", "args"],
    "OPEN": ["filename", "dev", "ino", "gen", "access", "created", "fd", "kind"],
    "READ": ["filename", "dev", "ino", "gen", "kind"],
    "WRITE": ["filename", "dev", "ino", "gen", "kind"],
    "CONNECT": ["family", "proto", "raddr", "rport"],
    "ACCEPT": ["family", "proto", "raddr", "rport", "lport", "laddr"],
    "SEND": ["family", "proto", "raddr", "rport", "lport", "laddr"],
    "RECV": ["family", "proto", "raddr", "rport", "lport", "laddr"],
    "EXIT": [],
}
JITTER_NS = 50_000_000  # events from different CPUs can arrive up to ~ms out of order


class Report:
    def __init__(self):
        self.errors = Counter()
        self.warnings = Counter()
        self.examples = defaultdict(list)

    def error(self, what, example):
        self.errors[what] += 1
        if len(self.examples[what]) < 3:
            self.examples[what].append(example)

    def warn(self, what, example):
        self.warnings[what] += 1
        if len(self.examples[what]) < 3:
            self.examples[what].append(example)


def _lines_until_eof(f, path, rep):
    """Yield lines; a gzip file cut short (collector killed, power loss) ends with a warning."""
    try:
        yield from f
    except EOFError:
        rep.warn("gzip file ends abruptly (collector was killed or the file is still being written)",
                 path)


def validate_file(path, rep, stats):
    opener = gzip.open if path.endswith(".gz") else open
    meta = None
    dedupe_ns = 0
    procs = {}            # (pid, start_ticks) -> dict(first_ts, comm, exited_ts, clone_ts, ppid)
    last_sent = {}        # (pid, start, type, dev, ino) -> ts, to verify de-duplication
    inode_paths = defaultdict(set)
    max_ts = 0
    max_backwards = 0
    first_event_ts = None

    with opener(path, "rt") as f:
        for n, line in enumerate(_lines_until_eof(f, path, rep), 1):
            where = f"{path}:{n}"
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                # a capture cut by power loss / kill -9 can end with half a line
                rep.warn("unparseable line (only expected as the very last line)", where)
                continue

            t = e.get("type")
            if n == 1:
                if t != "META" or e.get("schema_version") != 3:
                    rep.error("first line is not a schema v3 META header", where)
                    return
                meta = e
                dedupe_ns = e.get("dedupe_ns", 0)
                continue
            if t not in KNOWN:
                rep.error("unknown event type", f"{where} {t}")
                continue
            if t == "META":
                rep.error("META in the middle of a file", where)
                continue

            stats[t] += 1
            missing = [k for k in (["ts_ns", "pid", "comm", "start_ticks"] if t == "PROC"
                                   else COMMON + REQUIRED[t]) if k not in e]
            if missing:
                rep.error("missing fields", f"{where} {t} {missing}")
                continue

            ts = e["ts_ns"]
            key = (e["pid"], e["start_ticks"])

            if t == "PROC":
                if first_event_ts is not None:
                    rep.error("PROC snapshot line after kernel events", where)
                procs.setdefault(key, {"first_ts": ts, "comm": e["comm"], "snapshot": True})
                continue

            # ---------------- time ----------------
            if first_event_ts is None:
                first_event_ts = ts
            if ts < meta["ts_ns"] - 5_000_000_000:
                rep.error("event older than the file header (clock conversion bug)", where)
            if ts < max_ts:
                max_backwards = max(max_backwards, max_ts - ts)
                if max_ts - ts > JITTER_NS:
                    rep.warn("event > 50 ms out of order (busy CPU; sort by ts_ns when loading)", where)
            max_ts = max(max_ts, ts)
            if e["tid"] == 0 or e["pid"] == 0:
                rep.error("pid/tid 0 (kernel idle task should be filtered)", where)

            # ---------------- process lifecycle ----------------
            p = procs.get(key)
            if t == "CLONE":
                if p and p.get("clone_ts"):
                    rep.error("same process created twice (pid, start_ticks reused)", where)
                if e["start_ticks"] < e["parent_start_ticks"]:
                    rep.error("child started before its parent", where)
                if (e["ppid"], e["parent_start_ticks"]) not in procs:
                    procs[(e["ppid"], e["parent_start_ticks"])] = {"first_ts": ts, "comm": e["comm"]}
                if p is None:
                    p = procs[key] = {"first_ts": ts, "comm": e["comm"]}
                p["clone_ts"] = ts
                continue

            if p is None:
                # first time we see this process and it was not in the snapshot nor cloned:
                # normal only right after the file starts (processes created during the snapshot)
                p = procs[key] = {"first_ts": ts, "comm": e["comm"]}
                if ts - first_event_ts > 2_000_000_000:
                    rep.warn("process appears without CLONE or snapshot "
                             "(lost event, or created while the snapshot ran)", f"{where} {e['comm']}")
            if p.get("exited_ts") and ts > p["exited_ts"] + JITTER_NS:
                rep.error("event from a process after its EXIT", f"{where} {t} {e['comm']}")

            if t == "EXEC":
                p["comm"] = e["comm"]
                p["execed"] = True
            elif e["comm"] != p["comm"]:
                # programs may rename themselves (prctl PR_SET_NAME), e.g. browsers, systemd
                rep.warn("process name changed without EXEC (prctl rename)", f"{where} {p['comm']} -> {e['comm']}")
                p["comm"] = e["comm"]

            if t == "EXIT":
                if p.get("exited_ts"):
                    rep.error("two EXIT events for one process", where)
                p["exited_ts"] = ts
                continue

            # ---------------- objects ----------------
            if t in FILE_TYPES:
                fn = e["filename"]
                if e["kind"] == "pipe":
                    if not fn.startswith("pipe:["):
                        rep.error("pipe without pipe:[ino] name", where)
                elif not fn.startswith("/"):
                    rep.error("relative or empty path", f"{where} {t} {fn!r}")
                if e.get("path_truncated"):
                    rep.warn("path truncated (longer than 256 bytes or 40 levels)", where)
                if e["ino"] == 0:
                    rep.error("inode number 0", where)
                if t == "EXEC" and not e["args"]:
                    rep.warn("EXEC with empty argv (some programs exec with argv[] = {})", where)
                inode_paths[(e["dev"], e["ino"], e["gen"])].add(fn)
                okey = (key, t, e["dev"], e["ino"])
            else:
                try:
                    ipaddress.ip_address(e["raddr"])
                except ValueError:
                    rep.error("remote address does not parse", f"{where} {e['raddr']}")
                if e["rport"] == 0:
                    if t == "CONNECT" and e["proto"] == "udp":
                        # glibc's getaddrinfo() connect()s a UDP socket to each candidate address
                        # (port 0) to learn the source address it would use. No packet is sent.
                        stats["_udp_probes"] += 1
                    else:
                        rep.error("remote port 0", where)
                if t == "ACCEPT" and e["lport"] == 0:
                    rep.error("ACCEPT without local port", where)
                okey = None  # sockets are de-duplicated by socket inode, not visible here

            # ---------------- de-duplication ----------------
            if okey and t != "EXEC" and dedupe_ns:
                prev = last_sent.get(okey)
                if prev is not None and ts - prev < dedupe_ns - JITTER_NS:
                    rep.error("same (process, operation, object) twice inside the de-dup window", where)
                last_sent[okey] = ts

    renamed = sum(1 for paths in inode_paths.values() if len(paths) > 1)
    stats["_renamed_inodes"] += renamed
    stats["_processes"] += len(procs)
    stats["_max_out_of_order_ms"] = max(stats["_max_out_of_order_ms"], max_backwards // 1_000_000)
    if first_event_ts and max_ts:
        stats["_seconds"] += (max_ts - first_event_ts) / 1e9


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    rep, stats = Report(), Counter()
    for path in sys.argv[1:]:
        validate_file(path, rep, stats)

    secs = stats.pop("_seconds", 0) or 1
    probes = stats.pop("_udp_probes", 0)
    print(f"capture: {secs / 3600:.2f} h, {stats.pop('_processes')} processes, "
          f"{stats.pop('_renamed_inodes')} files seen under more than one name (renames), "
          f"max out-of-order {stats.pop('_max_out_of_order_ms')} ms")
    print(f"UDP connect probes to port 0 (name lookups, no traffic; fine): {probes}")
    print("events per hour: " + ", ".join(f"{t} {c * 3600 / secs:,.0f}" for t, c in stats.most_common()))
    for title, counter in (("ERRORS", rep.errors), ("WARNINGS", rep.warnings)):
        print(f"\n{title}: {sum(counter.values())}")
        for what, c in counter.most_common():
            print(f"  {c:7d}  {what}")
            for ex in rep.examples[what]:
                print(f"           e.g. {ex}")
    print("\nRESULT:", "OK" if not rep.errors else "ERRORS FOUND")
    sys.exit(1 if rep.errors else 0)


if __name__ == "__main__":
    main()
