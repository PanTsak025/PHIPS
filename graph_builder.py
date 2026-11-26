"""
Build a provenance graph from PHIPS collector captures (schema v3).

    python3 graph_builder.py capture.jsonl [more.jsonl.gz ...]

Nodes (and what makes two events refer to the SAME node):
    process   (boot_id, pid, start_ticks)  - start time makes it unique even when a pid is reused
    file      (dev, ino, gen)              - the inode: stays one node across rename / mv
    socket    (remote ip, service port, protocol)

Edges follow the flow of INFORMATION, like Orthrus / DARPA CDM:
    clone    parent  -> child
    exec     file    -> process   (the program's code flows into the process)
    open     file    -> process   (Orthrus also points EVENT_OPEN at the process)
    read     file    -> process
    write    process -> file
    connect  process -> socket
    send     process -> socket
    recv     socket  -> process
    accept   socket  -> process

So "curl downloads x.sh, sh runs it" is the directed path
    socket(203.0.113.7:80) -recv-> curl -write-> x.sh -read-> sh
"""
import gzip
import json
import sys
from collections import Counter

import networkx as nx

MIN_SCHEMA = 3


class GraphBuilder:
    def __init__(self):
        self.graph = nx.MultiDiGraph()
        self.boot_id = None   # from the META line of the file being loaded
        self.meta = []        # every META header seen
        self.stats = Counter()

    # ------------------------------------------------------------------ nodes
    def process(self, pid, start_ticks, comm=None):
        """Return the node key of a process, creating the node the first time it is seen."""
        key = ("process", self.boot_id, pid, start_ticks)
        if key not in self.graph:
            self.graph.add_node(
                key,
                node_type="process",
                pid=pid,
                comm=comm or "",
                exe="",          # program path, filled by EXEC or by the PROC snapshot
                cmdline="",      # arguments, filled by EXEC or by the PROC snapshot
                born_in_capture=False,  # True if we saw its CLONE
            )
        elif comm:
            self.graph.nodes[key]["comm"] = comm
        return key

    def file(self, e):
        key = ("file", e["dev"], e["ino"], e["gen"])
        if key not in self.graph:
            self.graph.add_node(key, node_type="file", kind=e.get("kind", "file"), path=e["filename"])
        else:
            # same inode, possibly a new name after a rename: keep the latest name as the label
            self.graph.nodes[key]["path"] = e["filename"]
        return key

    def socket(self, e):
        # The "service" port identifies the conversation: 443 for a browser talking to a web
        # server, 22 for clients of our sshd. The other side's port is random (ephemeral), and
        # keying on it would create one node per connection.
        lport, rport = e.get("lport", 0), e.get("rport", 0)
        service_port = lport if (lport and lport < rport) else rport
        key = ("socket", e["raddr"], service_port, e.get("proto", ""))
        if key not in self.graph:
            self.graph.add_node(key, node_type="socket", remote_addr=e["raddr"],
                                port=service_port, proto=e.get("proto", ""))
        return key

    def edge(self, src, dst, edge_type, e):
        self.graph.add_edge(src, dst, edge_type=edge_type, ts_ns=e["ts_ns"])
        self.stats[edge_type] += 1

    # ------------------------------------------------------------------ events
    def process_event(self, e):
        t = e["type"]

        if t == "META":
            if e.get("schema_version", 0) < MIN_SCHEMA:
                raise SystemExit(f"capture schema v{e.get('schema_version')} is too old: "
                                 f"re-record it with collector v{MIN_SCHEMA}")
            self.boot_id = e["boot_id"]
            self.meta.append(e)
            return

        if self.boot_id is None:
            raise SystemExit("no META header before the first event: not a collector v3 capture "
                             "(the old testsession*.jsonl / overnight.jsonl files are v1)")

        if t == "PROC":
            # snapshot of a process that was already running when the file started
            p = self.process(e["pid"], e["start_ticks"], e["comm"])
            n = self.graph.nodes[p]
            n.update(exe=e["filename"], cmdline=e["args"], uid=e["uid"], euid=e["euid"])
            return

        subject = self.process(e["pid"], e["start_ticks"], e.get("comm"))
        node = self.graph.nodes[subject]
        node.setdefault("uid", e["uid"])
        node["euid"] = e["euid"]

        if t == "CLONE":
            parent = self.process(e["ppid"], e["parent_start_ticks"])
            node["born_in_capture"] = True
            self.edge(parent, subject, "clone", e)

        elif t == "EXEC":
            f = self.file(e)
            self.edge(f, subject, "exec", e)
            node.update(exe=e["filename"], cmdline=e["args"], comm=e["comm"])

        elif t == "OPEN":
            self.edge(self.file(e), subject, "open", e)

        elif t == "READ":
            self.edge(self.file(e), subject, "read", e)

        elif t == "WRITE":
            self.edge(subject, self.file(e), "write", e)

        elif t == "CONNECT":
            self.edge(subject, self.socket(e), "connect", e)

        elif t == "SEND":
            self.edge(subject, self.socket(e), "send", e)

        elif t == "RECV":
            self.edge(self.socket(e), subject, "recv", e)

        elif t == "ACCEPT":
            self.edge(self.socket(e), subject, "accept", e)

        elif t == "EXIT":
            node["exit_ts_ns"] = e["ts_ns"]
            node["exit_code"] = e.get("exit_code")
            node["exit_signal"] = e.get("signal")

        else:
            self.stats["unknown_event"] += 1

    # ------------------------------------------------------------------ loading
    def load_jsonl(self, path):
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt") as f:
            try:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        self.process_event(json.loads(line))
                    except (json.JSONDecodeError, KeyError) as err:
                        # a capture cut by a crash/power loss can end with half a line
                        print(f"skipping bad line {line_num} in {path}: {err}", file=sys.stderr)
            except EOFError:
                # gzip file cut short (collector killed, or still being written): keep what we read
                print(f"{path}: ends abruptly, using the events before the cut", file=sys.stderr)

    # ------------------------------------------------------------------ report
    @staticmethod
    def label(attrs):
        t = attrs["node_type"]
        if t == "process":
            return attrs.get("exe") or attrs.get("comm", "?")
        if t == "file":
            return attrs.get("path", "?")
        return f"{attrs.get('remote_addr')}:{attrs.get('port')}/{attrs.get('proto')}"

    def summarize(self):
        types = Counter(a["node_type"] for _, a in self.graph.nodes(data=True))
        print(f"total nodes: {self.graph.number_of_nodes()}")
        for t, c in sorted(types.items()):
            print(f"  {t}: {c}")
        print(f"total edges: {self.graph.number_of_edges()}")
        for t, c in sorted(self.stats.items()):
            print(f"  {t}: {c}")

        procs = [(n, a) for n, a in self.graph.nodes(data=True) if a["node_type"] == "process"]
        no_label = sum(1 for _, a in procs if not a.get("exe"))
        print(f"processes without program path (comm only): {no_label}")
        print(f"processes with no edges: {sum(1 for n, _ in procs if self.graph.degree(n) == 0)}")

        print("\nmost active processes (edges in + out):")
        ranked = sorted(procs, key=lambda na: self.graph.degree(na[0]), reverse=True)
        for n, a in ranked[:10]:
            print(f"  pid={a['pid']:<8} edges={self.graph.degree(n):<7} {self.label(a)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    gb = GraphBuilder()
    for p in sys.argv[1:]:
        gb.load_jsonl(p)
    gb.summarize()
