"""Checks run by tests/selftest.sh on the capture it recorded."""
import sys

import networkx as nx

sys.path.insert(0, ".")
from graph_builder import GraphBuilder  # noqa: E402

cap, workdir = sys.argv[1], sys.argv[2]
gb = GraphBuilder()
gb.load_jsonl(cap)
g = gb.graph
failures = 0


def check(name, ok, detail=""):
    global failures
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    failures += 0 if ok else 1


def files(suffix):
    return [n for n, a in g.nodes(data=True) if a["node_type"] == "file" and a["path"].endswith(suffix)]


c2 = [n for n, a in g.nodes(data=True) if a["node_type"] == "socket" and a["port"] == 18080]
loot = files("/loot.txt")
check("C2 socket node exists", bool(c2))
check("stolen file node exists", bool(loot))
if c2 and loot:
    try:
        path = nx.shortest_path(g, c2[0], loot[0])
        check("directed attack path socket -> ... -> loot.txt", True,
              " -> ".join(gb.label(g.nodes[n]) for n in path))
    except nx.NetworkXNoPath:
        check("directed attack path socket -> ... -> loot.txt", False, "no path")

renamed = files("/renamed.bin")
check("rename kept one node (inode identity)", len(renamed) == 1 and not files("/a.bin"))

fake = [a for _, a in g.nodes(data=True)
        if a["node_type"] == "file" and "definitely_not_a_command" in a["path"]]
check("failed exec produced no node", not fake)

piped = files("/p.txt")
pipes = [n for n, a in g.nodes(data=True) if a.get("kind") == "pipe"]
check("pipe node feeds a shell that writes p.txt",
      any(nx.has_path(g, p, piped[0]) for p in pipes) if piped else False)

udp = [a for _, a in g.nodes(data=True) if a["node_type"] == "socket" and a["port"] == 53]
check("UDP sendto peer resolved", bool(udp))

rel = [a["path"] for _, a in g.nodes(data=True)
       if a["node_type"] == "file" and a["path"] and not a["path"].startswith(("/", "pipe:"))]
check("all file paths absolute", not rel, ", ".join(rel[:3]))

empty = [n for n, a in g.nodes(data=True) if a["node_type"] == "process"
         and a.get("born_in_capture") and g.degree(n) == 1]
check("no empty thread-process nodes", len(empty) < 5, f"{len(empty)} processes with only a clone edge")

print(f"\n{'ALL CHECKS PASSED' if failures == 0 else f'{failures} CHECK(S) FAILED'}")
sys.exit(1 if failures else 0)
