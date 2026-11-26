# Show which files a process touched most.
#     python3 inspect_pid.py capture.jsonl PID
import sys
from collections import Counter

from graph_builder import GraphBuilder

path, pid = sys.argv[1], int(sys.argv[2])
gb = GraphBuilder()
gb.load_jsonl(path)
g = gb.graph

# a pid can belong to several processes over time (pid reuse): one node per (pid, start time)
for node, attrs in g.nodes(data=True):
    if attrs["node_type"] != "process" or attrs["pid"] != pid:
        continue
    print(f"process {pid} started at tick {node[3]}: {gb.label(attrs)}  {attrs.get('cmdline', '')}")
    touched = Counter()
    # reads/opens/execs point file -> process, writes point process -> file
    for src, _, e in g.in_edges(node, data=True):
        if src[0] == "file":
            touched[(e["edge_type"], g.nodes[src]["path"])] += 1
    for _, dst, e in g.out_edges(node, data=True):
        if dst[0] == "file":
            touched[(e["edge_type"], g.nodes[dst]["path"])] += 1
    print(f"  file edges: {sum(touched.values())}, distinct (operation, file): {len(touched)}")
    for (op, p), n in touched.most_common(15):
        print(f"  {n:5d}  {op:6} {p}")
