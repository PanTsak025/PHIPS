from collections import Counter
from graph_builder import GraphBuilder

gb = GraphBuilder()
gb.load_jsonl("testsession1.jsonl")   # use whatever this new capture is named

matches = [key for key in gb.process_nodes if key[0] == 15122]
paths = []
for key in matches:
    for _, obj, attrs in gb.graph.out_edges(("process", key), data=True):
        if attrs["edge_type"] == "open":
            paths.append(obj[1])

print(f"total open edges: {len(paths)}")
print(f"unique paths: {len(set(paths))}")
print()
for path, count in Counter(paths).most_common(15):
    print(f"  {count:5d}  {path}")
