# Smoke test of the feature encoder on a real capture.
#     python3 test_feature_encoder.py capture.jsonl
import sys

from feature_encoder import FeatureEncoder, hash_string, node_label
from graph_builder import GraphBuilder

path = sys.argv[1] if len(sys.argv) > 1 else "capture.jsonl"
gb = GraphBuilder()
gb.load_jsonl(path)

fe = FeatureEncoder(hash_dim=32)
fe.fit(gb)

print("=== 1. determinism and similarity ===")
print("same label, same vector:", hash_string("bash", 32) == hash_string("bash", 32))
a, b, c = (hash_string(s, 32) for s in ("/usr/lib/a.so", "/usr/lib/b.so", "/tmp/x.sh"))
cos = lambda x, y: sum(i * j for i, j in zip(x, y))
print(f"similarity /usr/lib/a.so vs /usr/lib/b.so: {cos(a, b):.2f}   vs /tmp/x.sh: {cos(a, c):.2f}")

print("\n=== 2. most common and rarest labels in this capture ===")
scored = sorted((fe.rarity_of(t, lab), t, lab) for (t, lab) in fe.label_counts)
for r, t, lab in scored[:5]:
    print(f"  common {r:6.3f}  {t:8} {lab[:90]}")
for r, t, lab in scored[-5:]:
    print(f"  rare   {r:6.3f}  {t:8} {lab[:90]}")

print("\n=== 3. one edge, fully encoded ===")
u, v, data = next(iter(gb.graph.edges(data=True)))
vec = fe.transform_edge(data["edge_type"], u[0], gb.graph.nodes[u], v[0], gb.graph.nodes[v])
print(f"{data['edge_type']}: {node_label(u[0], gb.graph.nodes[u])[:50]} -> "
      f"{node_label(v[0], gb.graph.nodes[v])[:50]}")
print(f"vector length: {len(vec)}")

print("\n=== 4. edges the encoder can process ===")
print(gb.graph.number_of_edges())
