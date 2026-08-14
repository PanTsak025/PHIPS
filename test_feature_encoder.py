# test_feature_encoder.py
from graph_builder import GraphBuilder
from feature_encoder import FeatureEncoder, hash_string

gb = GraphBuilder()
gb.load_jsonl("testsession1.jsonl")   

fe = FeatureEncoder(hash_dim=32)   
fe.fit(gb)

print("=== 1. determinism check ===")
print(hash_string("bash", dim=32) == hash_string("bash", dim=32))

print("\n=== 2. rarest and most common entities in YOUR real data ===")
scored = []
for node_type, ident in fe.string_counts:
    r = fe.rarity(node_type, {"comm": ident, "path": ident})
    scored.append((r, node_type, ident))
scored.sort()

print("most common (lowest rarity):")
for r, t, ident in scored[:5]:
    print(f"  {r:.3f}  {t:8} {ident}")

print("rarest (highest rarity):")
for r, t, ident in scored[-5:]:
    print(f"  {r:.3f}  {t:8} {ident}")

print("\n=== 3. one real edge, fully encoded ===")
u, v, data = list(gb.graph.edges(data=True))[0]
u_attrs, v_attrs = gb.graph.nodes[u], gb.graph.nodes[v]
vec = fe.transform_edge(data["edge_type"], u[0], u_attrs, v[0], v_attrs)
print(f"edge_type={data['edge_type']}, u={u[0]}, v={v[0]}")
print(f"vector length: {len(vec)}")

print("\n=== 4. total edges the encoder can process ===")
print(gb.graph.number_of_edges())