import hashlib
import math

EDGE_TYPES = ["clone", "exec", "open", "connect"]
NODE_TYPES = ["process", "file", "socket"]

def hash_string(s, dim=32):
    digest = hashlib.sha256(s.encode("utf-8")).digest()
    as_int = int.from_bytes(digest, byteorder="big")

    bucket = as_int % dim

    sign = 1.0 if (as_int // dim) % 2 == 0 else -1.0

    vec = [0.0] * dim
    vec[bucket] = sign
    return vec

def _onehot(value, categories):
    return [1.0 if value == c else 0.0 for c in categories]

class FeatureEncoder:
    def __init__(self, hash_dim=32):
        self.hash_dim = hash_dim
        self.rarity_counts = {}
        self.total_fit_events = 0
        self.fitted = False

    def _identifying_string(self, node_type, attrs):
        if node_type == "process":
            return attrs.get("comm", "")
        elif node_type == "file":
            return attrs.get("path", "")
        elif node_type == "socket":
            return f"{attrs.get('remote_addr', '')}:{attrs.get('remote_port', '')}"
        return ""

    def fit(self, graph_builder):
        self.string_counts = {}
        self.total_count = 0

        for u, v, _ in graph_builder.graph.edges(data=True):
            for node_key in (u, v):
                node_type = node_key[0]
                attrs = graph_builder.graph.nodes[node_key]
                ident = self._identifying_string(node_type, attrs)
                key = (node_type, ident)
                self.string_counts[key] = self.string_counts.get(key, 0) + 1
                self.total_count += 1
 
        self.fitted = True

    def rarity(self, node_type, attrs):

        if not self.fitted:
            raise RuntimeError("call fit() before rarity()/transform_*()")
 
        ident = self._identifying_string(node_type, attrs)
        count = self.string_counts.get((node_type, ident), 0)

        freq = (count + 1) / (self.total_count + 1)
        return -math.log(freq)
 
    def transform_edge(self, edge_type, u_type, u_attrs, v_type, v_attrs):

        edge_onehot = _onehot(edge_type, EDGE_TYPES)
        u_type_onehot = _onehot(u_type, NODE_TYPES)
        v_type_onehot = _onehot(v_type, NODE_TYPES)
        u_embed = hash_string(self._identifying_string(u_type, u_attrs), self.hash_dim)
        v_embed = hash_string(self._identifying_string(v_type, v_attrs), self.hash_dim)
 
        return edge_onehot + u_type_onehot + v_type_onehot + u_embed + v_embed
