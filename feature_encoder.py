"""
Turn provenance-graph edges into fixed-size numeric vectors for a model.

Each node gets a label string (like Orthrus):
    process -> program path + command line   ("/usr/bin/curl -s -o /tmp/x http://...")
    file    -> path                           ("/tmp/claude/x.sh", "pipe:[641]")
    socket  -> remote address:port/protocol   ("203.0.113.7:80/tcp")

The label is split into tokens and each token is hashed into the vector (feature hashing,
"bag of tokens"). Labels that share tokens get similar vectors: /usr/lib/a.so and /usr/lib/b.so
share "usr" and "lib". Orthrus learns word2vec embeddings over the same kind of tokens; hashing
is the training-free stand-in, good enough to start with.

Edge vector = [edge type one-hot | src type one-hot | dst type one-hot |
               src tokens (dim) | dst tokens (dim) | src rarity | dst rarity]
"""
import hashlib
import math
import re

EDGE_TYPES = ["clone", "exec", "open", "read", "write", "connect", "accept", "send", "recv"]
NODE_TYPES = ["process", "file", "socket"]

# split on path separators, whitespace, '=' ':' ',' and the brackets of pipe:[123]
_TOKEN_RE = re.compile(r"[/\s=:,\[\]]+")


def tokenize(label):
    """'/usr/bin/curl -s http://x' -> ['usr', 'bin', 'curl', '-s', 'http', 'x']"""
    return [t for t in _TOKEN_RE.split(label) if t]


def _hash(token):
    return int.from_bytes(hashlib.sha256(token.encode("utf-8")).digest()[:8], "big")


def hash_tokens(tokens, dim=32):
    """Signed feature hashing: each token adds +-1 to one bucket; the result is L2-normalised."""
    vec = [0.0] * dim
    for tok in tokens:
        h = _hash(tok)
        vec[h % dim] += 1.0 if (h // dim) % 2 == 0 else -1.0
    norm = math.sqrt(sum(v * v for v in vec))
    return [v / norm for v in vec] if norm else vec


def hash_string(s, dim=32):
    return hash_tokens(tokenize(s), dim)


def _onehot(value, categories):
    return [1.0 if value == c else 0.0 for c in categories]


def node_label(node_type, attrs):
    if node_type == "process":
        exe = attrs.get("exe", "")
        cmd = attrs.get("cmdline", "")
        return f"{exe} {cmd}".strip() or attrs.get("comm", "")
    if node_type == "file":
        # pipe:[2798] -> "pipe": the inode number is random per pipe, so keeping it would make
        # every pipe look unique (maximally "rare") and anomalous. The graph keeps the real node.
        if attrs.get("kind") == "pipe":
            return "pipe"
        return attrs.get("path", "")
    if node_type == "socket":
        return f"{attrs.get('remote_addr', '')}:{attrs.get('port', '')}/{attrs.get('proto', '')}"
    return ""


class FeatureEncoder:
    def __init__(self, hash_dim=32):
        self.hash_dim = hash_dim
        self.label_counts = {}   # (node_type, label) -> how many edge endpoints had it in training
        self.total_count = 0
        self.fitted = False

    def fit(self, graph_builder):
        """Count how common each node label is in (benign) training data, for the rarity score."""
        self.label_counts = {}
        self.total_count = 0
        g = graph_builder.graph
        for u, v in g.edges():
            for n in (u, v):
                key = (n[0], node_label(n[0], g.nodes[n]))
                self.label_counts[key] = self.label_counts.get(key, 0) + 1
                self.total_count += 1
        self.fitted = True

    def rarity_of(self, node_type, label):
        """-log(frequency), with +1 smoothing so a never-seen label gets the highest value."""
        if not self.fitted:
            raise RuntimeError("call fit() before rarity()/transform_edge()")
        count = self.label_counts.get((node_type, label), 0)
        return -math.log((count + 1) / (self.total_count + 1))

    def rarity(self, node_type, attrs):
        return self.rarity_of(node_type, node_label(node_type, attrs))

    def transform_edge(self, edge_type, u_type, u_attrs, v_type, v_attrs):
        # rarity is divided by log(total) so it stays in [0, 1] whatever the training size
        scale = math.log(self.total_count + 1) or 1.0
        return (
            _onehot(edge_type, EDGE_TYPES)
            + _onehot(u_type, NODE_TYPES)
            + _onehot(v_type, NODE_TYPES)
            + hash_string(node_label(u_type, u_attrs), self.hash_dim)
            + hash_string(node_label(v_type, v_attrs), self.hash_dim)
            + [self.rarity(u_type, u_attrs) / scale, self.rarity(v_type, v_attrs) / scale]
        )
