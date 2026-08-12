import json
import sys
import networkx as nx
 
class GraphBuilder:
    def __init__(self):
        self.graph = nx.MultiDiGraph()
        self.process_nodes = {}         # (pid,first_seen_ts) is the key
        self.file_nodes = {}             # (path) is the key
        self.socket_nodes = {}           # (remote_addr, remote_port) is the key
 
        self.active_pid_to_key = {}       # search for the active process by pid
                                         # and then use the key to get the node in process_nodes
 
    def get_or_create_file(self, path):
        if path not in self.file_nodes:
            self.file_nodes[path] = {"node_type": "file", "path": path}
            self.graph.add_node(("file", path), **self.file_nodes[path])
        return ("file", path)
 
 
    def get_or_create_socket(self, remote_addr, remote_port):
        key = (remote_addr, remote_port)
        if key not in self.socket_nodes:
            self.socket_nodes[key] = {
            "node_type": "socket",
            "remote_addr": remote_addr,
            "remote_port": remote_port,
            }

            self.graph.add_node(("socket", key), **self.socket_nodes[key])
        return ("socket", key)
 
    
    def resolve_process(self, pid, event, comm=None):  # here I just check if process was never CLONED
        if pid in self.active_pid_to_key:
            return self.active_pid_to_key[pid]
 
        key = (pid, event["ts_ns"])
        self.process_nodes[key] = {
            "node_type": "process",
            "pid": pid,
            "comm": comm if comm is not None else "",
            "reconstructed": True,   # this process's real birth was never seen
            }
        self.graph.add_node(("process", key), **self.process_nodes[key])
        self.active_pid_to_key[pid] = key
        return key
 
 
    def process_event(self, event):
        etype = event["type"]
 
        if etype == "CLONE":
            child_pid = event["pid"]
            parent_pid = event["ppid"]
            ts = event["ts_ns"]
 
            child_key = (child_pid, ts)
            self.process_nodes[child_key] = {
                "node_type": "process",
                "pid": child_pid,
                "comm": event.get("comm", ""),   # inherited from parent at fork
                "reconstructed": False,
            }
            self.graph.add_node(("process", child_key), **self.process_nodes[child_key])
            self.active_pid_to_key[child_pid] = child_key
 
            parent_key = self.resolve_process(parent_pid, event)
            self.graph.add_edge(
                ("process", parent_key), ("process", child_key),
                edge_type="clone", ts_ns=ts,
            )
 
        elif etype == "EXEC":
            subject_key = self.resolve_process(event["pid"], event, comm=event.get("comm", ""))
            object_key = self.get_or_create_file(event["filename"])
 
            self.graph.add_edge(("process", subject_key), object_key,edge_type="exec", ts_ns=event["ts_ns"])
            # just update with new comm and filename, since the process node already exists from CLONE
            self.process_nodes[subject_key]["comm"] = event.get("comm", "")
            self.process_nodes[subject_key]["exec_filename"] = event["filename"]
 
        elif etype == "OPEN":
            subject_key = self.resolve_process(event["pid"], event, comm=event.get("comm", ""))
            object_key = self.get_or_create_file(event["filename"])
 
            self.graph.add_edge(("process", subject_key), object_key,edge_type="open", ts_ns=event["ts_ns"])
 
        elif etype == "CONNECT":
            subject_key = self.resolve_process(event["pid"], event, comm=event.get("comm", ""))
            object_key = self.get_or_create_socket(event["dst_ip"], event["dst_port"])
 
            self.graph.add_edge(("process", subject_key), object_key,edge_type="connect", ts_ns=event["ts_ns"])
 
        elif etype == "EXIT":
            subject_key = self.resolve_process(event["pid"], event, comm=event.get("comm", ""))
            self.process_nodes[subject_key]["last_exit_ts"] = event["ts_ns"]
 
            # Only retire the active-pid pointer when we know the WHOLE process ended, not just one thread 
            if event.get("group_dead"):
                self.active_pid_to_key.pop(event["pid"], None)
 
        else:
            raise ValueError(f"unknown event type: {etype!r}")
 
    def summarize(self):
        node_type_counts = {}
        for _, attrs in self.graph.nodes(data=True):
            t = attrs.get("node_type", "unknown")
            node_type_counts[t] = node_type_counts.get(t, 0) + 1
 
        edge_type_counts = {}
        for _, _, attrs in self.graph.edges(data=True):
            t = attrs.get("edge_type", "unknown")
            edge_type_counts[t] = edge_type_counts.get(t, 0) + 1
 
        reconstructed = sum(
            1 for a in self.process_nodes.values() if a.get("reconstructed")
        )
 
        print(f"total nodes: {self.graph.number_of_nodes()}")
        for t, c in sorted(node_type_counts.items()):
            print(f"  {t}: {c}")
        print(f"total edges: {self.graph.number_of_edges()}")
        for t, c in sorted(edge_type_counts.items()):
            print(f"  {t}: {c}")
        print(f"process nodes never seen at birth (reconstructed): {reconstructed}")
 
        print("\nmost active processes (by outgoing edge count):")
        out_degrees = [
            (n, self.graph.out_degree(n))
            for n in self.graph.nodes
            if n[0] == "process"
        ]
        out_degrees.sort(key=lambda x: x[1], reverse=True)
        for (node_type, key), degree in out_degrees[:10]:
            comm = self.process_nodes.get(key, {}).get("comm", "?")
            print(f"  pid={key[0]:<8} comm={comm:<20} outgoing_edges={degree}")
 
    def load_jsonl(self, path):
        with open(path) as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    self.process_event(json.loads(line))
                except (json.JSONDecodeError, KeyError) as e:
                    print(f"skipping bad line {line_num} in {path}: {e}", file=sys.stderr)
 
 
if __name__ == "__main__":
    gb = GraphBuilder()
    for path in sys.argv[1:]:
        gb.load_jsonl(path)
 
    gb.summarize()
 
