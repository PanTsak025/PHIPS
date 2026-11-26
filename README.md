# PHIPS
Provenance Host-based Intrusion and Prevention System.

An eBPF collector records what every process runs, reads, writes and talks to; the events become a
provenance graph (processes, files and sockets as nodes, system calls as edges) on which a
graph neural network learns normal behaviour, in the spirit of Orthrus (USENIX Security 2025).

| Part | Files | State |
|---|---|---|
| Collector (kernel + user space) | `probe.bpf.c`, `loader.c`, `event.h` | schema v3, see [docs/COLLECTOR.md](docs/COLLECTOR.md) |
| Provenance graph | `graph_builder.py` | done |
| Edge features | `feature_encoder.py` | token hashing + rarity |
| Self-test | `tests/selftest.sh` | 9 end-to-end checks |
| Service | `deploy/phips-collector.service` | `sudo make install` |
| PIDSMaker/Orthrus adapter, GNN | | next |

```bash
make && sudo tests/selftest.sh
sudo ./loader > capture.jsonl
python3 graph_builder.py capture.jsonl
```
