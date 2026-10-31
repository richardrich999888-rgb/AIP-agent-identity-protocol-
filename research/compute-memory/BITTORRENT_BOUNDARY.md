# BitTorrent boundary — model distribution is not distributed inference

| Question | Distribution (founder's proposal) | Distributed inference (separate, later hypothesis) |
|---|---|---|
| What moves between computers | immutable, hash-verified chunks of an approved model package | activations / KV state for every token of every request |
| When | install and update (rare, bulk) | every request (continuous, latency-critical) |
| What it can reduce | source-server egress, rollout time, re-transfer after interruption, duplicate downloads | per-node RAM for models larger than one node |
| What it cannot reduce | **RAM, KV cache, arithmetic or latency of inference on each node** — every node still loads the full model | nothing about rollout |
| Confidentiality exposure | model weights (approved, possibly sensitive IP); no customer data | **customer prompts**: layer holders see activations from which inputs are recoverable |
| Prior art | BitTorrent BEP 3/52, libtorrent, Dragonfly | Petals |
| Status here | measured on an emulated 5-peer LAN: 48 s vs 113 s when the source link is the bottleneck, 28.5 s vs 23.1 s when it is not; source egress 1.8× vs 5.0×; 0 bytes to unauthorised peers under SSL torrents (`research/bittorrent-p2p/EXPERIMENT_RESULTS.md`, commit a04b864 on `claude/syntriass-airgap-intelligence`) | **not pursued**; incompatible with per-principal confidentiality without further research |

Consequence for compute/memory research: none of the memory or compute
results in this directory depend on, or are improved by, P2P distribution.
It is an install/update lifecycle component, optional for single-node
installations (brief §13). Results that bear on it: E5 (two processes sharing
one mapped model file share its pages — the per-node memory question is
answered by mmap, not by the network).
