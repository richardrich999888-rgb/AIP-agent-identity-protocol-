# Architecture hypotheses — authenticated local BitTorrent-style model distribution

Scope: distributing an **approved model package** (immutable files) from one
publisher node to N authorised nodes inside one security domain. Not
distributed inference (see `research/compute-memory/BITTORRENT_BOUNDARY.md`).

Order of writing: H1–H5 were fixed in the experiment plan before the matrix
ran (bench/bench.py, run_matrix.sh); H6 was added after iteration 1 exposed
the resume defect; H7 was added for the authorisation test.

| ID | Hypothesis (falsifiable) | Mechanism | Strongest baseline |
|---|---|---|---|
| H1 | When the source uplink is the bottleneck, swarming completes the fleet faster than a central server | peers re-upload verified pieces; aggregate upload grows with N | HTTP server with `sendfile` |
| H2 | Swarming moves fewer bytes out of the source at every link ratio | the source sends each piece ≈ once plus duplicates | same |
| H3 | When the source uplink ≥ Σ client downlinks, the central server is as fast or faster | no bottleneck for swarming to remove; P2P adds bookkeeping | same |
| H4 | Swarming costs more CPU and memory per node | piece hashing, peer state, many connections | same |
| H5 | A peer serving corrupted bytes cannot place them in any honest copy | BEP 52 SHA-256 Merkle verification per piece; smart-ban | HTTP + end-to-end SHA-256 (detects but only after a full transfer) |
| H6 | An interrupted peer resumes without re-transferring verified data | on restart, existing pieces are re-hashed and kept | HTTP Range resume |
| H7 | Only nodes holding a certificate from the publisher CA can obtain pieces | libtorrent SSL torrent: TLS with the CA embedded in the torrent | private torrent + static peer list (no discovery, no access control) |

Architecture under test (reuse, not a new protocol):

```
publisher (approved release)                    authorised node
  model files ──► BEP 52 v2 torrent ──────────►  libtorrent session
  (SHA-256 Merkle roots)   private, v2-only      DHT/LSD/UPnP/NAT-PMP off
                           [SSL: publisher CA]   static peer list
                                                  [SSL: node cert from CA]
                                                  verify every piece
                                                  final SHA-256 = manifest
```

Out of scope and not claimed: a signed release manifest (version, rollback,
revocation) — protocol research item 11; certificate revocation (libtorrent
SSL torrents have none); cross-domain transfer (forbidden).
