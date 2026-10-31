# Protocol research and the first-principles challenge

## BitTorrent mechanisms (from the specifications)

| Mechanism | BEP 3 (v1) | BEP 52 (v2) |
|---|---|---|
| Piece integrity | SHA-1 hash per piece in the metainfo | SHA-256 binary Merkle tree per file over 16 KiB blocks; `pieces root` per file; `piece layers` verified against it |
| Piece size | any | power of two, ≥ 16 KiB |
| File layout | files concatenated; pieces may span files | each file aligned to a piece boundary; identical files have identical `pieces root` |
| Availability | `bitfield` at handshake, `have` on completion | same, plus `hash request` / `hashes` / `hash reject` (IDs 21–23) for Merkle proofs |
| Discovery | tracker (announce) | same; trackers, DHT and PEX are all optional |

Authenticated swarms: libtorrent **SSL torrents** embed the publisher's X.509
certificate in the torrent; every peer must present a certificate signed by
it, with SNI set to the info-hash. This makes swarm membership a publisher
decision rather than "anyone who knows IP:port". The source notes no
revocation mechanism.

## Alternatives that already solve parts of the problem

| Alternative | Solves | Missing for this use |
|---|---|---|
| Central HTTP server + range requests | resume, simple ops | server uplink is the bottleneck for N clients |
| Dragonfly (CNCF) | P2P model distribution, `hf://`, air-gapped seeding described | operates as cluster infrastructure; integrity/signing not discussed in the read source |
| rsync / zsync | incremental updates | still central; per-client server load |
| OCI registry + pull-through cache | content-addressed layers | caches still centralise; a whole model is often one large layer |
| IPFS-style blocks | content addressing, dedup | discovery assumptions oriented to open networks; operational weight |
| libtorrent (BEP 3/52, SSL torrents) | pieces, swarming, resume, v2 Merkle, CA-gated peers | publisher signature over *release metadata* (version, rollback, revocation) is outside the protocol |

## First-principles answers

1. **Why BitTorrent works well.** Every downloader becomes an uploader, so
   aggregate upload capacity grows with the number of peers; the source's
   uplink stops being the limit after the first copy of each piece leaves it.
2. **When it is slower than a central server.** When the server's uplink is
   much faster than the clients' links (a 10/25 GbE server feeding 1 GbE
   clients); when few clients download; when files are small (connection and
   piece bookkeeping dominate); when peers are on the same constrained shared
   segment (swarming cannot exceed the segment's capacity).
3. **Is model distribution a customer bottleneck?** Unknown. A 1–5 GB SLM
   package to tens of machines is minutes on 1 GbE from one server. It matters
   for large fleets, large models, constrained or shared links, or frequent
   updates. No customer data exists in this repository.
4. **Are weights suitable for chunking?** Yes: they are static, large,
   read-only files; GGUF/safetensors are opaque byte arrays with no ordering
   requirement during transfer.
5. **Can chunks be shared without disclosing confidential data?** Model weights
   from a public base model carry no customer data. A *fine-tuned* or
   customer-adapted package can encode training data and must be treated with
   that data's classification; the swarm must then be restricted to peers
   cleared for it.
6. **Authorising peers and versions offline.** Peers: certificates issued by an
   internal CA (libtorrent SSL torrents). Versions: a release manifest signed by
   an approved publisher key, checked against a locally installed trust anchor;
   no online check required.
7. **Chunk reuse across updates.** BEP 52 gives identical files identical roots,
   so unchanged files in a package need not move. A re-quantised or retrained
   weight file changes almost every block, so model updates usually reuse
   little; tokenizer/config/runtime files reuse fully.
8. **Partitions.** Peers on each side keep exchanging what that side has; a
   side with no complete copy of a piece stalls until reconnected. Partial
   files remain verified and resumable.
9. **Does the benefit justify maintaining a protocol?** Only if (a) a measured
   fleet update is too slow or too heavy on one server, and (b) an existing
   engine (libtorrent) is used, not a new protocol.
10. **Relation to System One.** Delivery mechanism for the models System One
    chooses between; no effect on inference quality or cost.
11. **What existing offline tools lack.** Not piece transfer itself. The gap is
    an air-gap release workflow: publisher-signed manifest, version and
    rollback rules, revocation, and binding the swarm to that approval.
12. **What would falsify the value.** Under the target LAN, a central server or
    a pull-through cache completes the fleet update within the maintenance
    window with acceptable server load.

Sources: BEP 3 https://www.bittorrent.org/beps/bep_0003.html ·
BEP 52 https://bittorrent.org/beps/bep_0052.html ·
libtorrent SSL torrents https://blog.libtorrent.org/?p=105 ·
Dragonfly https://www.cncf.io/blog/2026/04/06/peer-to-peer-acceleration-for-ai-model-distribution-with-dragonfly/
