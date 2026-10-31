# Baseline comparison — when does BitTorrent-style distribution beat a central server?

Numbers: EXPERIMENT_RESULTS.md (emulated links, one host). The strongest
central baseline here is a zero-copy HTTP server with Range resume
(`http_range`); it is never worse than `http_plain` and resumes exactly.

| Criterion | Resumable central server | BitTorrent (libtorrent, bounded queue) | Winner |
|---|---|---|---|
| Fleet time, source link = 1 client link (100 Mbit, 5 peers) | 113 s | 48–51 s | **BT, 2.2–2.4×** |
| Fleet time, source link = Σ client links (500 Mbit, 5 peers) | 23 s | 25–31 s | **Central** |
| Bytes leaving the source | 5.0× payload (N copies) | 1.8× (100 Mbit), 3.5–3.9× (500 Mbit) | **BT** |
| Total bytes on the network | 5.0× | 5.5–5.9× (≈ 10–18 % protocol + duplicate overhead) | **Central** |
| CPU (whole fleet) | ~10 s | ~66 s (piece hashing, peer management) | **Central** |
| Memory per node | ~31 MB | ~46 MB (131 MB with libtorrent defaults) | **Central** |
| Resume after a crash | exact (Range) | exact after configuration fix | tie |
| Corruption by a peer | not applicable (one trusted source); detected only by end-to-end hash | rejected per piece; never written into an honest copy | **BT** (needed only because peers serve data) |
| Who can download | anyone who reaches the server unless TLS client auth is added | anyone, unless SSL torrent; then only release-scoped CA certificates | tie — both need PKI |
| Operational complexity | one server, standard tooling | torrent creation, per-node certificates, libtorrent settings, port policy | **Central** |

## The decision rule this measurement supports

BitTorrent-style distribution wins on time **only when the source's uplink is
the bottleneck**, i.e. roughly when

    source uplink  <  (number of nodes updating at once) × (per-node downlink)

and it always saves source egress. On a modern LAN with a 10/25 GbE
distribution server and 1 GbE clients, the central server is not the
bottleneck until ≈ 10–25 simultaneous clients; below that a resumable HTTP
server (or an OCI registry / pull-through cache) is simpler and at least as
fast. Above it — large fleets, constrained or shared site links, repeated
large updates — swarming is the better mechanism.

Not measured, and needed before any customer claim: a real LAN; fleets
larger than 5; multi-GB models; Dragonfly as the alternative P2P system;
customer data on fleet size and update frequency (none exists in this
repository).
