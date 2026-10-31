# GO / NO-GO — BitTorrent-style model distribution for SYNTRIASS

## Decision

**CONDITIONAL GO as an optional install/update component built on
libtorrent. NO-GO on writing a new protocol. NO-GO on making it a default or
a dependency of single-node installations.**

## Why

| For | Against |
|---|---|
| 2.2–2.4× faster fleet rollout when the distribution server's link is the bottleneck (emulated) | slower than a central server when the server's link is fast (23 s vs 28.5 s) |
| 1.8–3.9× less source egress at every link ratio | ~6.6× more fleet CPU; more memory per node |
| per-piece integrity that keeps a malicious peer's bytes out | needs a PKI, per-release certificates and careful settings; defaults were wrong twice (resume, access) |
| release-scoped, CA-gated swarm membership works offline | release signing, revocation and rollback are not provided by the protocol |
| existing engine (libtorrent 2.1.1) did everything needed | no customer evidence yet that distribution is their bottleneck |

## Conditions before building beyond research

1. **Customer evidence**: at least one target installation where fleet model
   updates are measurably too slow or too heavy on one server. Without it,
   ship a resumable HTTP/OCI distribution and stop here.
2. **Real-LAN measurement** with ≥ 10 nodes and a multi-GB model, against an
   optimised central server *and* Dragonfly.
3. **Signed release manifest** verified before a torrent is accepted (design
   exists in protocol research item 11; not built).
4. Short-lived certificates and a documented compromise procedure (no
   revocation in SSL torrents).

## What to build vs reuse

| Reuse | Build (small) |
|---|---|
| libtorrent (pieces, Merkle v2, swarming, SSL torrents, smart-ban) | release manifest + verifier |
| OpenSSL / an internal CA | per-release certificate issuance policy (no `*`) |
| an HTTP/OCI server as the default path | the fixed settings profile (SECURITY_BOUNDARIES.md) and its conformance test |

## Truthful demonstration

On one machine with emulated 100 Mbit links: five nodes receive a 256 MiB
package in 48 s instead of 113 s; every copy is hash-verified; a corrupting
peer cannot poison any copy; an unauthorised node receives 0 bytes under an
SSL torrent and the whole file without one. Not demonstrable: LAN speed,
fleet scale, customer benefit.
