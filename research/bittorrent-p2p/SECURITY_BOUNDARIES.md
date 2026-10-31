# Security boundaries — authenticated local model distribution

## What is enforced, and by what

| Property | Mechanism | Tested here | Result |
|---|---|---|---|
| No contact outside the installation | DHT, LSD, UPnP, NAT-PMP disabled; private torrent; static peer list; testbed has no external route | egress check per run | no external route present |
| Bytes match the approved release | BEP 52 per-file SHA-256 Merkle root in the torrent; per-piece verification; final SHA-256 against the published digest | malicious seeder, 25 % of pieces corrupted | 0 corrupted honest copies |
| A misbehaving peer is cut off | libtorrent smart-ban | same | exchange ended after 1–2 failures |
| Only authorised nodes obtain pieces | SSL torrent: CA certificate embedded in the torrent; TLS mutual auth; leaf CN = release name | rogue-CA and wrong-release intruders | 0 bytes to either intruder |
| No access control without TLS | — | intruder with no certificate, private torrent | **intruder received the full file** |

## Boundaries that are NOT provided (must not be claimed)

1. **Release authenticity.** The torrent proves bytes match *the torrent*.
   Nothing here proves the torrent itself is an approved release. Required: a
   release manifest (model ID, version, digest, minimum version, revocation
   list) signed by the publisher key and verified against a locally installed
   trust anchor before the torrent is accepted. Not built.
2. **Certificate revocation.** libtorrent SSL torrents have no CRL/OCSP. A
   stolen node key works until expiry. Mitigation: short-lived per-release
   certificates (this test used 2 days) and re-issuing the torrent with a new
   CA on compromise. Not tested.
3. **Wildcard certificates.** A leaf with CN `*` is valid for every SSL
   torrent under that CA (observed in the CN experiment). Policy: forbid `*`;
   `bench/pki.py` refuses to issue it.
4. **Confidentiality of the model.** TLS protects pieces in transit only under
   SSL torrents. Without them any node on the segment can read pieces. A
   fine-tuned model can encode customer training data and must carry that
   data's classification.
5. **Cross-domain transfer.** Swarms must never span security domains. Peers
   are configured per domain; nothing here prevents a misconfigured peer list
   from naming a host in another domain except the network itself and the
   certificate scope. Physically separated networks are never bridged.
6. **Denial of service.** A peer can waste bandwidth or connections; smart-ban
   limits repeated bad data, not load. Not tested.
7. **Host compromise.** A compromised authorised node can serve corrupted
   pieces (rejected) and leak the model (not preventable by the protocol).

## Configuration that must be fixed in any deployment

| Setting | Required value | Why (measured) |
|---|---|---|
| `enable_dht`, `enable_lsd`, `enable_upnp`, `enable_natpmp` | false | no discovery outside the provisioned list |
| torrent `private` | true | no PEX/DHT announce |
| SSL torrent | required for restricted or fine-tuned models | private + static alone gave an intruder the whole file |
| leaf CN | the release name, never `*` | scoping; wildcard is valid for every release |
| `max_queued_disk_bytes` | small (4 MiB tested) | default 100 MiB lost all progress on crash; also 131 → 46 MB RSS |
