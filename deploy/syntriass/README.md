# SYNTRIASS — offline single-node installation

Research build. Single node, CPU only, no network at runtime. BitTorrent
distribution (`research/bittorrent-p2p`) is optional and never required.

## 1. Requirements (checked by `syntriass health`)

| Item | Requirement | Check |
|---|---|---|
| CPU | x86-64, ≥ 2 cores, AVX2 (AVX-512 used if present) | `cpu` |
| Memory | ≈ 320 MiB + 2.1 × model file size, available at start (estimate from the measured 1.5B Q8_0 peak of 3690 MiB) | `memory:<model>` |
| OS | Linux, glibc; `libstdc++.so.6`, `libgomp.so.1` | bundle `MANIFEST.json` |
| Python | ≥ 3.10 with numpy (interpretation/retrieval sidecar) | install step 3 |
| Network | none; host must have **no default route** | `offline` (reads routing tables, sends nothing) |
| GPU | not used, not supported | — |

## 2. Build a bundle (staging host, cargo cache populated)

```sh
deploy/syntriass/bundle.sh /media/syntriass-bundle /path/to/llama.cpp/bin \
  models/qwen2.5-1.5b-instruct-q4_k_m.gguf:<sha256> \
  models/qwen2.5-1.5b-instruct-q8_0.gguf:<sha256> \
  [models/<larger>.gguf:<sha256>]
```

A model whose SHA-256 differs from the declared one aborts the bundle. The
bundle carries `MANIFEST.json` (commit, rustc, llama.cpp build, models) and
`SHA256SUMS` over every file. Models and private keys are never committed to
the repository.

## 3. Install (air-gapped host)

```sh
/media/syntriass-bundle/install.sh /media/syntriass-bundle /opt/syntriass /var/lib/syntriass balanced [larger-model-file-substring]
```

Refuses on a host with a default route; verifies `SHA256SUMS`; installs to
`/opt/syntriass/releases/<commit>` and repoints `/opt/syntriass/current`;
creates the state directory (0700) and `config.json` (0600) only if absent;
runs `syntriass health` and exits with its verdict. Then edit `config.json`:
`policy_version`, `security_domain`, approver and expert **public** keys;
create `principals.json` (OS uid → tenant/clearance); ingest documents with
`syntriass ingest`.

## 4. Profiles

| Profile | Model | Resident | Use |
|---|---|---|---|
| `memory` | Q4_K_M | no (load per batch, charged to the request) | smallest idle footprint |
| `balanced` | Q4_K_M | yes | default |
| `speed` | Q8_0 | yes | fastest measured on this CPU class |
| `none` | — | — | capabilities and exact rules only; no model |
| `large` (optional key) | any GGUF | no (on demand) | one bounded escalation when the small tier's output is withheld |

## 5. Start / stop / health

There is no daemon. `syntriass ask` (one authenticated request) and
`syntriass serve --eval` (batch, evaluation only) start the model servers
they need as child processes and stop them on exit. Stop = terminate the
`syntriass` process (SIGTERM); its model servers are children.

```sh
syntriass health --config /var/lib/syntriass/config.json          # exit 0 = all checks pass
syntriass health --config ... --quick                             # skip model hashing (reported as NOT verified, exit 1)
syntriass audit-verify --config ...
```

## 6. Rollback

- **Binary**: `ln -sfn /opt/syntriass/releases/<previous> /opt/syntriass/current.tmp && mv -T /opt/syntriass/current.tmp /opt/syntriass/current`, then `syntriass health`. State is untouched by install, so it is shared across releases.
- **Capability**: `syntriass cap-rollback --config ... --to <superseded-hash> --actor <approver> --reason ...` (approver only; the current version is suspended, the approved older one re-activated).
- **State**: back up the state directory (corpus.db, capabilities/, experiences.jsonl, audit.jsonl) before upgrades; the audit chain is verifiable after restore.

## 7. Unsupported (explicit)

GPUs; multi-node or LAN serving; any configuration with a default route or
public peer discovery; bridging separated networks; persistent KV-cache
checkpoints; consequential (state-changing) capabilities — disabled until
AIP action authorization is integrated; authentication beyond the OS uid map;
`serve --eval` for real users (principals come from input lines); models whose
hash is not in `config.json`.

## 8. Verified here

`bundle.sh` + `install.sh` run on this 2-vCPU / 8 GB host inside a network
namespace with no route: tampered bundle refused, routed host refused, clean
install `health` exit 0 when idle; with two other model servers running the
memory check correctly failed (2061 MiB available < 2558 MiB needed).
