# `deploy/pilot/` — BFSI pilot deployment kit

This kit is the **procedure** for the pilot whose scope, threat model and
safety posture are set by `docs/pilot/BFSI_PILOT_PLAN.md`. The plan is the
authority on *what* and *why*; this kit is the authority on *how*. Read the
plan first — in particular §0 (what the pilot does not prove) and §4 (advisory,
non-gating, containment OFF).

## What is buildable **today** vs. what is a **Phase-1 build item**

This kit does not pretend the end-to-end observer pipeline ships. It gives you
the pieces that exist and clearly marks the ones that do not.

| Piece | State | Where |
|---|---|---|
| **Off-host collector key custody** (wrapped key, argon2 + chacha20poly1305, generated on the collector host, dev backend refused) | **buildable today** | `aip-observe`: `CollectorKey::production`, `CollectorSigner::with_custodian` |
| **Evidence API service** (auth, tenant isolation, Postgres backend) | **deployable today** (pilot-grade) | `deploy/docker/` |
| **Offline verifier** for the auditor | **exists today** | `aip-verify` |
| **`aip-probe`** — host-side daemon over the live perf sensors | **built (Phase 1)** — `cargo build --release -p aip-probe`; holds a transport-auth key only | `systemd/aip-probe.service`, `probe.env.example` |
| **Authenticated probe→collector transport** | **built (Phase 1)** — `aip-transport`, std-only TCP, Ed25519 challenge/response + per-frame signatures | `docs/pilot/PHASE1_DAEMONS.md` |
| **`aip-collector`** — daemon: attests authenticated batches under the wrapped key, persists chain state, keeps signed health fresh | **built (Phase 1)** — `cargo build --release -p aip-collector` | `systemd/aip-collector.service`, `collector.env.example` |

**Do not deploy `ghost-demo-collector` in the pilot.** It writes its signing key
to disk in plaintext on the observed host — the exact thing this topology exists
to prevent. It is a restart demonstrator, not a collector.

## Files

| File | Purpose |
|---|---|
| `collector.env.example` | Config for the off-host collector host (key path, passphrase source, strict continuity). |
| `probe.env.example` | Config for the host-side probe (holds no key; names the collector endpoint). |
| `systemd/aip-collector.service` | Unit for the collector daemon (env-driven; install the built binary at /usr/local/bin/aip-collector). |
| `systemd/aip-probe.service` | Unit for the probe daemon (env-driven; install the built binary at /usr/local/bin/aip-probe). |
| `templates/collector-key-provisioning.md` | The one security-critical procedure that is real today: generate the wrapped collector key **on the collector host**. |

## The rule this kit exists to enforce

The signing key is generated on, and never leaves, the **collector host**. The
probe on the observed (agent) host holds no key and cannot sign. This is what
makes the pilot's off-host-attestation claim (plan P3) true rather than
aspirational. If you shortcut it — a shared key, a key copied to the agent host,
the demo plaintext key — you have not run this pilot; you have run the
demonstrator with extra steps, and its guarantee does not hold.

## Order of operations

1. Provision the collector key on the collector host
   (`templates/collector-key-provisioning.md`). Never on an agent host.
2. Stand up the evidence API (`deploy/docker/`) with TLS terminated at the
   institution's ingress proxy (plan B1) — the service speaks plain HTTP.
3. Build and deploy the Phase-1 daemons (plan §7) — probe on agent hosts,
   collector on its own host, authenticated **and confidential** transport
   between them (R9). Start the collector first: it generates its Noise
   static key (`AIP_COLLECTOR_NOISE_KEY_PATH`, `0600`) and prints the public
   half at every start. Pin that value in each probe's
   `AIP_PROBE_COLLECTOR_NOISE_PUBKEY`; a probe refuses to start without it,
   and a probe pinning the wrong key fails the handshake before it is ever
   asked to authenticate. Then add each probe's transport public key (printed
   at its first start) to the collector's allow-list.
4. Run the RED suite on the pilot's own hardware (plan §3) and record results
   in `docs/security/ADVERSARIAL_RESULTS.md`. A pilot without this has not
   established the honesty property.
5. Hand the auditor a signed export bundle; have them reproduce offline
   verification with `aip-verify` (plan P4).

Containment stays **OFF** for the entire pilot (plan §4). This kit ships no
actuation configuration on purpose.
