# Security notes — one page per product (W8.1)

Every statement cites a file on `feature/wow-demos` (AIP) or OVERLAY's local
`feature/wow-demos` (not pushed). "Cannot prove" means no evidence exists yet,
not that the property is false. Measurements: one machine, 4 vCPU, 15 GB RAM,
no GPU. Machine-readable artefacts: `demos/evidence-pack/out/`.

---

## 1. Sniffer Dog — independent observation of an AI agent (AIP)

**What it does.** `aip-probe` watches a process from the kernel (sensors
`sched`, `sockstate`, `connector`, `fanotify`) and holds no key. `aip-collector`
holds the only signing key and signs the observed batches. `aip-observe-verify`
checks them offline with the public key alone.

**Shown.**
- The scripted test agent hides one outbound connection and one file write
  from its own log. Both were caught and attributed to the agent's process
  (pid, start tick, exe sha256): 10/10 lying runs detected, 10/10 honest runs
  clean, from clean commit `24d72c4`
  (`demos/lying-agent/evidence/acceptance-2026-11-07/`).
- Changing one signed byte makes offline verification fail, every run.
- An independent cross-check through auditd (a different kernel subsystem)
  sees the same connection.
- Rehearsal: 10/10 consecutive from the launcher (`docs/demos/REHEARSAL_LOG.md`).

**Cryptography.** Ed25519 signatures (`ed25519-dalek`). The probe-to-collector
transport is `Noise_NK_25519_ChaChaPoly_SHA256` (`snow`). The public-key parts
(Ed25519, X25519) are classical and quantum-vulnerable. `ml-dsa` is also linked; this pack does not establish that
it is used on the evidence path (`demos/evidence-pack/out/sbom-aip.cdx.json`).

**Requirements and limits.**
- Needs root and the host's initial network namespace: the process-connector
  sensor refuses to start inside another namespace (`demos/kit/README.md`).
- The cross-check depends on auditd running. One acceptance batch failed when
  auditd was down after a restart, and is kept as a FAIL.
- This host's clock is not NTP-synchronised. The collector ran with its clock
  check off and signed its worst-case clock error into the evidence.

**Cannot prove.**
- That it catches a real agent framework, or an agent that tries to evade it
  (the agent here is scripted to misbehave).
- Its CPU or memory overhead (not measured).
- That it works on any other kernel (one kernel tested).

**Licence.** AIP crates declare `LicenseRef-Proprietary`. The repository has no
LICENSE file, so the terms are not written down anywhere a buyer can read.

---

## 2. SYNTRIASS Overlay — post-quantum in one switch (OVERLAY, proof of concept)

**What it does.** A library loaded with `LD_PRELOAD` runs the overlay's own
handshake on an ordinary TCP connection and seals the bytes. Per its source,
the handshake is hybrid X25519 + ML-KEM-768, with Ed25519 + ML-DSA-65
signatures, and AES-256-GCM sealing. It is not TLS, and both ends must run it.

**Shown** (OVERLAY `demos/pq-switch/README.md`, evidence at `13c0fb1`):
- The same unmodified `nc` binary (sha256 unchanged in all 6 phases) carries
  the data with the overlay, and the data is not on the wire. Without the
  overlay it is in clear.
- Removing the client's identity, offering a fallback key, connecting a client
  without the overlay, or connecting with an unknown identity: in every case
  nothing is delivered to the server app, and nothing falls back to a weaker
  mode.
- Rehearsal: 10/10 consecutive.

**Cryptography.** The overlay's `self-inventory` lists X25519 and Ed25519
(quantum-vulnerable), ML-KEM-512/768/1024, ML-DSA-65, HKDF/HMAC-SHA256 and
AES-256-GCM (`cbom-overlay-self.cdx.json`). The capture shows a handshake of
about 13 KB, but not which algorithms ran.

**Cost.** About +13.2 KB on the wire per connection. Time added per connection:
median 0.0 to 3.1 ms over 3 runs of n=20, which is not separable from
`docker exec` noise at that sample size.

**Cannot prove.**
- Interoperability with anything else.
- Behaviour on a real network or under load.
- That a static binary is covered (`LD_PRELOAD` cannot reach one).

**Finding.** A refused connection is silent to the application: it exits 0
with no error.

**Licence.** `MIT OR Apache-2.0`, with LICENSE files.

---

## 3. CBOM engine — Quantum X-ray (OVERLAY `syntriass-cbom`)

**What it does.** Scans files, containers and binaries for cryptographic
assets, and writes a CycloneDX 1.6 CBOM, a risk overview and an inert
migration plan. The plan executes nothing.

**Shown.**
- On a synthetic server with 4 planted weaknesses, all 4 were found at their
  paths and nothing was invented: ACCEPTANCE PASS, 10/10 rehearsals
  (OVERLAY `demos/quantum-xray/README.md`).
- Test suite at `eccb668`: 2,054 tests executed in the CBOM pipeline steps,
  0 failed. 1,871 library tests after two fixes made on this branch, both with
  regression tests (nginx directives were skipped; a bare `TLSv1` was rated
  Unknown).

**Limits found.**
- The migration list omits 3DES and TLS 1.0/1.1, and lists one RSA key as 5
  entries.
- RC4 is flagged quantum-vulnerable but 3DES is not.
- Container mode reads only certificate folders.
- `binscan` reports only algorithms that leave recognisable constants. On the
  kit's 6 binaries it found SHA-256 (and AES/MD5 in one), and missed X25519,
  ML-KEM, Ed25519, ML-DSA and AES-GCM, which the overlay library performs
  (`cbom-kit-binaries.cdx.json` against `cbom-overlay-self.cdx.json`).
  **A binary scan is a floor, not an inventory.**
- No verified CNSA 2.0 or NIST IR 8547 policy pack ships, so no control is
  marked met.

**Cannot prove.** Coverage of any real estate (only a synthetic sample was
scanned).

**Licence.** `MIT OR Apache-2.0`.

---

## 4. SYNTRIASS intelligence runtime — taught capability (AIP)

**What it does.** Runs a typed, validated, signed and approved capability for
an organisation's procedure, with no model call on that path. The model is
used only when no capability applies.

**Shown** (recorded results, recomputed in `demos/benchmark/`):
- 37/40 correct with the capability, against 11–13/40 for model-based
  baselines.
- 0 false activations.
- On the 30 items the capability decided, 0 model calls and 0.03 CPU-s in total.

**Do not quote without context.**
- Across all 40 items it is 3.05 CPU-s per task, because 8 probes go to the
  model.
- One run per system, so no variance has been measured.
- One author wrote the procedure, the data and the system.
- The model could not draft the procedure; an engineer's corrections were
  required.

**Cannot prove.**
- That it learns by itself.
- That it transfers to other procedures.
- Human effort or cost (not measured).
- Any rerun in this loop: models are not staged (PR #14 is unmerged).
