# Vanian Technologies
## Autonomous Intelligence Trust Infrastructure

**Vanian makes autonomous systems cryptographically accountable.**

When an autonomous agent acts — approves a payment, opens a connection,
writes a file, spawns a process — this system can answer, to a skeptical
third party who does not trust the machine it ran on:

> Who was it? What was it allowed to do? What was it *expected* to do? What
> actually happened? Who observed that? What can be proven, what cannot,
> and can somebody else check the answer without trusting us?

The last question is the one that matters, and it is the one most systems
cannot answer. A proof this system produces is a file. Somebody else runs
one command against it with public keys **they** already trust. Their
program does not read our conclusion — it re-runs the same reconciliation
over the same evidence and checks that it gets the same answer.

---

## The layers, and what each one is for

```text
      AIP            identity and authority
                     who this is, and what it may do
        │
        ▼
  ExpectedExecution  authorized operational intent
                     signed by a decision point that is not the agent
        │
        ▼
   Sniffer Dog       independent runtime observation
                     kernel-sourced, probe holds no key, collector signs off-host
        │
        ▼
  Reconciliation     authorized-vs-observed evidence analysis
                     default answer: CANNOT_PROVE
        │
        ▼
    Warrant          cryptographic authorization for consequential response
                     severity × evidence strength × policy, no arithmetic
        │
        ▼
   Containment       controlled enforcement boundary
                     advisory by default; see the honest note below
        │
        ▼
     NEXORA          persistent provenance and offline verification
                     a portable proof that re-derives instead of asserting
```

Two properties run through all of it.

**Severity and evidence strength never combine into a number.** "How bad
would this be" and "how certain are we" are different questions, and a
high-severity guess is not a proven fact. Evidence strength is
`Heuristic → Correlated → Attested → Proven`, kept in its own type, and
there is no confidence score anywhere.

**Absence of evidence is never evidence of absence.** If the observer was
not watching, the answer is `CANNOT_PROVE` — not "it didn't happen".
Exactly one coverage state licenses a statement about something *not*
having occurred, and reaching it requires attested kernel-pushed coverage
of the exact window.

---

## Capability tiers

Read this section as the answer to "what can I actually rely on today".

### CURRENTLY IMPLEMENTED

Working code with tests, in this repository.

| Capability | Where |
|---|---|
| Identity, scoped tokens, delegation chains with per-hop signatures and lattice scope attenuation | `aip-core` |
| Injective canonical encoding, 26 distinct domain-separated signed structures | `aip-types`, all crates |
| EvidencePacket v1 and its 16-rule verification engine | `aip-protocol` |
| Independent decision point producing signed `ExpectedExecution` | `aip-authorize` |
| Kernel observation: socket state, process fork/exec, socket send, `AF_PACKET` headers, fanotify file writes | `aip-observe` |
| Keyless on-host probe with off-host collector attestation | `aip-observe` |
| Explicit observer health and continuity, with four named break kinds | `aip-observe` |
| Reconciliation engine, eight result classes, `CANNOT_PROVE` by default | `aip-reconcile` |
| Warrant engine over severity × evidence strength × policy | `aip-warrant` |
| Containment gates, cgroup v2 freeze actuator, signed containment records | `aip-containment` |
| Merkle commitment with inclusion and consistency proofs, signed heads | `aip-nexora` |
| Portable proof package, export/import, replay ledger | `aip-nexora` |
| Offline verifier (`nexora-verify`) that re-derives rather than believes | `aip-nexora` |

### VALIDATED

Demonstrated end-to-end on a real kernel, not only unit-tested.

- A real agent process makes a real authorised TCP connection; the kernel's
  socket table is read under a pidfd anchor, attested off-host, and
  reconciled by the engine — `ghost-demo/tests/live.rs`, and the same
  through kernel tracepoints, socket-send, exec and fanotify.
- That live result is packaged as a NEXORA proof, written to disk with
  every runtime value dropped, and verified by a **separate process**
  holding nothing but the file and its own anchors —
  `ghost-demo/tests/live_nexora.rs`.
- Eight mutations of that live package are each refused offline.
- A live execution that did not happen reconciles as `CANNOT_PROVE` and
  stays `CANNOT_PROVE` through the proof layer — never `PHANTOM_CLAIM`.
- 22 adversarial cases against the proof layer, plus a cross-crate audit of
  every signature, hash and encoding it depends on.
- Live evidence is reported as **`Attested`**, and the tests assert it is
  **not `Proven`**.

### PILOT-CAPABLE

Usable in a controlled pilot with a knowledgeable operator, on Linux.

- Single-host observation with an off-host collector.
- Offline verification of exported proofs on a disconnected machine.
- Advisory findings: alerting on reconciliation results, with the evidence
  and its strength attached.

Not suitable for unattended production. The APIs will change.

### DEPLOYMENT-DEPENDENT

Real capabilities whose value depends entirely on how they are deployed.

- **Observer independence** — the collector's key must genuinely be off the
  observed host. Run it on the same host and the guarantee is gone.
- **Trust anchors** — verification proves consistency with the keys the
  verifier chose. Provisioning them correctly, out of band, is the
  operator's job, and the anchor file this repository writes says so in its
  own text.
- **Revocation** — `revoked_jtis` is a list the operator hands the
  verifier. There is no distribution mechanism.
- **Key custody** — keys are software-held, and at rest in the reference
  store they are plaintext JSON.

### NOT YET IMPLEMENTED

Named here so nobody has to guess.

- External anchoring of the commitment head. Without it, a party
  controlling both the log and its archive can truncate history.
- Kernel-resident sensing: no eBPF, no XDP, no in-kernel programs.
- Packet payload inspection. The wire tap reads headers only.
- Post-quantum or hybrid signatures. Two algorithm identifiers exist in the
  type and are **refused**, not implemented.
- Hardware-backed key custody or hardware attestation.
- Autonomous containment (see below).
- Any hosted service, SDK ecosystem, or console.

---

## The honest note about containment

The containment layer is built, gated seventeen ways, and **unreachable
from real evidence** — deliberately.

Containing a workload requires `Proven` evidence. The reconciliation engine
produces every workload-facing result at `Attested`, because its sources
(`/proc` content, socket-table reads, kernel event streams) are attested
observations of a host's own reporting rather than facts a verifier can
independently recompute. The one result it produces at `Proven` is a
sensor-integrity failure — aimed at the observer, capped below containment,
because freezing a workload when a sensor fails is the wrong response to
the wrong party.

We could have made containment reachable by calling attested evidence
proven. That is precisely the substitution this architecture exists to
prevent, so we did not.
`aip-containment/tests/reachability.rs` proves the gap over the engine's
entire producible set, under the most permissive policy an operator could
write, and fails if it ever closes silently.
`docs/architecture/CONTAINMENT_MODEL.md` §10 records what would change the
answer.

**This system cannot autonomously contain a misbehaving agent today, and no
configuration changes that.**

---

## Defense and Sovereign Deployment

The architecture is designed for environments where the network is not
available, not trusted, or not there. **These are deployment targets. None
of them has been validated in its corresponding environment**, and this
section is a description of the design, not a claim of field readiness.

The operational model assumes connectivity is a bonus:

```text
edge / mission system → local autonomous intelligence → AIP identity
  → authority → ExpectedExecution → Sniffer Dog → off-host attestation
  → local reconciliation → warrant → local enforcement → NEXORA proof
  → offline / delayed verification → central system when the link returns
```

**Disconnected operation.** Nothing in the evidence path requires a cloud
service, a directory, or a clock server. There is no mandatory cloud
dependency anywhere in this repository.

**Air-gapped verification.** A proof is a file. The verifier opens no
socket, contacts no service, reads no database, and needs no relationship
to the system that produced it — this is tested by running it as a separate
process with two file paths and nothing else. Trust anchors travel
separately and by a different route, because a verifier that takes its keys
from beside the artifact has verified nothing.

**Edge autonomy.** Reconciliation, warrant evaluation and containment
decisions are local. A severed link degrades what can later be *proven to
others*; it does not stop the local pipeline from producing evidence.

**Delayed synchronisation.** Proofs are durable and order-independent. A
package produced today verifies identically in a decade — and the verifier
reports separately whether the authority behind it has since expired,
because a true statement about the past is not permission to act now.

**Hostile networks.** The wire is not trusted at any point: every record is
signed at rest by the party responsible for it, and the transport carries
nothing that verification depends on.

Deployment targets under consideration — **not validated**: mission
systems, robotics, uncrewed vehicles, industrial autonomy, sovereign AI
deployments, and critical infrastructure. Each has environmental,
certification and safety requirements this repository has not been tested
against.

---

## What must not be claimed

Stated plainly because the temptation runs the other way:

- production readiness, or readiness for field deployment
- post-quantum cryptography, or any hybrid signature scheme
- hardware-backed security, hardware attestation, or hardware roots of trust
- kernel-resident sensing (eBPF, XDP), packet capture, or payload inspection
- universal observation, complete coverage, or zero event loss
- resistance to root compromise of the observed host
- externally anchored history, or truncation resistance
- autonomous containment of a misbehaving agent
- deterministic replay of any model's internal reasoning
- any TRL, throughput figure, latency guarantee, or comparison to another
  system

---

## See it run

```bash
cd aip-standalone

# The original evidence-packet demo, with tamper detection.
cargo run -p banking-demo

# Live kernel observation and reconciliation (Linux; needs procfs + pidfd).
cargo test -p ghost-demo --test live

# A live execution, packaged as a proof and verified in a separate process.
cargo test -p ghost-demo --test live_nexora

# Verify a proof offline, by hand.
cargo build -p aip-nexora --bin nexora-verify
./target/debug/nexora-verify --proof proof.json --anchors anchors.json \
    --max-health-age-ms 3600000 --max-window-tolerance-ms 0
```

## Build & test

```bash
cd aip-standalone
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check

cd ../aip-service   # a separate root; the workspace run does not cover it
cargo test
```

Measured on one 4-vCPU virtual machine, release build: a proof of one
authorised action is ~10.3 kB and verifies cold — parse plus six signature
checks — in ~630 µs. Nothing is known about behaviour at scale, and these
figures are not a specification.

## Documents

Start here if you are doing diligence:

- [`docs/architecture/NEXORA_IMPLEMENTATION_REPORT.md`](docs/architecture/NEXORA_IMPLEMENTATION_REPORT.md)
  — the proof layer, its limitations (§12) and what must not be claimed
  about it (§13).
- [`docs/architecture/FINAL_AUDIT_RECONCILIATION.md`](docs/architecture/FINAL_AUDIT_RECONCILIATION.md)
  — every audit finding, classified FIXED / PARTIALLY FIXED / REMAINING /
  ACCEPTED, including three the work found itself.
- [`docs/architecture/SECURITY_INVARIANTS.md`](docs/architecture/SECURITY_INVARIANTS.md)
  — each invariant with the named test that fails if it stops holding.
- [`docs/architecture/CONTAINMENT_MODEL.md`](docs/architecture/CONTAINMENT_MODEL.md)
  — why enforcement is deliberately unreachable.
- [`docs/architecture/SNIFFER_DOG_PLAIN_ENGLISH.md`](docs/architecture/SNIFFER_DOG_PLAIN_ENGLISH.md)
  — the same system without the jargon, including what it does not do.
- [`docs/IP/INVENTION_REGISTER.md`](docs/IP/INVENTION_REGISTER.md)
  — the distinctive mechanisms, each with its own disclosure status.
- [`AIP_SPEC.md`](AIP_SPEC.md) — the EvidencePacket specification.
- [`AUDIT_CORRECTIONS.md`](AUDIT_CORRECTIONS.md) — what this repository
  previously overstated and what was done about it.

## Status, honestly

A tested evidence architecture with an offline-verifiable proof layer. Not
a product, not a hosted service, not an SDK ecosystem. The APIs will change
and the spec is a draft.

What it is: for every consequential claim there is an implementation, a
stated invariant, an adversarial test, runtime evidence, an independent
verification path, and an explicit failure mode. Where one of those is
missing, the documents say so instead of the README claiming otherwise.

## License

Core protocol and reference implementation: proprietary
(owner: **K. NAGA SRI GANESH**) — **open-sourcing of the spec and core
crates is planned**; see `ROADMAP.md`. Patent matters: provisional filings
exist covering delegation-bound audit binding; see `reports_and_patents/`
(attorney working documents). The mechanisms in
`docs/IP/INVENTION_REGISTER.md` carry their own disclosure status, and none
of them is asserted to be patentable — that requires prior-art search and
counsel.

© 2025–2026 K. NAGA SRI GANESH.
