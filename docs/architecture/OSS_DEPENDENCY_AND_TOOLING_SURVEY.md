# Open-source tooling survey — what may enter the trust path, and what may not

**Status** ENGINEERING ASSESSMENT — adoption decisions, not a procurement list
**Date** 2026-09-14
**Assessed head** `claude/vanian-audit-maturity-addendum-n5ysvd` (production branch
`12767ea` + the Sniffer Dog 3.0 tiers)
**Kernel of record** 6.18.44-fc-v24, capability facts re-verified for this document
**Related** ADR-015 (enforcement boundary), ADR-016 (approval tier),
`APPLICATION_LOG_SENSOR_DECISION.md`, `docs/IP/CLAIM_SUPPORT_MATRIX.md`,
`aip-service/deny.toml`

---

## 0. The question this document answers

"What open-source AI tools, plugins and dependencies exist for the Sniffer Dog
and the accountability stack" is two questions wearing one coat, and conflating
them is how accountability systems quietly lose their accountability.

**Question 1 — what goes in `Cargo.toml`?** A crate in a manifest is code that
runs inside the verifier. It can change what the system concludes. Its
maintainer is now part of the trust boundary.

**Question 2 — what do we run tools *against*?** A tool used to test, compare
or corroborate never gets a vote on a verdict. The AIRI validation record
already states the governing rule:

> *an external tool never becomes a trust anchor by having reported something.*

Every entry below is filed under exactly one of four classes. An entry may not
be promoted between classes without an ADR.

| Class | Meaning | Consequence if compromised |
|---|---|---|
| **DEPENDENCY** | Linked into a crate. Inside the trust boundary. | Can change a verdict. Requires pin + license + advisory review. |
| **REFERENCE INSTRUMENT** | Run beside the system during validation. | Can produce a misleading *comparison*. Cannot change a verdict. |
| **INTEROP TARGET** | A format or wire protocol we emit into or consume from. | Can carry a bad claim *outward*. Never an input to reconciliation. |
| **REJECTED** | Assessed and refused, with the reason recorded. | — |

The standing repository rules that bound every decision here: minimise
dependencies, prefer the standard library, pin versions, avoid unverified
libraries — and, from ADR-015, **the observer does not enforce and must not
link the enforcement path.**

---

## 1. What is in the trust path today

Verified by reading every `Cargo.toml` in the workspace, not by memory.

**Direct third-party crates (accountability core, `aip-standalone/`):**

| Crate | Pin | Used by | Why it is unavoidable |
|---|---|---|---|
| `ed25519-dalek` | `2.1` | `aip-crypto` | The signature scheme itself. |
| `sha2` | `0.10` | `aip-crypto`, `aip-core` | SHA-256 for every domain-separated digest. |
| `rand` | `0.8` | `aip-crypto`, `aip-core`, `aip-protocol` | `OsRng` for key and nonce generation. |
| `argon2` | `0.5` | `aip-crypto` | Key derivation. |
| `chacha20poly1305` | `0.10` | `aip-crypto` | Key-at-rest encryption. |
| `zeroize` | `1.8` | `aip-crypto` | Secret scrubbing. |
| `bs58` | `0.5` | `aip-crypto` | AIP-ID encoding (`derive_aip_id`). |
| `libc` | `0.2` | `aip-observe`, `aip-enforce`, `aip-containment` | Raw syscalls. No wrapper library. |
| `serde` / `serde_json` | `1.0` | most crates | Serialisation. Never the canonical preimage — that is hand-built, prefix-free, in `aip_types::canonical`. |
| `hex`, `base64` | `0.4` / `0.22` | encoding | Display only. |
| `zip` | `2` (deflate only) | `aip-protocol` | NEXORA package container. |
| `clap` | `4` | `aip-cli`, `aip-verify` | CLI only; no crate on the verdict path links it. |

**Service tier (`aip-service/`)** adds `axum 0.7`, `tokio 1`, `tower 0.5`,
`jsonwebtoken 9`, `uuid 1`, `chrono 0.4`, `sha3 0.10`, `tracing 0.1`,
`tracing-subscriber 0.3`, and optional `tokio-postgres 0.7` /
`deadpool-postgres 0.14`.

**Totals:** 276 entries in the single workspace `Cargo.lock`.
`aip-service/deny.toml` enforces a permissive-licence allow-list plus
`LicenseRef-Proprietary`, denies unknown registries and unknown git sources,
and carries exactly one accepted advisory — RUSTSEC-2026-0097, justified in
the file because AIP uses `OsRng` and installs no custom logger.

**The fact that most shapes this survey:** `aip-observe` loads **no eBPF
programs at all.** It reads the kernel through `perf_event_open` on static
tracepoints, the netlink process-event connector, `fanotify`, and `AF_PACKET`
— all through `libc`, with no BPF bytecode of its own. `aip-enforce` likewise
hand-builds its eight-instruction classic-BPF seccomp filter from `libc::sock_filter`
literals. That is not an omission to be fixed by adopting a BPF library; §5.5
explains why it is the design.

---

## 2. Environment constraints that eliminate candidates before evaluation

Re-verified on the kernel of record. A candidate that needs one of these is
not "future work" — it is unrunnable here today, and any claim resting on it
is unevidenced.

| Kernel option | State | What it eliminates |
|---|---|---|
| `CONFIG_BPF_LSM` | not set | Every BPF-LSM enforcement design, including the proposed active interception tier. |
| `CONFIG_KPROBES` | not set | kprobe-based instruments. |
| `CONFIG_FUNCTION_TRACER` | not set | fentry/fexit attachment. |
| `CONFIG_SECURITY_LANDLOCK` | **not set** | The `landlock` crate — the one enforcement primitive that would *not* have needed BPF-LSM. |
| `CONFIG_TCG_TPM` | **not set** | `tss-esapi` and every TPM-quote attestation path. |
| `CONFIG_IMA` | **absent** | Measured-boot / file-integrity anchoring. |
| `CONFIG_INTEGRITY` | not set | Same. |
| `CONFIG_SECURITY_YAMA` | not set | ptrace-scope hardening. |
| — | no in-kernel hash kfuncs (skcipher only; no shash) | In-kernel streaming SHA-256 over a socket stream. |
| `CONFIG_SECCOMP_FILTER` | `=y` | — (available; this is what `aip-enforce` uses) |
| `CONFIG_AUDIT` / `CONFIG_AUDITSYSCALL` | `=y` | — (available, unused; see §6.4) |
| `CONFIG_IO_URING` | `=y` | — (available; an unobserved-submission risk, not a tool) |
| `CONFIG_USER_NS` | `=y` | — (available) |

**The recorded trap stands.** `CONFIG_LSM="...,bpf"` in the boot string and
`BPF_PROG_TYPE_LSM` present in BTF are **not** evidence the feature works.
Neither is a crate that compiles.

**Consequence for the strategy brief.** Its TEE/measured-boot recommendations
cannot be exercised on this host at all — no TPM, no IMA. That is the same
class of environmental blocker as the missing kprobes, and it must be reported
that way rather than as a backlog item.

---

## 3. Decisions at a glance

| # | Gap | Candidate | Class | Call |
|---|---|---|---|---|
| 1 | Fork-consistency of the collector head (IR-08) | `ct-merkle 0.3.0` | DEPENDENCY | **ADOPT** (scoped to a new crate) |
| 1 | — | Sigstore Rekor v2 / `sigstore-rs 0.14.0` | INTEROP TARGET | **EVALUATE** — external witness, not a library |
| 2 | ML-DSA absent behind `AlgorithmId::MlDsa65` | `ml-dsa 0.1.1` (RustCrypto) | DEPENDENCY | **EVALUATE** — do not ship on this crate alone |
| 2 | — | `fips204 0.4.6` | — | **REJECT** — 21 months without a release |
| 2 | — | `oqs 0.11.0` (liboqs FFI) | — | **REJECT** — C FFI into the signature path |
| 3 | Hardware root of trust (`RootOfTrust::{Atecc608b,Tpm2}` unimplemented) | `tss-esapi 7.7.0` | DEPENDENCY (deferred) | **BLOCKED** — no TPM on the kernel of record |
| 4 | Hand-rolled seccomp filter | `seccompiler 0.5.0` | DEPENDENCY | **REJECT** — 8 instructions is not a dependency |
| 5 | eBPF loading | `aya 0.14.0` / `libbpf-rs 0.27.1` | REJECTED as dependency / REFERENCE INSTRUMENT | **REJECT for the probe**; keep for adversary simulation |
| 6 | Second enforcement primitive | `landlock 0.4.7` | — | **BLOCKED** — `CONFIG_SECURITY_LANDLOCK` not set |
| 7 | Physical validation environments (roadmap stages 2, 5) | ROS 2 Jazzy + Gazebo Harmonic; PX4 SITL | REFERENCE INSTRUMENT | **ADOPT** for validation only |
| 8 | Agent/MCP input surface | `mcp-scan`, Cisco `mcp-scanner` | REFERENCE INSTRUMENT | **EVALUATE** — comparison baseline, never an input |
| 9 | Outward interop | OTel GenAI semconv; in-toto/DSSE; SLSA | INTEROP TARGET | **EVALUATE** — emit-only, one-way |
| 10 | eBPF runtime-security field | Falco, Tetragon, Tracee | REFERENCE INSTRUMENT | **ADOPT** as comparison baselines |

---

## 4. Gap 1 — external anchoring and fork consistency

### 4.1 The gap, stated from the repository

`IR-08` records the boundary precisely. External anchoring of the collector
head is listed as an *alternative embodiment* that "would additionally defeat
truncation by a party who controls both the collector and its archive", and the
status line is unambiguous: **"External anchoring: interface present, not
exercised against any external service."**

The collector hash-chains its batches, so a verifier can detect an edit
**within a chain it holds**. Two properties it cannot supply on its own:

- **Truncation resistance** against a party controlling collector and archive
  — the case IR-08 names.
- **Fork consistency** — the collector showing two different, internally
  consistent chains to two verifiers. IR-08 does not name this one, and
  nothing in the repository provides it.

This matters more than it sounds. Every `Proven` classification in the system
rests on signature arithmetic over held bytes. A fork does not break the
arithmetic — it makes two mutually inconsistent sets of bytes both verify.

### 4.2 `ct-merkle` — ADOPT, scoped

| | |
|---|---|
| Version | `0.3.0` (latest; updated 2026-05-23) |
| Licence | MIT OR Apache-2.0 — both on the `deny.toml` allow-list |
| Downloads | 165,121 total / 127,822 recent |
| Repository | `github.com/rozbb/ct-merkle` |
| What it is | RFC 6962 append-only log: inclusion proofs, consistency proofs, verification |

**Why this one.** The problem is exactly the Certificate Transparency problem,
RFC 6962 is the specification that solved it, and `ct-merkle` implements that
specification and nothing else. It computes proofs; it does not hold keys, open
sockets, or decide anything. Its failure mode is a wrong proof, which the
verifier's own recomputation catches — the same posture as `recompute_coverage`
and NEXORA's `rederive`, both of which already refuse to read a conclusion out
of the artifact under judgement.

**Scope of adoption.** A new crate — proposed `aip-anchor` — depending on
`ct-merkle`, `sha2` and `aip-types` only. It must not be linked by
`aip-observe`, `aip-reconcile`, `aip-warrant` or `aip-containment`; the same
manifest-fence test `aip-approval` and `aip-enforce` already carry applies.
Consistency-proof failure produces a **new observer-directed finding**, never a
workload verdict — the ADR-015 boundary holds.

**What adoption does not buy.** A Merkle log proves the *log* is append-only.
It does not prove the log contains everything that happened. Coverage remains
`aip-observe`'s question, and the loss signals it derives from `ENOBUFS`,
`fanotify` queue overflow and the perf ring stay the only evidence of omission.
Say this out loud in the ADR, because "we added a transparency log" is exactly
the sentence that gets misread as "we closed the coverage gap."

### 4.3 Sigstore Rekor v2 — INTEROP TARGET, evaluate

Rekor v2 (`rekor-tiles`) went GA in October 2025 on a tile-backed
Trillian-Tessera backend, and — the part that matters here — **integrates
witnessing directly**, with an M-of-N trusted witness set distributed through
Sigstore's TUF root. That is a running, operated answer to fork consistency,
which is the expensive half of the problem: `ct-merkle` gives the mathematics,
but a witness set is an *operational* commitment somebody has to run.

Two cautions, both recorded rather than resolved:

1. **Anchoring publishes.** Submitting a head to a public log discloses that
   an event occurred at a time, to anyone. For a defence or BFSI deployment
   that may be unacceptable, and a private witness federation is then the only
   option — which returns the operational cost to us.
2. **The 2025 instance will be turned down** when a 2026 instance deploys, and
   Sigstore's own guidance is not to hardcode instance URLs. Any integration
   must treat the log endpoint as configuration, never as a constant.

`sigstore-rs 0.14.0` (Apache-2.0, 946k downloads) exists and is described by
its own authors as **experimental**. It is not a dependency candidate on that
description alone. Evaluate it as a client at the boundary, in a binary, never
in a verdict-path crate.

---

## 5. Gaps 2–6 — the crypto and kernel candidates

### 5.1 ML-DSA: `ml-dsa 0.1.1` — EVALUATE, with a condition

The state of the code is unambiguous and must not be softened:
`AlgorithmId::MlDsa65` is a **wire enum variant with no implementation behind
it**, and its only appearance in `aip-crypto` is a *negative* test asserting
that an Ed25519 signature mislabelled `MlDsa65` must not verify. "Post-quantum
stack" must not appear in any investor or procurement material until that
changes.

| | |
|---|---|
| Version | `0.1.1` (RustCrypto, updated 2026-06-05) |
| Licence | Apache-2.0 OR MIT — allowed |
| Downloads | 2,610,159 total / 1,631,010 recent |
| Audit status | **never independently audited**, per its own README |
| Known history | CVE-2026-24850 (CVSS 5.3): verification accepted signatures with **duplicate hint indices**, violating the FIPS 204 "strictly increasing" requirement — signature malleability. Affected ≤ `0.1.0-rc.3`; patched in `0.1.0-rc.4`. |

That CVE is the reason this is EVALUATE and not ADOPT, and it is worth being
precise about why. The bug was **in verification, accepting something it should
have refused.** This system's entire `Proven` tier is the proposition that a
third party recomputing signature arithmetic reaches the same answer. A
verifier that accepts malleable signatures does not merely have a bug; it
weakens the one class of evidence the architecture treats as strongest. The
fix landed pre-1.0, which is the right place for it to land — but a pre-1.0,
unaudited implementation of a lattice scheme is not something to put under
`Proven` on its own.

**Condition for adoption:** hybrid only. `AlgorithmId::Hybrid = 0x03` already
exists in the enum. Ed25519 remains mandatory and ML-DSA is additive, so a
soundness bug in the lattice implementation cannot by itself make a bad
signature verify. Ship `Hybrid` before, or at worst alongside, `MlDsa65`;
never `MlDsa65` alone.

**Rejected alternatives.** `fips204 0.4.6` — last released 2024-12-22, 21
months of silence, and an unmaintained cryptographic primitive is a liability
regardless of its quality on the day it stopped. `oqs 0.11.0` / `pqcrypto` —
FFI wrappers around C (liboqs / PQClean). Introducing a C dependency into the
signature verification path of a system whose credibility rests on
recomputable arithmetic trades a memory-safety guarantee for a convenience.
Refuse it.

### 5.2 Adjacent and actionable: `ed25519-dalek` is a major version behind

`aip-crypto` pins `ed25519-dalek 2.1`. The current release is **`3.0.0`**
(updated 2026-07-06). This is the crate that performs every signature
operation the `Proven` tier depends on. A major-version bump needs a deliberate
API and behaviour review — it is not a survey finding to be actioned casually —
but leaving the core signature dependency a major version behind is a
diligence question that will be asked. Raise it as its own task.

Related and already tracked: `deny.toml` notes a planned `rand 0.9` upgrade,
which is the correct closure for accepted advisory RUSTSEC-2026-0097 rather
than a permanent ignore entry.

### 5.3 TPM attestation: `tss-esapi 7.7.0` — BLOCKED, not deferred

| | |
|---|---|
| Version | `7.7.0` stable (`8.0.0-alpha.3` newest); updated 2026-08-24 |
| Licence | Apache-2.0 — allowed |
| Downloads | 3,460,279 total / 878,401 recent |
| Maintainer | `parallaxsecond/rust-tss-esapi` — the mainstream Rust TSS 2.0 wrapper |

The crate is healthy. The **host is not**: `CONFIG_TCG_TPM` is not set and
`CONFIG_IMA` is absent. There is no TPM to quote and no measured-boot chain to
quote about. `RootOfTrust::Tpm2` therefore stays an unimplemented variant, and
`aip-enforce` keeps refusing a provenance upgrade before the signature check
(`EpochError::RootOfTrustMismatch`) — which is the correct fail-closed
behaviour for a capability that does not exist.

Note the adjacent development rather than adopting it: Keylime's push-model
attestation ships a Rust agent in RHEL 10.2. It is the right thing to read
before designing this tier. It is not something to depend on from a host with
no TPM.

**The honest framing for external audiences:** hardware-rooted attestation is
*designed for* (`RootOfTrust` is a closed enum with the variants named and the
mismatch refusal implemented) and *not implemented*. Both halves, every time.

### 5.4 `seccompiler 0.5.0` — REJECT

Well-maintained (rust-vmm, 20M downloads, Apache-2.0 OR BSD-3-Clause), and
irrelevant here. `aip-enforce` needs **eight** classic-BPF instructions:
architecture check, two syscall comparisons, three returns. They are written
out as `libc::sock_filter` literals, each one readable, with the
`SECCOMP_RET_KILL_PROCESS` architecture-mismatch branch visible at the top.

Adding a dependency to generate eight instructions trades an auditable
artifact for an opaque one, in the one file where an examiner or a reviewer
most needs to see exactly what the kernel was told. Reject. Revisit only if
the filter grows a syscall table large enough that hand-writing it becomes the
error-prone option — and record that threshold when it is crossed, rather than
drifting across it.

### 5.5 `aya` / `libbpf-rs` — REJECT as dependency, KEEP as reference instrument

| Crate | Version | Licence | Downloads (total / recent) |
|---|---|---|---|
| `aya` | `0.14.0` (2026-06-24) | MIT OR Apache-2.0 | 3,816,239 / 1,453,024 |
| `libbpf-rs` | `0.27.1` (2026-09-03) | LGPL-2.1-only OR BSD-2-Clause | 7,421,861 / 1,464,961 |

Both are mature. Neither belongs in the probe, for a reason that is
architectural rather than technical.

**The current probe loads no code into the kernel.** It opens tracepoints,
reads netlink, reads `fanotify`, reads `AF_PACKET`. Every one of those is the
kernel *pushing* facts at a reader. Loading a BPF program inverts that: the
observer becomes a program running in the kernel, whose correctness the
verifier must now also trust, and which can itself be blinded.

The repository already proved that this is not hypothetical. The
observation-integrity work found that **any co-resident eBPF program on a
sampled tracepoint** can interfere — reproduced with a two-instruction BPF
program, mitigated through `PERF_EVENT_IOC_QUERY_BPF` foreign-program
enumeration and `ObserverState::IntegrityUnknown` (code `0x06`), and
re-verified against the reproduction. Adopting a BPF loader would put the
observer into the exact population it learned to be suspicious of.

Note also the licence: `libbpf-rs` is `LGPL-2.1-only OR BSD-2-Clause`. The
BSD-2-Clause branch is on the allow-list, so `cargo-deny` passes — but a
dual-licence where one branch is copyleft is a thing to elect explicitly in
writing, not to acquire by default.

**Where they stay useful:** building adversary programs for the
observation-integrity test suite. `aya` is preferred there — pure Rust, no C
toolchain, no libbpf runtime — and it lives in the validation tree, never in a
workspace member.

### 5.6 `landlock 0.4.7` — BLOCKED

Healthy crate (15.5M downloads, MIT OR Apache-2.0, updated 2026-07-27), and
it would have been the most attractive enforcement primitive available: an
unprivileged, non-BPF LSM needing no `CONFIG_BPF_LSM`. **`CONFIG_SECURITY_LANDLOCK`
is not set on the kernel of record**, so it is unavailable here.

This is worth carrying forward as a *deployment requirement* rather than a
dead end. Unlike BPF-LSM, Landlock is enabled by default on mainstream
distribution kernels. If the deployment target is a stock Ubuntu or RHEL host
rather than this one, Landlock is available there — and it is the cheapest
path to a second, independent enforcement primitive beside seccomp. Record the
kernel-configuration requirement in the deployment profile and re-test on the
target kernel; do not claim it on the strength of the crate compiling.

---

## 6. Reference instruments — used beside the system, never trusted by it

These are how we answer "is our answer right?" — by comparison against an
independent tool. The rule from the AIRI validation holds without exception:
**an external tool never becomes a trust anchor by having reported something.**
A disagreement between AIP and any tool below is a prompt to investigate, not
evidence of anything.

### 6.1 Falco / Tetragon / Tracee — ADOPT as comparison baselines

The three mainstream eBPF runtime-security projects, with genuinely different
postures: Falco is behavioural anomaly detection enriched with container and
Kubernetes metadata; **Tetragon performs in-kernel enforcement** (terminating
processes, dropping connections); Tracee targets forensic syscall tracing at
higher overhead.

Tetragon is the instructive one, and `COMPETITIVE_POSITIONING.md` §3 already
treats it as such. It occupies the position ADR-015 deliberately refused:
observation and enforcement in one component. Running it beside AIP on the
same workload is the cleanest way to make the architectural difference
demonstrable rather than asserted — *this is what a combined component
concludes; this is what a separated one concludes; here is the case where they
differ.*

Note that all three need the kernel features this host lacks, so a comparison
bench needs a different kernel than the one of record. Plan for it; do not
discover it mid-benchmark.

### 6.2 ROS 2 Jazzy + Gazebo Harmonic — ADOPT for roadmap stage 2

ROS 2 Jazzy with Gazebo Harmonic on Ubuntu 24.04 is the current mainstream
robotics simulation pairing, with sensor plugins that model IMU drift, GPS
precision and depth cameras.

**The ceiling must be stated with the adoption.** Simulation evidence is
`TEST-PROVEN`. It is not `EXECUTION-PROVEN` and never becomes
`REAL-WORLD PROVEN` by increasing simulation fidelity. Robotics
accountability stays at **TRL 4**, and physical autonomous-system
accountability at **TRL 2–3**, until something moves in the physical world
under observation. A simulator that renders beautifully is the most seductive
way to skip that step.

### 6.3 PX4 SITL — ADOPT for roadmap stage 5, with the gap named

PX4 SITL with Gazebo is the standard UAS software-in-the-loop environment
(`make px4_sitl gz_x500`), and `px4_ros_com` bridges PX4 topics into ROS 2.
Published work notes that PX4 **lacks native provisions for
hardware-in-the-loop validation** — which is precisely the boundary the UAS
profile has to cross, and precisely where SITL stops helping.

### 6.4 Already present and unused: the kernel audit subsystem

`CONFIG_AUDIT=y` and `CONFIG_AUDITSYSCALL=y` on the kernel of record. This is
an independent, kernel-pushed record path that costs no new dependency.

It is **not** a candidate observation source — `APPLICATION_LOG_SENSOR_DECISION.md`
(Gate 5, DECIDED) fenced host-side self-reporting out of observation, and while
auditd is kernel-generated rather than application-generated, admitting it needs
its own gate decision with its own loss-signal analysis, not a nod in a survey.

It **is** a first-class reference instrument, and the best one available on
this host: a second kernel-side record of the same syscalls the probe sampled,
against which the probe's coverage claims can be independently checked. That is
a cheap, high-value validation exercise that needs no procurement and no new
code in the trust path.

### 6.5 MCP security scanners — EVALUATE, comparison only

`mcp-scan` (Invariant Labs, Apache-2.0, since acquired by Snyk and rebranded
Agent Scan) detects prompt injection, tool poisoning and rug pulls in MCP
servers, with tool pinning that hashes tool descriptions to catch silent
post-install changes. Cisco's `mcp-scanner` is the YARA-based alternative.

Two observations that matter more than the tools themselves:

1. **Tool pinning is a hash-comparison mechanism against a sealed prior
   description** — structurally the same move as `ExpectedExecution` and as
   `aip-approval`'s shown-versus-authorized comparison. It is prior art
   adjacent to the approval tier and should be read before any filing that
   touches artifact pinning. `CLAIM_SUPPORT_MATRIX.md` §5 already states no
   prior-art search has been performed; this is a concrete place to start one.
2. **Detection is not accountability.** A scanner answering "does this tool
   description look malicious?" is making a judgement about content. This
   system's entire position is that content-derived findings are pinned at
   `Attested` and can never be `Proven`, because root can forge the bytes. A
   scanner's verdict would enter at `Heuristic` at best, and must never be
   allowed to raise a strength.

Use them as baselines. Do not integrate them as inputs.

---

## 7. Interop targets — one-way, outward

The rule for all three: **emit-only.** A format we export into cannot become a
path by which an external claim re-enters reconciliation, because the
reconciler has exactly one choke point — `Draft`, `prologue`,
`precondition_holds` — and a second authority is precisely what ADR-016 §4
forbids.

### 7.1 OpenTelemetry GenAI semantic conventions — EVALUATE

The conventions now model an agent run as a span tree — `invoke_agent`
containing `chat` and `execute_tool` children — and coding agents including
Claude Code, Codex and Copilot already emit them. As of the v1.42.0 release
(12 June 2026) the `gen_ai.*` attributes moved into a dedicated repository.

**Every `gen_ai.*` attribute, span, metric and event still carries the
"Development" stability badge. None is marked Stable.** Treat it as a
pre-stable export format: useful for landing AIP evidence in a customer's
existing observability plane, not something to build a contract on. Names can
change between versions.

The deeper point is one the standard cannot fix: an OTel span is **the agent's
self-report**. It is the `Claimed` side of the reconciliation, and it is
structurally the same kind of artifact as the application logs Gate 5 fenced
out. Exporting AIP's independently-observed side alongside it is valuable
precisely *because* the two can disagree. Emitting AIP conclusions as spans
and letting them mingle with self-reports in the same trace would destroy the
distinction the whole system exists to maintain.

### 7.2 in-toto / DSSE / SLSA — EVALUATE for the NEXORA envelope

in-toto attestations in DSSE envelopes are the established format for signed
statements about artifacts, and SLSA is the OpenSSF framework built on them.
NEXORA already produces a self-contained verifiable package whose claim is
re-derivable from its own evidence (`rederive`, `ClaimNotDerivable`). Wrapping
that in a DSSE envelope would make it consumable by existing supply-chain
tooling at low cost.

`in-toto 0.4.0` (the Rust implementation) was last updated **2024-12-11** with
1,554 recent downloads. That is not a dependency to take. Implement the
envelope format directly if the interop is wanted — DSSE is a small, stable
specification, and the repository already hand-builds its canonical encodings
for exactly this kind of reason.

### 7.3 IETF SPICE `draft-mw-spice-intent-chain`

Already identified in `CLAIM_SUPPORT_MATRIX.md` §4 as the closest neighbour
and the right interop target. The relationship restated: SPICE chains
*content provenance*; this system reconciles *sealed intent against
independently observed execution*. Track it; do not compete with it.

---

## 8. What this survey does not establish

- **That any recommended crate is safe.** Download counts and release dates
  measure popularity and activity, not correctness. `ml-dsa`'s CVE-2026-24850
  is the standing counter-example: 2.6M downloads and a verification
  soundness bug.
- **That the adopt calls are approved.** Every DEPENDENCY entry needs an ADR
  before it reaches a manifest. `ct-merkle` in particular needs the crate
  boundary, the manifest fence, and the observer-directed-finding design
  settled first.
- **That the blocked items are merely deferred.** Landlock, TPM attestation
  and BPF-LSM are unavailable on the kernel of record. Until they are tested
  on a kernel that has them, they are **unevidenced**, and the external framing
  is "designed to support", never "supports".
- **That the reference instruments agree with AIP.** None has been run beside
  it yet. §6 recommends the comparisons; it does not report results, and no
  result from any of them may raise an evidence strength when they are run.
- **Any prior-art or freedom-to-operate conclusion.** §6.5 notes that MCP tool
  pinning is structurally adjacent to the approval tier. That is an engineering
  observation and an instruction to search, not a novelty opinion.

---

## 9. Immediate actions, in order

1. **Raise `ed25519-dalek 2.1 → 3.0.0`** as its own task with an API review.
   It is the crate the `Proven` tier rests on and it is a major version behind.
2. **Close RUSTSEC-2026-0097 properly** by executing the `rand 0.9` upgrade
   `deny.toml` already names, rather than extending the ignore.
3. **Run the auditd comparison** (§6.4). No dependency, no procurement, and it
   independently tests the probe's coverage claims on the host we have.
4. **Write the `aip-anchor` ADR** before touching a manifest — crate boundary,
   manifest fence, observer-directed finding, and the explicit statement that
   fork consistency is not coverage.
5. **Record the Landlock kernel requirement** in the deployment profile so the
   target-kernel question is asked before a customer environment is chosen,
   not after.

---

**Sources.** ct-merkle, aya, libbpf-rs, tss-esapi, seccompiler, landlock,
sigstore, ml-dsa, fips204, pqcrypto-mldsa, oqs and ed25519-dalek metadata read
from the crates.io API on 2026-09-14. CVE-2026-24850 from the RustCrypto
signatures advisory (GHSA-5x2r-hc65-25f9). Rekor v2 witnessing from the
Sigstore project blog and `sigstore/rekor-tiles`. OTel GenAI stability status
from the OpenTelemetry semantic-conventions registry and the v1.42.0 release
notes. Kernel capability facts verified directly on 6.18.44-fc-v24. All
repository facts verified against the assessed head.
