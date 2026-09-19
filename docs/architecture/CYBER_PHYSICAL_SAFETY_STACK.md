# Cyber-physical safety stack — feasibility assessment and corrected architecture

**Status** ASSESSMENT — no implementation exists for anything in this document
**Date** 2026-09-10
**Kernel assessed** 6.18.44-fc-v24 (the validation host's kernel)
**Related** ADR-015 (enforcement boundary), ADR-002 (hardware attestation, PROPOSED),
`TRL_AND_PHYSICAL_VALIDATION_ROADMAP.md`, `OBSERVATION_INTEGRITY_DECISION_RECORD.md`

---

## 0. Summary of the assessment

A five-component proposal extends Sniffer Dog into a three-tier cyber-physical
safety stack. Assessed against the kernel in use and against the existing trust
model:

| # | component | verdict |
|---|---|---|
| 1 | BPF-LSM active interception | **NOT BUILDABLE AS SPECIFIED** — feature compiled out; and BPF cannot consult the hardware root of trust in any case. A working mechanism exists and is different (ADR-015) |
| 2 | eBPF socket filter with in-kernel SHA-256 | **PARTIALLY BUILDABLE** — socket capture works; **in-kernel cryptographic hashing does not exist on mainline BPF**. Hash in userspace, and reclassify the evidence accordingly |
| 3 | Hardware dead-man's switch | **BUILDABLE, AND THE STRONGEST ITEM** — with three corrections, one of which is a safety correction, not an engineering one |
| 4 | Taint-based prompt-injection lineage | **CONCEPT SATURATES** — binary taint is a constant for an agent whose job is ingesting untrusted input. Reformulate as scope attenuation |
| 5 | Multi-node attestation | **BUILDABLE IN REDUCED FORM** — the full NEXORA verifier does not fit a Cortex-M4, and the three roots of trust on the bench are not equivalent |

**The highest-leverage change to the plan is in §3.4**: the interlock hardware is
one wire away from being the programme's first genuine external observation
mechanism, which is the pivotal milestone in the validation roadmap.

---

## 1. Verified kernel capability baseline

Read from `/proc/config.gz` and `/sys/kernel/btf/vmlinux`.

| capability | status |
|---|---|
| BPF-LSM (`BPF_PROG_TYPE_LSM`) | **UNAVAILABLE** — `# CONFIG_BPF_LSM is not set` |
| kprobes / kretprobes | **UNAVAILABLE** — `# CONFIG_KPROBES is not set` |
| fentry / fexit | **UNAVAILABLE** — `# CONFIG_FUNCTION_TRACER is not set` |
| in-kernel hashing | **UNAVAILABLE** — skcipher kfuncs only; no shash; `CONFIG_IMA` absent |
| seccomp user-notify | available |
| fanotify `FAN_OPEN_PERM` | available (`CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`) |
| cgroup/connect4 | available |
| sk_msg / sock_ops / sockmap | available |
| uprobes | available |
| perf tracepoints | available — what Sniffer Dog uses today |
| netlink proc connector, fanotify, AF_PACKET | available — the gate-independent mechanisms |

The three unavailable BPF features are the same class of environmental blocker
as `CONFIG_KPROBES`, which already made Tetragon and OBI unusable during the AIRI
validation. **Any plan depending on them is a plan to replace the kernel first**,
and that is a deployment decision with its own consequences for defence and
industrial targets where the kernel is often not ours to choose.

---

## 2. Component-by-component

### 2.1 Intent-to-kernel attenuation bridge

**As proposed:** BPF-LSM hooks on `security_bprm_check`,
`security_socket_connect`, `security_file_open`; query ATECC608B/TPM inside the
hook; return `-EPERM` on failure.

**Two independent blockers.**

1. `CONFIG_BPF_LSM` is not set. The program type will not load.
2. **More fundamentally:** an eBPF program cannot perform I2C/SPI, cannot sleep
   on a device, and cannot take a mutex. An ATECC608B ECDSA verify is ~50–100 ms;
   a TPM 2.0 signing operation is tens to hundreds of ms. A hardware round trip
   on the per-`execve` path is a liveness failure, not a latency problem. This is
   true on every kernel.

**Corrected design** (full rationale in ADR-015):

- **seccomp user-notify** as the primary gate — the only available primitive that
  denies a syscall *and* blocks in sleepable userspace.
- **`cgroup/connect4`** for egress denial; **fanotify `FAN_OPEN_PERM`** for file
  opens.
- **Epoch pre-authorisation**: the ATECC608B signs a short-lived capability epoch
  over an `ExpectedExecution` digest, with its **monotonic counter** as the
  anti-replay value. Hardware is consulted per epoch (seconds), not per syscall
  (microseconds). Per-call cost becomes an O(1) map lookup.
- **Separate component.** `aip-enforce` never writes to the observation path,
  per ADR-015 §2 — otherwise a bypassed enforcer is undetectable, because the
  component that would notice is the one that was bypassed.

**What it establishes:** that permission was bound to a hardware-held key and a
monotonic counter at epoch issue.
**What it does not:** anything against an adversary who already has root — such an
adversary detaches the supervisor. It raises the cost of forging permission. It
does not make the gate unbypassable.

---

### 2.2 Socket-layer payload reconciliation

**As proposed:** `sock_ops` + `sk_msg` programs computing a streaming SHA-256 of
outgoing payloads *in kernel space*, reconciled against the agent's pre-signed
claim; halt the stream on divergence.

**What works:** the capture. `CONFIG_BPF_STREAM_PARSER=y`, `BPF_MAP_TYPE_SOCKHASH`
and `BPF_PROG_TYPE_SK_MSG` are all present. `bpf_dynptr_slice` is available for
payload access.

**What does not work:** the hashing. The only cryptographic kfuncs in this
kernel's BTF are **skcipher** — `bpf_crypto_encrypt`, `bpf_crypto_decrypt`,
`bpf_crypto_lskcipher_*`. There is **no hash or shash kfunc, and no
`bpf_sha256`**. `bpf_get_hash_recalc` is a 32-bit flow hash, not a digest.
`bpf_ima_file_hash` needs `CONFIG_IMA`, which is absent, and measures files
rather than payloads.

**Corrected design:** capture segments in `sk_msg` via `bpf_dynptr_slice`, stream
them to userspace over a ringbuf, and hash **in the collector process**.

**The consequence that must not be glossed.** Moving the hash to userspace moves
it onto the observed host. It therefore inherits the existing ceiling: content
read from the observed host is root-forgeable and is barred from `Proven`. A
payload digest computed this way is `Attested` **at best**, and only if the
hashing process is in the collector's trust domain rather than the workload's.

**On TLS.** Agent traffic to model providers and MCP servers is TLS. The socket
layer sees ciphertext. The standard answer is a **uprobe on the TLS library**
(`SSL_write`/`SSL_read`), which this kernel supports. But note what that costs:
a uprobe on the agent's own libssl is *inside the actor's address space*. It is
better than an SDK callback and it is **not** independent observation. It must be
capped at `Corroborative` unless the library is dynamically linked and its
content hash is attested — and even then a statically linked or patched TLS
implementation defeats it silently.

**The genuinely valuable part** is `PayloadDivergence` as a comparison class: the
agent claims `read_balance()`, the socket layer carries `POST /transfer_funds`.
That maps onto the existing `ActionComparison` machinery and is a real
gap-filler for AIRI limitation N-2. It should be built as a comparison, **not**
as a new verdict class.

**On halting the stream:** that is enforcement, and it belongs to `aip-enforce`
under ADR-015, not to the observer.

---

### 2.3 Hardware-bounded containment interlock

**This is the strongest component in the proposal and it should be built first.**

It correctly inverts the burden. Instead of requiring the system to *prove
badness* — which needs `Proven`, which the engine deliberately cannot emit — it
requires the system to *continuously prove goodness*. Absence of a valid
heartbeat is the unsafe state. That is the same fail-closed semantic the codebase
already implements everywhere else, expressed in copper.

**Design as proposed:** Linux sends a cryptographically signed heartbeat every
N ms; the STM32 drops its relay lines when the heartbeat stops, including when
Sniffer Dog suppresses it on `ObserverIntegrityUnknown`.

#### Correction 1 — it does not close B-3, and must not be described as doing so

B-3 is **ACCEPTED/JUSTIFIED** in `FINAL_AUDIT_RECONCILIATION.md` §13: the
software containment path is deliberately unreachable from engine-produced
evidence. A hardware interlock is a **different authority operating out of
band**. It does not make `ResponseClass::Contain` emittable, it produces no
`Reconciliation`, and it is not a Vanian verdict.

Describing it as closing B-3 would be exactly the claim inflation the forensic
audit exists to catch. Describe it as what it is: an **independent safety
function** whose trigger condition happens to include a Vanian signal.

#### Correction 2 — fail-closed is not the same as fail-safe

The proposal lists "motor power, network switches, weapon arming circuits" as
things to drop. **These do not share a safe state.**

| actuator | de-energised state | is that safe? |
|---|---|---|
| stationary manipulator | brakes engage, drives off | usually yes |
| gripper holding a load | may release | **no** if a person or the payload is below |
| multirotor in flight | motors stop | **no** — it falls |
| ground vehicle at speed | may lose steering and braking assist | **no** |
| weapon arming circuit | de-armed | yes |
| network switch | link down | depends — it may also cut the operator's ability to intervene |

A dead-man's switch that assumes "power off = safe" is a hazard for at least
three of those. Each actuator needs a declared safe state and a per-actuator
analysis (FMEA/HAZOP, in the shape of ISO 13849 / IEC 61508 for the industrial
targets, and the applicable airworthiness regime for anything that flies). **That
is a safety-engineering deliverable, and it gates the interlock, not the other
way round.**

For anything airborne the interlock's correct output is almost never "cut motor
power" — it is "command the flight controller's independent failsafe", which is a
different wire and a different contract.

#### Correction 3 — the interlock must not be reprogrammable by the host it guards

If the Linux host can reflash or reset the STM32 over the same link that carries
the heartbeat, the interlock is decorative against precisely the root-level
adversary it exists to defeat. Requirements:

- STM32 readout protection enabled (RDP Level 1 minimum; Level 2 for fielded
  units, accepting that it is irreversible).
- Programming header physically separate from the heartbeat link, and absent or
  disabled in fielded configurations.
- Ideally a **one-way heartbeat path** — TX-only from Linux, with no command
  channel back into the STM32 at all.
- The STM32 firmware is the authority on timing. It must not accept a
  host-supplied timeout, watchdog-disable, or maintenance-mode command.

#### Anti-replay and timing

- A signature alone is replayable: a captured heartbeat is a valid heartbeat
  forever. Bind each heartbeat to the **ATECC608B monotonic counter** or a
  strictly increasing epoch the STM32 tracks and refuses to see decrease.
- State the timing budget explicitly and treat it as a safety parameter:
  heartbeat period, number of tolerated misses, and worst-case actuation delay.
  A 100 ms period with 3 tolerated misses gives ~300 ms worst-case drop-out —
  and that number must be justified against the actuator's stopping distance,
  not chosen for convenience.
- Linux is **not** a real-time system. GC pauses, scheduler stalls, page-cache
  pressure and a busy `cargo test` run all produce missed heartbeats. Either the
  budget absorbs that or the heartbeat sender runs at real-time priority with
  memory locked. Nuisance trips are how safety systems get disabled by operators.

#### 3.4 The change worth making — measure, do not only cut

**A relay that only cuts is a safety function. A relay that cuts *and measures*
is an observer.**

The STM32 already sits outside the machine's own software, holds its own key, and
is wired into the actuator path. Add current sensing on the actuator line, or an
independent encoder tap wired to the STM32 rather than to the robot's controller,
and it produces an **off-machine, independently-keyed measurement of a physical
quantity**.

That is Stage 4 of the physical validation roadmap — the stage that gates every
physical claim in the programme, and the milestone identified as pivotal for the
next funding round. It is currently blocked on "a mechanism whose observations
reach `from_attested`". A current-sense ADC on an STM32 that already has a key
and an Ethernet link is that mechanism, for one quantity, at low cost.

Concretely: *the robot claims it moved; the encoder says the shaft turned; the
current sensor on the independent board says no current flowed.* Today the
robotics profile can only say `CANNOT_PROVE` for that. With the sense line it can
say the claim is **contradicted by an anchored observer** — which is the first
physical fact this system would ever be able to establish.

This is a larger strategic win than the interlock itself, and it is a wire and an
ADC channel away from a build that is already planned.

---

### 2.4 Semantic drift and prompt-injection attribution

**As proposed:** taint the process lineage on untrusted ingest; escalate when a
tainted process issues a privileged syscall; integrate an inference-time
interceptor into the Sniffer Dog runtime.

**Why binary taint saturates.** An AI agent's entire function is ingesting
untrusted input. If fetching a URL taints the lineage, every agent is
permanently tainted within seconds of starting work. A signal that is always
true carries no information, and an alerting system built on it gets switched
off in its first week.

**Reformulation: this is attenuation, not taint.** The useful invariant is not
*"did the agent touch untrusted data"* — it always did — but:

> After an untrusted ingest, the agent's effective scope may only **shrink**. Any
> capability exercised after the ingest that was not in the authorised set
> *before* it is the finding.

That reuses machinery that already exists and is already adversarially tested:
`is_scope_subset` from the delegation chain, and `ExpectedExecution`'s bounded
action set. It adds no verdict class, and — unlike taint — it produces a signal
that does not saturate, because it fires on *scope growth*, which is rare and
suspicious by construction.

**On the inference-time interceptor: no.** Putting a semantic interpreter inside
the observer breaks the independence boundary that the entire architecture rests
on. The observer sees syscalls and sockets; it cannot see prompts, and it must
not start guessing at them.

The correct split is the one the system already uses:

- **AIRI declares the ingest** — a self-reported event, `Corroborative` at best.
- **The observer independently confirms the socket read** that carried the bytes,
  bound to the process instance.
- **The reconciler joins them** and applies the attenuation rule.

Semantics stay in the actor's self-report where they are honestly labelled.
Mechanism stays in the observer where it is independent. Judgement stays in the
one reconciliation authority.

---

### 2.5 Multi-node attestation

**On porting the NEXORA verifier to a Cortex-M4.** The offline verifier's
distinguishing property is that it **re-runs the reconciler** and refuses
`ClaimNotDerivable` on mismatch. That is 2,000+ lines of allocating Rust. An
STM32-E407 has 192 KB of SRAM and 1 MB of flash. Full re-derivation will not fit.

What fits is a **reduced verification profile**: Ed25519 signature checks, Merkle
inclusion proofs, and a chain walk — explicitly **not** re-derivation of the
verdict. Ed25519 verification on a Cortex-M4 is on the order of 10 ms with a
decent implementation, so the arithmetic is fine; it is the reconciler that does
not fit.

**This must carry a distinct and weaker verification class.** The existing rule
is that a package's claim is only as strong as what was actually re-derived. An
MCU that checks signatures but cannot re-derive the verdict has established
*integrity and authorship*, not *derivability*. Calling both "NEXORA verified"
would repeat the exact error the audit recorded in Extension 11 §J.

**On heterogeneous roots of trust — they are not equivalent.**

| device | root of trust | can produce an attestation quote? |
|---|---|---|
| Linux host | TPM 2.0 | **yes** — PCR quote over a measured boot chain |
| STM32-E407 | ATECC608B | **no** — it is a key vault plus a monotonic counter. No PCRs, no measured boot, nothing to quote |
| ESP32-C3 | eFuse secure boot + flash encryption | **no quote** — it can enforce that only signed firmware boots, but it cannot attest that fact to a remote peer |

An mTLS peer-attestation protocol across this bench must therefore carry **which
root vouched**, and the ceiling must differ per root class. That is the existing
`EvidenceCeiling` pattern applied to hardware, and it is a clean reuse.

Treating an ATECC608B as interchangeable with a TPM for attestation is the
error to avoid: the ATECC608B proves *possession of a key*; the TPM proves
*possession of a key by a system in a measured state*. Only the second supports
"Node A may authorise actuation on Node B".

---

## 3. Recommended sequence

Ordered by evidence gained per unit of risk, not by architectural elegance.

| # | work | why here | gate to the next |
|---|---|---|---|
| **1** | **Interlock with sensing** (§2.3 + §3.4) — heartbeat, relay, current sense, per-actuator safe-state analysis | highest strategic value; unblocks Stage 4; needs no kernel changes; the safety analysis is on the critical path and is slow | one physical quantity contradicted or corroborated by an anchored off-machine observer |
| **2** | **Payload comparison** (§2.2) — sk_msg capture, userspace hashing, `PayloadDivergence` as an `ActionComparison` | closes part of AIRI N-2; builds entirely on available primitives | a claimed API action reconciled against captured payload on a real agent |
| **3** | **Scope-attenuation rule** (§2.4) | pure reconciler work, no new mechanism, reuses `is_scope_subset` | post-ingest scope growth detected without saturating on ordinary agent behaviour |
| **4** | **`aip-enforce`** (§2.1, ADR-015) — seccomp user-notify + epoch pre-authorisation | genuinely useful, but it is the item that changes the trust model, so it goes after the ADR is settled and after cheaper wins are banked | the bypass-detection case (ADR-015 §2) demonstrated: enforcer denies, observer sees execution |
| **5** | **Multi-node attestation** (§2.5) | depends on 1 and 4 existing; needs the per-root ceiling design first | Node A refuses to authorise Node B's actuation on a stale or absent PCR quote |

Component 1 of the original proposal is deliberately last, and the item that was
presented as infrastructure for everything else (BPF-LSM) is not in the plan at
all.

---

## 4. What this document does not establish

- That any of this is implemented. **None of it is.** No code exists for any of
  the five components.
- That the hardware bench has been exercised. It has not been touched by this
  assessment.
- That kernel capability on the validation host predicts kernel capability on a
  deployment host. Defence and industrial deployments frequently do not let us
  choose the kernel, and three of the primitives assessed here are absent on this
  one.
- That the safety analysis in §2.3 is complete. It names the hazard class; it is
  not an FMEA, and it must not be used as one.
