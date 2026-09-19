# ADR-015 — The enforcement boundary

**Status** PROPOSED
**Date** 2026-09-10
**Context branch** assessed against `claude/codebase-production-readiness-wm6idp` @ `12767ea`
**Supersedes** nothing. **Related** ADR-001 (autonomous containment), ADR-002 (hardware
attestation, PROPOSED), ADR-003 (observation class boundary), IR-04, IR-06, audit
findings I-16 and B-3.

---

## 1. The question

A proposal exists to extend Sniffer Dog from a read-only kernel observer into an
active interceptor that denies syscalls, backed by a hardware root of trust.

Two decisions are needed, and they are independent:

1. **May the observer enforce?**
2. **By what mechanism, given the kernel actually in use?**

Getting (1) wrong destroys the property the whole system is audited on. Getting
(2) wrong produces a design that cannot be built.

---

## 2. Decision 1 — the observer does not enforce

**Enforcement is a separate component, `aip-enforce`, with its own lifecycle, its
own key custody and its own trust domain. It never writes to the observation
path, and the observation path never depends on it.**

### Why

The audited value of this system is one sentence: *the actor should not control
the evidence used to judge the actor*. Three existing properties implement it:

- `ProcfsProbe` holds **no key material** and has **no signing method** (IR-04).
- The collector signs **off-host**, so root on the observed host can suppress or
  corrupt what is *offered* but cannot forge an attestation of it.
- Authorisation and observation are **different authorities, and neither may
  impersonate the other** (IR-06).

An enforcer must live in the syscall path of the workload. It therefore sits
*inside* the workload's blast radius by construction. If the observer and the
enforcer are one component, then:

- the observation path acquires a control-plane input that root can write to;
- a compromise of the enforcement decision becomes a compromise of the evidence;
- and — decisively — **a bypassed enforcer cannot be detected**, because the
  component that would notice is the same component that was bypassed.

Enforcement is a **third authority**, alongside authorisation and observation.
The existing architecture already refuses to let two authorities impersonate each
other; this ADR extends that refusal to the third.

### What this buys, concretely

Keeping them apart creates a reconciliation case that does not exist today and
that is worth more than the enforcement itself:

| enforcer says | observer says | reading |
|---|---|---|
| denied | no execution in the window | agreement — the gate held |
| denied | **execution observed** | **the enforcer was bypassed** — an enforcement-tier integrity failure |
| allowed | execution observed | ordinary `VerifiedExecution` path |
| allowed | no execution observed | the agent did not do what it was permitted to do — not a violation |

Row 2 is the whole argument. It is only expressible because the two components
are independent, and it is the enforcement-tier analogue of
`ObserverState::IntegrityUnknown`.

### Consequences

- An enforcement decision is a **claim by the enforcer**, not evidence. It enters
  reconciliation as an input with its own ceiling, never as an observation.
- `aip-enforce` gets its own signing key, distinct from the collector's. It is
  on the observed host and is therefore forgeable by root — stated, not hidden.
- No enforcement outcome may raise an evidence strength. It can only ever
  constrain what the workload was able to do.
- The reconciler gains no new verdict class. Row 2 maps onto the existing
  observer-directed failure shape and must reuse it rather than inventing a
  parallel vocabulary.

---

## 3. Decision 2 — the mechanism is not BPF-LSM

### 3.1 Verified kernel capability, 6.18.44-fc-v24

Read from `/proc/config.gz` and `/sys/kernel/btf/vmlinux` on the same kernel the
AIRI and observation-integrity validation runs on.

| capability | status | evidence |
|---|---|---|
| **BPF-LSM** (`BPF_PROG_TYPE_LSM`) | **UNAVAILABLE** | `# CONFIG_BPF_LSM is not set` |
| kprobes / kretprobes | **UNAVAILABLE** | `# CONFIG_KPROBES is not set` |
| fentry / fexit (BPF trampolines) | **UNAVAILABLE** | `# CONFIG_FUNCTION_TRACER is not set`; `CONFIG_DYNAMIC_FTRACE` absent |
| in-kernel cryptographic hashing | **UNAVAILABLE** | only skcipher kfuncs exist (`bpf_crypto_encrypt`/`_decrypt`, `bpf_crypto_lskcipher_*`). No shash/hash kfunc. `CONFIG_IMA` absent, so `bpf_ima_*_hash` is inert |
| **seccomp user-notify** | **available** | `CONFIG_SECCOMP_FILTER=y`; `seccomp_notif_addfd`, `seccomp_notify_recv` in BTF |
| **fanotify permission events** | **available** | `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y` |
| **cgroup/connect4** | **available** | `CONFIG_CGROUP_BPF=y`; `BPF_CGROUP_INET4_CONNECT` in BTF |
| sk_msg / sock_ops / sockmap | **available** | `CONFIG_BPF_STREAM_PARSER=y`; `BPF_MAP_TYPE_SOCKHASH`, `BPF_PROG_TYPE_SK_MSG` |
| uprobes | **available** | `CONFIG_UPROBES=y`, `CONFIG_UPROBE_EVENTS=y` |

> **A trap worth recording.** `CONFIG_LSM="lockdown,yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf"`
> lists `bpf` — and `BPF_PROG_TYPE_LSM` appears in the kernel's BTF. Neither is
> evidence the feature works: the string is the compiled-in default *ordering*,
> and the BTF entry is a UAPI enum constant that exists whether or not the
> feature is built. The authoritative fact is `# CONFIG_BPF_LSM is not set`, and
> a program of that type will be rejected at load.
>
> This is the same error class the audit already catalogued: a symbol that looks
> like coverage is not coverage.

### 3.2 The mechanism cannot be BPF, independent of the config

Even with `CONFIG_BPF_LSM=y`, the proposed design does not work.

The proposal is: on `security_bprm_check`, query the ATECC608B or the TPM for a
session clearance, and return `-EPERM` if it fails.

An eBPF program **cannot** perform an I2C or SPI transaction, cannot take a
mutex, and cannot sleep on a device. An ATECC608B ECDSA verify is roughly
50–100 ms over I2C; a TPM 2.0 signing operation is tens to hundreds of
milliseconds. Blocking every `execve` in the agent's process tree for that long
is not a performance problem to be optimised — it is a liveness failure.

**The hardware round trip cannot be on the per-syscall path.** That is a
property of the hardware, not of the kernel version, and no amount of kernel
rebuilding changes it.

### 3.3 What is adopted

**Primary gate: seccomp user-notify (`SECCOMP_RET_USER_NOTIF`).**

It is the only primitive available on this kernel that both (a) denies a syscall
and (b) blocks in a *sleepable userspace* supervisor — which is exactly what a
hardware round trip needs. The agent is launched under Vanian's supervision, so
installing the filter at spawn is available to us.

Supplementary gates, used where they fit better:

- **`cgroup/connect4`** for egress denial. It is coarser than
  `security_socket_connect` (address and port, not full LSM context) but it is
  present and it genuinely denies.
- **fanotify `FAN_OPEN_PERM`** for file-open gating. `aip-observe` already
  consumes fanotify, so the mechanism is in-tree.

**Rejected: BPF-LSM.** Unavailable on the target kernel, and structurally unable
to consult the hardware root of trust even where available. If a future
deployment kernel enables it, BPF-LSM becomes a useful *fast path* in front of
the seccomp supervisor — never a replacement for it.

### 3.4 The latency fix — pre-authorisation, not per-call signing

The hardware must bind the decision without being on the hot path. The design is
an **epoch**, and it reuses machinery that already exists:

1. A decision point issues a signed `ExpectedExecution` covering a bounded action
   set and a bounded window. *(exists today)*
2. The ATECC608B signs a short-lived **capability epoch** over that expectation's
   digest, with its **monotonic counter** as the anti-replay value. One hardware
   operation per epoch, not per syscall.
3. `aip-enforce` verifies the epoch once, caches it, and per-syscall performs an
   O(1) lookup plus a counter and window comparison.
4. Epoch rotation is measured in seconds. Syscall decisions are measured in
   microseconds.

The monotonic counter is load-bearing: a signature alone is replayable, and a
replayed epoch is an expired authority presented as a live one. The counter is
the only part of the ATECC608B that makes this better than a software key.

**Stated limitation.** This binds the *authority* to hardware. It does not bind
the *execution* to hardware, and it does not survive an adversary who already has
root — such an adversary detaches the seccomp supervisor. Hardware-bound
authority raises the cost of forging permission; it does not make the gate
unbypassable, and nothing in this ADR should be read as claiming it does.

### 3.5 Known hazard: TOCTOU in the supervisor

seccomp user-notify hands the supervisor syscall *arguments*, including user
pointers. Dereferencing them naively is a time-of-check/time-of-use bug: the
target process can rewrite the memory after the check and before the kernel reads
it.

The implementation must use `SECCOMP_IOCTL_NOTIF_ID_VALID` around every read of
target memory, and prefer `SECCOMP_IOCTL_NOTIF_ADDFD` over path-based decisions
where a file descriptor can carry the identity instead. Any decision that cannot
be made TOCTOU-safely must **deny**, not guess.

---

## 4. What this ADR does not decide

- Whether autonomous containment should become reachable. **B-3 remains
  ACCEPTED/JUSTIFIED.** Enforcement at the syscall boundary is a *preventive*
  control that runs before a verdict exists; it is not the containment path and
  does not make `ResponseClass::Contain` emittable. Conflating the two would be
  claim inflation.
- Any hardware actuation behaviour. That is the interlock, specified separately
  in `CYBER_PHYSICAL_SAFETY_STACK.md` §3, and it is deliberately **not** a
  Vanian verdict either.
- Whether `aip-enforce` ships. This records the boundary a decision to ship
  would have to respect.

---

## 5. Invariants any implementation must preserve

Non-negotiable, in the style of the observation-integrity decision record:

1. The observation path acquires **no** input from the enforcement path.
2. `ProcfsProbe` remains keyless. The enforcer's key is a different key, in a
   different component, with a different custody statement.
3. No enforcement outcome raises an `EvidenceStrength` or licenses a
   non-occurrence claim. A denied syscall is an enforcer's claim; the *absence*
   of the execution is still the observer's finding to make or withhold.
4. `CANNOT_PROVE` semantics are untouched. An enforcer that cannot reach its
   hardware **denies the action and reports degraded**; it does not silently
   allow, and it does not assert coverage.
5. There is still exactly one reconciliation authority.
6. A bypassed enforcer must be **detectable by the observer** — which is the
   whole reason for §2.
