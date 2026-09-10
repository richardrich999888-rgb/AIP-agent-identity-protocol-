# VANIAN INDEPENDENT VALIDATION TOOLING REPORT

**Branch** `claude/codebase-production-readiness-wm6idp` at `2c79363`
**main** `872dbf3`, untouched · **213 commits** separate them
**Scope** tooling setup and validation design only. No Vanian code, no CI
file, and no security semantic was modified by this work.

## Status

# VALIDATION TOOLING BLOCKED

Two independent reasons, either sufficient on its own.

1. **Four of the five named tools do not exist** in this Claude Code
   environment. They cannot be configured, and no substitute was installed
   in their place.
2. **The independent layer that does exist is not running on the branch
   under validation.** CI last ran on this branch on 2026-06-18 at commit
   `6c407d0`. Everything since — Skills 10–23, Defect #5, key custody,
   SIGNER_ANCHORED, 213 commits — has been validated **only by agents
   running cargo locally**.

That second point is the finding that matters most, because it is exactly
the failure mode this exercise exists to prevent:

> Vanian must NOT rely on Claude alone to declare itself secure.

At present it does. Every "three consecutive clean runs, fmt and clippy
clean" statement in this repository's recent history — including the ones I
wrote — is an agent's report of an agent's local run, with no independent
execution behind it.

---

## 1. Installed tools

| Tool | Installed | Purpose | Evidence |
|---|---|---|---|
| **GitHub integration** | yes, working | PRs, workflow runs, job-level conclusions, commit and branch history | used throughout this report |
| **cargo-audit 0.22.2** | installed locally during this work | RUSTSEC advisory scan | ran; results below |
| rustfmt / clippy | in-tree, in CI | style, lint | configured in `ci.yml` |
| cargo-deny | configured, **not installed locally** | licence, advisory, source policy | `aip-standalone/deny.toml`, `aip-service/deny.toml` (identical) |
| gitleaks | in CI only | secret scan | `security.yml`; **failing** — see F2 |
| trivy | in CI only | secret + IaC misconfiguration | `security.yml`; passing |
| cargo-llvm-cov | in CI, best-effort | coverage | `ci.yml`, `continue-on-error` |

## 2. Available tools not installed

| Requested tool | State | Note |
|---|---|---|
| **Codex Security** | **UNAVAILABLE** | Not in the plugin catalog. Searched by name and by function. |
| **Codex Replay** | **UNAVAILABLE** | As above. |
| **Git Diff Patcher Bridge** | **UNAVAILABLE** | As above. |
| **ArmorCodex** | **UNAVAILABLE** | As above. |
| GitHub integration | **AVAILABLE** | Already present; used. |

Searches returned only unrelated plugins (Unity, SigNoz, Auth0, Adobe,
Adspirer), which is a clear negative rather than an ambiguous one. No
substitute was installed, per the mandate.

**One related plugin exists and was deliberately not installed.**
`security-guidance` (Security Guidance) offers pattern-based edit warnings,
LLM diff review on Stop, and an agentic commit reviewer. It is
`reach: privileged` and ships four hooks — `PostToolUse`, `SessionStart`,
`Stop`, `UserPromptSubmit`. Hooks that fire on tool use and on Stop can act
on edits, which is the opposite of the READ/ANALYZE/REPORT default this
mandate requires for validation tooling. It is a reasonable candidate for a
deliberate decision by the owner; it is not something to enable silently in
a repository whose whole thesis is that scanners must not rewrite
security-sensitive code.

## 3. Permission model

Nothing was granted write, commit, push, or auto-fix capability. The
scanners exercised are read-only by construction:

| Capability | cargo-audit | trivy | gitleaks | GitHub MCP (as used) |
|---|---|---|---|---|
| read repository files | yes | yes | yes | yes |
| execute commands | no | no | no | no |
| modify files | no | no | no | **not used** |
| modify Git / commit / push | no | no | no | **not used** |
| network | advisory DB + registry | vuln DB | no | GitHub API, read |

The GitHub integration can write; it was used for reads only (workflow
runs, jobs, pull requests). No GitHub setting was changed.

## 4–6. Repository and GitHub coverage

**Confirmed inspectable:** pull requests, workflow runs, per-job
conclusions, per-step timings, commit history, branch history. All findings
below rest on that evidence.

**Not inspectable in this environment:** code-scanning alerts, Dependabot
alerts. No CodeQL, Semgrep, Snyk or Dependabot configuration exists in the
repository, so there is nothing to inspect rather than an access problem.

## 7. Replay capability

**None available.** Codex Replay is not present.

What replay *would* be for here, recorded so the requirement is not lost:
re-execute the test and validation commands from a commit in an environment
the original agent did not control, and compare. That would convert
"the agent reported 966 passing" into "966 passing was reproduced". Nothing
in this environment does that today; CI is the nearest equivalent, and
see F1.

## 8. Diff-review capability

**No dedicated tool.** Git Diff Patcher Bridge is not present. Diff review
in this report was done with `git diff` and targeted structural queries
against the declared security properties — adequate for the specific
questions asked, not a substitute for an independent reviewer.

## 9. Agent-governance capability

**None available.** ArmorCodex is not present. No mechanism enforces
declared intent before a security-sensitive change, separates analysis from
modification, or gates branch operations. The only governance in effect is
the discipline written into the mandates themselves and whatever a human
reads afterwards.

---

## 10. Supply-chain validation

### Scan performed

```
cargo audit 0.22.2 · advisory DB 1240 advisories
scope: repository-root Cargo.lock (the authoritative one)
result: 272 crate dependencies scanned, 0 vulnerabilities
```

The yanked-crate check could not complete (registry 503 through the
sandbox proxy). That is an environment limitation, not a finding, and it
does not affect the advisory result.

### F3 — `cargo audit` in `aip-standalone` fails outright · **CONFIRMED · HIGH**

Skill 16 (`283c473`) deliberately unified the two Cargo workspaces and
removed `aip-standalone/Cargo.toml` and `aip-standalone/Cargo.lock`. The
root `Cargo.toml` documents this at length and is correct to have done it.

Both workflows still run the audit from that directory:

```
ci.yml       supply-chain:  (cd aip-standalone && cargo audit --ignore RUSTSEC-2026-0097)
security.yml cargo-audit:   (cd aip-standalone && cargo audit --ignore RUSTSEC-2026-0097 --json ...)
```

Measured, not inferred:

```
$ cd aip-standalone && cargo audit --ignore RUSTSEC-2026-0097
error: not found: Couldn't load Cargo.lock
exit code: 2
```

Both steps use `set -e`, so both jobs fail at this line. This is a broken
gate rather than a false pass — but see F1: nothing has run it since the
breakage was introduced, so the breakage is unobserved.

**Not fixed here.** The mandate is explicit that CI must not be altered to
make a scanner green, and the correct fix is a decision about scope (audit
the root once, or audit per-member) rather than a path edit.

### F4 — `aip-service/Cargo.lock` is orphaned and stale · **CONFIRMED · MEDIUM**

The root `Cargo.toml` states: *"There is now exactly one workspace root and
one `Cargo.lock` in this repository; the old `aip-standalone/Cargo.lock`
was removed with it, because a second lockfile that nothing reads is a trap
for whoever next tries to reproduce a build from it."*

`aip-service/Cargo.lock` survived that reasoning and is exactly that trap.

| | root `Cargo.lock` | `aip-service/Cargo.lock` |
|---|---|---|
| packages | **272** | **252** |
| last updated | `bf87b8e` (Skill 23) | `b89a833` (custody merge) |
| references to Skill 16–23 crates | 7 | **0** |

Measured:

```
$ cd aip-service && cargo audit --json     → 252 deps scanned, 0 vulnerabilities
$ cargo audit --json          (root)       → 272 deps scanned, 0 vulnerabilities
```

`aip-service` is a member of the root workspace (its package is named
`airon-aip`), so cargo builds it from the root lockfile. The audit
invocation, run from that directory, reads the stale local lockfile
instead — auditing 20 packages fewer than the build actually uses,
including the entire Skill 16–23 dependency closure.

No vulnerability is hidden by this **today**, because the root scan is also
clean. The defect is that the CI invocation does not scan what is built.

### Other supply-chain state

- **Dependency pinning:** one lockfile, committed. Correct.
- **Licence policy:** `deny.toml` present in both crate directories,
  byte-identical, twelve allowed licences including
  `LicenseRef-Proprietary`. Consistent.
- **`RUSTSEC-2026-0097` is ignored** in both `deny.toml` files and both
  workflow invocations, with a written justification (rand unsoundness
  reachable only via `rand::rng()` plus a custom logger; this repository
  uses `OsRng`). The justification is specific and checkable, which is the
  right shape for an ignore. It was not independently re-verified here.

---

## 11. Security scan baseline

Baseline tests, mutation tests and security scans were kept separate. No
mutation was run concurrently with a validation suite.

| scanner | version | command | scope | result |
|---|---|---|---|---|
| cargo-audit | 0.22.2 | `cargo audit` | root workspace, 272 deps | **0 vulnerabilities** |
| cargo-audit | 0.22.2 | `cd aip-service && cargo audit` | stale lock, 252 deps | 0 vulnerabilities — **wrong scope**, F4 |
| cargo-audit | 0.22.2 | `cd aip-standalone && cargo audit` | — | **exit 2, no Cargo.lock**, F3 |
| cargo-deny | not installed | — | — | **not run locally** |
| gitleaks | CI only | `gitleaks-action@v2` | full history | **failing in CI**, F2 |
| trivy | CI only | `trivy fs --scanners secret,misconfig` | repository | passing in CI |

**Unresolved:** cargo-deny was not run locally, so licence and source policy
were verified by reading the configuration rather than by execution.

---

## 12. Secret / key scanning

Independent scan of the tracked tree. No PEM blocks, no key files, no
hardcoded credentials in production paths.

| Check | Result | Classification |
|---|---|---|
| `BEGIN … PRIVATE KEY` / `BEGIN CERTIFICATE` in tracked files | one hit, in `aip-service/tests/key_custody.rs:256`, inside an assertion that the string is **absent** from rendered output | **FALSE POSITIVE** — the test proves the opposite |
| files named `*.pem`, `*.key`, `id_rsa`, `*secret*` | none | clean |
| `password|passphrase|secret|token|api_key = "…"` in non-test paths | none | clean |
| passphrase literals | three, all under `tests/`: `aip-service/tests/key_custody.rs`, `aip-core/tests/custody.rs`, `aip-observe/tests/custody.rs` | **FALSE POSITIVE** — integration tests, not compiled into any shipped library |
| development custody backend reachable from a production path | `ServiceKey::generate()` is used only by `test_support.rs` and `development_key()`; `main.rs:93` uses `load_or_create` | **verified, not merely documented** |

**One deployment-dependent state worth naming, not a finding.**
`ServiceKey::load_or_create(path, passphrase: Option<&[u8]>)` falls back to
`Backend::PlaintextFile` when no passphrase is supplied. That backend is
named, `is_production()` returns false for it, the file is created
owner-only, and startup logs a warning naming `AIP_KEY_PASSPHRASE`. This is
honest and deliberate — a production deployment that supplies no passphrase
gets a posture the code itself refuses to call production.

---

## 13. Diff review — `main` → `2c79363`

Reviewed against the specific risks the mandate names.

| Risk | Finding |
|---|---|
| `EvidenceStrength` weakened | **No.** Still exactly `Heuristic`, `Correlated`, `Attested`, `Proven`. The whole crate is new relative to `main`, so the diff is an addition, not a change. |
| Verifier-owned types became deserializable | **No.** `VerifiedProof` is `Serialize` only; `VerifierCapability` has no `Deserialize`. Both Defect #5 guarantees **survived the cross-branch merge**, which was the specific thing worth checking. |
| Second verifier / reconciler / observer / custody model | **No.** One `Custodian` trait (`aip-crypto::custody`), consumed by `aip-observe` and `aip-service`. |
| Observer key ownership moved | **No.** `aip-observe::custody` still owns it. |
| Package-controlled authority | **No** on the paths checked. |
| New public constructors on trust types | **One, latent — see F5.** |

### F5 — `EffectFinding` carries a caller-choosable ceiling · **LIKELY (latent) · MEDIUM**

`aip-effect/src/finding.rs` documents its ceiling as *"computed, never
chosen: `min(class ceiling, profile capability)`"*. The type is:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffectFinding {
    Corroborated { ceiling: EvidenceCeiling, supporting: u32 },
    …
}
```

No `#[non_exhaustive]`, no crate-private field, no provenance marker — and
`Deserialize`. So a downstream crate can construct `Corroborated` with any
ceiling it likes, and any byte sequence can become one. That is precisely
the shape Defect #5 and AUDIT §14 closed elsewhere: a value documented as
derived, carried in a type that lets a caller choose it.

**Why LIKELY and not CONFIRMED.** Nothing consumes it as a gate yet.
`EffectFinding` appears only in `aip-effect`, `aip-edge` and `aip-uas`;
`aip-reconcile`, `aip-warrant` and `aip-containment` contain no reference to
its ceiling. There is no current path by which a forged finding reaches a
security decision.

**Why it still matters.** The crate's own doc comment says *"this crate
does not gate on it, because gating is the reconciler's job"* — that is, the
intended wiring is exactly the wiring that would make this exploitable. The
hole is pre-positioned for the moment the design completes.

**Not fixed here**, per the mandate. Recommended action: seal
`EffectFinding` the way `Reconciliation` was sealed (`#[non_exhaustive]`
plus a crate-private provenance), **before** any reconciler consumes it.

---

## 14. CI findings

### F1 — CI has not run on this branch for 213 commits · **CONFIRMED · HIGH**

The most recent workflow run on `claude/codebase-production-readiness-wm6idp`
is **run #10, 2026-06-18, commit `6c407d0`** (Security and CI, both green).

Since then the branch has advanced to `2c79363`. Nothing in between has been
built, tested, linted, audited or secret-scanned by anything other than an
agent on a local machine.

Cause, from the workflow triggers:

```yaml
# ci.yml
on:
  pull_request:
  push:
    branches: [develop, main]      # this branch is neither
```

`security.yml` triggers on `pull_request` and `schedule` only. The single
open pull request is **#3**, for `import/orbitaltrust-accountability-layer`
— a different branch. There is **no PR for the canonical development
branch**, so no `pull_request` run fires, and pushes to it match no branch
filter.

The consequence is the one this whole exercise is about: the independent
challenge layer exists, is correctly configured for `main`, and has been
silently inapplicable to every commit of the work being validated.

### F2 — the Security workflow fails on every scheduled run · **CONFIRMED · HIGH**

Runs 68–72 on `main` (`872dbf3`), 15–19 August, all
`conclusion: failure`. Job-level detail from run `32212846746`:

| job | conclusion |
|---|---|
| `cargo audit (RUSTSEC)` | success |
| `trivy filesystem scan` | success |
| **`gitleaks (secret scan)`** | **failure**, at the "Run gitleaks" step |

So the secret-scanning gate specifically has been red daily for at least
five consecutive scheduled runs, on `main`, and the failure has not been
acted on. The step fails three seconds in, which is more consistent with an
action-configuration failure (`gitleaks-action@v2` licence requirement) than
with a detected secret — but that is an inference from timing, and the step
log was not retrieved. **Classified UNKNOWN as to cause; CONFIRMED as to
the gate being red.**

Note the interaction with my own independent scan: I found no secrets in the
tracked tree. That does not clear this. gitleaks with `fetch-depth: 0`
scans **history**, which my scan did not.

---

## 15. Tool limitations

- Four named tools do not exist; no replay, no independent diff bridge, no
  agent governance.
- cargo-deny not executed, only read.
- gitleaks and trivy exist only inside CI, which does not run on this branch.
- The yanked-crate check cannot complete in this sandbox.
- gitleaks scans history; my local secret scan did not.
- **No scanner used here can evaluate a Vanian semantic property.** Every
  one of them checks dependencies, syntax, patterns or configuration.

## 16. Vanian controls independently challenged

| Vanian control | Existing test | External tool | Independent evidence obtained | Limitation |
|---|---|---|---|---|
| Self-report ≠ observation | reconciler suites, `adversarial.rs` | none applicable | **none** | no scanner can express it; the Vanian test remains the only evidence |
| Package ≠ verifier authority | Gate 10, `capability.rs` (17) | structural diff review | `VerifiedProof` Serialize-only and `VerifierCapability` non-`Deserialize` **confirmed to have survived the merge** | a diff check proves the guard exists, not that it is sufficient |
| Observer key isolation | `aip-observe/tests/custody.rs::a_14` source fence | diff review | ownership confirmed unmoved; one `Custodian` trait workspace-wide | the source guard remains authoritative |
| Key custody | Phase A suite (15) | secret scan + code read | no key material in tree; dev backend unreachable from the service startup path — **verified by reading the call site, not the doc comment** | scanner cannot evaluate custody *design* |
| Bundle signer ≠ trusted signer | Phase B suite (9) | none applicable | **none** | semantic; requires the Vanian test |
| PhysicalEffect ceiling | Skill 21 suites | diff review | **F5 found**: the ceiling type is constructible and deserializable | latent; physical truth still requires a real mechanism |
| Dependency risk | — | **cargo-audit** | **272 deps, 0 vulnerabilities** — genuine independent evidence | only as current as the advisory DB |

The honest summary of this table: external tooling produced exactly one
piece of independent security evidence (the clean advisory scan) and one
new finding (F5, via structured review rather than a tool). Every
distinctively Vanian property was challenged by reading, not by a scanner,
because no scanner in this environment can express those properties.

## 17. Areas external tools cannot validate

- That absence of observation is not treated as absence of effect.
- That a re-derived verdict genuinely re-derives.
- That an evidence ceiling is the minimum of what the mechanisms support.
- That an observer is independent of the observed subject.
- That a warrant's response ceiling is not reachable by accumulating weak
  signals.
- That a proof establishes what it says and nothing more.

These are the properties Vanian exists to provide. They remain the
exclusive responsibility of Vanian's own tests, and no external tool
installed or evaluated here reduces that responsibility.

## 18. Recommended permanent CI integration

Recommendations only. Nothing below was applied.

**Blocking, and in this order:**

1. **Make CI run on this branch.** Either open a pull request for
   `claude/codebase-production-readiness-wm6idp`, or add it to the `push`
   branch filter. Until this is done, no other recommendation has any
   effect, and 213 commits of security work remain unvalidated by anything
   but an agent.
2. **Decide the audit scope and fix F3** — deliberately, not by editing a
   path until it goes green. One root-level `cargo audit` now matches the
   one-workspace design.
3. **Delete `aip-service/Cargo.lock`** (F4), for the reason the root
   `Cargo.toml` already gives about the lockfile that was removed.
4. **Diagnose the gitleaks failure** (F2) and either fix the action
   configuration or act on what it found. A gate that has been red for five
   days is not a gate.

**Recommended, non-blocking:**

5. Seal `EffectFinding` before a reconciler consumes it (F5).
6. Run `cargo deny check` locally at least once; it is configured but has
   never been observed to execute here.
7. Consider `security-guidance` as an independent reviewer — as an explicit
   owner decision, with its hook permissions understood, and configured to
   report rather than to act.
8. Consider CodeQL for Rust as a genuinely independent static analyser.
   None is configured today.

---

## Epistemic classification

- **CODE-PROVEN:** one workspace, 29 members, `aip-service` a member as
  `airon-aip`; `aip-standalone/Cargo.{toml,lock}` absent; `VerifiedProof`
  Serialize-only; `VerifierCapability` non-`Deserialize`; one `Custodian`
  trait; `EffectFinding` unsealed and deserializable; `PlaintextFile` is not
  production.
- **TEST-PROVEN:** cargo-audit 272 deps / 0 vulnerabilities; the two CI
  audit paths measured directly (exit 2; 252 deps).
- **DOCUMENTED:** deny.toml policy and the RUSTSEC ignore justification —
  read, not re-verified.
- **INFERRED:** the gitleaks failure is a configuration problem rather than
  a detected secret. Timing only; the step log was not retrieved.
- **UNKNOWN:** whether gitleaks has found a secret in history; whether
  cargo-deny passes; whether any Vanian semantic property is violated in a
  way no test covers.

## Final confirmations

`main` untouched · nothing promoted · Skill 24 not started · Skills 25–30
not started · no Vanian security semantic modified · no CI file modified ·
no scanner finding auto-applied · no duplicate security mechanism created ·
no second verifier, reconciler, observer, trust anchor or identity model
introduced.
