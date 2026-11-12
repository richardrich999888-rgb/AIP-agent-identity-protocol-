# Independent verification — current scope

**Full release verification: NOT READY.** The complete kit has not been installed
on an independent clean machine or accepted by an external evaluator. The bounded
C1 diagnostic reproduced on CI; that connected build is not kit acceptance.
Source checkouts, unit tests,
new directories and development namespaces do not satisfy that requirement.

## Latest lifecycle isolation checkpoint

Source `ee3850c0c67995ee53e2e82b4983f6e0b55460fd` fixes cross-tenant/domain
supersession and rollback. Its hosted merge `5acfc0efdb9703fe43f29e9b4375d713d1bf1aa6`
has the same tree. These original records use the existing v1 signed suites and
approvals; the human-teaching authority flow remains incomplete.

```bash
(cd docs/demos/evidence/p0-051-iteration-3 && sha256sum -c SHA256SUMS)
export P051_SCOPE_REVIEW="$(mktemp -d)"
unzip -q docs/demos/evidence/p0-051-iteration-3/ci-teaching-original.zip \
  -d "$P051_SCOPE_REVIEW/ci"
python3 docs/demos/evidence/p0-051-iteration-3/verify_lifecycle_records.py \
  "$P051_SCOPE_REVIEW/ci/lifecycle-isolation-evidence" \
  --trusted-pins docs/demos/evidence/p0-051-iteration-3/ci-synthetic-trust-pins.json
```

Expected: ORIGINAL_SYNTHETIC_SIGNATURES_VERIFIED, 11 fixture worlds, no failed
test world. Authenticate the selected source/archive and pins independently.
The original CI ZIP SHA-256 is
`d0b43c755fb23e2bb74f7669355b023959472cc64793cde98da6dca49e9cc5b9`.
The verifier uses Python cryptography (recorded 50.0.0) and checks capability,
source-dependency, validation-report and signed-suite bindings. It needs no
original private key or agent runtime. It does **not** authenticate the unsigned
lifecycle history, expert identity, current authority validity or execution.
Even authentic baseline signatures accompany six failing behavior tests; inspect
and rerun the behavior tests before claiming isolation.

```bash
SYNTRIASS_LIFECYCLE_EVIDENCE="$P051_SCOPE_REVIEW/fresh" \
  cargo test --locked --offline -p syntriass-runtime --test lifecycle_isolation
```

Stage the exact toolchain/dependency cache before disconnecting. This is an
engineering test, not the final offline installer. Seven tests must pass,
including real CLI supersession and rollback, with foreign records unchanged.
The checkpoint retains baseline failures, correct results and six verifier
mutations: approval byte, source/suite/tenant binding, missing approval and wrong
trust. Those mutations reject. All full-mode rehearsal counts remain zero.

For the previous C1 replay helper against this checkpoint's teaching inputs,
select the independently checked current binary hash:
`6624ef6ad82d529c5f311254c0ddd95a96583c1ba4fbf190e3a7143416e1617f`.
The old binary hash in iteration 2 below intentionally identifies that earlier
source. Current CI originals replay 11/12 rejected, 12/12 and 26/26 passing,
with examples reported as 3/3 separately; replay transcripts are retained.

## Iteration 2: replay the explicit example mapping

Use trusted source `7c9a0b385d88460d19da100a4c99dd0ff3c2a2c0` (or its later
documentation-only checkpoint). The hosted merge has identical tree
`90f9291d7ec392db466c52016c581112815080b0`. Stage all prerequisites first;
these commands do not download anything. The recorded native binary SHA-256 is
`e6bdba858687677d0a928035db55e5e002d06f5cf1eff5d33a4a351148a56c5c`.
An independent build may differ; select and verify its hash separately instead
of silently accepting an archive-supplied executable.

```bash
(cd docs/demos/evidence/p0-051-iteration-2 && sha256sum -c SHA256SUMS)
export P051_MAPPING_REVIEW="$(mktemp -d)"
unzip -q docs/demos/evidence/p0-051-iteration-2/ci-teaching-original.zip \
  -d "$P051_MAPPING_REVIEW/ci"
python3 docs/demos/evidence/p0-051-iteration-2/replay_retained_session.py \
  --repo "$PWD" --binary "$PWD/target/debug/syntriass" \
  --binary-sha256 e6bdba858687677d0a928035db55e5e002d06f5cf1eff5d33a4a351148a56c5c \
  --folder "$P051_MAPPING_REVIEW/ci/session-scoreboard-evidence/corrected-validation" \
  --trusted-keys "$P051_MAPPING_REVIEW/ci/session-scoreboard-evidence/corrected-validation/expert-public.json" \
  --out "$P051_MAPPING_REVIEW/recomputed-validation"
```

The original CI ZIP hash is
`e566d34a6294e8c37a35106d37b45e26a67e1ef4a8ad357e02cc8d55dcf87648`.
The command above uses that archive's **synthetic test authority**; it verifies
the documented experiment, not a real expert identity. Establish trust in the
archive/source independently. For other evidence, pass an independently provisioned
public-key map. A key bundled by an untrusted sender is not an authority.

Expect native signed-suite **12/12**, explicit examples **3/3 separately**, exit 0.
Use `corrected-attacks` and a different output directory for 26/26 (six probes
are a subset). `rejected-control` must exit 3 with 11/12 despite 3/3 examples.
The helper rebuilds the disposable session state, rechecks the content hash,
source spans and bound answers, recompiles and invokes the native validator.
It never reads the retained `result.json`, scoreboard verdict or bound capability
as its decision input. It is not pack import and writes no production lifecycle.

`local-original.zip` retains both original and replayed runs. The replay controls
retain one-byte signed-suite mutation, wrong authority, changed mapping and
altered saved verdicts. The first three reject; altering saved verdicts leaves
the actual recomputation unchanged. Reports and map declarations are unsigned.
Full authenticated C2 approval and the final independent evaluator remain open.

## Iteration 1 retained originals and reproducible diagnostic

Use source `5bc0c5f68690e5d2656716a97c2cfbb2ce105e08`. Its CI merge
`9892299fbbb4d76c8dfe62665a8ddd950221fe18` has the same source tree. Stage Python
3.10+, Git, a trusted Linux `syntriass`/`vanian` binary and `unzip` before disconnecting.
The existing suite signature checker additionally requires the recorded
`cryptography==50.0.0`; frozen-case replay uses OpenSSL. Nothing below installs
or downloads a dependency.

```bash
(cd docs/demos/evidence/p0-051-iteration-1 && sha256sum -c SHA256SUMS)
export P051_REVIEW="$(mktemp -d)"
unzip -q docs/demos/evidence/p0-051-iteration-1/local-original.zip -d "$P051_REVIEW/local"
unzip -q docs/demos/evidence/p0-051-iteration-1/ci-teaching-original.zip -d "$P051_REVIEW/ci"
python3 docs/demos/evidence/p0-049-iteration-1/verify_suite_signatures.py \
  "$P051_REVIEW/local/session-clean" \
  --trusted-keys "$P051_REVIEW/local/session-clean/corrected-validation/expert-public.json"
python3 docs/demos/evidence/p0-049-iteration-1/verify_suite_signatures.py \
  "$P051_REVIEW/ci/session-scoreboard-evidence" \
  --trusted-keys "$P051_REVIEW/ci/session-scoreboard-evidence/corrected-validation/expert-public.json"
python3 research/capability-learning/harness/record_session_scoreboard.py \
  --binary target/debug/syntriass --out "$P051_REVIEW/new-session"
```

These commands reproduce the documented synthetic test-key checks; accompanying
keys alone never establish real authority. Expect three suite signatures per
host, preserved 11/12 rejection, corrected 12/12 and 26/26, and no activation.
Inspect the original source, questions/answers and exact links in the retained
control. A fresh recording uses new session IDs and temporary keys. It is a
new component exercise, not a replay of the original key custody or a full W3 run.
The existing pinned applicability replay below can also be run on the extracted
`local/applicability-clean` and `ci/exclusion-evidence` with their separately
reviewed trust files in this evidence directory; update only the trusted runtime
hash for your independently built binary.

Verify the original CI runner bundle with public material in a new process:

```bash
target/debug/vanian verify --public "$P051_REVIEW/ci/sandbox-evidence/public.json" \
  --bundle "$P051_REVIEW/ci/sandbox-evidence/authorized.json"
target/debug/vanian verify --public "$P051_REVIEW/ci/sandbox-evidence/public.json" \
  --bundle "$P051_REVIEW/ci/sandbox-evidence/tampered-exit.json"
```

The first exits 0 and reports AUTHORIZED_AND_RUNNER_ATTESTED with independent
observation CANNOT_PROVE. The second must exit 1. This bundle is a namespace
runner exercise, **not** Sniffer Dog native observation or independent administration.
The original CI ZIP's digest is
`9f7f02803e53e48b337ea96b24790e9cace6cce259db99e400f33e9c05b7ef38`.

Final release acceptance still needs the complete offline installer, live models,
all required modes, original native/PQ evidence, separate clean hosts, benchmarks
and ten/twenty consecutive rehearsals. Signature validity alone closes none of
those missing behavior gates.

## Verify P0-050 iteration 1's accepted component

Use implementation `ef3d9d434e5ed55e5994331abc91c03833f997ff` and the current
command in `DEMO_GUIDE.md`. Build dependencies must already be staged for offline
use. Expect PASS_BOUNDED_B3, exit 0: holdout 12/12, expanded attacks 26/26, frozen
nonactivation subset 6/6. The rejected copied-plural control remains 11/12 and
18/26. Passing validation does not activate anything.

From the repository root, with Python 3.10+ and `cryptography==50.0.0` pre-staged:

```bash
cd docs/assurance/evidence/p0-050-iteration-1
sha256sum -c SHA256SUMS
python3 compare_runs.py baseline local ci/exclusion-evidence
python3 ../../../demos/evidence/p0-049-iteration-1/verify_suite_signatures.py \
  local --trusted-keys local/expert-public.json
python3 ../../../demos/evidence/p0-049-iteration-1/verify_suite_signatures.py \
  ci/exclusion-evidence --trusted-keys ci/exclusion-evidence/expert-public.json
```

The comparison uses only the standard library and does not import the compiler.
It checks unchanged labels, actual questions (each separately bound to its own
session), unchanged capability fields other than applicability, reported state
preservation and the six frozen cases. It is a consistency check of **unsigned
diagnostics**, not authentication of verdicts. Rerun the actual validator for
independent acceptance. The eight suite signatures authenticate synthetic test
inputs only. Use an independently held expert trust map in a real evaluation;
never trust an authority solely because its public key accompanied an archive.

`ci-teaching-original.zip` is the original GitHub artifact, SHA-256
`a35cecd3141759fb088df7bf1ac752b1f3ab909c5c227076ccbd7749c65f9489`.
Its original extracted files and manifests are retained. The CI merge
`de0786e22a433512c50c402af4057d28564452d1` and implementation both have tree
`d8e21fc9b2fa8ae4ad981036f0c082916fc51e86`. Local and CI binaries and hosts differ;
compare each separately. Evidence includes the failed parent, development
attempt, previous-binary run, fresh build, full logs, tampered-signature rejection
and an initially incorrect comparison-script assumption plus its recovery.

No complete offline kit, fresh-machine install, initial-netns sensor isolation,
pack verification, answer receipt, packet capture or external expert acceptance
is proved here. Existing deployed artifacts require explicit revalidation and
new approval after recompilation; no automatic migration or activation occurs.

## Replay without trusting diagnostic PASS fields

The new `research/capability-learning/harness/verify_applicability.py` uses
pre-staged Python 3.10+, OpenSSL and a separately trusted `syntriass` binary. It
checks external trust/byte pins, frozen cases, Ed25519 suite signatures and every
recomputed native result. It ignores packet `scoreboard.json` and `result.json`.
Missing checks fail closed. No downloads, model calls or activation occur.

From the repository root, first verify the retained files:

```bash
(cd docs/assurance/evidence/p0-050-replay && sha256sum -c SHA256SUMS)
(cd docs/assurance/evidence/p0-050-iteration-1 && sha256sum -c SHA256SUMS)
```

Select runtime and trust pins independently. A packet's accompanying public key
cannot establish authority. The commands below reproduce only the **synthetic**
evaluation, using its documented CI key and capability hash. Set `P050_RUNTIME`
to a trusted, already staged binary. If building first, use reviewed source and
`cargo build --locked --offline -p syntriass-runtime --bin syntriass`; missing
dependencies must fail. A rebuild can have a different binary hash.

```bash
export P050_RUNTIME=/absolute/path/to/trusted/syntriass
export P050_REVIEW="$(mktemp -d)"
python3 - <<'PY'
import hashlib, json, os
from pathlib import Path
trust = json.loads(Path('docs/assurance/evidence/p0-050-replay/ci-trust.json').read_text())
# Independently review this runtime before recording its hash. Other pins stay fixed.
trust['binary_sha256'] = hashlib.sha256(Path(os.environ['P050_RUNTIME']).read_bytes()).hexdigest()
Path(os.environ['P050_REVIEW'], 'trust.json').write_text(json.dumps(trust))
PY
python3 research/capability-learning/harness/verify_applicability.py \
  --evidence docs/assurance/evidence/p0-050-iteration-1/ci/exclusion-evidence \
  --trust "$P050_REVIEW/trust.json" --binary "$P050_RUNTIME" \
  --out "$P050_REVIEW/recomputed"
```

Expect exit 0, signature PASS and recomputed **12/12 plus 26/26**; six
nonactivation probes are a subset of 26. Changed capability bytes, signatures,
frozen cases or recomputed outcomes must fail. Use a new output directory each
time; prior evidence is preserved. OpenSSL supplies a separate signature
implementation; the native outcome engine is trusted, not reimplemented.
Synthetic keys prove neither expert identity nor independent administration.
The new report is unsigned; rerun the checks instead of trusting its PASS field.

Fresh replays, 22 positive/refusal tests, source hashes, hardware and command
results are in [`p0-050-replay/`](../assurance/evidence/p0-050-replay/README.md).
This closes a component verification gap, with no full-mode rehearsal,
expert-approval, pack or clean-machine installation credit.

## Reproduce historical P0-049 iteration 3's rejected candidate

Use source `4d002accbf6759fe1845872ac5579815c8081631` and the exclusion-policy
`record_exclusion_policy.py` command at that historical source. The correct observed result is exit **3** and
`PARTIAL_B3_ADVERSARIAL_FAILURE`, not green acceptance. Verify original 11/12,
explicit-forms 12/12, attack-control 17/26, and corrected attacks 25/26. The
remaining fa-3 failure must retain NOT_APPLICABLE as its expected label.

```bash
cd docs/demos/evidence/p0-049-iteration-3
sha256sum -c SHA256SUMS
python3 ../p0-049-iteration-1/verify_suite_signatures.py local \
  --trusted-keys local/expert-public.json
python3 ../p0-049-iteration-1/verify_suite_signatures.py ci/exclusion-evidence \
  --trusted-keys ci/exclusion-evidence/expert-public.json
```

The signature checker needs pre-staged `cryptography==50.0.0`; the recorder itself
uses only the standard library. Eight synthetic suites verify; modifying a signed
label is rejected. Retained test keys establish integrity, not expert identity.
The CI merge `192acf0` and implementation have tree
`ac6a26bcfec23e8da962d2e30633a056c9694950`; verify that equality before comparing
them. Per-host timing/CPU/RSS/network data remain separate. No rehearsal or
independent offline-install credit is earned by these runs.

## Reproduce the C1 diagnostic

Build a binary from the immutable implementation commit recorded in the evidence,
then run `record_scoreboard.py` as documented in `DEMO_GUIDE.md`. On a disconnected
host, use an already staged binary, Python, Git and this source checkout; the
recorder performs no downloads.
It regenerates the exact pinned datasets and refuses a hash mismatch.

Check `result.json`: source SHA and dirty status, binary hash, hardware and limits,
per-case status, full elapsed times, model calls (zero), and limitations. Inspect
the actual `scoreboard.json` files instead of relying only on the summary. The
transformer candidate must still fail `val-09`; hiding it invalidates acceptance.

```bash
sha256sum target/debug/syntriass
cargo test --locked -p syntriass-runtime --test teaching_scoreboard
cd /path/to/recorded/output
sha256sum -c SHA256SUMS
```

The suite signature is Ed25519 over `syntriass-expert-suite/v1\n` followed by compact
JSON with fields in this exact order: `suite_id`, `tenant`, `task`, `expert_id`,
`cases`. Each case is ordered `id`, `text`, `expected`, `counterexample`. Use the
operator's independently held expert public key. The retained public key in this
synthetic exercise is evidence of which test key was used; it is not independent
proof that a domain expert authorized it. `suite.rs` defines the canonical bytes.
The scoreboard recomputes validation; it does not accept an imported verdict.

A second Ed25519 implementation is retained with the evidence. With Python
`cryptography==50.0.0` already installed, from the repository root:

```bash
cd docs/demos/evidence/p0-049-iteration-1
sha256sum -c SHA256SUMS
python3 verify_suite_signatures.py scoreboard --trusted-keys scoreboard/expert-public.json
python3 verify_suite_signatures.py scoreboard-ci --trusted-keys scoreboard-ci/expert-public.json
```

Those commands reproduce the synthetic test-key check only. For real evaluation,
replace `--trusted-keys` with an independently provisioned expert-key mapping;
never trust a key merely because an imported pack contains it. Six suite
signatures passed; changing an expected label produced `InvalidSignature`, exit 1.
Hashes, suite signatures and matching report bindings do not authenticate the
unsigned diagnostic's claimed verdict; rerun the validator on trusted inputs.

Local and CI `result.json` files intentionally have different binary hashes,
hardware and timings. The CI merge and implementation commits share the exact
tree `557935e887f10328fb60355968503d8a619e3c1f`. Both runs use debug binaries.
The local network namespace had only loopback, with zero before/after byte and
packet increments. CI was connected and shows traffic. Neither has packet
captures or initial-netns sensor evidence, so neither closes Phase 2 acceptance.

The diagnostic JSON is **unsigned**. Existing validation/approval records have
their own binding format; no signed per-answer receipt or signed knowledge pack
was added by this iteration. A matching hash is not an approval.

## Verify the dependency upgrade

For the separate dependency/gate change in iteration 2, use the commands and
immutable RustSec snapshot in `P0-049-ITERATION-2.md`. The regression fixture was
written by SQLite 3.46.0 and read by linked SQLite 3.54.1. Check its hash and
producer before running `cargo test --locked -p vanian-sovereign --test sqlite_upgrade`.
Passing proves the tested compatibility and access restrictions; it is not a
malicious-WAL exploit test. The audit gate tests intentionally inject nonzero
Cargo exits and verify they cannot be hidden by report generation.

## Verify retained Sniffer Dog evidence

From a W checkout at `6ad92ae` and a built verifier:

```bash
cargo build --locked -p aip-observe-verify
target/debug/aip-observe-verify \
  --observer-id collector.lying --key-version 1 \
  --pubkey-file demos/lying-agent/evidence/2026-11-06/public/observer.pub \
  --batches demos/lying-agent/evidence/2026-11-06/public/attested.archive.jsonl \
  --health demos/lying-agent/evidence/2026-11-06/public/health.archive.jsonl --json
```

Observed again in P0-049: **7 linked signed batches, 86 kernel events, 1 health
record, no signature/chain findings**. Replacing `--batches` with
`demos/lying-agent/evidence/2026-11-06/tampered.attested.archive.jsonl` returns 1.

The retained health state is **ContinuityUnverified**, with zero records asserting
coverage and an unsynchronised clock. Verification proves these signed bytes and
their internal links, not complete observation, an honest root, current sensor
availability or absence of truncation. Independently retained boundary checkpoints
are needed to detect a valid-prefix/suffix truncation. Do not report this as a new
live kernel-observation run.

## External evaluator acceptance still required

The evaluator must obtain a complete immutable bundle and release trust material
independently; install it without internet on supported clean hardware; retain
host identity/provisioning, hashes, signed records, packet captures and interface
counters; run every required mode ten consecutive times and W3 twenty, including
fresh installs every fifth W3 run; preserve failures and reset the relevant pass
count. Reproduce benchmarks on that second machine with its own hardware label.
OVERLAY's original unavailable W4/W5 commits cannot be used as reproduction bases.

## S2 runner evidence (source 6764c7e)

See `../assurance/evidence/p0-050-sandbox/README.md` for exact source, original
ZIP digest, public-material pins, failed attempts and commands. With a trusted
`vanian` build, verify the retained `authorized.json` against the separately
authenticated `public.json`. Expect AUTHORIZED_AND_RUNNER_ATTESTED and independent
observation CANNOT_PROVE. A signature authenticates the runner's statement; it
does not prove a kernel observation or a logical agent's attribution.

The retained one-byte exit mutation and wrong-anchor copy must each exit 1.
`verify_download.py` repeats these checks and the signed 38-case teaching replay
with separately built binaries, into a new output directory. The reference trial
ran without an external network route. This is not a complete offline installer,
authenticated expert workflow or separately administered custody acceptance.

## P0-051 iteration 4 — policy-bound approval

Source `00c06de1503785470a73a7a2f0890ad8f9c1ce84` adds optional strict expert
authority grants and v2 Ed25519 approvals. Approval/activation/rollback/use enforce
key, tenant/domain, scope/version, clearance, expiry and revocation. Policy removal
cannot downgrade a v2 approval. Native CLI rechecks source dependencies.

Local runtime **201 pass**, teaching Python **445 pass**; teaching CI **303 Rust /
267 focused Python pass** (overlapping counts). Holdout **12/12**, attacks **26/26**
including six nonactivation probes; rejected control remains **11/12**. Independent
verification of original local/offline/hosted signatures passes; six tamper controls
reject. Full evidence, commands, source/host hashes, CI and failed recorder attempts
are in [iteration 4](evidence/p0-051-iteration-4/README.md). Native policy setup is
in [APPROVAL-AUTHORITY.md](APPROVAL-AUTHORITY.md).

**NOT READY. C2 remains partial.** Actor/role strings do not authenticate operators;
C1 session/full-document/example-map approval binding, policy rollback resistance,
per-approval revocation and transactional writes remain open. Strict policy must
be explicitly configured; legacy mode is not C2-qualified. Packs, models, UI/API,
OVERLAY, clean-host installation and independent demo acceptance remain open.
No new qualifying rehearsal: the offline 33-test component run on this same host
counts as zero demos. No live investor runtime, second host or sensor qualification.
