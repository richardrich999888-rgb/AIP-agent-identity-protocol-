# P0-051 completion checkpoint — release NOT READY

12 November 2026 (Asia/Kolkata). This report closes a bounded teaching diagnostic
item. It is not a final-release acceptance certificate.

## Iteration 3: lifecycle scope isolation

Published source **`ee3850c0c67995ee53e2e82b4983f6e0b55460fd`**, CI merge
`5acfc0efdb9703fe43f29e9b4375d713d1bf1aa6`, identical tree
`0adadc1fc3d6ebd48fc13cf7d6a0f87f664546fc`.

The existing lifecycle selected active versions by capability ID alone. In a
shared store, activating/superseding one tenant's capability could displace
another tenant's version; rollback could suspend another security domain's
record. The added tests reproduced **six failures and one pass** on the prior
module, including both real CLI attacks. The original failed states, signed
suites/approvals and public test keys are retained.

Version selection now uses **tenant + security domain + capability ID** in
activation, direct transitions, supersession and rollback. Cross-scope records
remain byte-for-byte unchanged. Existing same-scope conflict and unapproved-target
refusals remain intact. This is a lifecycle selection repair, not proof that an
actor string authenticates an operator. Authenticated C2 approval, expiry,
revocation, policy floors and transactional storage-failure handling remain open.

Fresh checks: **194 runtime tests** pass locally (including seven new tests),
**445 full Python teaching tests** pass, and scoped Clippy/format checks pass.
Hosted teaching **43224795762 passes 296 relevant Rust and 267 focused Python**
tests. Counts overlap. The original control remains 11/12 rejected; corrected
12/12 and 26/26, including the six nonactivation probes, replay using the current
binary from the downloaded CI originals. Example agreement remains separately
3/3. No frozen task/dataset bytes changed.

The 11 successful fixture worlds on the clean local source and the 11 hosted
worlds retain original signed suites, approval records, snapshots and public
keys. A separate Python cryptography verifier checks the existing signatures,
capability/report/suite hashes and tenant bindings. One-byte approval modification,
changed source/suite/tenant, missing approval and wrong trust each reject.
**Lifecycle history is unsigned**; signature verification alone also succeeds
for the failing baseline's authentic approvals. The behavior tests and original
before/after states establish the selection defect and its fix.

The clean scoped test command ran in a local network namespace in
**0.560703042003297 s**, child CPU **1.194756 s**, peak child RSS **53908 KiB**;
only loopback existed and byte counters remained zero. This is a parallel unit/
CLI component observation, not a commercial demo timing or hardware sizing result.
No model, sensor, packet capture, clean-machine installation or final rehearsal ran.

Main CI **43224795474** is tracked separately in the evidence provider snapshot;
no pending result is credited. Security **43224795526 fails four HIGH findings**
in the retained historical Helm output. The prior mapping source `7c9a0b3` main
CI 43220664053 subsequently passed; it is not substituted for this new source.
See [iteration 3 originals](evidence/p0-051-iteration-3/README.md). Release **NOT READY**.

## Iteration 2: explicit example validation

Published implementation **`7c9a0b385d88460d19da100a4c99dd0ff3c2a2c0`**, tree
`90f9291d7ec392db466c52016c581112815080b0`. Hosted merge
`c6fd26a1468644b16261e16b2ef36ec9a94acb3b` has the identical tree.

The general session diagnostic accepts an explicit outcome/label mapping bound
to the session, capability, source, task, answers and signed suite. It replays
original examples in the native engine and reports them separately. Unmapped,
missing-input, ambiguous, out-of-domain and failed execution results stay
withheld. A refusal cannot satisfy a negative example; passing examples cannot
override a failed independent suite. The map is an **unsigned review declaration**,
not authenticated expert approval. No lifecycle writes or activation occur.

Fresh results: **445 full Python tests pass without skips**, including 37 new
mapping checks. Hosted teaching run **43220664054 passes**: 267 focused Python
checks and 289 relevant Rust tests (187 runtime, 102 sovereign). Counts overlap;
no totals are added across local/CI runs. Frozen task/dataset bytes are unchanged.
The control remains **11/12 rejected**; corrected suites remain **12/12 and 26/26**,
including the same six nonactivation cases. All three scenarios separately
show **3/3** reviewed examples; the control still rejects. No map leaves examples
NOT_MEASURED. The new tests include stale bindings, malformed maps, unsafe refusal
mappings, omitted/reordered/substituted native results and unchanged lifecycle.

Original local and downloaded CI session inputs were replayed in new processes
inside a network namespace with no external route, without the original private
state. Native source/citation/answer compilation and signed-suite checks rerun;
saved PASS fields are not trusted. Six signature instances per host verify with
Python cryptography: these are **three unique signed suites duplicated before
and after review**, not six independent suites. One-byte suite tampering, wrong
public authority and stale map bindings are rejected. Altered stored diagnostic
verdicts do not affect recomputed outcomes. This is not independent administration.

The original first regression (67 pass / 1 fail) remains retained: its new
missing-input test lacked taught context and correctly got NOT_APPLICABLE. The
input was corrected to include that context; frozen labels were untouched. A
first replay-control script expected exit 2 for a structurally valid wrong key;
the documented native validator returns rejection exit 3. That original is kept;
the corrected control additionally asserts failed validation and zero passed
expert cases. Neither failure was hidden or converted into an accepted capability.

The local component ran in **2.5933206640002027 s**, child CPU
**1.9584009999999996 s**, peak child RSS **62592 KiB**; full Python regression was
running concurrently. The hosted run took **1.8950681390000028 s**, child CPU
**1.014322 s**, RSS **67640 KiB**, on separately recorded hardware. These are
single component observations, not a benchmark range or complete demo duration.
Local namespace interface counters stayed zero; there is no packet capture,
model inference, sensor run, complete kit installation or rehearsal credit.

Security **43220664086 fails the same four HIGH Helm-render findings**; audit
and secret scanning pass. Original SARIF is retained without suppression.
Main CI **43220664053 is tracked in the checkpoint provider snapshot**; a
pending result is not a pass. The earlier `5bc0c5f` main CI subsequently passed.
Original inputs, signed suites, raw CI ZIP/log, failures, replay helpers and
SHA-256 manifests are in [iteration 2 evidence](evidence/p0-051-iteration-2/README.md).

Next: authenticated C2 authority and signed teaching approval, binding the
reviewed mapping digest as well as source/suite/capability/scope. PDF/DOCX scoring,
E1 and every other release gate remain as listed in the matrix. **NOT READY.**

## Previous iteration: session integration (`5bc0c5f`)

Implementation `5bc0c5f68690e5d2656716a97c2cfbb2ce105e08` extends draft
[PR #21](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/pull/21)
on `feature/airon-teach-demo`. No merge or force push occurred. The CI merge
`9892299fbbb4d76c8dfe62665a8ddd950221fe18` and implementation have identical tree
`751702c7f6472d52062040b942132c88341a31b5`.

The general TXT session diagnostic reads a content-verified stored session,
checks original document bytes and cited spans, regenerates the draft/questions,
applies bound expert answers and recomputes an independent signed suite through
the existing native validator. A rejected case links to exact question IDs,
citations, quotations and edits. Links identify review candidates or authors of
the executed rule; they do not assert a proven cause. Original lifecycle state
is unchanged; output is owner-only; no approval or activation occurs.

The branch advanced during the audit. Reviewed `6764c7e` already supplied the
sandbox readiness repair, post-probe authority/program checks, stronger timeout
test and signed CLI recorder. That work was fast-forwarded and preserved. The
overlapping local repair was retained as superseded development work and never
pushed. P0-050's existing independent applicability replay was also preserved.

## Fresh verification

| Check | Observed result | Scope |
|---|---|---|
| Full Python teaching regression | 408 passed, no skips | Clean published source and rebuilt native binary; includes 33 new session checks |
| Runtime Rust regression | 187 passed | Existing lifecycle, scope, citations and capability gates |
| Sovereign Rust regression | 102 passed | 76 library + 24 sandbox + 2 SQLite upgrade; distinct from runtime suite |
| Hosted focused teaching regression | 230 passed | Overlaps the 408 local Python tests; do not add them |
| General session diagnostic, local and CI | Control 11/12 rejected; corrected 12/12 and 26/26 | Six nonactivation probes are a subset of 26; exact native outcomes and capability hashes agree |
| Existing applicability recorder/replay | 12/12 and 26/26, frozen subset 6/6 | Local and original CI evidence reverified with OpenSSL and native case replay |
| General-session signed suites | Three local and three CI signatures verified | Separate Python cryptography implementation; synthetic keys, not expert identity proof |
| Signed runner bundle | Local recorder passes; downloaded CI original verifies locally; one-byte tamper rejected | Separate verifier process, no private state; independent observation remains CANNOT_PROVE |
| Source/format/input checks | Clean source; matching CI tree; frozen data/task bytes unchanged; format passes | No acceptance label changed |

The new attacks cover changed source, content-hashed forged citations, wrong
tenant/task/domain/policy, insufficient clearance, stale drafts/questions,
unknown/incomplete answers, unsupported used numbers, forged/changed signed
suites, untrusted/wrong keys, a trusted self-evaluator, overwritten evidence,
non-finite/duplicate JSON and substituted native rows. These are diagnostic
checks, not the still-missing expired/revoked approval authority tests.

CI teaching run [43215328974](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43215328974)
passes. Its sandbox runs as uid 1001; the temporary profile is removed and the
host-wide namespace restriction remains 1. This tests the supported hosted path,
not an independently administered customer sensor installation. Main CI is
tracked in the retained final provider snapshot; no pending job is a pass.

Security run [43215329189](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43215329189)
fails Trivy on four HIGH findings in the retained historical
`validation/enterprise/results/HELM_20261028T103133Z/template-enabled.yaml`:
KSV-0009 hostNetwork, KSV-0010 hostPID, KSV-0118 root privileges and KSV-0121 `/proc`
mount. These were not suppressed or removed. Cargo audit reports no vulnerabilities
under the existing policy, which already contains advisory exception
`RUSTSEC-2026-0097`; this iteration adds no exception. Gitleaks passes.

## Evidence and limits

Original ZIPs, logs, source/hardware hashes, public trust, failed attempts,
signed suites and verification outputs are retained in
[`evidence/p0-051-iteration-1/`](evidence/p0-051-iteration-1/README.md).
Its SHA-256 manifest detects byte changes; it is not a signature or proof of
authority. Authenticate trust separately and rerun verification.

| One component observation | Host | Wall seconds | Child CPU seconds | Peak child RSS KiB |
|---|---|---:|---:|---:|
| Published session recorder | Development Linux x86-64, 9 logical CPUs | 0.9302947449996282 | 0.645871 | 62592 |
| Same-source hosted recorder | GitHub Linux runner; exact hardware in original ZIP | 0.7274345790000041 | 0.632221 | 67416 |

These are separate single-run measurements, not a range, investor-show runtime,
second-machine offline benchmark or sizing guarantee. No model was loaded. No
packet capture, initial-netns native sensor run, final kit installation or
qualifying full-mode rehearsal was performed. Final consecutive-pass credit: zero.

Development failures remain retained: the original sandbox regression failed on
the old source; two initial new mutations did not affect used rule values; an
initial full Python run skipped two tests because it defaulted to an absent
release binary. Correcting the mutations and explicitly selecting the staged
binary produced the later passes. No frozen expectation was relabelled.

OVERLAY's authorized remote inventory is accessible, but the git checkout attempt
failed because git credentials were unavailable. The connector still exposes
source metadata; this is not total repository inaccessibility. All six recorded
W4/W5 revisions remain unavailable by commit lookup. No original was invented,
no replacement was claimed implemented, and no OVERLAY draft PR was fabricated.

## Next acceptance work

At iteration 1, C1 remained partial for session-example mapping and PDF/DOCX integration.
Iteration 2 above closes only the explicit TXT example-mapping mechanism.
Then complete authenticated signed expert approval/authority expiry and
revocation, safe activation/supersession/rollback, signed packs and answer
receipts. The UI/APIs, two full synthetic domains, PQ/CBOM replacements, offline
payloads, separate clean hosts, benchmarks and required rehearsals remain open.
See the [release gap matrix](P0-051-RELEASE-GAP-MATRIX.md) and
[open gaps](P0-051-OPEN-GAPS.md). The release remains **NOT READY**.
