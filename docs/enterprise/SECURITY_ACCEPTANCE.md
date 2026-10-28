# Security acceptance and evidence meanings

Each property has an independent status. Signature validity does not establish
live coverage, logical-agent identity, a completed bank transaction, independent
administration or production approval.

| Property | What can establish it | What remains outside that proof |
| --- | --- | --- |
| Evidence integrity | Existing signatures/chains plus independently retained checkpoint | Host honesty, complete ground truth and institutional custody |
| Observation coverage | Signed health for the actual interval, adequate sensors, clock and loss/integrity gates | Effects outside that coverage or unsupported event classes |
| Process attribution | Boot ID, PID, start ticks, executable and namespace evidence | An in-process logical sub-agent or tool-server-to-agent delegation |
| Logical attribution | Independently authenticated orchestration/delegation evidence | Agent logs alone; timestamp proximity alone |
| Gateway request verification | Signed expectation plus signed receipt of actual gateway-received canonical parameters | Business effect or tool-server truth |
| Business outcome | Authoritative business-system evidence and domain acceptance | A Forwarded receipt, model recommendation or kernel packet |
| Collector custody | Separately controlled host/key/storage evidence | Two accounts or containers on one kernel |

The new composition reuses the existing `ReconciliationResult` semantics.
`ghost.tool.invoke.v1` is an application-level action. Request-document
agreement may coexist with kernel `CannotProve/ActionEvidenceUnavailable`.
The output must keep those results distinct. Expected-side completeness stays
unknown unless a separately valid signed completeness record establishes it.
Missing authority is not automatically unauthorized execution.

## Required cases

| Case | Required behavior and retained evidence |
| --- | --- |
| A: authorized action | Genuine model chooses allowed read; independent authority signs; gateway verifies actual parameters; original kernel records/coverage and supported finding retained |
| B: parameter mismatch | Controlled changed request reaches actual gateway under original signed decision; signed Refused receipt and document divergence, with no extra upstream read |
| C: missing authorization | Evaluate captured records without expectation/completeness; explicit inability to prove; no unauthorized classification |
| D: observer interruption | Actual authorized isolated degradation; signed coverage withdrawn, recovery does not backfill. Typed regressions/RBI history are distinct from a genuine-workload interruption |
| E: missing receipt | Kernel result cannot acquire application-level proof; tool boundary is NotEvaluated/NoReceipt |
| F: wrong process | IdentityDivergence only after valid signatures, process/claim and integrity prerequisites; insufficient linkage stays CannotProve |
| G: tamper/truncation | Altered signed expectation/receipt/verdict, interior mutations, duplication/reordering/corruption rejected; valid prefix/suffix deletion requires independent checkpoint |

Unit fixtures are ordinary predicate tests and must remain labeled. Offline
mutations of actual captured records are controlled negative verification;
they do not assert that the genuine agent performed an adversarial action.
Live interruption and actual parameter-mismatch stimuli identify their
controller origin explicitly. Exact executed results belong in the retained
run report; this table is not itself a passing result.

## Isolation checks

The agent must be unable to read authority, gateway or collector keys. Its
gateway credential must have only read/execute permission, with default broad
roles revoked. Actual attempts to administer the gateway and bypass it through
the direct tool endpoint must fail. Measured inference uses only the pinned
local model and permitted local endpoints. Linux capabilities are dropped and
no-new-privileges is asserted. Host root/kernel remains trusted in the local
profile. An external collector is required for the stronger compromise claim.

The final retained signed health record is authoritative. A previous Active
record cannot replace a later degraded record. Backwards health chronology is
rejected, and the collector must seal the frozen final batch head before export.
Neither signed archive tails nor adverse health records may be trimmed to
produce a favorable result.
