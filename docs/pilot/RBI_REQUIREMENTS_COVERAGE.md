# RBI ecosystem requirements → coverage matrix

> **Status: normative for the roadmap, September 2026.** Every requirement an
> agent deployment inside an RBI-regulated entity must meet, drawn from
> `RBI_AGENT_RISK_MAP.md`, with one of four dispositions:
>
> - **EXISTS** — code and a test that exercises it, named.
> - **BUILD** — inside the accountability domain; roadmap item and acceptance
>   test named. Not shipped until the test passes.
> - **INTEGRATE** — the RE's or a partner's system supplies it; we supply the
>   evidence it consumes or the interface it calls.
> - **OUT OF SCOPE** — a different discipline with a named owner. Claiming it
>   would be false and RBI would find it.
>
> "Every solution the ecosystem requires" is honest only in this form: the
> accountability and evidence domain covered completely, and everything else
> attributed to its owner. A vendor that claims all four columns as EXISTS is
> the vendor RBI's own FREE-AI report warns REs about.

## 1. The matrix

### A. Authority and mandate (who may do what)

| # | Requirement | Instrument | Disposition | Where / acceptance |
|---|---|---|---|---|
| A1 | Authorization adjudicated **outside the agent**, signed before the act | FREE-AI accountability; IMF "verifiable mandates" | EXISTS | `aip-authorize::DecisionPoint::adjudicate`; `tests/adversarial.rs` |
| A2 | Delegation attenuates only (scope, expiry, depth); issuer must hold the parent | IT Outsourcing "cannot outsource accountability"; MRM third-party | EXISTS | `aip-core::delegation::verify_delegation_chain`; P0-2 tests |
| A3 | Self-issued authority refused | FREE-AI accountability | EXISTS at decision point; **BUILD** in the protocol verifier | R6: `verify_packet` gains an `independent_authority_required` context flag; test: self-issued admin root fails `AUTHORITY_CHAIN` when set |
| A4 | Authority over **named resources**, not only actions | MRM "agent-level authority matrix"; Digit critique | **BUILD** | R1–R2: signed resource registry + resource scope in tokens; test: connect to a resource outside scope is denied at adjudication and, if executed, reconciles `UNATTRIBUTED_EFFECT` |
| A5 | Mandate carries transaction parameters (amount, beneficiary) without observer payload access | NPCI UAP; fraud-liability burden of proof | **BUILD** | R4: agent framework signs tool-call parameters into the expectation's parameter digest; test: mismatch between signed parameters and gateway receipt fails `ACTION_EVIDENCE_DOES_NOT_MATCH` |
| A6 | Revocation reaches verification, tenant-scoped | IT Governance access control | EXISTS (service) | `aip-service/tests/revocation_scope.rs` |
| A7 | Revocation distributed to **offline** verifiers with freshness | IT Governance non-repudiation | **BUILD** | R7: signed revocation list with issued-at and validity, consumed by `aip-verify --revocations`; test: stale list → `REVOCATION` NOT EVALUATED, never PASS |

### B. Independent observation (what actually executed)

| # | Requirement | Instrument | Disposition | Where / acceptance |
|---|---|---|---|---|
| B1 | Execution observed from the kernel, not from the agent | IT Governance audit trail; FREE-AI | EXISTS | perf tracepoints + connector, `aip-observe`; `ghost-demo/tests/live_*` |
| B2 | Process identity by content hash and instance, not PID or path | IT Governance forensics | EXISTS | `ExecutionBinding`; `live.rs` scenario D |
| B3 | Container / namespace identity in the binding | same | **BUILD** | R5: cgroup id + pid/mnt/net namespace inodes in `ExecutionBinding` v2; test: two containers sharing a PID view yield distinct bindings |
| B4 | Evidence key off the observed host | IT Outsourcing; CERT-In evidence integrity | EXISTS | `aip-collector` wrapped custodian; `tests/e2e.rs` |
| B5 | Blinded observer says so, never "nothing happened" | FREE-AI safety; non-repudiation | EXISTS | `IntegrityUnknown` across the split; ledger OI-01..OI-12 |
| B6 | Gate-independent coverage for non-occurrence claims | non-repudiation | EXISTS in pilot | connector in `aip-probe`; `covers_process_lifecycle` |
| B7 | File and wire evidence in the pilot probe | forensics | **BUILD** | R8: fanotify + AF_PACKET in `aip-probe` with capability trimming; live tests mirror `ghost-demo` |
| B8 | No payload capture, ever | DPDP data minimisation | EXISTS (invariant I23) | `wiretap.rs` header-only decoder; grep-clean of payload capture |
| B9 | Confidential probe→collector link | IT Governance; DPDP | **BUILD** | R9: TLS or Noise wrapper around `aip-transport`; test: plaintext observation metadata absent from a captured session |

### C. Reconciliation and verdicts (did execution match authority)

| # | Requirement | Instrument | Disposition | Where / acceptance |
|---|---|---|---|---|
| C1 | Closed verdict vocabulary with `CANNOT_PROVE` default | FREE-AI understanding by design | EXISTS | `aip-reconcile::ReconciliationResult` |
| C2 | Evidence strength separated from severity; no self-report raises strength | MRM explainability; FREE-AI | EXISTS | `Draft::precondition_holds`; three-crate pins |
| C3 | Verdicts name **resources**, not addresses | RE audit usability | **BUILD** | R3: access ledger resolves endpoints against the signed registry version in force |
| C4 | Per-agent, per-window **access ledger**: every resource reached, verdict, strength, signed, committed | FREE-AI AI inventory; IT Governance; Digital Lending LSP accountability | **BUILD** | R3: `aip-ledger`; test: ledger over a live run lists exactly the observed endpoints with their verdicts and verifies offline |
| C5 | Verdicts stored and served by the RE's own service | FREE-AI audit; RBI inspection | **BUILD** | R10: `aip-service` links `aip-reconcile`; `POST /v1/verdicts`, `GET /v1/agents/{id}/ledger`; tenant-scoped; test: cross-tenant 404 |
| C6 | `PHANTOM_CLAIM` demonstrated on real hardware with the two-daemon pair | evidence honesty | **BUILD** (pilot Phase 4) | RED suite on institution hosts; ledger row |

### D. Evidence integrity, portability and verification

| # | Requirement | Instrument | Disposition | Where / acceptance |
|---|---|---|---|---|
| D1 | Every artefact signed, domain-separated, canonically encoded | non-repudiation | EXISTS | `aip-types::canonical`; Gate-13 distinct-domain test |
| D2 | Append-only commitment with inclusion and consistency proofs | IT Governance; CERT-In | EXISTS | `aip-nexora` Merkle log, signed heads |
| D3 | External anchoring of log heads | tamper evidence against the operator | **BUILD** | R11: anchor sink to an RE-controlled second system (HSM-signed timestamp or independent ledger); test: a rewritten head fails against the anchor |
| D4 | Offline verification with RE-held keys, no call-home | data residency; RBI inspection | EXISTS | `aip-verify`, `nexora-verify`; both in releases |
| D5 | Signed audit-export bundle for the auditor | audit | EXISTS | `/v1/evidence/{id}/export`; `verify_zip` |
| D6 | Release artefacts **signed**, not only checksummed | supply-chain assurance; MRM third-party | **BUILD** | R12: sigstore/cosign in `release.yml`; test: verification step in CI against the published key |
| D7 | Storage-enforced immutability and retention (WORM, RLS, 180-day floor) | CERT-In 180 days; IT Governance | **BUILD** | R13: Postgres RLS + `REVOKE DELETE`, retention policy table, legal hold; test: delete attempt by the service role fails at the database |

### E. Operations and incident handling

| # | Requirement | Instrument | Disposition | Where / acceptance |
|---|---|---|---|---|
| E1 | Incident evidence bundle producible in minutes | CERT-In 6 hours; FREE-AI incident form | **BUILD** | R14: `aip-incident export --agent --window` → signed bundle (verdicts, batches, health, registry version, coverage statements); test: bundle verifies offline and lists coverage gaps explicitly |
| E2 | Metrics, SIEM export, runbook | IT Governance; SOC | **BUILD** | R15: OpenTelemetry metrics + syslog/CEF export of verdicts; runbook in `deploy/pilot/` |
| E3 | Kill-switch trigger interface | MRM kill switch | **INTEGRATE** | We emit graded verdicts and (advisory) warrants; the RE's orchestration or SOAR pulls the switch. Containment stays advisory in pilot. |
| E4 | Clock discipline (NTP), time anchoring of evidence | CERT-In | EXISTS partly | `BootClockAnchor` per batch; INTEGRATE: host NTP to NIC/NPL servers per CERT-In |
| E5 | Backup, DR, BCP for the evidence store | IT Governance BCP | **BUILD** | R13 (with D7); documented in `docs/BACKUP_AND_RECOVERY.md` with a tested restore |
| E6 | TLS and rate limiting at the service ingress | IT Governance | **BUILD** | R9: in-process TLS optional, ingress reference config mandatory; request timeouts and body limits; test: unauthenticated flood bounded |
| E7 | KMS/HSM custody for signing keys | IT Governance key management | **BUILD** | R16: PKCS#11 `Custodian` backend; test: key never leaves the module in the structural test |

### F. Governance artefacts the RE must hold

| # | Requirement | Instrument | Disposition | Where / acceptance |
|---|---|---|---|---|
| F1 | AI inventory entry per agent, six-monthly review, inspectable | FREE-AI | INTEGRATE + **BUILD** | The RE keeps the inventory; R3's access ledger is its evidence attachment; R17: export in the FREE-AI inventory shape |
| F2 | Control-framework mapping (IT Governance, Outsourcing, Digital Lending, FREE-AI, MRM, CERT-In, DPDP) to code and tests | all | **BUILD** | R18: `docs/compliance/CONTROL_MAP.md`: control ID → requirement → code → test → evidence artefact; every row must name a test or say NONE |
| F3 | Independent security assessment (CERT-In empanelled) | CERT-In; segment regulator | INTEGRATE | Commission it; R14's bundle and this matrix are its inputs |
| F4 | Red teaming of the observer and the decision point, trigger-based | FREE-AI | EXISTS partly | `ADVERSARIAL_RESULTS.md` ledger; BUILD: R19 scripted RED suite runnable on institution hardware |
| F5 | Third-party model and vendor-agent accountability | MRM; Outsourcing | EXISTS (evidence) | Observation is external to the vendor process; INTEGRATE: contract clauses requiring the probe on vendor-operated hosts |
| F6 | DPDP field-level review of every observed field | DPDP | **BUILD** | R20: data inventory of every batch field with lawful-basis note; DPO sign-off template in `deploy/pilot/` |

### G. Out of scope — named owners

| # | Requirement | Instrument | Owner |
|---|---|---|---|
| G1 | Model bias, fairness, drift, data quality | MRM; FREE-AI fairness | Model risk function; model vendors |
| G2 | Explainability of model decisions | MRM | Model vendors; RE model validation |
| G3 | Customer disclosure, consent, grievance redress | DPDP; Digital Lending; RBC | RE compliance; consent managers |
| G4 | Transaction-content fraud scoring, mule detection | MuleHunter / IDPIC | RBIH, IDPIC, RE fraud teams |
| G5 | What was said inside a TLS session or a chat | — | Agent framework (sign tool calls, R4) and gateway receipts |
| G6 | Root or kernel compromise of the observed host | — | Host hardening, hardware attestation (ADR-002), off-host observation research |
| G7 | Concentration risk across vendors | Governor's seven risks | RE board; RBI supervision |
| G8 | Performance, throughput, latency figures | — | Benchmark on institution hardware; none quoted until then |

## 2. Roadmap (build items referenced above)

Ordered by what an RBI-supervised evaluator asks for first. Each item ships
only with its acceptance test.

| Item | Scope | Depends on | Acceptance |
|---|---|---|---|
| **R1 Resource registry** | `aip-registry`: signed, versioned registry of named resources (address ranges, ports, protocol, criticality class), canonical encoding, offline verification, endpoint→resource resolution with "unregistered" as an explicit outcome | — | Signed registry verifies; tampered entry refused; ambiguous overlap refused at load; resolution is deterministic and total |
| **R2 Resource scope** | Resource grants in tokens and expectations, attenuating down the chain; decision point refuses out-of-scope resources | R1 | Protocol change guard review; wire version bump; adversarial tests mirror the action-scope suite |
| **R3 Access ledger** | `aip-ledger`: per-agent, per-window signed ledger of resources reached with verdict and strength, committed as its own leaf kind, verifiable offline | R1 | Live run → ledger lists exactly the observed endpoints resolved to names; every row cites its verdict; mutation refused |
| **R4 Signed tool calls** | Agent-framework SDK signs tool-call parameters into the expectation's parameter digest; gateway receipt countersigned | R2 | Parameter mismatch reconciles to a named failure; observer never reads payload (grep-clean) |
| **R5 Binding v2** | cgroup id and namespace inodes in `ExecutionBinding` | — | Container-distinct bindings; PID-reuse across containers refused |
| **R6 Independent authority in the verifier** | `verify_packet` context flag refusing self-issued roots | — | Self-issued admin root fails when set; default unchanged and documented |
| **R7 Revocation distribution** | Signed, time-bounded revocation list for offline verifiers | A6 | Stale list → NOT EVALUATED |
| **R8 Pilot probe sensors** | fanotify, AF_PACKET in `aip-probe` | — | Live tests; capability trim per sensor |
| **R9 Confidential transport + ingress** | TLS/Noise on probe→collector; ingress reference; timeouts | — | Capture shows no plaintext metadata |
| **R10 Verdict API** | `aip-service` links the reconciler; tenant-scoped verdict and ledger routes | R3 | Cross-tenant 404; verdict verifies offline from the API response |
| **R11 External anchoring** | Head anchor sink to an RE-controlled second system | — | Rewritten head fails against anchor |
| **R12 Signed releases** | sigstore in `release.yml` | — | CI verifies signature |
| **R13 Storage controls** | RLS, `REVOKE DELETE`, retention table, legal hold, tested restore | — | Service role cannot delete; restore drill documented |
| **R14 Incident bundle** | `aip-incident export` | R3 | Bundle verifies offline; coverage gaps listed |
| **R15 Metrics/SIEM/runbook** | OTel metrics, CEF/syslog verdict export, runbook | R10 | SIEM receives every verdict; runbook exercised |
| **R16 HSM custodian** | PKCS#11 backend | — | Structural test: no key export path |
| **R17 Inventory export** | FREE-AI inventory shape | R3 | Export validates against the form |
| **R18 Control map** | control ID → code → test → artefact | all | No row without a test or an explicit NONE |
| **R19 RED suite harness** | scripted attacks for institution hardware | — | Every ledger row reproducible by script |
| **R20 DPDP field inventory** | every batch field, lawful basis, DPO template | — | DPO sign-off obtained before Phase 1 |

## 3. Reading this matrix with RBI

Lead with the EXISTS rows and their tests. Show the BUILD rows with their
acceptance tests as commitments with dates, not as features. Show the OUT OF
SCOPE table unprompted: an evaluator who finds it before you say it will
assume the rest of the matrix is equally optimistic. The INTEGRATE rows are
where the RE's own teams and the RE's vendors must act; name them in the
pilot's roles section.
