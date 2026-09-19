# Data Protection Officer sign-off — Sniffer Dog / AIP observation pilot

**This template is completed by the regulated entity, not by VANIAN.** The
supplier cannot make a lawful-basis determination on the entity's behalf, and
a template that pre-filled one would be inviting exactly that mistake.

Required before Phase 1 of the pilot (`docs/pilot/BFSI_PILOT_PLAN.md`).
Stricter review applies where the observed agent touches lending or insurance
workloads.

---

## 1. What is being reviewed

The complete set of fields that leave the observed host is generated from the
code rather than written by hand:

```sh
cargo run -p aip-conformance --bin emit-compliance -- docs/compliance
```

produces `docs/compliance/DPDP_FIELD_INVENTORY.csv` and `.json`. Attach the
copy generated from the exact build being deployed — not a copy from the
repository — and record its checksum below.

A repository test (`aip-conformance/tests/dpdp_inventory.rs`) derives the
field set from the observation structure itself and fails the build if a
field is added without an inventory row. The inventory therefore cannot
silently fall behind the code between this review and the next.

| Item | Value |
|---|---|
| Build / release tag reviewed | |
| Inventory file SHA-256 | |
| Number of fields | |
| Fields classed `DIRECT` (carry personal data whenever populated) | |
| Date generated | |

If the `DIRECT` count is not zero, **stop**: the system's claim that no
personal data is collected directly no longer holds, and the basis for the
pilot has to be re-established rather than adjusted.

## 2. Determinations the entity must record

| # | Question | Determination | Signed by |
|---|---|---|---|
| 2.1 | Is any field classed `POSSIBLE-BY-CONFIGURATION` in fact personal in this deployment? Consider agent identifiers derived from staff identity, probe names, and executable paths under home directories. | | |
| 2.2 | Lawful basis for processing the observation data. | | |
| 2.3 | Purpose limitation: is the data used for anything other than accountability for agent actions? | | |
| 2.4 | Retention period, and how it relates to the 180-day CERT-In floor enforced in `deploy/sql/hardening.sql`. | | |
| 2.5 | Who inside the entity may read observation data, and under what control. | | |
| 2.6 | Whether data subjects (including staff whose hosts are observed) require notice. | | |
| 2.7 | Cross-border: confirm the deployment is on-premises and that no evidence or key leaves the entity's environment. | | |

## 3. Configuration commitments

These reduce the personal-data surface and are the entity's to make. Record
the decision either way; "not done" is an answer, "not considered" is not.

| # | Commitment | Adopted? | Note |
|---|---|---|---|
| 3.1 | Agent identifiers are derived from workload identity, not from a person. | | |
| 3.2 | Probes are named after hosts or roles, not after individuals. | | |
| 3.3 | Agents run from system paths, so no executable path carries a username. | | |
| 3.4 | The file-write sensor (which records paths) is not enabled in this pilot. | | |
| 3.5 | Access to the collector host is restricted to named administrators. | | |

## 4. Scope limits this review does not cover

Stated so that a later reader does not mistake this sign-off for more than
it is:

- **Model behaviour.** This system observes execution, not model outputs. Bias,
  fairness and drift are the model risk function's, and no field here speaks
  to them.
- **Application payloads.** No payload is captured or hashed anywhere in the
  observation pipeline. Transaction parameters enter signed documents only as
  domain-separated commitments; the arguments themselves are never present.
- **The entity's own records.** Authority tokens, decisions and the AI
  inventory are the entity's processing and are inventoried with the rest of
  it.

## 5. Sign-off

| Role | Name | Signature | Date |
|---|---|---|---|
| Data Protection Officer | | | |
| Information Security | | | |
| Business owner of the observed agent | | | |

**Review due:** at the next of — a change to the inventory file's checksum, a
new sensor being enabled, the pilot moving to a new workload, or six months.
