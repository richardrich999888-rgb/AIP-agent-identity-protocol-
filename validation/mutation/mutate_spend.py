#!/usr/bin/env python3
"""Mutation matrix for spend authority (ADR-018).

Three layers, each mutated against its own package's tests:

- `aip-spend`: the signed policy, the pure evaluation, the signed records;
- `aip-authorize`: step 5c at the decision point and the records it signs;
- `aip-aibom`: limits and approval thresholds assessed against them.

Most mutations try to let money through or let the report overclaim: read
an amount permissively, move a boundary, drop a refusal, sign an
attestation that binds nothing, or credit a limit nobody signed. The
forensic machinery — unique fragment, changed digest, successful compile,
byte-identical restore — is `mutate_core.run_matrix`, not reimplemented.
"""
import sys
import importlib.util
import pathlib

_HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("mutate_core", _HERE / "mutate_core.py")
_core = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_core)

REPO = _core.REPO
STANDALONE = REPO / "aip-standalone"


def m(id_, pkg, file, invariant, old, new):
    return {
        "id": id_,
        "pkg": pkg,
        "file": STANDALONE / pkg / "src" / file,
        "invariant": invariant,
        "old": old,
        "new": new,
    }


def sp(id_, file, invariant, old, new):
    return m(id_, "aip-spend", file, invariant, old, new)


def dp(id_, file, invariant, old, new):
    return m(id_, "aip-authorize", file, invariant, old, new)


def ab(id_, file, invariant, old, new):
    return m(id_, "aip-aibom", file, invariant, old, new)


MUTATIONS = [
    # ── aip-spend: evaluation ──────────────────────────────────────────
    sp("SP-01", "evaluate.rs", "an amount equal to the maximum is within it",
       "    if amount > limit {", "    if amount >= limit {"),
    sp("SP-02", "evaluate.rs", "an amount equal to the threshold needs no approval",
       "Some(threshold) if amount > threshold =>", "Some(threshold) if amount >= threshold =>"),
    sp("SP-03", "evaluate.rs", "an unreadable amount is refused",
       "matches!(self, Self::Exceeded { .. } | Self::Unreadable { .. })",
       "matches!(self, Self::Exceeded { .. })"),
    sp("SP-04", "evaluate.rs", "only ASCII digits are an amount",
       "if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {", "if bytes.is_empty() {"),
    sp("SP-05", "evaluate.rs", "more digits than a u64 holds is out of range",
       "    if bytes.len() > MAX_AMOUNT_DIGITS {", "    if false {"),
    sp("SP-06", "evaluate.rs", "an amount never wraps",
       "acc.checked_mul(10)", "Some(acc.wrapping_mul(10))"),
    sp("SP-07", "evaluate.rs", "a policy governs only its own agent",
       "    if policy.policy().agent_id != agent_id {", "    if false {"),
    sp("SP-08", "evaluate.rs", "a missing amount is not read as zero",
       "match param(&rule.amount_parameter) {", "match param(&rule.amount_parameter).or(Some(&b\"0\"[..])) {"),

    # ── aip-spend: policy ──────────────────────────────────────────────
    sp("SP-09", "policy.rs", "a threshold above the maximum is malformed",
       "if self.approval_above.is_some_and(|t| t > self.max_per_action) {", "if false {"),
    sp("SP-10", "policy.rs", "one rule per action",
       "if !seen.insert(action_key(&r.action)) {", "if false && !seen.insert(action_key(&r.action)) {"),
    sp("SP-11", "policy.rs", "a currency is three uppercase letters",
       "\n            && self.currency.bytes().all(|b| b.is_ascii_uppercase());", ";"),
    sp("SP-12", "policy.rs", "a policy changed after signing is refused",
       "        if self.signature.payload_hash != sha256(&p.canonical_bytes()) {", "        if false {"),
    sp("SP-13", "policy.rs", "verify validates, whoever signed",
       "        p.validate()?;\n        let key = anchors", "        let key = anchors"),
    sp("SP-14", "policy.rs", "rule order is not a change",
       "        rules.sort();\n", ""),
    sp("SP-15", "policy.rs", "the maximum is in the digest",
       "        put_u64(b, self.max_per_action);\n", ""),

    # ── aip-spend: records ─────────────────────────────────────────────
    sp("SP-16", "record.rs", "a record changed after signing is refused",
       "    if signature.payload_hash != sha256(preimage) {", "    if false {"),
    sp("SP-17", "record.rs", "a record's signature names its decision point",
       "    if signature.signer_id != signer {", "    if false {"),
    sp("SP-18", "record.rs", "the refused amount is signed",
       "        put_opt_u64(&mut b, &self.requested_minor_units);\n", ""),
    sp("SP-19", "record.rs", "the attestation verdict is signed",
       "        put_u8(&mut b, self.verdict.code());\n", ""),
    sp("SP-20", "record.rs", "an unknown record version is refused as such",
       "    if version != SPEND_RECORD_VERSION {", "    if false {"),

    # ── aip-authorize: step 5c ─────────────────────────────────────────
    dp("DP-01", "decision.rs", "a refusing outcome is refused",
       "if let Some(check) = spend.as_ref().filter(|c| c.outcome.refuses()) {",
       "if let Some(check) = spend.as_ref().filter(|_| false) {"),
    dp("DP-02", "decision.rs", "a held policy is consulted",
       "let spend = self.spend_policies.get(&req.agent_id).and_then(|policy| {",
       "let spend = None::<&VerifiedSpendPolicy>.and_then(|policy| {"),
    dp("DP-03", "decision.rs", "the amount is read from the request's own parameters",
       "                req.parameters.get(k)\n", "                req.parameters.get(k).and(Some(&b\"0\"[..]))\n"),
    dp("DP-04", "decision.rs", "an authorised governed decision is attested",
       ".and_then(|c| sign_attestation(c, &ee, &self.private_key))",
       ".and_then(|_| None::<Result<SignedSpendAttestation, aip_spend::RecordError>>)"),
    dp("DP-05", "decision.rs", "an exceeded limit is denied as such",
       "            aip_spend::SpendOutcome::Exceeded { amount, limit } => (\n                DenialReason::SpendLimitExceeded,",
       "            aip_spend::SpendOutcome::Exceeded { amount, limit } => (\n                DenialReason::SpendAmountUnreadable,"),
    dp("DP-06", "decision.rs", "a refusal is timed at the decision",
       "            refused_at_ms: now_ms,", "            refused_at_ms: 0,"),
    dp("DP-07", "spend.rs", "configuration cannot roll a limit back",
       "            if offered <= held {", "            if offered < held {"),
    dp("DP-08", "spend.rs", "a refusal carries the requested amount",
       "        requested_minor_units: requested,", "        requested_minor_units: None,"),
    dp("DP-09", "spend.rs", "a refusal binds the exact request",
       "        request_digest: ctx.request_digest,", "        request_digest: [0; 32],"),
    dp("DP-10", "spend.rs", "an approval-required decision is marked so",
       "SpendOutcome::ApprovalRequired { .. } => Some(SpendVerdict::ApprovalRequired),",
       "SpendOutcome::ApprovalRequired { .. } => Some(SpendVerdict::Within),"),
    dp("DP-11", "spend.rs", "an attestation binds its expectation",
       "        expectation_digest: expectation_digest(ee),", "        expectation_digest: [0; 32],"),
    dp("DP-12", "spend.rs", "an attestation is timed at its decision",
       "        attested_at_ms: ee.issued_at,", "        attested_at_ms: 0,"),
    dp("DP-13", "spend.rs", "an attestation carries the threshold applied",
       "        approval_threshold: check.rule.approval_above,", "        approval_threshold: None,"),

    # ── aip-aibom: limits and thresholds ───────────────────────────────
    ab("AS-01", "assess/spend.rs", "a limit differing from the signed one is contradicted",
       "Some(rule) if same_amount(rule.max_per_action, rule, &limit.max) => {", "Some(rule) if true => {"),
    ab("AS-02", "assess/spend.rs", "another currency is not the same amount",
       "\n        && rule.currency == declared.currency", ""),
    ab("AS-03", "assess/spend.rs", "another scale is not the same amount",
       "\n        && rule.exponent == declared.exponent", ""),
    ab("AS-04", "assess/spend.rs", "a per-day limit is governed by no per-action rule",
       "LimitPeriod::PerDay | LimitPeriod::PerMonth => None,",
       "LimitPeriod::PerDay | LimitPeriod::PerMonth => ev.rule(&limit.action),"),
    ab("AS-05", "assess/spend.rs", "a record citing another policy is reported",
       "    if cited.digest == held.digest() {", "    if true {"),
    ab("AS-06", "assess/spend.rs", "a signed limit nobody is shown enforcing is reported",
       "                if !ev.enforced {", "                if false {"),
    ab("AS-07", "assess/spend.rs", "equivocating policies are not relied on",
       "if at_top.any(|v| v.policy().digest() != first.policy().digest()) {", "if false {"),
    ab("AS-08", "assess/spend.rs", "the highest revision governs",
       ".map(|v| v.policy().revision).max()?", ".map(|v| v.policy().revision).min()?"),
    ab("AS-09", "assess/spend.rs", "another agent's policy does not count",
       "        if s.policy.agent_id != agent {", "        if false {"),
    ab("AS-10", "assess/spend.rs", "an issuer or decision point under the agent's key is refused",
       "matches!((key, i.context.agent_public_key.as_deref()), (Some(k), Some(a)) if k == a)",
       "false && key.is_some()"),
    ab("AS-11", "assess/spend.rs", "another agent's refusal does not count",
       "        if r.agent_id != agent {", "        if false {"),
    ab("AS-12", "assess/spend.rs", "another agent's attestation does not count",
       "        if a.agent_id != agent {", "        if false {"),
    ab("AS-13", "assess/spend.rs", "an attestation offered with a different expectation is refused",
       "if bound.is_some_and(|ee| expectation_digest(ee) != a.expectation_digest) {", "if false {"),
    ab("AS-14", "assess/spend.rs", "a record must verify to count",
       "    match verified {\n        Ok(()) => true,", "    match verified.or(Ok::<(), aip_spend::RecordError>(())) {\n        Ok(()) => true,"),
    ab("AS-15", "assess/spend.rs", "an approval-required decision is tracked",
       "        if a.verdict == SpendVerdict::ApprovalRequired {", "        if false {"),
    ab("AS-16", "assess/spend.rs", "the refused amount is reported",
       "                requested_minor_units: r.requested_minor_units,", "                requested_minor_units: None,"),
    ab("AS-17", "assess/spend.rs", "a gate differing from the signed threshold is contradicted",
       "        Some(t) if same_amount(t, rule, &gate.above) => Standing::Verified {",
       "        Some(_) => Standing::Verified {"),
    ab("AS-18", "assess/spend.rs", "a gate the policy does not require is contradicted",
       "    let rule = ev.rule(&gate.action)?;",
       "    let rule = ev.rule(&gate.action).filter(|r| r.approval_above.is_some())?;"),
    ab("AS-19", "assess/approvals.rs", "an approval for another decision does not satisfy this one",
       "        if !agreed.iter().any(|(_, d)| d == decision_id) {", "        if !agreed.iter().any(|_| true) {"),
    ab("AS-20", "assess/approvals.rs", "the approver is the author's word",
       "                format!(\"{path}.approver\"),\n                Standing::SelfReported,",
       "                format!(\"{path}.approver\"),\n                Standing::Verified { verifier: crate::standing::Verifier::SpendPolicy },"),
    ab("AS-21", "assess/approvals.rs", "a signed threshold nobody is shown enforcing is reported",
       "if matches!(threshold, Standing::Verified { .. }) && !spend.enforced {", "if false {"),
    ab("AS-22", "evidence.rs", "a context file anchors spend-policy issuers",
       "ctx.spend_policy_anchors = ctx.spend_policy_anchors.trust(id, &key);", "let _ = (id, key);"),
    ab("AS-23", "evidence.rs", "spend refusals in a bundle are bounded",
       "            (\"spend_refusals\", b.spend_refusals.len()),\n", ""),
]

if __name__ == "__main__":
    sys.exit(
        _core.run_matrix(
            MUTATIONS,
            REPO / "validation/mutation/SPEND_MUTATION_RESULTS.json",
            sys.argv[1:] or None,
            ["aip-spend", "aip-authorize", "aip-aibom"],
        )
    )
