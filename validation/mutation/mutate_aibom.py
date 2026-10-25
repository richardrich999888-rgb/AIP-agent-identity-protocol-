#!/usr/bin/env python3
"""Mutation matrix for `aip-aibom`, the evidence-gap assessor.

Every mutation breaks one stated invariant of the product (ADR-017,
`docs/architecture/AIBOM_ARCHITECTURE.md` §5) and must be killed by the
crate's own tests. The forensic machinery — unique fragment, changed digest,
successful compile, byte-identical restore — is imported from
`mutate_core.py`, not reimplemented.

The product's whole claim is that it never reports more than the evidence
supports. So most mutations here try to make it overclaim: count a rejected
artifact, ignore a revocation, raise NEXORA's strength, read a secret into the
output, or let a typo pass for a security gate.
"""
import sys
import importlib.util
import pathlib

_HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("mutate_core", _HERE / "mutate_core.py")
_core = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_core)

REPO = _core.REPO
SRC = REPO / "aip-standalone/aip-aibom/src"
PKG = "aip-aibom"


def m(id_, file, invariant, old, new):
    return {"id": id_, "pkg": PKG, "file": SRC / file, "invariant": invariant, "old": old, "new": new}


MUTATIONS = [
    # ── Precedence: fail-closed combination (A5) ───────────────────────
    m("AB-01", "standing.rs", "a rejected artifact is never outvoted",
      "Self::EvidenceRejected { .. } => 7,", "Self::EvidenceRejected { .. } => 0,"),
    m("AB-02", "standing.rs", "one live grant outranks a lapsed one",
      "Self::Lapsed { .. } => 3,", "Self::Lapsed { .. } => 5,"),

    # ── Authority (C5, C8) ─────────────────────────────────────────────
    m("AB-03", "assess/authority.rs", "an explicitly denied declared action is a contradiction",
      "Outcome::Valid { scope, .. } if scope.denied.contains(a) =>",
      "Outcome::Valid { scope, .. } if scope.denied.is_empty() && false =>"),
    m("AB-04", "assess/authority.rs", "the assessor's revocation set is applied",
      "let revoked = chain.jtis().iter().any(|j| ctx.revoked_jtis.contains(j));",
      "let revoked = false;"),
    m("AB-05", "assess/authority.rs", "a revoked delegation hop revokes the whole chain",
      "let revoked = chain.jtis().iter()", "let revoked = [chain.root.jti].iter()"),
    m("AB-06", "assess/authority.rs", "an expired chain is lapsed at the assessor's present",
      ".filter(|u| now > *u)", ".filter(|u| now > *u && false)"),
    m("AB-07", "assess/authority.rs", "a chain before its issuance is not yet valid",
      "} else if now < from {", "} else if now < from && false {"),
    m("AB-08", "evidence.rs", "a chain's window ends at its earliest expiry",
      "            .flatten()\n            .min();", "            .flatten()\n            .max();"),
    m("AB-09", "assess/authority.rs", "another agent's authority does not count for this one",
      "        if c.holder() == agent {", "        if true {"),
    m("AB-10", "assess/authority.rs", "foreign evidence is reported",
      "    if foreign > 0 {\n        sheet.finding(\n            Component::Permissions,",
      "    if foreign > usize::MAX - 1 {\n        sheet.finding(\n            Component::Permissions,"),
    m("AB-11", "assess/authority.rs", "an unbacked declared permission is reported",
      "            sheet.finding(\n                Component::Permissions,\n                path.clone(),\n                FindingKind::PermissionNotBacked,\n            );\n",
      ""),
    m("AB-12", "assess/authority.rs", "undeclared live authority is reported",
      "                if !declared.contains(&label) {", "                if false {"),
    m("AB-13", "assess/authority.rs", "a forged chain is charged against the action it claimed",
      "Outcome::Rejected(_) if claimed_scope(e.chain).contains(a) =>",
      "Outcome::Rejected(_) if claimed_scope(e.chain).contains(a) && false =>"),
    m("AB-14", "assess/spend.rs", "a limit no artifact carries is reported as unenforceable",
      "            None => {\n                sheet.finding(\n                    Component::Permissions,\n                    path.clone(),\n                    FindingKind::LimitNotEnforceable,\n                );\n",
      "            None => {\n"),
    m("AB-15", "assess/authority.rs", "an undeclared delegator is reported",
      "if issuer != agent && !declared.iter().any(|d| d == issuer) {", "if false {"),
    m("AB-16", "assess/authority.rs", "onward delegation is credited only for a hop this agent issued",
      ".any(|h| h.issuer_id == agent && &h.grantee_id == y)", ".any(|h| &h.grantee_id == y)"),

    # ── Identity (C1, C10) ─────────────────────────────────────────────
    m("AB-17", "assess/identity.rs", "a valid document for another agent is a contradiction",
      "    if doc.id != declared {", "    if false {"),
    m("AB-18", "assess/identity.rs", "an identity whose signed status is not Active is not live",
      "    if doc.status != IdentityStatus::Active {", "    if false {"),
    m("AB-19", "assess/identity.rs", "an identity document must pass validate_aid",
      "    if let Err(e) = aip_core::validate_aid(doc) {",
      "    if let Err(e) = Ok::<(), aip_types::AipError>(()) {"),
    m("AB-20", "assess/controls.rs", "the identity-key algorithm is compared with the validated key",
      "Some(d) if d.primary_key.algorithm == declared =>", "Some(_) if true =>"),

    # ── Execution (C7) and NEXORA (A4) ─────────────────────────────────
    m("AB-21", "assess/execution.rs", "a declared binary the decision point did not authorise is contradicted",
      "Some(d) if d == authorised => Standing::Verified {", "Some(_) => Standing::Verified {"),
    m("AB-22", "assess/execution.rs", "an expectation must verify under the assessor's anchors",
      "match aip_authorize::verify_expected_execution(ee, &i.context.decision_points) {",
      "match Ok::<(), aip_authorize::ExpectedVerifyError>(()) {"),
    m("AB-23", "assess/execution.rs", "a proof NEXORA refuses is rejected",
      "        if !v.is_valid() {", "        if false {"),
    m("AB-24", "assess/execution.rs", "Observed carries NEXORA's strength, never raised",
      "Some(d) if d == observed => Standing::Observed { verdict, strength },",
      "Some(d) if d == observed => Standing::Observed { verdict, strength: aip_reconcile::EvidenceStrength::Proven.max(strength) },"),
    m("AB-25", "assess/execution.rs", "a NEXORA identity divergence is a contradiction",
      "(IdentityComparison::Divergent { .. }, _, _) =>", "(IdentityComparison::Ambiguous { .. }, _, _) =>"),
    m("AB-26", "assess/execution.rs", "proofs offered without verifier anchors are reported",
      "        if !mine.is_empty() {", "        if mine.is_empty() {"),

    # ── Inventory (C2, C4) ─────────────────────────────────────────────
    m("AB-27", "assess/inventory.rs", "hosted model identity cites N-3",
      "Hosting::Hosted => NonEstablishment::N3,", "Hosting::Hosted => NonEstablishment::N4,"),
    m("AB-28", "assess/tools.rs", "only an MCP tool can be discovered from an MCP config",
      "        if tool.kind == ToolKind::Mcp {", "        if tool.kind == tool.kind {"),
    m("AB-29", "assess/tools.rs", "a shadow tool is reported",
      "            if !declared_mcp.contains(s.name.as_str()) {", "            if false {"),
    m("AB-30", "assess/tools.rs", "an inline credential becomes a finding",
      "        for x in &d.exposures {", "        for x in d.exposures.iter().take(0) {"),

    # ── C6 data access against the signed access ledger ────────────────
    m("AB-47", "assess/access.rs", "a resource a verified ledger shows reached is credited",
      "        if reached.named.contains(&d.resource) {", "        if false {"),
    m("AB-48", "assess/access.rs", "a ledger must verify under the assessor's ledger-signer anchors",
      "        if let Err(e) = ledger.verify(&i.context.ledger_signers) {",
      "        if let Err(e) = Ok::<(), aip_ledger::LedgerError>(()) {"),
    m("AB-49", "assess/access.rs", "another agent's ledger does not count for this one",
      "        if ledger.agent_id != agent {", "        if false {"),
    m("AB-50", "assess/access.rs", "an adverse ledger row is reported",
      "                    if entry.standing == RowStanding::Adverse {\n                        reached.adverse.insert(name.to_string());",
      "                    if false {\n                        reached.adverse.insert(name.to_string());"),
    m("AB-51", "assess/access.rs", "an undeclared resource reached is reported",
      ".filter(|n| !declared.contains(n.as_str()))", ".filter(|_| false)"),
    m("AB-52", "assess/access.rs", "an unregistered endpoint reached is reported",
      "    if reached.unregistered > 0 {", "    if false {"),
    m("AB-53", "assess/access.rs", "a failed ledger is charged against the resources it claimed",
      "                rejected.entry(name).or_insert_with(|| reason.clone());", "                let _ = name;"),

    # ── C4 tools against gateway receipts ──────────────────────────────
    m("AB-54", "assess/tools.rs", "a gateway anchored under the agent's own key is refused",
      "            &i.context.gateways,\n            i.context.agent_public_key.as_deref(),\n        ) {",
      "            &i.context.gateways,\n            None,\n        ) {"),
    m("AB-55", "assess/tools.rs", "a refused call is not credited as use",
      "GatewayDisposition::Forwarded | GatewayDisposition::Failed => {",
      "GatewayDisposition::Forwarded | GatewayDisposition::Failed | GatewayDisposition::Refused => {"),
    m("AB-56", "assess/tools.rs", "another agent's receipt does not count for this one",
      "        if signed.receipt.agent_id != agent {", "        if false {"),
    m("AB-57", "assess/tools.rs", "a tool used at the gateway and undeclared is reported",
      ".filter(|t| !declared.contains(t.as_str()))", ".filter(|_| false)"),
    m("AB-58", "assess/tools.rs", "a verified gateway receipt credits the declared tool",
      "        if r.used.contains(&tool.id) {", "        if false {"),

    # ── C5 approval gates against the approval tier ────────────────────
    m("AB-59", "assess/approvals.rs", "an agreeing approval is counted",
      "            ShownVsAuthorized::Agrees { .. } => {\n                agreed.push((ee.action_kind.clone(), ee.decision_id))\n            }",
      "            ShownVsAuthorized::Agrees { .. } => {}"),
    m("AB-60", "assess/approvals.rs", "a shown-versus-authorised divergence is critical",
      "FindingKind::ApprovalDiverged {\n                    divergence: divergence_label(&divergence).into(),",
      "FindingKind::ApprovalNotEvaluated {\n                    reason: divergence_label(&divergence).into(),"),
    m("AB-61", "assess/approvals.rs", "another agent's approval does not count for this one",
      "        if ee.agent_id != agent {\n            continue;", "        if false {\n            continue;"),
    m("AB-62", "assess/approvals.rs", "an approval counts only for a gate on its own action",
      ".filter(|(a, _)| authority_label(a) == label)",
      ".filter(|_| true)"),
    m("AB-63", "assess/approvals.rs", "an approval surface anchored under the agent's own key is refused",
      "            i.context.agent_public_key.as_deref(),\n        ) {",
      "            None,\n        ) {"),

    # ── Validity and seal (C13, A10) ───────────────────────────────────
    m("AB-31", "assess/validity.rs", "a lapsed manifest is lapsed",
      "Some(until) if now > until => Standing::Lapsed {", "Some(until) if now > until && false => Standing::Lapsed {"),
    m("AB-32", "seal.rs", "a seal is over exactly one manifest",
      "    if seal.manifest_sha256 != hex::encode(manifest_digest(m)) {", "    if false {"),
    m("AB-33", "seal.rs", "a seal's fields are covered by its signature",
      "    if seal.signature.payload_hash != sha256(&seal.signing_preimage()) {", "    if false {"),

    # ── Canonical encoding (A9) ────────────────────────────────────────
    m("AB-34", "canonical.rs", "sets are order-independent", "    encoded.sort();\n", "\n"),
    m("AB-35", "canonical.rs", "every field is in the digest", "    put_str(b, &a.owner);\n", "\n"),

    # ── Discovery (A11) ────────────────────────────────────────────────
    m("AB-36", "adapters/mcp_config.rs", "a `${...}` template is a reference, not a secret",
      "    if value.contains(\"${\") {", "    if false {"),
    m("AB-37", "adapters/mcp_config.rs", "URL userinfo never reaches the recorded endpoint",
      "                SecretIndicator::UrlUserinfo,\n            );\n            h\n",
      "                SecretIndicator::UrlUserinfo,\n            );\n            authority\n"),
    m("AB-38", "adapters/mcp_config.rs", "a credential-named env value is located",
      "            if let Some(i) = indicator(k, value) {\n                expose(out, server, SecretLocation::Env",
      "            if let Some(i) = indicator(k, value).filter(|_| false) {\n                expose(out, server, SecretLocation::Env"),
    m("AB-39", "adapters/mcp_config.rs", "a value after a credential flag is located",
      "                if credential_name(flag) {", "                if false {"),
    m("AB-40", "adapters/mcp_config.rs", "a file that is not an MCP config is refused, not read as empty",
      "        .ok_or(DiscoveryError::NotAnMcpConfig)?;",
      "        .cloned().unwrap_or_default();\n    let servers = &servers;"),

    # ── Interfaces ─────────────────────────────────────────────────────
    m("AB-41", "bin/aibom.rs", "a usage error is never the gate status",
      "if e.use_stderr() { EXIT_INPUT } else { EXIT_OK }", "if e.use_stderr() { EXIT_GATE } else { EXIT_OK }"),
    m("AB-42", "bin/aibom.rs", "a critical finding trips the gate",
      "Ok(if a.has_critical() { EXIT_GATE } else { EXIT_OK })", "Ok(EXIT_OK)"),
    m("AB-43", "report.rs", "a CSV cell cannot become a formula",
      "    let guarded = if raw.starts_with(FORMULA_LEADERS) {", "    let guarded = if false {"),

    # ── Change detection ───────────────────────────────────────────────
    m("AB-44", "diff.rs", "a redenominated limit widens",
      "                None => push(\n                    out,\n                    Direction::Widening,",
      "                None => push(\n                    out,\n                    Direction::Neutral,"),
    m("AB-45", "diff.rs", "raising a cap widens",
      "        (Direction::Narrowing, Direction::Widening)\n", "        (Direction::Widening, Direction::Narrowing)\n"),
    m("AB-46", "diff.rs", "removing a security control widens",
      "        controls(old),\n        controls(new),\n        Direction::Narrowing,",
      "        controls(old),\n        controls(new),\n        Direction::Widening,"),
]

if __name__ == "__main__":
    sys.exit(
        _core.run_matrix(
            MUTATIONS,
            REPO / "validation/mutation/AIBOM_MUTATION_RESULTS.json",
            sys.argv[1:] or None,
            [PKG],
        )
    )
