import type {
  VerificationReport,
  TrustFloor,
  RuleIdentifier,
} from "@/types/verification";
import type { EvidencePacket } from "@/lib/types";
import { verifySinglePrincipalReachability } from "./reachability";
import { computeHierarchicalLayout } from "./dagLayout";
import type {
  AccountabilityFlowNode,
  AccountabilityFlowEdge,
  FlowGraphResult,
  FlowNodeKind,
  FlowRelation,
  LayoutDirection,
  TransformOptions,
} from "./types";

const formatFingerprint = (hex?: string): string => {
  if (!hex || hex.length < 16) return hex || "N/A (Not Provided)";
  return `${hex.slice(0, 8)}...${hex.slice(-8)}`;
};

/**
 * Transforms EvidencePacket and VerificationReport into fully-enriched
 * @xyflow/react nodes and edges with deterministic hierarchical layout,
 * reachability analysis, and Graphviz DOT representation.
 */
export function transformWasmGraphToFlow(options: TransformOptions): FlowGraphResult {
  const {
    packet,
    report,
    direction = "LR",
    onSelectNode,
  } = options;

  const isRulePassing = (rule: RuleIdentifier): boolean => {
    if (!report || !report.checks) return true;
    const check = report.checks.find((c) => c.rule === rule);
    return check ? check.pass : true;
  };

  const getRuleDetail = (rule: RuleIdentifier): string | undefined => {
    return report?.checks?.find((c) => c.rule === rule)?.detail;
  };

  const nodes: AccountabilityFlowNode[] = [];
  const edges: AccountabilityFlowEdge[] = [];

  // 1. Principal Node (Root)
  const rootAuth = packet.root_authority;
  const principalVerified = isRulePassing("ROOT_TOKEN_SIGNATURE");
  nodes.push({
    id: "principal",
    type: "principal",
    position: { x: 0, y: 0 },
    data: {
      id: "principal",
      kind: "principal",
      label: `${rootAuth.display_role} (${rootAuth.principal_id})`,
      verified: principalVerified,
      layoutDirection: direction,
      ruleName: "ROOT_TOKEN_SIGNATURE",
      ruleDetail: getRuleDetail("ROOT_TOKEN_SIGNATURE"),
      principal_id: rootAuth.principal_id,
      display_role: rootAuth.display_role,
      isTrustedAnchor: true,
      algorithm: "Ed25519",
      metadata: {
        principal_id: rootAuth.principal_id,
        display_role: rootAuth.display_role,
      },
      onSelectNode,
    },
  });

  // 2. AuthorityGrant Node (Root Token)
  const rootToken = rootAuth.root_token;
  const revocationClear = isRulePassing("REVOCATION");
  const authGrantVerified = principalVerified && revocationClear && isRulePassing("TEMPORAL_VALIDITY");
  nodes.push({
    id: "authority_grant",
    type: "authority_grant",
    position: { x: 0, y: 0 },
    data: {
      id: "authority_grant",
      kind: "authority_grant",
      label: `root token ${rootToken.jti.slice(0, 8)} → ${rootToken.agent_id}`,
      verified: authGrantVerified,
      layoutDirection: direction,
      ruleName: "ROOT_TOKEN_SIGNATURE",
      ruleDetail: getRuleDetail("ROOT_TOKEN_SIGNATURE"),
      jti: rootToken.jti,
      issuer_id: rootToken.issuer_id,
      agent_id: rootToken.agent_id,
      scope: rootToken.scope,
      issued_at: rootToken.issued_at,
      expires_at: rootToken.expires_at,
      isRevoked: !revocationClear,
      metadata: {
        jti: rootToken.jti,
        issuer_id: rootToken.issuer_id,
        agent_id: rootToken.agent_id,
        scope: rootToken.scope,
        issued_at: rootToken.issued_at,
        expires_at: rootToken.expires_at,
      },
      onSelectNode,
    },
  });

  edges.push({
    id: "e_issues",
    source: "principal",
    target: "authority_grant",
    type: "accountability",
    animated: principalVerified && authGrantVerified,
    data: {
      relation: "Issues",
      verified: principalVerified && authGrantVerified,
      ruleName: "ROOT_TOKEN_SIGNATURE",
      sourceKind: "principal",
      targetKind: "authority_grant",
    },
  });

  // 3. Delegation Hops
  let lastAuthorityId = "authority_grant";
  const delegationChainPassing = isRulePassing("DELEGATION_CHAIN");
  const delegationVerified = delegationChainPassing && revocationClear && isRulePassing("TEMPORAL_VALIDITY");

  if (packet.delegation_chain && packet.delegation_chain.length > 0) {
    let parentScope = rootToken.scope;

    packet.delegation_chain.forEach((hop, idx) => {
      const hopId = `delegation:${idx}`;
      const allowedCount = hop.scope?.allowed?.length ?? 0;
      const parentAllowedCount = parentScope?.allowed?.length ?? allowedCount;
      const attenuationDelta = allowedCount - parentAllowedCount;

      nodes.push({
        id: hopId,
        type: "delegation",
        position: { x: 0, y: 0 },
        data: {
          id: hopId,
          kind: "delegation",
          label: `hop ${idx} (depth ${hop.depth}): ${hop.issuer_id} → ${hop.grantee_id}`,
          verified: delegationVerified,
          layoutDirection: direction,
          ruleName: "DELEGATION_CHAIN",
          ruleDetail: getRuleDetail("DELEGATION_CHAIN"),
          hop_index: idx,
          depth: hop.depth,
          jti: hop.jti,
          parent_jti: hop.parent_jti,
          issuer_id: hop.issuer_id,
          grantee_id: hop.grantee_id,
          scope: hop.scope,
          attenuationDelta,
          isRevoked: !revocationClear,
          metadata: {
            jti: hop.jti,
            parent_jti: hop.parent_jti,
            issuer_id: hop.issuer_id,
            grantee_id: hop.grantee_id,
            depth: hop.depth,
            scope: hop.scope,
            issued_at: hop.issued_at,
            expires_at: hop.expires_at,
          },
          onSelectNode,
        },
      });

      edges.push({
        id: `e_delegates_${idx}`,
        source: lastAuthorityId,
        target: hopId,
        type: "accountability",
        animated: delegationVerified,
        data: {
          relation: "Delegates",
          verified: delegationVerified,
          ruleName: "DELEGATION_CHAIN",
          sourceKind: idx === 0 ? "authority_grant" : "delegation",
          targetKind: "delegation",
        },
      });

      lastAuthorityId = hopId;
      parentScope = hop.scope;
    });
  }

  // 4. Agent Node
  const agentBindingPassing = isRulePassing("AGENT_ID_BINDING");
  const agentSigPassing = isRulePassing("AGENT_SIGNATURE");
  const agentCanonicalPassing = isRulePassing("CANONICAL_HASH");
  const agentVerified = agentBindingPassing && agentSigPassing && agentCanonicalPassing;
  const agentPubKey = packet.agent.public_key.key_bytes;

  nodes.push({
    id: "agent",
    type: "agent",
    position: { x: 0, y: 0 },
    data: {
      id: "agent",
      kind: "agent",
      label: packet.agent.aip_id,
      verified: agentVerified,
      layoutDirection: direction,
      ruleName: "AGENT_ID_BINDING",
      ruleDetail: getRuleDetail("AGENT_ID_BINDING"),
      aip_id: packet.agent.aip_id,
      algorithm: packet.agent.algorithm,
      public_key: agentPubKey,
      public_key_hex: agentPubKey,
      fingerprint: formatFingerprint(agentPubKey),
      provenance: packet.agent.provenance,
      metadata: {
        aip_id: packet.agent.aip_id,
        algorithm: packet.agent.algorithm,
        public_key: agentPubKey,
        provenance: packet.agent.provenance,
      },
      onSelectNode,
    },
  });

  const actsUnderVerified = agentVerified && isRulePassing("AUTHORITY_CHAIN");
  edges.push({
    id: "e_acts_under",
    source: lastAuthorityId,
    target: "agent",
    type: "accountability",
    animated: actsUnderVerified,
    data: {
      relation: "ActsUnder",
      verified: actsUnderVerified,
      ruleName: "AUTHORITY_CHAIN",
      sourceKind: lastAuthorityId === "authority_grant" ? "authority_grant" : "delegation",
      targetKind: "agent",
    },
  });

  // 5. Decision Node
  const decisionScopePassing = isRulePassing("SCOPE_AUTHORITY");
  const decisionVerified = decisionScopePassing && isRulePassing("TEMPORAL_VALIDITY");
  const decidedAtIso =
    packet.decision.decided_at && !isNaN(packet.decision.decided_at)
      ? new Date(packet.decision.decided_at).toISOString()
      : "N/A (Not Provided)";

  nodes.push({
    id: "decision",
    type: "decision",
    position: { x: 0, y: 0 },
    data: {
      id: "decision",
      kind: "decision",
      label: packet.decision.summary,
      verified: decisionVerified,
      layoutDirection: direction,
      ruleName: "SCOPE_AUTHORITY",
      ruleDetail: getRuleDetail("SCOPE_AUTHORITY"),
      decision_id: packet.decision.decision_id,
      action_kind: packet.decision.action_kind,
      summary: packet.decision.summary,
      input_hash: packet.decision.input_hash,
      rationale_hash: packet.decision.rationale_hash,
      decided_at: packet.decision.decided_at,
      decided_at_iso: decidedAtIso,
      metadata: {
        decision_id: packet.decision.decision_id,
        action_kind: packet.decision.action_kind,
        summary: packet.decision.summary,
        input_hash: packet.decision.input_hash,
        rationale_hash: packet.decision.rationale_hash,
        decided_at: packet.decision.decided_at,
      },
      onSelectNode,
    },
  });

  const decidesVerified = agentVerified && decisionVerified;
  edges.push({
    id: "e_decides",
    source: "agent",
    target: "decision",
    type: "accountability",
    animated: decidesVerified,
    data: {
      relation: "Decides",
      verified: decidesVerified,
      ruleName: "AGENT_SIGNATURE",
      sourceKind: "agent",
      targetKind: "decision",
    },
  });

  // 6. Action Nodes
  const actionPassing = isRulePassing("ACTION_ATTESTATIONS");
  const actionVerified = actionPassing && decisionScopePassing;

  packet.actions.forEach((act, idx) => {
    const actId = `action:${idx}`;
    const performedAtIso =
      act.performed_at && !isNaN(act.performed_at)
        ? new Date(act.performed_at).toISOString()
        : "N/A (Not Provided)";

    nodes.push({
      id: actId,
      type: "action",
      position: { x: 0, y: 0 },
      data: {
        id: actId,
        kind: "action",
        label: act.description,
        verified: actionVerified,
        layoutDirection: direction,
        ruleName: "ACTION_ATTESTATIONS",
        ruleDetail: getRuleDetail("ACTION_ATTESTATIONS"),
        action_id: act.action_id,
        action_kind: act.action_kind,
        description: act.description,
        payload_hash: act.payload_hash,
        performed_at: act.performed_at,
        performed_at_iso: performedAtIso,
        index: idx,
        metadata: {
          action_id: act.action_id,
          action_kind: act.action_kind,
          description: act.description,
          payload_hash: act.payload_hash,
          performed_at: act.performed_at,
        },
        onSelectNode,
      },
    });

    edges.push({
      id: `e_performs_${idx}`,
      source: "decision",
      target: actId,
      type: "accountability",
      animated: decisionVerified && actionVerified,
      data: {
        relation: "Performs",
        verified: decisionVerified && actionVerified,
        ruleName: "ACTION_ATTESTATIONS",
        sourceKind: "decision",
        targetKind: "action",
      },
    });
  });

  // 7. Receipt Node (if present)
  if (packet.receipt_binding) {
    const rb = packet.receipt_binding;
    const receiptPassing = isRulePassing("RECEIPT_BINDING");
    const receiptVerified = receiptPassing && isRulePassing("TRUST_FLOOR");
    const countersigned = !!rb.counterparty_sig;

    nodes.push({
      id: "receipt",
      type: "receipt",
      position: { x: 0, y: 0 },
      data: {
        id: "receipt",
        kind: "receipt",
        label: `${rb.receipt_id} @ ${rb.receipt_system}`,
        verified: receiptVerified,
        layoutDirection: direction,
        ruleName: "RECEIPT_BINDING",
        ruleDetail: getRuleDetail("RECEIPT_BINDING"),
        receipt_id: rb.receipt_id,
        receipt_system: rb.receipt_system,
        receipt_hash: rb.receipt_hash,
        counterparty_id: rb.counterparty_id,
        countersigned,
        verified_status: countersigned ? "COUNTERSIGNED" : "HASH_ONLY",
        metadata: {
          receipt_system: rb.receipt_system,
          receipt_id: rb.receipt_id,
          receipt_hash: rb.receipt_hash,
          counterparty_id: rb.counterparty_id,
          countersigned,
        },
        onSelectNode,
      },
    });

    packet.actions.forEach((_, idx) => {
      edges.push({
        id: `e_produces_${idx}`,
        source: `action:${idx}`,
        target: "receipt",
        type: "accountability",
        animated: actionVerified && receiptVerified,
        data: {
          relation: "Produces",
          verified: actionVerified && receiptVerified,
          ruleName: "RECEIPT_BINDING",
          sourceKind: "action",
          targetKind: "receipt",
        },
      });
    });
  }

  // Reachability Analysis
  const reachability = verifySinglePrincipalReachability(
    nodes.map((n) => ({ id: n.id, kind: n.data.kind })),
    edges.map((e) => ({ source: e.source, target: e.target }))
  );

  // Layout calculation
  const layoutResult = computeHierarchicalLayout(nodes, edges, { direction });

  // Generate Graphviz DOT string (conforming to F9.5 / P1.4)
  const dotLines: string[] = ["digraph AccountabilityGraph {", "  rankdir=LR;"];
  for (const n of layoutResult.nodes) {
    const kind = (n.data?.kind || n.type || "").toLowerCase();
    const shape =
      kind === "principal"
        ? "house"
        : kind === "authority_grant"
        ? "note"
        : kind === "delegation"
        ? "cds"
        : kind === "agent"
        ? "component"
        : kind === "decision"
        ? "diamond"
        : kind === "action"
        ? "box"
        : "tab";
    dotLines.push(
      `  "${n.id}" [label="${(n.data?.label || n.id).replace(/"/g, '\\"')}", shape="${shape}"];`
    );
  }
  for (const e of layoutResult.edges) {
    dotLines.push(`  "${e.source}" -> "${e.target}" [label="${e.data?.relation}"];`);
  }
  dotLines.push("}");
  const dotString = dotLines.join("\n");

  const claimedTrustFloor = packet.claimed_trust_floor;
  const derivedTrustFloor = report?.derived_trust_floor ?? claimedTrustFloor;

  return {
    nodes: layoutResult.nodes,
    edges: layoutResult.edges,
    reachability,
    claimedTrustFloor,
    derivedTrustFloor,
    packetId: packet.packet_hash,
    dotString,
  };
}
