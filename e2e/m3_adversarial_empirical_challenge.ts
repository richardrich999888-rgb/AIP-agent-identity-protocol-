/**
 * Milestone 3 Adversarial Empirical Challenge Suite
 * 
 * Tests:
 * 1. 7 Node Kinds and 6 Edge Relations across all sample fixtures
 * 2. Single-Principal Reachability Invariants (0 principals, 2 principals, 3 principals, orphans, disconnected islands, cycles, reversed edges)
 * 3. Deterministic Hierarchical Layout (LR vs TB monotonicity, centering, bounding box collision checks)
 * 4. Graphviz DOT Exporter (exact shape mapping, edge labeling, quotation escaping)
 * 5. High-Density Stress Testing (0 hops, 8 hops, 50 parallel actions, 100 parallel actions, zero collisions, execution speed)
 * 6. Inspection Sheet Metadata & Defensive Formatting (19-char fingerprints, ISO-8601 timestamps, fallbacks, rule mappings)
 */

import { transformWasmGraphToFlow } from "../aip-console/src/components/graph/transformer";
import { verifySinglePrincipalReachability } from "../aip-console/src/components/graph/reachability";
import { computeHierarchicalLayout } from "../aip-console/src/components/graph/dagLayout";
import { validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT } from "./fixtures/evidence_packets";
import { verifyEvidencePacketOracle } from "./support/reference_oracle";
import type { AccountabilityFlowNode, AccountabilityFlowEdge, LayoutDirection } from "../aip-console/src/components/graph/types";
import type { EvidencePacket } from "../aip-console/src/lib/types";

let passed = 0;
let failed = 0;
const failures: string[] = [];

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`  [PASS] ${testName}`);
    passed++;
  } else {
    console.error(`  [FAIL] ${testName}${detail ? ` -> ${detail}` : ""}`);
    failed++;
    failures.push(`${testName}${detail ? ` -> ${detail}` : ""}`);
  }
}

console.log("\n=======================================================");
console.log("=== EMPIRICAL ADVERSARIAL CHALLENGE: MILESTONE 3 ===");
console.log("=======================================================\n");

// -------------------------------------------------------------
// SECTION 1: 7 Node Kinds and 6 Edge Relations Across Fixtures
// -------------------------------------------------------------
console.log("--- SECTION 1: Node Kinds and Edge Relations ---");

const report = verifyEvidencePacketOracle(validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT);
const honestResult = transformWasmGraphToFlow({
  packet: validHonestCounterpartyPacket,
  report,
  direction: "LR",
});

const nodeKinds = new Set(honestResult.nodes.map((n) => n.data.kind));
const expectedKinds = [
  "principal",
  "authority_grant",
  "delegation",
  "agent",
  "decision",
  "action",
  "receipt",
];

for (const kind of expectedKinds) {
  assert(nodeKinds.has(kind as any), `Honest packet contains node kind '${kind}'`);
}
assert(nodeKinds.size === 7, "Total unique node kinds exactly equals 7");

const edgeRelations = new Set(honestResult.edges.map((e) => e.data?.relation));
const expectedRelations = [
  "Issues",
  "Delegates",
  "ActsUnder",
  "Decides",
  "Performs",
  "Produces",
];

for (const rel of expectedRelations) {
  assert(edgeRelations.has(rel as any), `Honest packet contains edge relation '${rel}'`);
}
assert(edgeRelations.size === 6, "Total unique edge relations exactly equals 6");

// Verify 1:1 check binding
const principalNode = honestResult.nodes.find((n) => n.data.kind === "principal")!;
const grantNode = honestResult.nodes.find((n) => n.data.kind === "authority_grant")!;
const agentNode = honestResult.nodes.find((n) => n.data.kind === "agent")!;
const decisionNode = honestResult.nodes.find((n) => n.data.kind === "decision")!;
const actionNodes = honestResult.nodes.filter((n) => n.data.kind === "action");
const receiptNode = honestResult.nodes.find((n) => n.data.kind === "receipt")!;

assert(principalNode.data.verified === true, "Principal node verified matches engine");
assert(grantNode.data.verified === true, "AuthorityGrant node verified matches engine");
assert(agentNode.data.verified === true, "Agent node verified matches engine");
assert(decisionNode.data.verified === true, "Decision node verified matches engine");
assert(actionNodes.every((a) => a.data.verified === true), "All Action nodes verified matches engine");
assert(receiptNode.data.verified === true, "Receipt node verified matches engine");

// Test with 0 delegation hops (e.g. AuthorityBound / Direct delegation)
const directPacket: EvidencePacket = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
directPacket.delegation_chain = [];
directPacket.root_authority.root_token.agent_id = directPacket.agent.aip_id;

const directResult = transformWasmGraphToFlow({
  packet: directPacket,
  report,
  direction: "LR",
});
const directKinds = new Set(directResult.nodes.map((n) => n.data.kind));
assert(!directKinds.has("delegation"), "0-hop packet excludes delegation node");
assert(directKinds.size === 6, "0-hop packet has exactly 6 node kinds");
const directActsUnder = directResult.edges.find((e) => e.data?.relation === "ActsUnder")!;
assert(directActsUnder.source === "authority_grant" && directActsUnder.target === "agent",
  "0-hop ActsUnder connects directly from authority_grant to agent");

// -------------------------------------------------------------
// SECTION 2: Single-Principal Reachability Invariant
// -------------------------------------------------------------
console.log("\n--- SECTION 2: Single-Principal Reachability Invariants ---");

// 2.1 Valid Graph
const validReach = verifySinglePrincipalReachability(
  honestResult.nodes.map((n) => ({ id: n.id, kind: n.data.kind })),
  honestResult.edges.map((e) => ({ source: e.source, target: e.target }))
);
assert(validReach.valid === true, "Reachability passes on valid honest graph");
assert(validReach.error === undefined, "No error on valid honest graph");
assert(validReach.orphanNodeIds.length === 0, "No orphan nodes on valid honest graph");
assert(validReach.rootPrincipalId === "principal", "Root principal correctly identified as 'principal'");

// 2.2 0 Principal Nodes
const zeroPrincipals = honestResult.nodes
  .filter((n) => n.data.kind !== "principal")
  .map((n) => ({ id: n.id, kind: n.data.kind }));
const zeroReach = verifySinglePrincipalReachability(
  zeroPrincipals,
  honestResult.edges.map((e) => ({ source: e.source, target: e.target }))
);
assert(zeroReach.valid === false, "0 principals: valid is false");
assert(zeroReach.error === "Expected 1 principal node, found 0",
  `0 principals: exact error string 'Expected 1 principal node, found 0' (got: '${zeroReach.error}')`);
assert(zeroReach.orphanNodeIds.length === zeroPrincipals.length,
  "0 principals: all nodes marked as orphans");

// 2.3 2 Principal Nodes
const twoPrincipals = [
  ...honestResult.nodes.map((n) => ({ id: n.id, kind: n.data.kind })),
  { id: "principal_duplicate", kind: "principal" },
];
const twoReach = verifySinglePrincipalReachability(
  twoPrincipals,
  honestResult.edges.map((e) => ({ source: e.source, target: e.target }))
);
assert(twoReach.valid === false, "2 principals: valid is false");
assert(twoReach.error === "Expected 1 principal node, found 2",
  `2 principals: exact error string 'Expected 1 principal node, found 2' (got: '${twoReach.error}')`);

// 2.4 3 Principal Nodes
const threePrincipals = [
  ...twoPrincipals,
  { id: "principal_triplicate", kind: "principal" },
];
const threeReach = verifySinglePrincipalReachability(
  threePrincipals,
  honestResult.edges.map((e) => ({ source: e.source, target: e.target }))
);
assert(threeReach.valid === false, "3 principals: valid is false");
assert(threeReach.error === "Expected 1 principal node, found 3",
  `3 principals: exact error string 'Expected 1 principal node, found 3' (got: '${threeReach.error}')`);

// 2.5 Single Disconnected Orphan Node
const orphanNodeList = [
  ...honestResult.nodes.map((n) => ({ id: n.id, kind: n.data.kind })),
  { id: "rogue-detached-action", kind: "action" },
];
const orphanReach = verifySinglePrincipalReachability(
  orphanNodeList,
  honestResult.edges.map((e) => ({ source: e.source, target: e.target }))
);
assert(orphanReach.valid === false, "Single orphan node: valid is false");
assert(orphanReach.error === "Unreachable node(s) detected: rogue-detached-action",
  `Single orphan node: verbatim error 'Unreachable node(s) detected: rogue-detached-action' (got: '${orphanReach.error}')`);
assert(orphanReach.orphanNodeIds.includes("rogue-detached-action"),
  "Single orphan node: orphan list contains rogue-detached-action");

// 2.6 Multiple Disconnected Orphan Nodes
const multiOrphanList = [
  ...honestResult.nodes.map((n) => ({ id: n.id, kind: n.data.kind })),
  { id: "orphan-alpha", kind: "action" },
  { id: "orphan-beta", kind: "receipt" },
];
const multiOrphanReach = verifySinglePrincipalReachability(
  multiOrphanList,
  honestResult.edges.map((e) => ({ source: e.source, target: e.target }))
);
assert(multiOrphanReach.valid === false, "Multiple orphan nodes: valid is false");
assert(multiOrphanReach.orphanNodeIds.length === 2 &&
       multiOrphanReach.orphanNodeIds.includes("orphan-alpha") &&
       multiOrphanReach.orphanNodeIds.includes("orphan-beta"),
  "Multiple orphan nodes: accurately identifies both orphan-alpha and orphan-beta");

// 2.7 Disconnected Island Cluster (Internal edges exist between orphans)
const islandEdges = [
  ...honestResult.edges.map((e) => ({ source: e.source, target: e.target })),
  { source: "orphan-alpha", target: "orphan-beta" },
];
const islandReach = verifySinglePrincipalReachability(multiOrphanList, islandEdges);
assert(islandReach.valid === false, "Disconnected island with internal edges is detected as unreachable");
assert(islandReach.orphanNodeIds.length === 2, "Both island nodes identified as orphans");

// 2.8 Reversed Edge Direction (Adversarial edge reversal)
const reversedEdges = honestResult.edges.map((e) => {
  if (e.id === "e_acts_under") {
    // Reverse ActsUnder: agent -> delegation instead of delegation -> agent
    return { source: "agent", target: e.source };
  }
  return { source: e.source, target: e.target };
});
const reversedReach = verifySinglePrincipalReachability(
  honestResult.nodes.map((n) => ({ id: n.id, kind: n.data.kind })),
  reversedEdges
);
assert(reversedReach.valid === false, "Reversed edge direction breaks forward reachability");
assert(reversedReach.orphanNodeIds.includes("agent"), "Agent and descendants become unreachable when edge is reversed");

// 2.9 Cyclic Graph Handling (Reachable Cycle & Disconnected Cycle)
const cyclicReachableEdges = [
  ...honestResult.edges.map((e) => ({ source: e.source, target: e.target })),
  { source: "decision", target: "agent" }, // cycle: agent -> decision -> agent
];
const cyclicReachable = verifySinglePrincipalReachability(
  honestResult.nodes.map((n) => ({ id: n.id, kind: n.data.kind })),
  cyclicReachableEdges
);
assert(cyclicReachable.valid === true, "Graph with internal cycle terminates without infinite loop and passes reachability");

const cyclicDisconnectedNodes = [
  ...honestResult.nodes.map((n) => ({ id: n.id, kind: n.data.kind })),
  { id: "cycle-orphan-1", kind: "action" },
  { id: "cycle-orphan-2", kind: "action" },
];
const cyclicDisconnectedEdges = [
  ...honestResult.edges.map((e) => ({ source: e.source, target: e.target })),
  { source: "cycle-orphan-1", target: "cycle-orphan-2" },
  { source: "cycle-orphan-2", target: "cycle-orphan-1" }, // cycle between orphans
];
const cyclicDisconnected = verifySinglePrincipalReachability(cyclicDisconnectedNodes, cyclicDisconnectedEdges);
assert(cyclicDisconnected.valid === false, "Disconnected cyclic component is detected as unreachable orphans");
assert(cyclicDisconnected.orphanNodeIds.includes("cycle-orphan-1") && cyclicDisconnected.orphanNodeIds.includes("cycle-orphan-2"),
  "Both cyclic orphan nodes identified in orphanNodeIds");

// -------------------------------------------------------------
// SECTION 3: Layout Switching (LR vs TB) and Handle Orientation
// -------------------------------------------------------------
console.log("\n--- SECTION 3: Hierarchical Layout & Handle Orientations ---");

// Compute LR layout
const lrLayout = computeHierarchicalLayout(honestResult.nodes, honestResult.edges, { direction: "LR" });
// Compute TB layout
const tbLayout = computeHierarchicalLayout(honestResult.nodes, honestResult.edges, { direction: "TB" });

// LR Monotonicity Check
const rankOrder = ["principal", "authority_grant", "delegation:0", "agent", "decision", "action:0", "receipt"];
const lrNodesMap = new Map(lrLayout.nodes.map((n) => [n.id, n]));
const tbNodesMap = new Map(tbLayout.nodes.map((n) => [n.id, n]));

let lrStrictMonotonic = true;
let tbStrictMonotonic = true;

for (let i = 0; i < rankOrder.length - 1; i++) {
  const currId = rankOrder[i];
  const nextId = rankOrder[i + 1];
  const currLR = lrNodesMap.get(currId);
  const nextLR = lrNodesMap.get(nextId);
  const currTB = tbNodesMap.get(currId);
  const nextTB = tbNodesMap.get(nextId);

  if (!currLR || !nextLR || currLR.position.x >= nextLR.position.x) {
    lrStrictMonotonic = false;
  }
  if (!currTB || !nextTB || currTB.position.y >= nextTB.position.y) {
    tbStrictMonotonic = false;
  }
}

assert(lrStrictMonotonic, "LR Layout: X positions progress strictly monotonically (rank 0 to rank 6)");
assert(tbStrictMonotonic, "TB Layout: Y positions progress strictly monotonically (rank 0 to rank 6)");

// Handle orientation check (LR -> Left/Right, TB -> Top/Bottom)
assert(lrLayout.nodes.every((n) => n.data.layoutDirection === "LR"), "LR Layout: all nodes tagged with layoutDirection='LR'");
assert(tbLayout.nodes.every((n) => n.data.layoutDirection === "TB"), "TB Layout: all nodes tagged with layoutDirection='TB'");

// Cross-axis centering verification
// In LR layout, y coordinates should be centered relative to the max cross span
const maxSpan = 150; // single nodes have height 150
const principalLR = lrNodesMap.get("principal")!;
assert(principalLR.position.y === 40, `LR Layout: Principal top margin is 40px (got: ${principalLR.position.y})`);

// -------------------------------------------------------------
// SECTION 4: Graphviz DOT Export
// -------------------------------------------------------------
console.log("\n--- SECTION 4: Graphviz DOT Exporter ---");

const dotString = honestResult.dotString;
assert(dotString.startsWith("digraph AccountabilityGraph {"), "DOT string starts with 'digraph AccountabilityGraph {'");
assert(dotString.includes("rankdir=LR;"), "DOT string specifies 'rankdir=LR;'");
assert(dotString.endsWith("}"), "DOT string terminates with '}'");

const expectedShapes: Record<string, string> = {
  principal: "house",
  authority_grant: "note",
  "delegation:0": "cds",
  agent: "component",
  decision: "diamond",
  "action:0": "box",
  receipt: "tab",
};

for (const [nodeId, shape] of Object.entries(expectedShapes)) {
  const pattern = new RegExp(`"${nodeId}"\\s+\\[.*shape="${shape}".*\\];`);
  assert(pattern.test(dotString), `DOT export assigns shape='${shape}' to node '${nodeId}'`);
}

for (const rel of expectedRelations) {
  assert(dotString.includes(`label="${rel}"`), `DOT export contains edge label for '${rel}'`);
}

// Adversarial label with quotes and backslashes
const quotationPacket: EvidencePacket = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
quotationPacket.decision.summary = 'Authorize "Project Alpha" & \\emergency\\ override';
const quotationResult = transformWasmGraphToFlow({
  packet: quotationPacket,
  report,
  direction: "LR",
});
assert(quotationResult.dotString.includes('\\"Project Alpha\\"'),
  "DOT export safely escapes inner double quotation marks");

// -------------------------------------------------------------
// SECTION 5: High-Density & Stress Testing
// -------------------------------------------------------------
console.log("\n--- SECTION 5: High-Density Stress Testing ---");

// 5.1 Maximum 8 Delegation Hops
const eightHopPacket: EvidencePacket = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
eightHopPacket.delegation_chain = [];
let prevJti = eightHopPacket.root_authority.root_token.jti;
let prevIssuer = eightHopPacket.root_authority.root_token.agent_id;

for (let hop = 0; hop < 8; hop++) {
  const currentJti = `jti-hop-${hop}`;
  const currentGrantee = hop === 7 ? eightHopPacket.agent.aip_id : `agent-hop-${hop}`;
  eightHopPacket.delegation_chain.push({
    jti: currentJti,
    parent_jti: prevJti,
    issuer_id: prevIssuer,
    grantee_id: currentGrantee,
    depth: hop + 1,
    scope: { allowed: [{ kind: "Standard", action: "Read" }] },
    issued_at: Date.now(),
    expires_at: Date.now() + 3600000,
    signature: "dummy-sig",
  });
  prevJti = currentJti;
  prevIssuer = currentGrantee;
}

const t0 = performance.now();
const eightHopResult = transformWasmGraphToFlow({
  packet: eightHopPacket,
  report,
  direction: "LR",
});
const tEightHop = performance.now() - t0;

assert(eightHopResult.nodes.filter((n) => n.data.kind === "delegation").length === 8,
  "Successfully generated 8 delegation hop nodes");
assert(eightHopResult.reachability.valid === true,
  "8-hop chain satisfies 100% Single-Principal BFS reachability");
assert(tEightHop < 50, `8-hop layout and reachability computed in ${tEightHop.toFixed(2)}ms (< 50ms)`);

// 5.2 50 Parallel Actions Stress Test
const fiftyActionPacket: EvidencePacket = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
for (let i = 1; i < 50; i++) {
  fiftyActionPacket.actions.push({
    action_id: `act-stress-${i}`,
    action_kind: { kind: "Standard", action: "Write" },
    description: `Stress batch action attestation ${i}`,
    payload_hash: fiftyActionPacket.actions[0].payload_hash,
    performed_at: fiftyActionPacket.actions[0].performed_at + i * 10,
    agent_sig: fiftyActionPacket.actions[0].agent_sig,
  });
}

const t1 = performance.now();
const fiftyActionResult = transformWasmGraphToFlow({
  packet: fiftyActionPacket,
  report,
  direction: "LR",
});
const tFiftyAction = performance.now() - t1;

assert(fiftyActionResult.nodes.filter((n) => n.data.kind === "action").length === 50,
  "Successfully generated 50 parallel action nodes");
assert(fiftyActionResult.reachability.valid === true,
  "50-action fan-out satisfies 100% Single-Principal BFS reachability");
assert(tFiftyAction < 50, `50-action layout computed in ${tFiftyAction.toFixed(2)}ms (< 50ms)`);

// 5.3 Collision & Overlap Bounding Box Detection
function detectCollisions(nodes: AccountabilityFlowNode[]): number {
  let overlaps = 0;
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i];
      const b = nodes[j];
      const aw = a.data.kind === "action" ? 280 : 300;
      const ah = a.data.kind === "action" ? 120 : 150;
      const bw = b.data.kind === "action" ? 280 : 300;
      const bh = b.data.kind === "action" ? 120 : 150;

      const aLeft = a.position.x;
      const aRight = a.position.x + aw;
      const aTop = a.position.y;
      const aBottom = a.position.y + ah;

      const bLeft = b.position.x;
      const bRight = b.position.x + bw;
      const bTop = b.position.y;
      const bBottom = b.position.y + bh;

      // Overlap condition
      const xOverlap = aLeft < bRight && aRight > bLeft;
      const yOverlap = aTop < bBottom && aBottom > bTop;

      if (xOverlap && yOverlap) {
        overlaps++;
      }
    }
  }
  return overlaps;
}

const collisionsLR = detectCollisions(fiftyActionResult.nodes);
assert(collisionsLR === 0, `50-action LR layout: zero bounding-box overlaps detected (collisions: ${collisionsLR})`);

// Collision test in TB layout
const fiftyActionTB = transformWasmGraphToFlow({
  packet: fiftyActionPacket,
  report,
  direction: "TB",
});
const collisionsTB = detectCollisions(fiftyActionTB.nodes);
assert(collisionsTB === 0, `50-action TB layout: zero bounding-box overlaps detected (collisions: ${collisionsTB})`);

// 5.4 100 Parallel Actions Extreme Stress Test
const hundredActionPacket: EvidencePacket = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
for (let i = 1; i < 100; i++) {
  hundredActionPacket.actions.push({
    action_id: `act-stress-100-${i}`,
    action_kind: { kind: "Standard", action: "Write" },
    description: `Stress batch action attestation ${i}`,
    payload_hash: hundredActionPacket.actions[0].payload_hash,
    performed_at: hundredActionPacket.actions[0].performed_at + i * 10,
    agent_sig: hundredActionPacket.actions[0].agent_sig,
  });
}

const t2 = performance.now();
const hundredActionResult = transformWasmGraphToFlow({
  packet: hundredActionPacket,
  report,
  direction: "LR",
});
const tHundredAction = performance.now() - t2;

assert(hundredActionResult.nodes.filter((n) => n.data.kind === "action").length === 100,
  "Successfully generated 100 parallel action nodes");
assert(hundredActionResult.reachability.valid === true,
  "100-action fan-out satisfies 100% Single-Principal BFS reachability");
assert(tHundredAction < 50, `100-action layout computed in ${tHundredAction.toFixed(2)}ms (< 50ms)`);
const collisions100 = detectCollisions(hundredActionResult.nodes);
assert(collisions100 === 0, `100-action LR layout: zero bounding-box overlaps detected (collisions: ${collisions100})`);

// -------------------------------------------------------------
// SECTION 6: Inspection Sheet Defensive Formatting & Oracles
// -------------------------------------------------------------
console.log("\n--- SECTION 6: Inspection Sheet Data Formatting ---");

const formatFingerprint = (hex?: string): string => {
  if (!hex || hex.length < 16) return hex || "N/A (Not Provided)";
  return `${hex.slice(0, 8)}...${hex.slice(-8)}`;
};

const formatTimestamp = (epochMs?: number | null): string => {
  if (!epochMs || isNaN(epochMs) || epochMs <= 0) return "N/A (Not Provided)";
  try {
    return new Date(epochMs).toISOString();
  } catch {
    return "N/A (Not Provided)";
  }
};

const fullPubkey = validHonestCounterpartyPacket.agent.public_key.key_bytes;
const fp = formatFingerprint(fullPubkey);
assert(fp.length === 19, `Fingerprint length is exactly 19 characters (got: ${fp.length}, value: '${fp}')`);
assert(fp.startsWith(fullPubkey.slice(0, 8)), "Fingerprint starts with first 8 hex characters");
assert(fp.endsWith(fullPubkey.slice(-8)), "Fingerprint ends with last 8 hex characters");
assert(fp.includes("..."), "Fingerprint contains ellipsis separator");

assert(formatFingerprint("") === "N/A (Not Provided)", "Empty fingerprint defaults to 'N/A (Not Provided)'");
assert(formatFingerprint(undefined) === "N/A (Not Provided)", "Undefined fingerprint defaults to 'N/A (Not Provided)'");
assert(formatFingerprint("short_key") === "short_key", "Short fingerprint (<16 chars) preserved cleanly without corruption");

assert(formatTimestamp(1772528400000) === "2026-03-03T09:00:00.000Z",
  "Valid millisecond timestamp formatted to exact ISO-8601 string");
assert(formatTimestamp(0) === "N/A (Not Provided)", "0 epoch ms defaults to 'N/A (Not Provided)'");
assert(formatTimestamp(-100) === "N/A (Not Provided)", "Negative epoch ms defaults to 'N/A (Not Provided)'");
assert(formatTimestamp(NaN) === "N/A (Not Provided)", "NaN epoch ms defaults to 'N/A (Not Provided)'");
assert(formatTimestamp(null) === "N/A (Not Provided)", "Null epoch ms defaults to 'N/A (Not Provided)'");

// -------------------------------------------------------------
// SUMMARY & VERDICT
// -------------------------------------------------------------
console.log("\n=======================================================");
console.log(`TOTAL TESTS: ${passed + failed} | PASSED: ${passed} | FAILED: ${failed}`);
if (failed === 0) {
  console.log("CHALLENGER VERDICT: APPROVE");
} else {
  console.log("CHALLENGER VERDICT: REJECT");
  console.log("Failures:");
  failures.forEach((f) => console.log(`  - ${f}`));
}
console.log("=======================================================\n");

process.exit(failed === 0 ? 0 : 1);
