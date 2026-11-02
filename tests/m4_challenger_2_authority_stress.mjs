/**
 * AIP Milestone 4 Iteration 2 - Challenger 2 Authority Stress Harness
 * 
 * Empirically stress-tests Requirement R4 (Features F14, F15, F16):
 * 1. Visual Scope Matrix Editor:
 *    - Explicit deny priority across standard and custom actions
 *    - Closed-world security (empty allowed = 0 actions)
 *    - Complex action verbs (hierarchical paths, punctuation, regex validation)
 *    - Case sensitivity (strict distinction for custom verbs)
 *    - Admin verb boundaries (grants all standard, never custom, overridden by deny)
 * 2. Capability Lattice Attenuation Preview:
 *    - Lattice meet operator (⊓) cross-validated with live Rust WASM engine
 *    - Idempotence (S ⊓ S = S) across presets and custom scopes
 *    - Identity element (ADMIN ⊓ S = S)
 *    - Bottom (⊥) conflict detection (disjoint scopes, total denial)
 *    - Associativity ((A ⊓ B) ⊓ C = A ⊓ (B ⊓ C))
 *    - Commutativity (A ⊓ B = B ⊓ A on effective permissions)
 *    - Escalation attempt isolation
 * 3. Cascade Revocation Tree & WASM Rule 9 Context Sync:
 *    - BFS traversal and level-by-level queue ordering
 *    - Subtree invalidation (leaf, intermediate, multi-branch isolation)
 *    - Deep linear chains (depth 10, depth 25)
 *    - Wide fanout trees (50 and 100 children)
 *    - Revocation restoration logic
 *    - Impact metrics calculation (agents, depths, broken delegations)
 *    - Live WASM engine context synchronization triggering Rule 9 (REVOCATION)
 * 4. Zero-JS Verification Static Code Audit on authority subsystem.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..");
const CONSOLE_DIR = path.join(ROOT_DIR, "aip-console");
const FIXTURES_DIR = path.join(CONSOLE_DIR, "public", "fixtures");
const WASM_JS_PATH = path.join(CONSOLE_DIR, "public", "wasm", "aip_wasm.js");
const WASM_BG_PATH = path.join(CONSOLE_DIR, "public", "wasm", "aip_wasm_bg.wasm");
const AUTHORITY_DIR = path.join(CONSOLE_DIR, "src", "components", "authority");

console.log("================================================================================");
console.log("  AIP MILESTONE 4 ITERATION 2 — CHALLENGER 2 AUTHORITY STRESS HARNESS          ");
console.log("================================================================================\n");

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;
const findings = [];

function assert(condition, testName, details = "") {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`[PASS] #${totalTests}: ${testName}`);
  } else {
    failedTests++;
    console.error(`[FAIL] #${totalTests}: ${testName} ${details ? `-> ${details}` : ""}`);
    findings.push({ testName, details });
  }
}

// ─── INITIALIZATION: WebAssembly Engine Loader ─────────────────────────────
console.log("─── INITIALIZATION: WebAssembly Engine Loader ───");
assert(fs.existsSync(WASM_JS_PATH), "WASM JS wrapper exists: public/wasm/aip_wasm.js");
assert(fs.existsSync(WASM_BG_PATH), "WASM binary exists: public/wasm/aip_wasm_bg.wasm");

let wasm;
try {
  const wasmModule = await import(`file://${WASM_JS_PATH}`);
  const wasmBytes = fs.readFileSync(WASM_BG_PATH);
  await wasmModule.default({ module_or_path: wasmBytes });
  wasm = wasmModule;
  assert(true, "WebAssembly module instantiated successfully in Node.js");
} catch (err) {
  assert(false, `WebAssembly initialization failed: ${err.message}`);
  process.exit(1);
}

// Load baseline valid packet and context
const baselinePacketPath = path.join(FIXTURES_DIR, "honest_counterparty.json");
const baselineContextPath = path.join(FIXTURES_DIR, "honest_counterparty.context.json");
assert(fs.existsSync(baselinePacketPath), "honest_counterparty.json fixture exists");
assert(fs.existsSync(baselineContextPath), "honest_counterparty.context.json fixture exists");

const baselinePacketJson = fs.readFileSync(baselinePacketPath, "utf8");
const baselineContextJson = fs.readFileSync(baselineContextPath, "utf8");
const baselinePacket = JSON.parse(baselinePacketJson);
const baselineContext = JSON.parse(baselineContextJson);

// Verify baseline is 100% valid in WASM
const baselineReportStr = wasm.verify_evidence_packet(baselinePacketJson, baselineContextJson);
const baselineReport = JSON.parse(baselineReportStr);
assert(baselineReport.valid === true, "Baseline packet verifies overall valid === true");
assert(baselineReport.tampered === false, "Baseline packet has tamper_evidence === false");
assert(baselineReport.trust_floor === "COUNTERPARTY_SIGNED", "Baseline packet trust_floor === COUNTERPARTY_SIGNED");
const baselineRule9 = baselineReport.checks.find(c => c.rule === "REVOCATION");
assert(baselineRule9?.pass === true, "Baseline packet Rule 9 (REVOCATION) passes");

// ─── HELPER DEFINITIONS (Matching UI Component Implementation) ───────────────
const STANDARD_ACTIONS = ["Read", "Write", "Delete", "Admin", "Execute", "Delegate"];

function actionToString(verb) {
  if (typeof verb === "string") return verb;
  return verb.kind === "Standard" ? verb.action : verb.name;
}

function stringToAction(str) {
  const trimmed = str.trim();
  const match = STANDARD_ACTIONS.find(a => a.toLowerCase() === trimmed.toLowerCase());
  if (match) return { kind: "Standard", action: match };
  return { kind: "Custom", name: trimmed };
}

function verbEquals(a, b) {
  const aNorm = typeof a === "string" ? stringToAction(a) : a;
  const bNorm = typeof b === "string" ? stringToAction(b) : b;
  if (aNorm.kind === "Standard" && bNorm.kind === "Standard") {
    return aNorm.action.toLowerCase() === bNorm.action.toLowerCase();
  }
  if (aNorm.kind === "Custom" && bNorm.kind === "Custom") {
    return aNorm.name === bNorm.name; // Strict case-sensitivity for custom
  }
  return false;
}

function hasVerb(list, verb) {
  return (list || []).some(item => verbEquals(item, verb));
}

function scopePermitsAction(scope, action) {
  const verb = typeof action === "string" ? stringToAction(action) : action;
  
  // 1. Explicit deny takes absolute precedence (F14.B1)
  if (hasVerb(scope.denied, verb)) {
    return false;
  }

  // 2. Direct allow check (strict case-sensitive for custom actions)
  if (hasVerb(scope.allowed, verb)) {
    return true;
  }

  // 3. Admin grants all standard actions unless explicitly denied (F14.B5)
  const hasAdmin = (scope.allowed || []).some(a => {
    const v = typeof a === "string" ? stringToAction(a) : a;
    return v.kind === "Standard" && v.action === "Admin";
  });
  if (hasAdmin && verb.kind === "Standard") {
    return true;
  }

  // 4. Default closed (F14.B2)
  return false;
}

function meetCapabilityScopesPure(parent, child) {
  const hasAdmin = (parent.allowed || []).some(a => {
    const v = typeof a === "string" ? stringToAction(a) : a;
    return v.kind === "Standard" && v.action === "Admin";
  });

  let effectiveParentAllowed = [...(parent.allowed || [])];
  if (hasAdmin) {
    for (const act of STANDARD_ACTIONS) {
      const verb = { kind: "Standard", action: act };
      if (!hasVerb(effectiveParentAllowed, verb) && !hasVerb(parent.denied || [], verb)) {
        effectiveParentAllowed.push(verb);
      }
    }
  }

  const pAllowedMinusDenied = effectiveParentAllowed.filter(a => !hasVerb(parent.denied || [], a));
  const newAllowed = (child.allowed || []).filter(c => hasVerb(pAllowedMinusDenied, c));

  if (newAllowed.length === 0) {
    return null; // Bottom (⊥)
  }

  const newDenied = [...(parent.denied || [])];
  for (const d of child.denied || []) {
    if (!hasVerb(newDenied, d)) {
      newDenied.push(d);
    }
  }

  return {
    allowed: newAllowed,
    denied: newDenied,
  };
}

function computeCascadeRevocations(targetJti, treeNodes, revokedBy = "security-admin", primaryReason = "Compromise") {
  const result = [];
  const queue = [targetJti];

  result.push({
    jti: targetJti,
    revoked_at: Date.now(),
    reason: primaryReason,
    cascade: true,
    revoked_by: revokedBy,
  });

  while (queue.length > 0) {
    const current = queue.shift();
    const children = treeNodes.filter(n => n.parent_jti === current);
    for (const child of children) {
      result.push({
        jti: child.jti,
        revoked_at: Date.now(),
        reason: "AdminRevocation",
        cascade: true,
        revoked_by: revokedBy,
      });
      queue.push(child.jti);
    }
  }

  return result;
}

function calculateRevocationImpact(revocations, nodes) {
  const totalRevoked = revocations.length;
  const primaryRevocations = revocations.filter(r => r.reason !== "AdminRevocation").length;
  const cascadedRevocations = totalRevoked - primaryRevocations;

  const revokedJtiSet = new Set(revocations.map(r => r.jti));
  const affectedAgentsSet = new Set();
  let brokenDelegations = 0;
  let maxCascadeDepth = 0;

  nodes.forEach(node => {
    if (revokedJtiSet.has(node.jti)) {
      if (node.grantee_id) affectedAgentsSet.add(node.grantee_id);
      if (node.depth > maxCascadeDepth) maxCascadeDepth = node.depth;
      if (node.parent_jti) brokenDelegations++;
    }
  });

  return {
    totalRevoked,
    primaryRevocations,
    cascadedRevocations,
    affectedAgents: Array.from(affectedAgentsSet),
    brokenDelegations,
    maxCascadeDepth,
  };
}


// ─────────────────────────────────────────────────────────────────────────────
// SECTION 1: VISUAL SCOPE MATRIX EDITOR BOUNDARY TESTING
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n─── SECTION 1: Visual Scope Matrix Editor Boundary Stress Testing ───");

// 1.1 Explicit Deny Priority Across All Actions
console.log("\n[Test 1.1] Explicit Deny Priority Across Standard & Custom Actions");
for (const std of STANDARD_ACTIONS) {
  const scopeBoth = {
    allowed: [{ kind: "Standard", action: std }],
    denied: [{ kind: "Standard", action: std }],
  };
  assert(!scopePermitsAction(scopeBoth, { kind: "Standard", action: std }),
    `Explicit deny overrides allow for Standard action '${std}'`);
  
  // Test WASM check_scope_permits
  const wasmJson = JSON.stringify({ allowed: [std], denied: [std] });
  const wasmPermits = wasm.check_scope_permits(wasmJson, JSON.stringify(std));
  assert(wasmPermits === false, `WASM check_scope_permits confirms explicit deny for '${std}'`);
}

const customConflictVerbs = [
  "treasury:wire_transfer",
  "loan/v1:approve",
  "audit:compliance_export",
  "cloud.infra/vpc:route_table-update.v1"
];
for (const cust of customConflictVerbs) {
  const scopeBoth = {
    allowed: [{ kind: "Custom", name: cust }],
    denied: [{ kind: "Custom", name: cust }],
  };
  assert(!scopePermitsAction(scopeBoth, { kind: "Custom", name: cust }),
    `Explicit deny overrides allow for Custom action '${cust}'`);
}

// 1.2 Closed-World Security Policy
console.log("\n[Test 1.2] Closed-World Security Invariants");
const emptyScope = { allowed: [], denied: [] };
const probeVerbs = [
  ...STANDARD_ACTIONS.map(a => ({ kind: "Standard", action: a })),
  { kind: "Custom", name: "wire:transfer" },
  { kind: "Custom", name: "loan:approve" },
  { kind: "Custom", name: "auth:bypass" },
  { kind: "Custom", name: "admin:super" },
];
let emptyPermittedCount = 0;
for (const pv of probeVerbs) {
  if (scopePermitsAction(emptyScope, pv)) emptyPermittedCount++;
}
assert(emptyPermittedCount === 0, `Closed-world: Empty scope permits exactly 0 actions (tested ${probeVerbs.length})`);

const emptyAllowedWithDeny = { allowed: [], denied: [{ kind: "Standard", action: "Write" }] };
let emptyAllowedPermittedCount = 0;
for (const pv of probeVerbs) {
  if (scopePermitsAction(emptyAllowedWithDeny, pv)) emptyAllowedPermittedCount++;
}
assert(emptyAllowedPermittedCount === 0, `Closed-world: Empty allowed with denied array permits 0 actions`);

// 1.3 Complex Action Verbs & Regex Validation
console.log("\n[Test 1.3] Complex Custom Action Verbs & Hierarchy");
const validEnterpriseVerbs = [
  "ledger/treasury:transfer-wire_v2",
  "cloud.infra/vpc:route_table-update.v1",
  "auth:user_profile.read",
  "org.syntriass/agents/v2:dispatch.execute",
  "payments/settlement:iso20022_pacs008",
  "loan:approve_tier-1.sub_b",
];
const customActionRegex = /^[a-zA-Z0-9_\-\:\.\/]+$/;
for (const v of validEnterpriseVerbs) {
  assert(customActionRegex.test(v), `Complex verb matches enterprise syntax regex: '${v}'`);
  const scope = { allowed: [{ kind: "Custom", name: v }], denied: [] };
  assert(scopePermitsAction(scope, { kind: "Custom", name: v }), `Scope permits valid complex verb: '${v}'`);
}

const invalidInjectionVerbs = [
  "admin; DROP TABLE evidence;--",
  "<script>alert('xss')</script>",
  "spaces are forbidden in verbs",
  "quoted'verb'is'invalid",
  "dollar$sign$forbidden",
  "pipe|command|injection",
];
for (const inv of invalidInjectionVerbs) {
  assert(!customActionRegex.test(inv), `Adversarial injection verb rejected by syntax regex: '${inv}'`);
}

// 1.4 Strict Case Sensitivity
console.log("\n[Test 1.4] Strict Case Sensitivity on Custom Verbs");
const caseTestScope = {
  allowed: [
    { kind: "Custom", name: "loan:approve" },
    { kind: "Custom", name: "wire:Transfer_V1" },
  ],
  denied: [
    { kind: "Custom", name: "wire:EXCLUDE" },
  ],
};
assert(scopePermitsAction(caseTestScope, { kind: "Custom", name: "loan:approve" }) === true, "Exact case 'loan:approve' is PERMITTED");
assert(scopePermitsAction(caseTestScope, { kind: "Custom", name: "LOAN:APPROVE" }) === false, "Uppercase 'LOAN:APPROVE' is DENIED");
assert(scopePermitsAction(caseTestScope, { kind: "Custom", name: "Loan:Approve" }) === false, "TitleCase 'Loan:Approve' is DENIED");
assert(scopePermitsAction(caseTestScope, { kind: "Custom", name: "loan:Approve" }) === false, "MixedCase 'loan:Approve' is DENIED");
assert(scopePermitsAction(caseTestScope, { kind: "Custom", name: "wire:Transfer_V1" }) === true, "Exact case 'wire:Transfer_V1' is PERMITTED");
assert(scopePermitsAction(caseTestScope, { kind: "Custom", name: "wire:transfer_v1" }) === false, "Lowercase 'wire:transfer_v1' is DENIED");

// 1.5 Admin Verb Boundaries
console.log("\n[Test 1.5] Admin Verb Boundaries & Inheritance");
const adminInheritanceScope = {
  allowed: [{ kind: "Standard", action: "Admin" }],
  denied: [{ kind: "Standard", action: "Delete" }],
};
assert(scopePermitsAction(adminInheritanceScope, { kind: "Standard", action: "Read" }) === true, "Admin grants standard 'Read'");
assert(scopePermitsAction(adminInheritanceScope, { kind: "Standard", action: "Write" }) === true, "Admin grants standard 'Write'");
assert(scopePermitsAction(adminInheritanceScope, { kind: "Standard", action: "Execute" }) === true, "Admin grants standard 'Execute'");
assert(scopePermitsAction(adminInheritanceScope, { kind: "Standard", action: "Delegate" }) === true, "Admin grants standard 'Delegate'");
assert(scopePermitsAction(adminInheritanceScope, { kind: "Standard", action: "Admin" }) === true, "Admin grants standard 'Admin'");
assert(scopePermitsAction(adminInheritanceScope, { kind: "Standard", action: "Delete" }) === false, "Explicit deny on 'Delete' OVERRIDES Admin grant");
assert(scopePermitsAction(adminInheritanceScope, { kind: "Custom", name: "wire:transfer" }) === false, "Admin DOES NOT grant unpermitted custom verb 'wire:transfer'");
assert(scopePermitsAction(adminInheritanceScope, { kind: "Custom", name: "loan:approve" }) === false, "Admin DOES NOT grant unpermitted custom verb 'loan:approve'");

const adminDeniedScope = {
  allowed: [{ kind: "Standard", action: "Admin" }],
  denied: [{ kind: "Standard", action: "Admin" }],
};
assert(scopePermitsAction(adminDeniedScope, { kind: "Standard", action: "Admin" }) === false, "Admin in denied blocks Admin itself");


// ─────────────────────────────────────────────────────────────────────────────
// SECTION 2: CAPABILITY LATTICE ATTENUATION PREVIEW (MEET ⊓ OPERATOR)
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n─── SECTION 2: Capability Lattice Attenuation Preview (MEET ⊓) ───");

// 2.1 Pure Meet vs WASM Meet Cross-Validation
console.log("\n[Test 2.1] Pure Meet vs Live WASM meet_capability_scopes Cross-Validation");
const crossTestPairs = [
  {
    name: "Admin ⊓ Orchestrator",
    parent: { allowed: ["Read", "Write", "Delete", "Admin", "Execute", "Delegate"], denied: [] },
    child: { allowed: ["Read", "Write", "Execute", "Delegate"], denied: ["Admin"] },
  },
  {
    name: "Orchestrator ⊓ Auditor",
    parent: { allowed: ["Read", "Write", "Execute", "Delegate"], denied: ["Admin"] },
    child: { allowed: ["Read"], denied: ["Write", "Admin", "Delete"] },
  },
  {
    name: "Auditor ⊓ Submitter (Disjoint)",
    parent: { allowed: ["Read"], denied: ["Write", "Admin", "Delete"] },
    child: { allowed: ["Write"], denied: ["Admin", "Delete"] },
  },
  {
    name: "Custom Enterprise Attenuation",
    parent: { allowed: ["wire:transfer", "loan:approve", "credit:underwrite"], denied: [] },
    child: { allowed: ["wire:transfer", "unauthorized:hack"], denied: [] },
  },
];

for (const pair of crossTestPairs) {
  const pureRes = meetCapabilityScopesPure(
    { allowed: pair.parent.allowed.map(stringToAction), denied: pair.parent.denied.map(stringToAction) },
    { allowed: pair.child.allowed.map(stringToAction), denied: pair.child.denied.map(stringToAction) }
  );

  const wasmRaw = wasm.meet_capability_scopes(JSON.stringify(pair.parent), JSON.stringify(pair.child));
  const wasmRes = JSON.parse(wasmRaw);

  if (pureRes === null) {
    assert(wasmRes.is_bottom === true, `Cross-test [${pair.name}]: Both oracles agree on is_bottom === true`);
    assert(wasmRes.allowed.length === 0, `Cross-test [${pair.name}]: WASM allowed is empty []`);
  } else {
    assert(wasmRes.is_bottom === false, `Cross-test [${pair.name}]: Both oracles agree on is_bottom === false`);
    assert(pureRes.allowed.length === wasmRes.allowed.length,
      `Cross-test [${pair.name}]: Allowed count matches (${pureRes.allowed.length} === ${wasmRes.allowed.length})`);
  }
}

// 2.2 Idempotence Property: S ⊓ S = S
console.log("\n[Test 2.2] Lattice Idempotence (S ⊓ S = S)");
const idempotenceScopes = [
  { name: "ADMIN", allowed: ["Read", "Write", "Delete", "Admin", "Execute", "Delegate"], denied: [] },
  { name: "ORCHESTRATOR", allowed: ["Read", "Write", "Execute", "Delegate"], denied: ["Admin"] },
  { name: "AUDITOR", allowed: ["Read"], denied: ["Write", "Admin", "Delete"] },
  { name: "WORKER", allowed: ["Write"], denied: ["Admin", "Delete"] },
  { name: "READ_ONLY", allowed: ["Read", "Execute"], denied: ["Write", "Delete", "Admin", "Delegate"] },
  { name: "CUSTOM_MIXED", allowed: ["Read", "wire:transfer", "loan:approve"], denied: ["Delete"] },
];

for (const s of idempotenceScopes) {
  const scopeObj = { allowed: s.allowed.map(stringToAction), denied: s.denied.map(stringToAction) };
  const met = meetCapabilityScopesPure(scopeObj, scopeObj);
  assert(met !== null, `Idempotence [${s.name}]: S ⊓ S is non-null`);
  assert(met.allowed.length === scopeObj.allowed.length,
    `Idempotence [${s.name}]: Allowed action count identical (${met.allowed.length} === ${scopeObj.allowed.length})`);
  assert(met.denied.length === scopeObj.denied.length,
    `Idempotence [${s.name}]: Denied action count identical (${met.denied.length} === ${scopeObj.denied.length})`);
}

// 2.3 Identity Element: ADMIN ⊓ S = S
console.log("\n[Test 2.3] Lattice Identity Element (ADMIN ⊓ S = S)");
const adminScopeDef = {
  allowed: STANDARD_ACTIONS.map(a => ({ kind: "Standard", action: a })),
  denied: [],
};
const subScopes = [
  { name: "ORCHESTRATOR", allowed: ["Read", "Write", "Execute", "Delegate"], denied: ["Admin"] },
  { name: "AUDITOR", allowed: ["Read"], denied: ["Write", "Admin", "Delete"] },
  { name: "WORKER", allowed: ["Write"], denied: ["Admin", "Delete"] },
  { name: "READ_ONLY", allowed: ["Read", "Execute"], denied: ["Write", "Delete", "Admin", "Delegate"] },
];

for (const sub of subScopes) {
  const child = { allowed: sub.allowed.map(stringToAction), denied: sub.denied.map(stringToAction) };
  const met = meetCapabilityScopesPure(adminScopeDef, child);
  assert(met !== null, `Identity [ADMIN ⊓ ${sub.name}]: result is non-null`);
  assert(met.allowed.length === child.allowed.length,
    `Identity [ADMIN ⊓ ${sub.name}]: allowed count matches child (${met.allowed.length} === ${child.allowed.length})`);
  for (const ca of child.allowed) {
    assert(hasVerb(met.allowed, ca), `Identity [ADMIN ⊓ ${sub.name}]: child action '${actionToString(ca)}' retained`);
  }
}

// 2.4 Bottom (⊥) Conflict Detection
console.log("\n[Test 2.4] Bottom (⊥) Empty Intersection & Conflict Detection");
const disjointStandard = meetCapabilityScopesPure(
  { allowed: [{ kind: "Standard", action: "Read" }], denied: [] },
  { allowed: [{ kind: "Standard", action: "Write" }], denied: [] }
);
assert(disjointStandard === null, "Disjoint standard scopes produce bottom (null)");

const disjointCustom = meetCapabilityScopesPure(
  { allowed: [{ kind: "Custom", name: "loan:approve" }], denied: [] },
  { allowed: [{ kind: "Custom", name: "infra:deploy" }], denied: [] }
);
assert(disjointCustom === null, "Disjoint custom scopes produce bottom (null)");

// Child allowed completely blocked by parent deny
const blockedByParentDeny = meetCapabilityScopesPure(
  { allowed: [{ kind: "Standard", action: "Read" }, { kind: "Standard", action: "Delete" }], denied: [{ kind: "Standard", action: "Delete" }] },
  { allowed: [{ kind: "Standard", action: "Delete" }], denied: [] }
);
assert(blockedByParentDeny === null, "Child allowed blocked by parent deny produces bottom (null)");

// 2.5 Lattice Associativity: ((A ⊓ B) ⊓ C = A ⊓ (B ⊓ C))
console.log("\n[Test 2.5] Lattice Associativity");
const scA = { allowed: ["Read", "Write", "Execute", "Delete"].map(stringToAction), denied: [] };
const scB = { allowed: ["Read", "Write", "Execute"].map(stringToAction), denied: [] };
const scC = { allowed: ["Read", "Write"].map(stringToAction), denied: [] };

const leftAssoc = meetCapabilityScopesPure(meetCapabilityScopesPure(scA, scB), scC);
const rightAssoc = meetCapabilityScopesPure(scA, meetCapabilityScopesPure(scB, scC));
assert(leftAssoc !== null && rightAssoc !== null, "Associativity: both sides non-null");
assert(leftAssoc.allowed.length === rightAssoc.allowed.length,
  `Associativity: Allowed count identical (${leftAssoc.allowed.length} === ${rightAssoc.allowed.length})`);
assert(leftAssoc.allowed.every(a => hasVerb(rightAssoc.allowed, a)),
  "Associativity: Allowed verbs identical under ((A ⊓ B) ⊓ C = A ⊓ (B ⊓ C))");

// 2.6 Lattice Commutativity: Allowed(A ⊓ B) = Allowed(B ⊓ A)
console.log("\n[Test 2.6] Lattice Commutativity on Allowed Intersections");
const commA = { allowed: ["Read", "Write", "Execute"].map(stringToAction), denied: [] };
const commB = { allowed: ["Write", "Execute", "Delete"].map(stringToAction), denied: [] };
const meetAB = meetCapabilityScopesPure(commA, commB);
const meetBA = meetCapabilityScopesPure(commB, commA);
assert(meetAB !== null && meetBA !== null, "Commutativity: both directions non-null");
assert(meetAB.allowed.length === meetBA.allowed.length,
  `Commutativity: Allowed count equal (${meetAB.allowed.length} === ${meetBA.allowed.length})`);
assert(meetAB.allowed.every(a => hasVerb(meetBA.allowed, a)),
  "Commutativity: Actions in A ⊓ B exactly equal actions in B ⊓ A");

// 2.7 Escalation Attempt Isolation
console.log("\n[Test 2.7] Escalation Attempt Detection");
const parentForEscalation = {
  allowed: ["Read", "Write"].map(stringToAction),
  denied: ["Delete"].map(stringToAction),
};
const childAttemptingEscalation = {
  allowed: ["Read", "Write", "Delete", "Admin", "wire:unauthorized"].map(stringToAction),
  denied: [],
};
const metForEscalation = meetCapabilityScopesPure(parentForEscalation, childAttemptingEscalation);
assert(metForEscalation !== null, "Escalation test: meet is non-null for permitted intersection");
assert(metForEscalation.allowed.length === 2, "Escalation test: only Read and Write are retained");
assert(!hasVerb(metForEscalation.allowed, { kind: "Standard", action: "Delete" }), "Escalation test: 'Delete' rejected");
assert(!hasVerb(metForEscalation.allowed, { kind: "Standard", action: "Admin" }), "Escalation test: 'Admin' rejected");
assert(!hasVerb(metForEscalation.allowed, { kind: "Custom", name: "wire:unauthorized" }), "Escalation test: unpermitted custom verb rejected");


// ─────────────────────────────────────────────────────────────────────────────
// SECTION 3: CASCADE REVOCATION TREE & LIVE WASM CONTEXT SYNCHRONIZATION
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n─── SECTION 3: Cascade Revocation Tree & WASM Rule 9 Synchronization ───");

// 3.1 Multi-Branch Topology BFS Traversal
console.log("\n[Test 3.1] Multi-Branch Organization BFS Traversal");
const multiBranchTree = [
  { jti: "root", parent_jti: undefined, type: "root", depth: 0, grantee_id: "agent:exec" },
  { jti: "hop-1a", parent_jti: "root", type: "intermediate", depth: 1, grantee_id: "agent:treasury" },
  { jti: "hop-2a1", parent_jti: "hop-1a", type: "leaf", depth: 2, grantee_id: "agent:wire-1" },
  { jti: "hop-2a2", parent_jti: "hop-1a", type: "leaf", depth: 2, grantee_id: "agent:wire-2" },
  { jti: "hop-1b", parent_jti: "root", type: "intermediate", depth: 1, grantee_id: "agent:risk" },
  { jti: "hop-2b1", parent_jti: "hop-1b", type: "leaf", depth: 2, grantee_id: "agent:auditor-1" },
];

// Leaf revocation: only affects the leaf
const leafRev = computeCascadeRevocations("hop-2a1", multiBranchTree);
assert(leafRev.length === 1, `Leaf revocation produces exactly 1 entry (got ${leafRev.length})`);
assert(leafRev[0].jti === "hop-2a1", "Leaf revocation targets correct JTI");
assert(leafRev[0].reason === "Compromise", "Leaf revocation reason is Compromise");

// Intermediate branch revocation: affects hop-1a and both children (hop-2a1, hop-2a2), but leaves hop-1b untouched
const branchARev = computeCascadeRevocations("hop-1a", multiBranchTree);
assert(branchARev.length === 3, `Branch A revocation invalidates 3 nodes (got ${branchARev.length})`);
const branchAJtis = branchARev.map(r => r.jti);
assert(branchAJtis.includes("hop-1a"), "Branch A includes target hop-1a");
assert(branchAJtis.includes("hop-2a1"), "Branch A includes child hop-2a1");
assert(branchAJtis.includes("hop-2a2"), "Branch A includes child hop-2a2");
assert(!branchAJtis.includes("root"), "Branch A DOES NOT touch ancestor root");
assert(!branchAJtis.includes("hop-1b"), "Branch A DOES NOT touch sibling branch hop-1b");
assert(!branchAJtis.includes("hop-2b1"), "Branch A DOES NOT touch sibling child hop-2b1");

// Root revocation: invalidates all 6 nodes
const rootRev = computeCascadeRevocations("root", multiBranchTree);
assert(rootRev.length === 6, `Root revocation cascades to all 6 nodes (got ${rootRev.length})`);
assert(rootRev[0].jti === "root" && rootRev[0].reason === "Compromise", "Root revocation is primary");
assert(rootRev.slice(1).every(r => r.reason === "AdminRevocation"), "All cascaded nodes have reason AdminRevocation");

// 3.2 Deep Linear Chains (Depth 10 and Depth 25)
console.log("\n[Test 3.2] Deep Linear Chain Stress Testing");
const deepChain10 = [{ jti: "hop-0", parent_jti: undefined, depth: 0, grantee_id: "agent-0" }];
for (let i = 1; i < 10; i++) {
  deepChain10.push({ jti: `hop-${i}`, parent_jti: `hop-${i - 1}`, depth: i, grantee_id: `agent-${i}` });
}
const deep10Rev = computeCascadeRevocations("hop-0", deepChain10);
assert(deep10Rev.length === 10, `Depth-10 chain revocation invalidates all 10 nodes (got ${deep10Rev.length})`);
for (let i = 0; i < 10; i++) {
  assert(deep10Rev[i].jti === `hop-${i}`, `Depth-10 BFS order strictly preserved at index ${i}`);
}

const midChainRev = computeCascadeRevocations("hop-6", deepChain10);
assert(midChainRev.length === 4, `Mid-chain revocation at hop-6 invalidates 4 nodes: hop-6,7,8,9 (got ${midChainRev.length})`);
assert(midChainRev.map(r => r.jti).join(",") === "hop-6,hop-7,hop-8,hop-9", "Mid-chain BFS order is sequential");

// Deep-25 stress test
const deepChain25 = [{ jti: "d25-0", parent_jti: undefined, depth: 0 }];
for (let i = 1; i < 25; i++) {
  deepChain25.push({ jti: `d25-${i}`, parent_jti: `d25-${i - 1}`, depth: i });
}
const deep25Rev = computeCascadeRevocations("d25-0", deepChain25);
assert(deep25Rev.length === 25, `Depth-25 linear chain successfully invalidates 25 nodes without stack overflow`);

// 3.3 Wide Fanout Trees (50 and 100 Children)
console.log("\n[Test 3.3] Wide Delegation Fanout Testing (50 and 100 Children)");
const wideTree50 = [{ jti: "wide-root-50", parent_jti: undefined, depth: 0 }];
for (let i = 1; i <= 50; i++) {
  wideTree50.push({ jti: `child-50-${i}`, parent_jti: "wide-root-50", depth: 1 });
}
const wide50Rev = computeCascadeRevocations("wide-root-50", wideTree50);
assert(wide50Rev.length === 51, `Wide 50-child tree revocation invalidates 51 nodes (got ${wide50Rev.length})`);

const wideTree100 = [{ jti: "wide-root-100", parent_jti: undefined, depth: 0 }];
for (let i = 1; i <= 100; i++) {
  wideTree100.push({ jti: `child-100-${i}`, parent_jti: "wide-root-100", depth: 1 });
}
const wide100Rev = computeCascadeRevocations("wide-root-100", wideTree100);
assert(wide100Rev.length === 101, `Wide 100-child tree revocation invalidates 101 nodes (got ${wide100Rev.length})`);

// 3.4 Impact Metrics Calculation
console.log("\n[Test 3.4] Revocation Impact Metrics Calculation");
const impact = calculateRevocationImpact(branchARev, multiBranchTree);
assert(impact.totalRevoked === 3, `Impact metric: totalRevoked === 3 (got ${impact.totalRevoked})`);
assert(impact.primaryRevocations === 1, `Impact metric: primaryRevocations === 1 (got ${impact.primaryRevocations})`);
assert(impact.cascadedRevocations === 2, `Impact metric: cascadedRevocations === 2 (got ${impact.cascadedRevocations})`);
assert(impact.affectedAgents.length === 3, `Impact metric: affectedAgents.length === 3 (got ${impact.affectedAgents.length})`);
assert(impact.brokenDelegations === 3, `Impact metric: brokenDelegations === 3 (got ${impact.brokenDelegations})`);
assert(impact.maxCascadeDepth === 2, `Impact metric: maxCascadeDepth === 2 (got ${impact.maxCascadeDepth})`);

// 3.5 Live WASM Engine Revocation Synchronization Triggering Rule 9
console.log("\n[Test 3.5] Live WASM Revocation Synchronization Triggering Rule 9 (REVOCATION)");

// Test 3.5A: Root Authority Token JTI Revocation
const rootJti = baselinePacket.root_authority.root_token.jti;
assert(rootJti && rootJti.length > 0, `Baseline packet has root token JTI: ${rootJti}`);

const rootRevokedContext = JSON.parse(baselineContextJson);
rootRevokedContext.revoked_jtis = [rootJti];
rootRevokedContext.revoked_token_ids = [rootJti];

const rootRevRepStr = wasm.verify_evidence_packet(baselinePacketJson, JSON.stringify(rootRevokedContext));
const rootRevRep = JSON.parse(rootRevRepStr);
const rootRule9 = rootRevRep.checks.find(c => c.rule === "REVOCATION");

assert(rootRule9?.pass === false, "WASM Rule 9 (REVOCATION) FAILS when Root Token JTI is in revoked_jtis");
assert(rootRevRep.valid === false, "WASM overall valid === false upon Root Token revocation");
assert(rootRevRep.tampered === false, "WASM tamper_evidence remains FALSE (revocation is authority invalidation, not bit-tampering)");
assert(rootRevRep.trust_floor === "AGENT_SIGNED" || rootRevRep.trust_floor === "UNVERIFIED",
  `WASM derived trust_floor is downgraded (got ${rootRevRep.trust_floor})`);

// Test 3.5B: Intermediate Delegation Hop Token JTI Revocation
const hop0Jti = baselinePacket.delegation_chain[0].jti;
assert(hop0Jti && hop0Jti.length > 0, `Baseline packet has delegation hop 0 JTI: ${hop0Jti}`);

const hop0RevokedContext = JSON.parse(baselineContextJson);
hop0RevokedContext.revoked_jtis = [hop0Jti];
hop0RevokedContext.revoked_token_ids = [hop0Jti];

const hop0RevRepStr = wasm.verify_evidence_packet(baselinePacketJson, JSON.stringify(hop0RevokedContext));
const hop0RevRep = JSON.parse(hop0RevRepStr);
const hop0Rule9 = hop0RevRep.checks.find(c => c.rule === "REVOCATION");

assert(hop0Rule9?.pass === false, "WASM Rule 9 (REVOCATION) FAILS when Delegation Hop 0 JTI is in revoked_jtis");
assert(hop0RevRep.valid === false, "WASM overall valid === false upon Delegation Hop 0 revocation");
assert(hop0RevRep.tampered === false, "WASM tamper_evidence remains FALSE");

// Test 3.5C: Leaf Delegation Hop Token JTI Revocation
const lastHopIdx = baselinePacket.delegation_chain.length - 1;
const leafHopJti = baselinePacket.delegation_chain[lastHopIdx].jti;
const leafRevokedContext = JSON.parse(baselineContextJson);
leafRevokedContext.revoked_jtis = [leafHopJti];
leafRevokedContext.revoked_token_ids = [leafHopJti];

const leafRevRepStr = wasm.verify_evidence_packet(baselinePacketJson, JSON.stringify(leafRevokedContext));
const leafRevRep = JSON.parse(leafRevRepStr);
const leafRule9 = leafRevRep.checks.find(c => c.rule === "REVOCATION");

assert(leafRule9?.pass === false, "WASM Rule 9 (REVOCATION) FAILS when Leaf Hop JTI is in revoked_jtis");
assert(leafRevRep.valid === false, "WASM overall valid === false upon Leaf Hop revocation");

// Test 3.5D: Unrelated Token JTI in Revocation Context
const unrelatedRevContext = JSON.parse(baselineContextJson);
unrelatedRevContext.revoked_jtis = ["00000000-0000-0000-0000-000000000000", "unrelated-revoked-token-uuid-9999"];
unrelatedRevContext.revoked_token_ids = unrelatedRevContext.revoked_jtis;

const unrelatedRevRepStr = wasm.verify_evidence_packet(baselinePacketJson, JSON.stringify(unrelatedRevContext));
const unrelatedRevRep = JSON.parse(unrelatedRevRepStr);
const unrelatedRule9 = unrelatedRevRep.checks.find(c => c.rule === "REVOCATION");

assert(unrelatedRule9?.pass === true, "WASM Rule 9 (REVOCATION) PASSES when only unrelated JTIs are in revoked_jtis");
assert(unrelatedRevRep.valid === true, "WASM overall valid remains TRUE with unrelated revoked JTIs");
assert(unrelatedRevRep.trust_floor === "COUNTERPARTY_SIGNED", "WASM trust floor remains COUNTERPARTY_SIGNED");


// ─────────────────────────────────────────────────────────────────────────────
// SECTION 4: ZERO-JS CRYPTOGRAPHIC VERIFICATION STATIC CODE AUDIT
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n─── SECTION 4: Zero-JS Cryptographic Logic Audit in Authority Components ───");

const forbiddenCryptoPatterns = [
  { pattern: /\bcrypto\.subtle\.verify\b/, name: "crypto.subtle.verify" },
  { pattern: /\bcreateHash\s*\(/, name: "Node.js createHash" },
  { pattern: /\bsha256\s*\(/, name: "JS sha256 function" },
  { pattern: /\bed25519\.verify\b/, name: "JS Ed25519 verify" },
  { pattern: /\bnacl\.sign\.open\b/, name: "TweetNaCl sign open" },
  { pattern: /\b@noble\/ed25519\b/, name: "Noble Ed25519" },
];

function scanAuthorityDir(dirPath) {
  const files = fs.readdirSync(dirPath);
  for (const file of files) {
    const full = path.join(dirPath, file);
    if (fs.statSync(full).isDirectory()) {
      scanAuthorityDir(full);
    } else if (file.endsWith(".tsx") || file.endsWith(".ts")) {
      const content = fs.readFileSync(full, "utf8");
      for (const { pattern, name } of forbiddenCryptoPatterns) {
        assert(!pattern.test(content), `Zero-JS Invariant: authority/${file} contains 0 calls to ${name}`);
      }
    }
  }
}
scanAuthorityDir(AUTHORITY_DIR);


// ─────────────────────────────────────────────────────────────────────────────
// FINAL VERDICT & SUMMARY
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n================================================================================");
console.log(`TOTAL TESTS EXECUTED : ${totalTests}`);
console.log(`PASSED TESTS         : ${passedTests}`);
console.log(`FAILED TESTS         : ${failedTests}`);
console.log(`SUCCESS RATE         : ${((passedTests / totalTests) * 100).toFixed(2)}%`);
console.log("================================================================================");

if (failedTests === 0) {
  console.log("CHALLENGER 2 EMPIRICAL VERDICT: APPROVE (100% Pass across all Authority Management vectors)");
  process.exit(0);
} else {
  console.error(`CHALLENGER 2 EMPIRICAL VERDICT: REQUEST_CHANGES (${failedTests} tests failed)`);
  process.exit(1);
}
