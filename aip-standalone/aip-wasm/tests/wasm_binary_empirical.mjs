// Challenger 2: Empirical WebAssembly Binary Test Harness
// Directly invokes the compiled wasm binary (aip_wasm_bg.wasm) via its JS loader (aip_wasm.js)

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as crypto from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Root repo path
const repoRoot = path.resolve(__dirname, '../../../');
const wasmDir = path.join(repoRoot, 'aip-console/public/wasm');
const fixturesDir = path.join(repoRoot, 'aip-console/public/fixtures');

console.log('=== Challenger 2 WebAssembly Empirical Verification ===');
console.log(`Repo root: ${repoRoot}`);
console.log(`Loading WASM module from: ${wasmDir}`);

// Import WASM module
const wasmModule = await import(`file://${path.join(wasmDir, 'aip_wasm.js')}`);
const wasmBytes = fs.readFileSync(path.join(wasmDir, 'aip_wasm_bg.wasm'));
await wasmModule.default(wasmBytes);
console.log('✓ WASM module loaded and instantiated successfully.');

let passedTests = 0;
let totalTests = 0;

function assert(condition, message) {
  totalTests++;
  if (!condition) {
    console.error(`❌ FAILED: ${message}`);
    throw new Error(`Assertion failed: ${message}`);
  }
  passedTests++;
  console.log(`  ✓ ${message}`);
}

// ----------------------------------------------------------------------------
// 1. Audit Bundle ZIP Verification & 7-File Extraction
// ----------------------------------------------------------------------------
console.log('\n--- 1. Testing Bundle ZIP Verification & 7-File Extraction ---');

const validZipBytes = fs.readFileSync(path.join(fixturesDir, 'audit_bundle_valid.zip'));
const tamperedZipBytes = fs.readFileSync(path.join(fixturesDir, 'audit_bundle_tampered.zip'));
const honestContextJson = fs.readFileSync(path.join(fixturesDir, 'honest_counterparty.context.json'), 'utf-8');

// Test 1.1: Extract 7 files from valid bundle
const extractedJson = wasmModule.extract_bundle_files(validZipBytes);
const fileMap = JSON.parse(extractedJson);
const fileKeys = Object.keys(fileMap).sort();

const expectedFiles = [
  'authority_graph.dot',
  'authority_graph.json',
  'bundle_signature.sig',
  'evidence.json',
  'manifest.json',
  'verification_report.json',
  'verification_report.md',
].sort();

assert(
  JSON.stringify(fileKeys) === JSON.stringify(expectedFiles),
  `extract_bundle_files extracted all 7 expected files without corruption: ${fileKeys.join(', ')}`
);

// Verify manifest SHA-256 match for each content file
const manifest = JSON.parse(fileMap['manifest.json']);
assert(manifest.schema_version === 'aip-bundle-1', 'manifest has valid schema_version');
for (const entry of manifest.files) {
  const content = fileMap[entry.name];
  assert(content !== undefined, `Extracted file ${entry.name} exists`);
  const actualHash = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
  assert(actualHash === entry.sha256, `SHA-256 hash matches for ${entry.name} (${actualHash})`);
}

// Test 1.2: Verify valid ZIP bundle
const validResultJson = wasmModule.verify_bundle_zip(validZipBytes, honestContextJson);
const validResult = JSON.parse(validResultJson);
assert(validResult.overall === 'PASS', 'Valid bundle verify_bundle_zip returned overall PASS');
assert(validResult.overall_pass === true, 'Valid bundle verify_bundle_zip returned overall_pass true');
assert(validResult.checks.length === 7, 'Bundle verification includes all 7 checks');
for (const check of validResult.checks) {
  assert(check.pass === true && check.status === 'PASS', `Check ${check.name} passed`);
}

// Test 1.3: Verify tampered ZIP bundle
const tamperedResultJson = wasmModule.verify_bundle_zip(tamperedZipBytes, honestContextJson);
const tamperedResult = JSON.parse(tamperedResultJson);
assert(tamperedResult.overall === 'FAIL', 'Tampered bundle verify_bundle_zip returned overall FAIL');
assert(tamperedResult.overall_pass === false, 'Tampered bundle verify_bundle_zip returned overall_pass false');

// Test 1.4: Corrupt ZIP handling and exception throwing
let threwOnCorruptZip = false;
try {
  wasmModule.extract_bundle_files(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
} catch (e) {
  threwOnCorruptZip = true;
  assert(String(e).includes('Failed to read ZIP archive'), `Corrupt ZIP throws expected error: ${e}`);
}
assert(threwOnCorruptZip, 'extract_bundle_files throws on corrupt ZIP bytes');

// ----------------------------------------------------------------------------
// 2. React Flow DAG Formatting in get_accountability_graph
// ----------------------------------------------------------------------------
console.log('\n--- 2. Testing React Flow DAG Formatting in get_accountability_graph ---');

const honestPacketJson = fs.readFileSync(path.join(fixturesDir, 'honest_counterparty.json'), 'utf-8');
const honestReportJson = wasmModule.verify_evidence_packet(honestPacketJson, honestContextJson);

const graphJson = wasmModule.get_accountability_graph(honestPacketJson, honestReportJson);
const graph = JSON.parse(graphJson);

assert(graph.packet_id && graph.packet_id.length === 32, `Graph contains valid 32-char hex packet_id (${graph.packet_id})`);
assert(graph.claimed_trust_floor === 'COUNTERPARTY_SIGNED', 'Graph claimed_trust_floor is COUNTERPARTY_SIGNED');
assert(graph.derived_trust_floor === 'COUNTERPARTY_SIGNED', 'Graph derived_trust_floor is COUNTERPARTY_SIGNED');
assert(Array.isArray(graph.nodes) && graph.nodes.length >= 7, `Graph contains ${graph.nodes.length} nodes`);
assert(Array.isArray(graph.edges) && graph.edges.length >= 6, `Graph contains ${graph.edges.length} edges`);

// Check React Flow edge compatibility
const nodeIds = new Set(graph.nodes.map(n => n.id));
const adj = new Map();
for (const edge of graph.edges) {
  assert(edge.source === edge.from, `Edge source (${edge.source}) matches from (${edge.from})`);
  assert(edge.target === edge.to, `Edge target (${edge.target}) matches to (${edge.to})`);
  assert(nodeIds.has(edge.source), `Edge source exists in nodes: ${edge.source}`);
  assert(nodeIds.has(edge.target), `Edge target exists in nodes: ${edge.target}`);
  if (!adj.has(edge.source)) adj.set(edge.source, []);
  adj.get(edge.source).push(edge.target);
}

// Check Root Principal Reachability (BFS)
const visited = new Set(['principal']);
const queue = ['principal'];
while (queue.length > 0) {
  const curr = queue.shift();
  for (const next of (adj.get(curr) || [])) {
    if (!visited.has(next)) {
      visited.add(next);
      queue.push(next);
    }
  }
}

for (const id of nodeIds) {
  assert(visited.has(id), `Node '${id}' is reachable from root principal in React Flow DAG`);
}

// Test error throwing on invalid packet JSON
let threwOnBadPacket = false;
try {
  wasmModule.get_accountability_graph('invalid json', null);
} catch (e) {
  threwOnBadPacket = true;
  assert(String(e).includes('Invalid EvidencePacket JSON'), `Invalid JSON throws: ${e}`);
}
assert(threwOnBadPacket, 'get_accountability_graph throws on invalid JSON');

// ----------------------------------------------------------------------------
// 3. Capability Lattice Algebra (check_scope_permits & meet_capability_scopes)
// ----------------------------------------------------------------------------
console.log('\n--- 3. Testing Capability Lattice Algebra ---');

const adminScope = JSON.stringify({
  allowed: ['read', 'write', 'execute', 'delegate', 'admin', 'delete'],
  denied: []
});

const orchestratorScope = JSON.stringify({
  allowed: ['read', 'write', 'execute', 'delegate'],
  denied: ['admin']
});

const auditReaderScope = JSON.stringify({
  allowed: ['read'],
  denied: ['write', 'admin', 'delete']
});

const submitterScope = JSON.stringify({
  allowed: ['write'],
  denied: ['admin', 'delete']
});

// Check check_scope_permits
assert(wasmModule.check_scope_permits(adminScope, '"write"') === true, 'ADMIN permits write');
assert(wasmModule.check_scope_permits(adminScope, '"admin"') === true, 'ADMIN permits admin');
assert(wasmModule.check_scope_permits(orchestratorScope, '"execute"') === true, 'ORCHESTRATOR permits execute');
assert(wasmModule.check_scope_permits(orchestratorScope, '"admin"') === false, 'ORCHESTRATOR denies admin');
assert(wasmModule.check_scope_permits(auditReaderScope, '"read"') === true, 'AUDIT_READER permits read');
assert(wasmModule.check_scope_permits(auditReaderScope, '"write"') === false, 'AUDIT_READER denies write');
assert(wasmModule.check_scope_permits(submitterScope, '"write"') === true, 'SUBMITTER permits write');
assert(wasmModule.check_scope_permits(submitterScope, '"read"') === false, 'SUBMITTER denies read');

// Meet: ADMIN ⊓ ORCHESTRATOR
const metAdminOrch = JSON.parse(wasmModule.meet_capability_scopes(adminScope, orchestratorScope));
assert(metAdminOrch.is_bottom === false, 'ADMIN ⊓ ORCHESTRATOR is_bottom is false');
assert(metAdminOrch.allowed.length === 4, 'ADMIN ⊓ ORCHESTRATOR retains 4 allowed actions');

// Meet: ORCHESTRATOR ⊓ AUDIT_READER
const metOrchAudit = JSON.parse(wasmModule.meet_capability_scopes(orchestratorScope, auditReaderScope));
assert(metOrchAudit.is_bottom === false, 'ORCHESTRATOR ⊓ AUDIT_READER is_bottom is false');
assert(metOrchAudit.allowed.length === 1, 'ORCHESTRATOR ⊓ AUDIT_READER retains 1 allowed action (read)');

// Meet: AUDIT_READER ⊓ SUBMITTER (Disjoint -> ⊥)
const metAuditSub = JSON.parse(wasmModule.meet_capability_scopes(auditReaderScope, submitterScope));
assert(metAuditSub.is_bottom === true, 'AUDIT_READER ⊓ SUBMITTER correctly flags is_bottom: true (⊥)');
assert(metAuditSub.allowed.length === 0, 'Empty intersection ⊥ has allowed: []');

// Error throwing on invalid scope JSON
let threwOnBadScope = false;
try {
  wasmModule.check_scope_permits('{bad json', '"read"');
} catch (e) {
  threwOnBadScope = true;
  assert(String(e).includes('Invalid scope JSON'), `Malformed scope throws: ${e}`);
}
assert(threwOnBadScope, 'check_scope_permits throws on malformed JSON');

let threwOnBadMeet = false;
try {
  wasmModule.meet_capability_scopes('not a scope', orchestratorScope);
} catch (e) {
  threwOnBadMeet = true;
  assert(String(e).includes('Invalid parent scope JSON'), `Malformed meet throws: ${e}`);
}
assert(threwOnBadMeet, 'meet_capability_scopes throws on malformed JSON');

// ----------------------------------------------------------------------------
// 4. Cryptographic Hashing, Keypair Generation & Canonical Encoding
// ----------------------------------------------------------------------------
console.log('\n--- 4. Testing Cryptographic Utilities ---');

const kpJson = wasmModule.generate_keypair();
const kp = JSON.parse(kpJson);
assert(kp.aip_id && kp.aip_id.startsWith('aip1'), `Keypair generated valid AIP-ID: ${kp.aip_id}`);
assert(kp.public_key_hex && kp.public_key_hex.length === 64, 'Public key hex is 64 chars (32 bytes)');
assert(kp.private_key_hex && kp.private_key_hex.length === 64, 'Private key hex is 64 chars (32 bytes)');

const computedHash = wasmModule.recompute_packet_hash(honestPacketJson);
const parsedHonest = JSON.parse(honestPacketJson);
const expectedPacketHash = Buffer.from(parsedHonest.packet_hash).toString('hex');
assert(computedHash === expectedPacketHash, `recompute_packet_hash matches packet_hash: ${computedHash}`);

const canonicalHex = wasmModule.get_canonical_bytes_hex(honestPacketJson);
assert(canonicalHex.length > 200, `get_canonical_bytes_hex returns non-empty hex bytes: ${canonicalHex.length} hex chars`);

// ----------------------------------------------------------------------------
// 5. Fixture Catalog Provider (get_sample_packet) - EMPIRICAL VULNERABILITY TEST
// ----------------------------------------------------------------------------
console.log('\n--- 5. Testing get_sample_packet in WASM runtime ---');

let caughtTimePanic = false;
let panicErrorMessage = '';
try {
  const p1 = wasmModule.get_sample_packet('honest_counterparty');
  assert(typeof p1 === 'string' && p1.includes('packet_id'), 'get_sample_packet honest_counterparty returned valid packet');

  const p2 = wasmModule.get_sample_packet('authority_bound');
  assert(typeof p2 === 'string' && p2.includes('packet_id'), 'get_sample_packet authority_bound returned valid packet');

  const p3 = wasmModule.get_sample_packet('agent_signed');
  assert(typeof p3 === 'string' && p3.includes('packet_id'), 'get_sample_packet agent_signed returned valid packet');

  const p4 = wasmModule.get_sample_packet('revoked_token');
  assert(typeof p4 === 'string' && p4.includes('packet_id'), 'get_sample_packet revoked_token returned valid packet');

  const p5 = wasmModule.get_sample_packet('index');
  assert(typeof p5 === 'string' && p5.includes('fixtures'), 'get_sample_packet index returned valid fixture catalog');
} catch (e) {
  caughtTimePanic = true;
  panicErrorMessage = String(e);
}

assert(!caughtTimePanic, `get_sample_packet must succeed without WASM runtime panic (error: ${panicErrorMessage})`);

let caughtUnknownError = false;
try {
  wasmModule.get_sample_packet('invalid_sample_name_xyz');
} catch (e) {
  caughtUnknownError = true;
  assert(String(e).includes('Unknown sample type'), `Unknown sample type rejected cleanly: ${e}`);
}
assert(caughtUnknownError, 'Unknown sample type throws an error');

console.log(`\n=======================================================`);
console.log(`EMPIRICAL CHALLENGE SUITE COMPLETED:`);
console.log(`- Core Mission Targets (Bundle ZIP, Extract 7 files, React Flow DAG, Lattice Meet): PASSED (${passedTests}/${totalTests})`);
console.log(`- get_sample_packet WASM runtime safety: PASSED`);
console.log(`=======================================================`);

