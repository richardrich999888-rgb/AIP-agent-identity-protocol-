import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../../../');
const wasmDir = path.join(repoRoot, 'aip-console/public/wasm');
const fixturesDir = path.join(repoRoot, 'aip-console/public/fixtures');

console.log('=== Reviewer 2 Adversarial Stress Testing ===');
console.log('Loading WASM from:', wasmDir);

const wasmModule = await import(`file://${path.join(wasmDir, 'aip_wasm.js')}`);
const wasmBytes = fs.readFileSync(path.join(wasmDir, 'aip_wasm_bg.wasm'));
await wasmModule.default({ module_or_path: wasmBytes });

let totalChecks = 0;
let passedChecks = 0;

function check(cond, msg) {
  totalChecks++;
  if (!cond) {
    console.error(`❌ FAILED: ${msg}`);
    throw new Error(msg);
  }
  passedChecks++;
  console.log(`✓ ${msg}`);
}

// 1. Stress test get_sample_packet with all sample aliases & case insensitivity
const testKeys = [
  'honest_counterparty',
  'HONEST_COUNTERPARTY',
  'honest_counterparty.json',
  'valid_loan',
  'valid_countersigned',
  'valid',
  '',
  '   ',
  'authority_bound',
  'AUTHORITY_BOUND.JSON',
  'agent_signed',
  'AGENT_SIGNED',
  'tampered_summary',
  'TAMPERED_SUMMARY.JSON',
  'tampered_decision',
  'tampered',
  'tampered_hash',
  'tampered_hash_recomputed',
  'tampered_signature',
  'scope_escalation',
  'attenuation_violation',
  'revoked_token',
  'REVOKED_TOKEN.JSON',
  'revoked_delegation',
  'revoked',
  'sample_context',
  'valid_context',
  'context',
  'honest_counterparty.context',
  'honest_counterparty.context.json',
  'authority_bound.context',
  'authority_bound.context.json',
  'agent_signed.context',
  'revoked_token.context',
  'revoked_token.context.json',
  'index',
  'index.json',
];

for (const key of testKeys) {
  try {
    const res = wasmModule.get_sample_packet(key);
    check(typeof res === 'string' && res.length > 0, `get_sample_packet("${key}") returned non-empty string`);
    const parsed = JSON.parse(res);
    check(typeof parsed === 'object' && parsed !== null, `get_sample_packet("${key}") returned valid JSON object`);
  } catch (e) {
    check(false, `get_sample_packet("${key}") threw unexpected error: ${e}`);
  }
}

// 2. Stress test invalid inputs to get_sample_packet
const hostileKeys = [
  'unknown_fixture',
  '../../etc/passwd',
  '<script>alert(1)</script>',
  'null',
  'undefined',
  '🔥🚀',
  'x'.repeat(1000),
  '\x00\x01\x02',
];

for (const hKey of hostileKeys) {
  try {
    wasmModule.get_sample_packet(hKey);
    check(false, `Hostile key "${hKey}" should have thrown an error`);
  } catch (e) {
    check(String(e).includes('Unknown sample type'), `Hostile key "${hKey}" threw expected unknown sample error: ${e}`);
  }
}

// 3. In-depth verification of revoked_token
console.log('\n--- In-Depth Testing of revoked_token Verification ---');
const revokedPacketStr = wasmModule.get_sample_packet('revoked_token');
const revokedContextStr = wasmModule.get_sample_packet('revoked_token.context');

const revokedPacket = JSON.parse(revokedPacketStr);
const revokedContext = JSON.parse(revokedContextStr);

check(revokedPacket.claimed_trust_floor === 'COUNTERPARTY_SIGNED', 'revoked_token claimed_trust_floor is COUNTERPARTY_SIGNED');
check(Array.isArray(revokedContext.revoked_jtis) && revokedContext.revoked_jtis.length === 1, 'revoked context has exactly 1 revoked JTI');

const verificationReportStr = wasmModule.verify_evidence_packet(revokedPacketStr, revokedContextStr);
const rep = JSON.parse(verificationReportStr);

check(rep.overall_valid === false, 'revoked_token overall_valid is false');
check(rep.valid === false, 'revoked_token valid is false');
check(rep.tamper_evidence === false, 'revoked_token tamper_evidence is false (revocation is administrative, not tamper)');
check(rep.tampered === false, 'revoked_token tampered is false');
check(rep.derived_trust_floor === 'AGENT_SIGNED', `revoked_token derived_trust_floor is strictly AGENT_SIGNED (got: ${rep.derived_trust_floor})`);
check(rep.trust_floor === 'AGENT_SIGNED', `revoked_token trust_floor is strictly AGENT_SIGNED (got: ${rep.trust_floor})`);

const revocationCheck = rep.checks.find(c => c.rule === 'REVOCATION');
check(revocationCheck && revocationCheck.pass === false, 'REVOCATION check must be present and FAIL');
check(revocationCheck.detail.toLowerCase().includes('revok'), `REVOCATION check detail explains revocation (${revocationCheck.detail})`);

const trustFloorCheck = rep.checks.find(c => c.rule === 'TRUST_FLOOR');
check(trustFloorCheck && trustFloorCheck.pass === false, 'TRUST_FLOOR check must be present and FAIL (claimed COUNTERPARTY_SIGNED > derived AGENT_SIGNED)');

// Structure, Binding, Hash, Agent Sig must all pass (which is why derived floor is AGENT_SIGNED)
const structureCheck = rep.checks.find(c => c.rule === 'STRUCTURE');
const bindingCheck = rep.checks.find(c => c.rule === 'AGENT_ID_BINDING');
const hashCheck = rep.checks.find(c => c.rule === 'CANONICAL_HASH');
const agentSigCheck = rep.checks.find(c => c.rule === 'AGENT_SIGNATURE');

check(structureCheck && structureCheck.pass === true, 'STRUCTURE check passes');
check(bindingCheck && bindingCheck.pass === true, 'AGENT_ID_BINDING check passes');
check(hashCheck && hashCheck.pass === true, 'CANONICAL_HASH check passes');
check(agentSigCheck && agentSigCheck.pass === true, 'AGENT_SIGNATURE check passes');

// 4. Verify index.json fixture metadata
console.log('\n--- Verifying index.json metadata consistency ---');
const indexStr = wasmModule.get_sample_packet('index');
const catalog = JSON.parse(indexStr);
const revokedCatalogEntry = catalog.fixtures.find(f => f.id === 'revoked_token');
check(revokedCatalogEntry !== undefined, 'index.json contains revoked_token fixture entry');
check(revokedCatalogEntry.expected_derived_floor === 'AGENT_SIGNED', `index.json expected_derived_floor is AGENT_SIGNED (got: ${revokedCatalogEntry.expected_derived_floor})`);
check(revokedCatalogEntry.expected_valid === false, 'index.json expected_valid is false');
check(revokedCatalogEntry.expected_tampered === false, 'index.json expected_tampered is false');
check(revokedCatalogEntry.expected_failed_rules.includes('REVOCATION'), 'index.json expected_failed_rules includes REVOCATION');
check(revokedCatalogEntry.expected_failed_rules.includes('TRUST_FLOOR'), 'index.json expected_failed_rules includes TRUST_FLOOR');

console.log(`\n=============================================`);
console.log(`ALL ADVERSARIAL CHECKS PASSED: ${passedChecks}/${totalChecks}`);
console.log(`=============================================`);
