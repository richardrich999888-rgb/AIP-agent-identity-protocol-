import fs from 'fs';
import path from 'path';

async function runAdversarialChallenges() {
  console.log('=== STARTING EMPIRICAL ADVERSARIAL CHALLENGES ===\n');

  const wasmPath = path.resolve('aip-console/public/wasm/aip_wasm_bg.wasm');
  const wasmJsPath = path.resolve('aip-console/public/wasm/aip_wasm.js');
  const wasmModule = await import('file:///' + wasmJsPath.replace(/\\/g, '/'));
  const bytes = fs.readFileSync(wasmPath);
  await wasmModule.default(bytes);

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  [PASS] ${message}`);
      passed++;
    } else {
      console.error(`  [FAIL] ${message}`);
      failed++;
    }
  }

  // ---------------------------------------------------------
  // 1. CORRUPTED JSON INPUTS
  // ---------------------------------------------------------
  console.log('\n--- 1. Corrupted & Edge-Case JSON Inputs ---');

  const corruptedJsonCases = [
    { name: 'Empty string', input: '' },
    { name: 'Whitespace only', input: '   \n\t  ' },
    { name: 'Plain text', input: 'This is not JSON at all' },
    { name: 'Truncated JSON', input: '{"magic": [65, 69, 80, 49], "version": 1,' },
    { name: 'Empty JSON object', input: '{}' },
    { name: 'JSON array', input: '[]' },
    { name: 'JSON null', input: 'null' },
    { name: 'JSON primitive number', input: '12345' },
    { name: 'Null byte injection', input: '{"packet_id": "\u0000\u0000\u0000"}' },
  ];

  for (const tc of corruptedJsonCases) {
    try {
      const res = wasmModule.verify_evidence_packet(tc.input, '{}');
      // If it returned without throwing, check if it returned an invalid report
      const parsed = JSON.parse(res);
      assert(!parsed.overall_valid, `${tc.name}: Returned report with overall_valid=false`);
    } catch (err) {
      assert(err instanceof Error || typeof err === 'string', `${tc.name}: Clean error thrown without crash: ${String(err).slice(0, 60)}...`);
    }
  }

  // ---------------------------------------------------------
  // 2. CORRUPTED & EDGE-CASE ZIP INPUTS
  // ---------------------------------------------------------
  console.log('\n--- 2. Corrupted & Edge-Case ZIP Inputs ---');

  const corruptedZipCases = [
    { name: '0-byte empty array', bytes: new Uint8Array(0) },
    { name: 'Garbage 4 bytes', bytes: new Uint8Array([0xde, 0xad, 0xbe, 0xef]) },
    { name: 'Random 256 bytes', bytes: new Uint8Array(256).fill(0x42) },
    { name: 'Fake zip header but truncated', bytes: new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x00, 0x00]) },
  ];

  for (const tc of corruptedZipCases) {
    // Test verify_bundle_zip
    try {
      const res = wasmModule.verify_bundle_zip(tc.bytes, '{}');
      const parsed = JSON.parse(res);
      assert(!parsed.overall_pass, `${tc.name} verify_bundle_zip: Handled cleanly, overall_pass=false`);
    } catch (err) {
      assert(true, `${tc.name} verify_bundle_zip: Threw clean error: ${String(err).slice(0, 60)}...`);
    }

    // Test extract_bundle_files
    try {
      wasmModule.extract_bundle_files(tc.bytes);
      assert(false, `${tc.name} extract_bundle_files: Expected throw on corrupt zip`);
    } catch (err) {
      assert(true, `${tc.name} extract_bundle_files: Clean error thrown on corrupt zip: ${String(err).slice(0, 60)}...`);
    }
  }

  // ---------------------------------------------------------
  // 3. SAMPLE FIXTURE & TRUST ANCHOR RE-VERIFICATION
  // ---------------------------------------------------------
  console.log('\n--- 3. Trust Anchor Re-Verification Tests ---');

  const honestSample = wasmModule.get_sample_packet('honest_counterparty');
  assert(typeof honestSample === 'string' && honestSample.length > 0, 'get_sample_packet(honest_counterparty) returns valid packet JSON');

  const bankingContext = JSON.parse(wasmModule.get_sample_packet('honest_context'));
  const validContextJson = JSON.stringify(bankingContext);

  // 3a. Verify with valid context -> should be overall valid, TrustFloor=COUNTERPARTY_SIGNED
  const validReportStr = wasmModule.verify_evidence_packet(honestSample, validContextJson);
  const validReport = JSON.parse(validReportStr);
  assert(validReport.overall_valid === true, 'Honest sample with valid banking context is overall_valid');
  assert(validReport.derived_trust_floor === 'COUNTERPARTY_SIGNED', 'Derived trust floor is COUNTERPARTY_SIGNED (Level 3)');

  // 3b. Verify with empty context -> should pass Layer 1 but fail root token / authority checks
  const emptyReportStr = wasmModule.verify_evidence_packet(honestSample, '{}');
  const emptyReport = JSON.parse(emptyReportStr);
  assert(emptyReport.overall_valid === false, 'Honest sample with empty context fails overall validity');
  const rootCheck = emptyReport.checks.find(c => c.rule === 'ROOT_TOKEN_SIGNATURE');
  assert(rootCheck && !rootCheck.pass, 'ROOT_TOKEN_SIGNATURE rule fails when root issuer key is omitted from context');

  // 3c. Verify with revoked JTI in context -> Rule 9 REVOCATION should fail!
  // Find a token JTI in the honest packet
  const packetObj = JSON.parse(honestSample);
  const rootJti = packetObj.root_authority.jti;
  const revokedContext = {
    ...bankingContext,
    revoked_jtis: [rootJti],
  };
  const revokedReportStr = wasmModule.verify_evidence_packet(honestSample, JSON.stringify(revokedContext));
  const revokedReport = JSON.parse(revokedReportStr);
  assert(revokedReport.overall_valid === false, 'Packet with revoked root token fails overall verification');
  const revCheck = revokedReport.checks.find(c => c.rule === 'REVOCATION');
  assert(revCheck && !revCheck.pass, `REVOCATION rule fails when root JTI ${rootJti} is in revoked_jtis`);

  // 3d. High throughput re-verification loop: 500 context updates
  console.log('\n--- 4. Trust Anchor High-Throughput Re-Verification Stress ---');
  const startMs = Date.now();
  const iterations = 500;
  for (let i = 0; i < iterations; i++) {
    const isRevoked = i % 2 === 0;
    const ctx = isRevoked ? revokedContext : bankingContext;
    const repStr = wasmModule.verify_evidence_packet(honestSample, JSON.stringify(ctx));
    const rep = JSON.parse(repStr);
    if (isRevoked) {
      if (rep.overall_valid !== false) throw new Error(`Iteration ${i} expected false`);
    } else {
      if (rep.overall_valid !== true) throw new Error(`Iteration ${i} expected true`);
    }
  }
  const durationMs = Date.now() - startMs;
  console.log(`  Completed ${iterations} WASM re-verifications in ${durationMs}ms (${(durationMs / iterations).toFixed(2)}ms per re-verification)`);
  assert(durationMs < 2000, `High throughput re-verification completed well under 2000ms (took ${durationMs}ms)`);

  // ---------------------------------------------------------
  // 5. SUMMARY
  // ---------------------------------------------------------
  console.log(`\n=== ADVERSARIAL CHALLENGES COMPLETED: ${passed} PASSED, ${failed} FAILED ===\n`);
  if (failed > 0) {
    process.exit(1);
  }
}

runAdversarialChallenges().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
