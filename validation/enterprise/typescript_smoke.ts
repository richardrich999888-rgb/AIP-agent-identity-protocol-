import assert from "node:assert/strict";
import {VanianClient, VanianError} from "../../sdk/typescript/dist/index.js";

const base = process.env.VANIAN_TEST_BASE_URL!;
const a = new VanianClient(base, () => process.env.VANIAN_TEST_READER_A!, {allowLoopbackHttp: true, retries: 0});
const b = new VanianClient(base, () => process.env.VANIAN_TEST_READER_B!, {allowLoopbackHttp: true, retries: 0});
assert.equal((await a.access()).role, "reader");
assert.equal((await a.getEvidenceMetadata(process.env.VANIAN_TEST_EVIDENCE_ID!)).independent_execution_verified, false);
assert.equal((await a.verifyEvidence(process.env.VANIAN_TEST_EVIDENCE_ID!)).verification_scope, "integrity_only");
assert.ok(await a.getVerdict(process.env.VANIAN_TEST_VERDICT_ID!));
assert.equal((await a.verifyObservation(process.env.VANIAN_TEST_OBSERVATION_ID!)).verified, true);
await assert.rejects(b.getObservationMetadata(process.env.VANIAN_TEST_OBSERVATION_ID!), (e: unknown) => e instanceof VanianError && e.status === 404);
await assert.rejects(b.getVerdict(process.env.VANIAN_TEST_VERDICT_ID!), (e: unknown) => e instanceof VanianError && e.status === 404);
console.log("TypeScript real API retrieval and cross-tenant refusal: PASS");
