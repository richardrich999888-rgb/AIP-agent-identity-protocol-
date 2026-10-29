import assert from "node:assert/strict";
import {VanianClient, VanianError} from "../../sdk/typescript/dist/index.js";

const base = process.env.VANIAN_RUN_BASE_URL!;
const id = process.env.VANIAN_RUN_ARTIFACT_ID!;
const expected = JSON.parse(process.env.VANIAN_RUN_EXPECTED!);
const a = new VanianClient(base, () => process.env.VANIAN_RUN_READER!, {allowLoopbackHttp: true, retries: 0});
const b = new VanianClient(base, () => process.env.VANIAN_RUN_OTHER_READER!, {allowLoopbackHttp: true, retries: 0});
assert.deepEqual(await a.getRunMetadata(id), expected);
assert.deepEqual(await a.evaluateRun(id), expected.evaluation);
const signedVerdict = JSON.parse(process.env.VANIAN_RUN_SIGNED_VERDICT ?? "null");
if (signedVerdict !== null) assert.deepEqual(await a.getRunVerdict(id), signedVerdict);
assert.ok((await a.getAgentRuns(expected.agent_id, 100)).items.some(row => row.run_artifact_id === id));
await assert.rejects(b.getRunMetadata(id), (error: unknown) => error instanceof VanianError && error.status === 404);
await assert.rejects(b.evaluateRun(id), (error: unknown) => error instanceof VanianError && error.status === 404);
console.log("TypeScript same-run retrieval and cross-tenant refusal: PASS");
