import test from "node:test";
import assert from "node:assert/strict";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { verifyObserver, evaluateAuthority } from "../bridge/observer.mjs";

const base = new URL("../public/upstream-replay/", import.meta.url);
const expected=JSON.parse(await readFile(new URL("./golden/native-transcript.json", import.meta.url)));
let receive, outcome;
globalThis.self={location:{href:new URL("worker.mjs",base).href},addEventListener(_,fn){receive=fn;},postMessage(value){outcome=value;}};
globalThis.fetch=async url=>new Response(await readFile(fileURLToPath(url)));
await import(new URL("worker.mjs",base));
const call=async(sample,check)=>{outcome=null;await receive({data:{sample,check}});return outcome;};
for (const [name,{exitCode,report}] of Object.entries(expected.observerCases)){
  test("shipped observer WASM matches native: "+name,async()=>{
    const [sample,check]=name.split("/");
    const {ok,result}=await call(sample,check);assert.equal(ok,true);
    assert.equal(result.accepted,exitCode===0);assert.equal(result.customerTelemetry,false);
    assert.deepEqual(result.findings.map(f=>f.kind),report.findings.map(f=>f.kind));
    if(exitCode===0){
      assert.equal(result.scope.finalHead,report.batches.final_head);assert.deepEqual(result.scope.health,report.health.states);
      assert.equal(result.scope.withCoverage,0);assert.equal(result.scope.clockUnstated,1);
      assert.equal(result.events.length,report.batches.kernel_events);assert.ok(result.events.every(e=>e.agent===null && e.humanOwner===null));
      if(sample==="t09")assert.deepEqual(result.events.map(e=>e.kind),["Fork","Exec","Exit"]);
      else assert.ok(result.scope.droppedEvents>0);
    }else{assert.deepEqual(result.events,[]);assert.equal(result.scope,null);}
  });
}
for(const [name,expectedCase] of Object.entries(expected.authorityCases)){
  test("shipped AIP WASM matches native: "+name,async()=>{
    const [sample,check]=name.split("/");const {ok,result}=await call(sample,check);assert.equal(ok,true);
    assert.equal(result.customerTelemetry,false);assert.equal(result.verdict,expectedCase.result);
    if(expectedCase.exitCode===0){
      assert.equal(result.reason,expectedCase.reason);
      assert.equal(result.signedReconciliationVerified,expectedCase.signedReconciliationVerified);
      assert.equal(result.gatewayReceiptVerified,expectedCase.gatewayReceiptVerified);
      assert.equal(result.authorizationVerified,expectedCase.authorizationVerified);
      assert.equal(result.archiveIntegrityVerified,expectedCase.archiveVerified);
    }else{assert.equal(result.accepted,false);assert.equal(result.state,"Rejected");}
  });
}
test("invalid research selection is refused",async()=>{
  assert.equal((await call("unknown","original")).ok,false);
  assert.equal((await call("t09","missing-receipt")).ok,false);
});
test("the shipped worker rejects altered bundled asset bytes before execution",async()=>{
  const fetchOriginal=globalThis.fetch;
  try{
    globalThis.fetch=async url=>{
      const bytes=await readFile(fileURLToPath(url));
      if(String(url).endsWith("t09-batches.jsonl"))bytes[2]^=1;
      return new Response(bytes);
    };
    const result=await call("t09","original");assert.equal(result.ok,false);assert.match(result.message,/integrity/);
  }finally{globalThis.fetch=fetchOriginal;}
});
test("native observer bridge snapshots and verifies signed evidence",{skip:!process.env.OBSERVER_VERIFIER},async()=>{
  const fixtures=new URL("./fixtures/",base);
  const batch=fileURLToPath(new URL("t09-batches.jsonl",fixtures)), health=fileURLToPath(new URL("t09-health.jsonl",fixtures));
  const trust=JSON.parse(await readFile(new URL("t09-trust.json",fixtures)));
  const input={binary:process.env.OBSERVER_VERIFIER,...trust,batches:batch,health,provenance:"archived lab"};
  const good=await verifyObserver(input);assert.equal(good.verification,"Verified");assert.equal(good.events.length,3);
  const bad=await verifyObserver({...input,publicKey:"00".repeat(32)});assert.equal(bad.verification,"Rejected");assert.deepEqual(bad.events,[]);
});
test("native AIP bridge preserves incomplete actions",{skip:!process.env.AIP_EVALUATOR},async()=>{
  const dir=await mkdtemp(join(tmpdir(),"vanian-replay-test-"));
  try{
    const bundle=join(dir,"bundle.json");
    await writeFile(bundle,gunzipSync(await readFile(new URL("./fixtures/same-run-bundle.json.gz",base))));
    const result=await evaluateAuthority({binary:process.env.AIP_EVALUATOR,bundle,trust:fileURLToPath(new URL("./fixtures/same-run-trust.json",base)),provenance:"archived lab"});
    assert.equal(result.accepted,true);assert.equal(result.verdict,"CannotProve");assert.equal(result.gatewayReceiptVerified,true);assert.equal(result.reason,"ActionEvidenceUnavailable");
  }finally{await rm(dir,{recursive:true,force:true});}
});
