import { WASI, File, OpenFile, ConsoleStdout, PreopenDirectory } from "@bjorn3/browser_wasi_shim";
import { normalizeObserver, summarizeAuthority } from "../bridge/projection.mjs";
import { pins } from "./digests.mjs";

const encoder=new TextEncoder(),decoder=new TextDecoder();
const provenance="Archived P0-057 lab capture";
const researchCommit="d8ea36255d311b10b9b5b6e844336058622d45c6";
async function verifiedAsset(name,load){
  if(!Object.hasOwn(pins,name))throw Error("Unknown replay asset.");
  const data=new Uint8Array(await load(name));
  const hash=new Uint8Array(await crypto.subtle.digest("SHA-256",data));
  const hex=Array.from(hash,v=>v.toString(16).padStart(2,"0")).join("");
  if(hex!==pins[name])throw Error("Replay asset integrity check failed.");
  return data;
}
async function moduleRun({binary,args,env=[],files,stdin="",load}){
  const bytes=await verifiedAsset(binary+".wasm",load);
  const stdout=[],stderr=[];
  const fds=[new OpenFile(new File(encoder.encode(stdin))),ConsoleStdout.lineBuffered(line=>stdout.push(line)),
    ConsoleStdout.lineBuffered(line=>stderr.push(line)),new PreopenDirectory(".",Object.entries(files).map(([name,data])=>[name,new File(encoder.encode(data),{readonly:true})]))];
  const wasi=new WASI([binary,...args],env,fds,{debug:false});
  const {instance}=await WebAssembly.instantiate(bytes,{wasi_snapshot_preview1:wasi.wasiImport});
  const code=wasi.start(instance);
  let report=null;const output=stdout.join("\n");
  if(output.trim())report=JSON.parse(output);
  return {code,report};
}
const labCases=["t09","t15","same-run","same-run-interruption"];
export async function runResearchReplay(sample,check="original",load){
  if(!labCases.includes(sample))throw Error("Unknown research sample.");
  const observer=sample==="t09"||sample==="t15";
  if(!(observer?["original","tampered","wrong-key"]:["original","missing-receipt","wrong-key"]).includes(check))throw Error("Unsupported verification check for this sample.");
  const txt=async(name)=>decoder.decode(await verifiedAsset("fixtures/"+name,load));
  const details={sample,challenge:check,provenance,sourceCommit:researchCommit,verifiedAt:new Date().toISOString(),customerTelemetry:false};
  if(observer){
    const [raw,health,anchorText]=await Promise.all([txt(sample+"-batches.jsonl"),txt(sample+"-health.jsonl"),txt((check==="wrong-key"?(sample==="t09"?"t15":"t09"):sample)+"-trust.json")]);
    const anchor=JSON.parse(anchorText);
    const batches=check==="tampered"?raw.replace(/("claimed_from_ms":)1\b/,(_,prefix)=>prefix+"2"):raw;
    if(check==="tampered" && (batches===raw||batches.length!==raw.length))throw Error("Unable to apply the one-byte integrity check.");
    const {code,report}=await moduleRun({binary:"aip-observe-verify",args:["--observer-id",anchor.observerId,"--key-version",String(anchor.keyVersion),"--pubkey",anchor.publicKey,"--batches","batches.jsonl","--health","health.jsonl","--json"],files:{"batches.jsonl":batches,"health.jsonl":health},load});
    if(!report||![0,1].includes(code)||report.observer_id!==anchor.observerId||report.public_key!==anchor.publicKey)throw Error("The upstream observer verifier did not complete.");
    return {...details,...normalizeObserver({code,report,batches,provenance})};
  }
  const [gz,trustText]=await Promise.all([verifiedAsset("fixtures/"+sample+"-bundle.json.gz",load),txt(sample+"-trust.json")]);
  const stream=new Blob([gz]).stream().pipeThrough(new DecompressionStream("gzip"));
  let input=await new Response(stream).text(),trust=trustText;
  if(check==="missing-receipt"){const data=JSON.parse(input);data.signed_receipt=null;input=JSON.stringify(data);}
  if(check==="wrong-key"){const data=JSON.parse(trust);data.gateway_public_key_hex="00".repeat(32);trust=JSON.stringify(data);}
  const {code,report}=await moduleRun({binary:"aip-execution-assurance",args:["evaluate"],env:["AIP_RUN_TRUST_FILE=trust.json"],files:{"trust.json":trust},stdin:input,load});
  if(code===0 && report) return {...details,...summarizeAuthority(report)};
  if(code===1 && check!=="original")return {...details,source:"aip-execution-assurance",accepted:false,state:"Rejected",verdict:null,reason:"The upstream evaluator rejected the evidence."};
  throw Error("The upstream AIP evaluator did not complete.");
}
