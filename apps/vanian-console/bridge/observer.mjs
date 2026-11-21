import { execFile, spawn } from "node:child_process";
import { constants } from "node:fs";
import { mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { createHash } from "node:crypto";
import { promisify } from "node:util";
import { normalizeObserver, summarizeAuthority } from "./projection.mjs";

const execute = promisify(execFile);
const MAX_ARCHIVE = 16 * 1024 * 1024;
const MAX_OUTPUT = 8 * 1024 * 1024;
const digest = data => createHash("sha256").update(data).digest("hex");

async function snapshotFile(path, maxBytes) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size > maxBytes) throw Error("Input must be a bounded regular file.");
    const data = Buffer.alloc(info.size + 1);
    let offset = 0;
    while (offset < data.length) {
      const {bytesRead} = await handle.read(data, offset, data.length - offset, offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    if (offset !== info.size) throw Error("Archive changed while being read.");
    return data.subarray(0, offset);
  } finally { await handle.close(); }
}

async function run(binary, args, options={}) {
  if (!isAbsolute(binary)) throw Error("Configure the verifier with an absolute executable path.");
  try {
    const {stdout} = await execute(binary, args, {
      env: { PATH: "/usr/bin:/bin", ...options.env },
      timeout: 30_000, maxBuffer: MAX_OUTPUT, encoding: "utf8"
    });
    return {code:0, report:JSON.parse(stdout)};
  } catch(error) {
    if (error.code === 1 && error.stdout) return {code:1,report:JSON.parse(error.stdout)};
    throw Error("The configured native verifier did not produce a complete report.");
  }
}

export async function verifyObserver({ binary, observerId, keyVersion, publicKey, batches, health, provenance }) {
  if (!observerId || !Number.isSafeInteger(keyVersion) || keyVersion < 1 || !/^[a-fA-F0-9]{64}$/.test(publicKey)) throw Error("Supply a trusted observer, key version and Ed25519 public key outside the archive.");
  const [batchBytes, healthBytes] = await Promise.all([snapshotFile(batches, MAX_ARCHIVE), snapshotFile(health,MAX_ARCHIVE)]);
  const directory=await mkdtemp(join(tmpdir(),"vanian-observer-"));
  try {
    const batchFile=join(directory,"batches.jsonl"),healthFile=join(directory,"health.jsonl");
    await Promise.all([writeFile(batchFile,batchBytes,{flag:"wx",mode:0o600}),writeFile(healthFile,healthBytes,{flag:"wx",mode:0o600})]);
    const {code,report}=await run(binary,["--observer-id",observerId,"--key-version",String(keyVersion),"--pubkey",publicKey,"--batches",batchFile,"--health",healthFile,"--json"]);
    if (report.observer_id!==observerId || report.key_version!==keyVersion || report.public_key!==publicKey.toLowerCase()) throw Error("Verifier returned a different trust context.");
    return {
      ...normalizeObserver({code,report,batches:batchBytes.toString("utf8"),provenance}),
      inputSha256:{batches:digest(batchBytes),health:digest(healthBytes)},verifiedAt:new Date().toISOString()
    };
  } finally { await rm(directory,{recursive:true,force:true}); }
}


export async function evaluateAuthority({binary,bundle,trust,provenance,validateTrust}) {
  if (!isAbsolute(binary)) throw Error("Configure the comparator with an absolute executable path.");
  const [raw,anchor] = await Promise.all([snapshotFile(bundle,MAX_ARCHIVE),snapshotFile(trust,MAX_ARCHIVE)]);
  const authorityContext=JSON.parse(anchor.toString("utf8"));
  if(validateTrust)validateTrust(authorityContext);
  const directory=await mkdtemp(join(tmpdir(),"vanian-aip-"));
  try {
    const trustFile=join(directory,"trust.json");
    await writeFile(trustFile,anchor,{flag:"wx",mode:0o600});
    const result=await new Promise((resolve,reject)=>{
      const child=spawn(binary,["evaluate"],{env:{PATH:"/usr/bin:/bin",AIP_RUN_TRUST_FILE:trustFile},stdio:["pipe","pipe","pipe"],timeout:30_000});
      const output=[];let size=0;
      child.on("error",()=>reject(Error("The configured AIP comparator is unavailable.")));
      child.stdin.on("error",()=>{});
      child.stdout.on("data",chunk=>{size+=chunk.length;if(size>MAX_OUTPUT)child.kill("SIGKILL");else output.push(chunk);});
      child.stderr.resume();
      child.on("close",(code,signal)=>{
        if(signal || size>MAX_OUTPUT) return reject(Error("The AIP comparator did not produce a complete report."));
        if(code!==0)return resolve({accepted:false,source:"aip-execution-assurance",state:"Rejected",verdict:null});
        try { resolve(summarizeAuthority(JSON.parse(Buffer.concat(output).toString("utf8")))); }
        catch { reject(Error("Invalid AIP comparator report.")); }
      });
      child.stdin.end(raw);
    });
    return {...result,provenance,trustObserverKey:authorityContext.observer_public_key_hex,inputSha256:{bundle:digest(raw),trust:digest(anchor)},verifiedAt:new Date().toISOString()};
  } finally {await rm(directory,{recursive:true,force:true});}
}
