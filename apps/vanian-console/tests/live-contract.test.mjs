import test from "node:test";
import assert from "node:assert/strict";
import { promisify } from "node:util";
import { execFile } from "node:child_process";
import { mkdtemp,rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
const run=promisify(execFile);
test("console live.ts passes a real TLS round trip to the native reader and rejects unavailable records",{skip:!["SELF_SAMPLE_GENERATOR","OBSERVER_VERIFIER","VANIAN_LIVE_SOURCE","TSX_LOADER"].every(key=>process.env[key])},async()=>{
  const dir=await mkdtemp(join(tmpdir(),"vanian-tls-contract-"));
  try{
    await run(process.env.SELF_SAMPLE_GENERATOR,[dir]);
    await run("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=VANIAN local test only",
      "-addext","subjectAltName=IP:127.0.0.1","-addext","basicConstraints=critical,CA:true",
      "-keyout",join(dir,"key.pem"),"-out",join(dir,"cert.pem")]);
    const {stdout}=await run(process.execPath,["--import",process.env.TSX_LOADER,fileURLToPath(new URL("./support/live-proxy.mjs",import.meta.url)),dir],
      {env:{...process.env,NODE_EXTRA_CA_CERTS:join(dir,"cert.pem")},timeout:20000});
    assert.match(stdout,/HTTPS console-to-native round trip/);
  }finally{await rm(dir,{recursive:true,force:true});}
});
