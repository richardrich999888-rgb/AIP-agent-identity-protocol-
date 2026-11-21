// Qualification fixture. Reads only its own process and uses an ephemeral in-memory lab key.
use aip_observe::{CollectorKey, CollectorRuntime, CollectorStore, ContinuityPolicy, ObservedEffect, ProcfsProbe, SourceMechanism, Started};
use std::{env,fs,path::PathBuf,time::{SystemTime,UNIX_EPOCH}};

fn main(){
    let out=PathBuf::from(env::args().nth(1).expect("test directory"));
    let store=CollectorStore::open(out.join("collector")).expect("collector store");
    let key=CollectorKey::development();
    let public=key.public_key().iter().map(|x|format!("{x:02x}")).collect::<String>();
    let mut rt=match CollectorRuntime::start_with_custodian(store,"observer.test-self",1,key.into_custodian(),ContinuityPolicy::Strict).expect("collector"){
        Started::Running(runtime,_)=>runtime,
        Started::Refused(_)=>panic!("fixture startup refused"),
    };
    rt.signer_mut().register_probe("probe-test",&[SourceMechanism::ProcfsPoll]);
    let mut probe=ProcfsProbe::new("probe-test");
    let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    let mut rows=Vec::new();
    for _ in 0..3 {
        let process=probe.measure(std::process::id()).expect("own process measurement");
        rows.push(probe.observation(process,ObservedEffect::ProcessPresent,None,now));
    }
    let batch=probe.batch([1;16],now.saturating_sub(1),now+1,rows);
    let signed=rt.attest(batch).expect("attestation");
    let health=rt.health(now+2).expect("health");
    fs::write(out.join("batches.jsonl"),serde_json::to_string(&signed).unwrap()+"\n").unwrap();
    fs::write(out.join("health.jsonl"),serde_json::to_string(&health).unwrap()+"\n").unwrap();
    fs::write(out.join("anchor.json"),serde_json::json!({"observerId":"observer.test-self","keyVersion":1,"publicKey":public}).to_string()).unwrap();
}
