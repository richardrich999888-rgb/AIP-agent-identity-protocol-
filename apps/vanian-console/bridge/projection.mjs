// Project the existing verifier's output. Identity and coverage have their own evidence.
export function normalizeObserver({code,report,batches,provenance}) {
  const findings=report.findings;
  if(!Array.isArray(findings)||!Number.isInteger(code))throw Error("Invalid native verifier response.");
  const accepted=code===0 && findings.length===0 && report.batches?.records>0 && report.health?.records>0;
  const common={schema:"vanian.native-observer.v1",provenance,verifier:"aip-observe-verify",accepted,verification:accepted?"Verified":"Rejected",
    observerId:report.observer_id,keyVersion:report.key_version,publicKey:report.public_key,findings};
  if(!accepted)return {...common,events:[],scope:null,observations:null};
  const records=batches.split(/\r?\n/).filter(line=>line.trim()).map(line=>JSON.parse(line,(key,value,context)=>{
    if(key==="kernel_timestamp_ns" && typeof value==="number"){
      if(context?.source)return context.source;
      if(!Number.isSafeInteger(value))return null;
      return String(value);
    }return value;
  }));
  if(!records.length || records.length!==report.batches.records)throw Error("Verified batch count mismatch.");
  const events=records.flatMap(record=>{
    const batch=record.batch, runId=(batch.probe_run_id||[]).map(n=>n.toString(16).padStart(2,"0")).join("");
    return batch.kernel_events.map((event,index)=>{
      const [kind,details]=Object.entries(event.kind)[0]||["Unparsed",{}];
      return {
        id:[record.observer_id,record.key_version,record.sequence,index].join("/"), source:"kernel",
        mechanism:event.mechanism,kind,probeId:event.probe_id,probeRunId:runId,batchSequence:record.sequence,
        sequence:event.probe_seq,monotonicNs:event.kernel_timestamp_ns,collectorAttestedAt:new Date(record.attested_at_ms).toISOString(),
        clockAnchorPresent:batch.clock_anchor!=null,agent:null,humanOwner:null,logicalAgentAttribution:"Unresolved",
        reportedProcessAttribution:typeof event.attribution==="string"?event.attribution:Object.keys(event.attribution||{})[0]||"Unknown",
        processBound:event.bound!=null,processId:details.pid??null,parentPid:details.parent_pid??null,childPid:details.child_pid??null,
        exitCode:kind==="Exit"?details.exit_code:null
      };
    });
  });
  if(events.length!==report.batches.kernel_events)throw Error("Verified event count mismatch.");
  const processSamples=records.flatMap(record=>record.batch.observations.map((sample,index)=>{
    const effect=typeof sample.effect==="string"?sample.effect:Object.keys(sample.effect||{})[0]||"Unparsed";
    return {id:[record.observer_id,record.key_version,record.sequence,"sample",index].join("/"),kind:effect,source:"Sampled process",
      mechanism:sample.mechanism,probeId:sample.probe_id,collectorAttestedAt:new Date(record.attested_at_ms).toISOString(),
      processId:sample.observed?.process?.pid??null,reportedProcessAttribution:typeof sample.attribution==="string"?sample.attribution:Object.keys(sample.attribution||{})[0]||"Unknown",
      processBound:sample.mechanism==="PidFdAnchored",logicalAgentAttribution:"Unresolved",agent:null,humanOwner:null};
  }));
  if(processSamples.length!==report.batches.observations)throw Error("Verified sample count mismatch.");
  return {...common,scope:{
    finalHead:report.batches.final_head,start:report.batches.start,records:report.batches.records,
    activeMechanisms:[...new Set(records.flatMap(record=>record.batch.active_mechanisms))],
    health:report.health.states,withCoverage:report.health.with_coverage,withoutCoverage:report.health.without_coverage,
    clockUnstated:report.health.clock_not_stated,clockSynchronized:report.health.clock_synchronised,
    clockUnsynchronized:report.health.clock_unsynchronised,droppedEvents:records.reduce((total,record)=>total+Number(record.batch.dropped_events??0),0),
    collectorAttestedAt:records.map(r=>new Date(r.attested_at_ms).toISOString()).sort().at(-1)
  },observations:report.batches.observations,events,processSamples};
}
export function summarizeAuthority(report) {
  const r=report.reconciliation;
  if(typeof r?.result!=="string" || typeof report.signed_reconciliation_verified!=="boolean")throw Error("Invalid AIP reconciliation report.");
  return {schema:"vanian.aip-evaluation.v1",source:"aip-execution-assurance",accepted:report.signed_reconciliation_verified,
    signedReconciliationVerified:report.signed_reconciliation_verified,archiveIntegrityVerified:report.archive_integrity_verified===true,authorizationVerified:report.authorization_verified===true,
    checkpointVerified:report.checkpoint_verified===true,receiptWithinAuthorization:report.receipt_within_authorization??null,gatewayDisposition:report.gateway_disposition??null,
    agentId:report.agent_id??null,runId:report.run_id??null,state:report.signed_reconciliation_verified?"Signature verified":"Signature unverified",verdict:r.result,reason:r.reason??null,
    identity:r.identity??null,temporal:r.temporal??null,strength:r.strength??null,lineage:r.lineage??null,
    gatewayReceiptVerified:report.gateway_receipt_verified===true,assessmentTime:new Date(r.verification_time_ms).toISOString()};
}
