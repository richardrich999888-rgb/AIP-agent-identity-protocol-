export function startReplay(sample,check="original",signal){
  return new Promise((resolve,reject)=>{
    if(signal?.aborted){reject(new DOMException("Verification cancelled.","AbortError"));return;}
    const worker=new Worker(new URL("./worker.mjs",import.meta.url),{type:"module"});
    const timer=setTimeout(()=>{finish();reject(Error("Research verification timed out."));},30000);
    const abort=()=>{finish();reject(new DOMException("Verification cancelled.","AbortError"));};
    const finish=()=>{clearTimeout(timer);signal?.removeEventListener("abort",abort);worker.terminate();};
    signal?.addEventListener("abort",abort,{once:true});
    worker.addEventListener("message",({data})=>{finish();if(data.ok)resolve(data.result);else reject(Error(data.message));},{once:true});
    worker.addEventListener("error",()=>{finish();reject(Error("The research verifier could not start."));},{once:true});
    worker.postMessage({sample,check});
  });
}
