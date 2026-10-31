"""Pinned local inference diagnostic; no cloud calls; first 70 frozen cases.
Typed evidence shared across modes. Not an independent text extraction test.
"""
import json,pathlib,subprocess,time,urllib.request,hashlib,resource,sys
R=pathlib.Path(__file__).resolve().parent;ROOT=R.parents[1]
POLICY='Assess dispatch. SHIP iff stock >= need AND capacity >= need AND need * unit_weight <= limit. Each list contains possible values; consider all combinations. Return SHIP if all combinations ship; HOLD if none ships; ABSTAIN if outcomes differ. Also ABSTAIN on empty lists, tenant mismatch or intent other than assess. Respond with exactly one label: SHIP, HOLD, ABSTAIN.'
SKILL='Equivalent monotone check: worst = min(stock)>=need and min(capacity)>=need and need*max(unit_weight)<=limit; best = max(stock)>=need and max(capacity)>=need and need*min(unit_weight)<=limit. If worst then SHIP; else if not best then HOLD; else ABSTAIN. Apply authorization/missing checks first.'
def main():
 out=R/'results'/('llm-fewshot-dev' if '--dev' in sys.argv else 'llm-fewshot' if '--fewshot' in sys.argv else 'llm');out.mkdir(parents=True,exist_ok=False)
 model=ROOT/'.local/runtime/qwen3-4b.gguf';server=ROOT/'.local/runtime/build/bin/llama-server'
 digest=hashlib.file_digest(model.open('rb'),'sha256').hexdigest()
 log=(out/'server.log').open('w');cmd=[str(server),'-m',str(model),'--host','127.0.0.1','--port','18129','-t','8','-c','4096','-ngl','0']
 p=subprocess.Popen(cmd,stdout=log,stderr=log);raw=[]
 try:
  for _ in range(120):
   if p.poll() is not None:raise RuntimeError('server exited')
   try:
    urllib.request.urlopen('http://127.0.0.1:18129/health',timeout=1);break
   except Exception:time.sleep(1)
  else:raise RuntimeError('health timeout')
  rows=json.loads((R/('datasets/dev.json' if '--dev' in sys.argv else 'datasets/heldout.json')).read_text())[:(14 if '--dev' in sys.argv else 70)]
  modes=['few_shot_skill'] if '--fewshot' in sys.argv else ['direct','structured_skill','rag']
  for mode in modes:
   for x in rows:
    data={k:v for k,v in x.items() if k not in ['expected','kind','id','request']}
    # Lossless decision-relevant extrema for this monotone task, shared by all modes.
    for k in ['stock','capacity','unit_weight']:
     if data[k]:data[k]=sorted(set([min(data[k]),max(data[k])]))
    instruction=POLICY if mode=='direct' else (POLICY+'\n'+SKILL if mode=='structured_skill' else 'Use the retrieved warehouse policy below.\n<source id="warehouse-policy">'+POLICY+'</source>')
    payload=dict(model='local',messages=[dict(role='system',content=instruction),dict(role='user',content=json.dumps(data)+' /no_think')],temperature=0,max_tokens=32,chat_template_kwargs={'enable_thinking':False})
    if mode=='few_shot_skill':
     examples='\nExample: tenant=a, record_tenant=a, intent=assess, stock=[20,30], capacity=[20,40], unit_weight=[1,2], need=10, limit=30. Answer: SHIP.\nExample: same context but need=50. Answer: HOLD.\nExample: same context but stock=[5,20], need=10. Answer: ABSTAIN.\n'
     payload['messages']=[dict(role='user',content=POLICY+'\n'+SKILL+examples+'Now solve this case:\n'+json.dumps(data)+'\nAnswer with one label. /no_think')]
    t=time.perf_counter();req=urllib.request.Request('http://127.0.0.1:18129/v1/chat/completions',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=120) as response:answer=json.load(response)
    text=answer['choices'][0]['message']['content'];clean=text.strip();got=clean if clean in ('SHIP','HOLD','ABSTAIN') else 'INVALID'
    raw.append(dict(id=x['id'],mode=mode,expected=x['expected'],got=got,wall_seconds=time.perf_counter()-t,response=answer,request=payload))
    (out/'raw.json').write_text(json.dumps(raw,indent=1)+'\n')
    if len(raw)%10==0:print('completed',len(raw),flush=True)
  summary={m:dict(n=len(rows),correct=sum(x['got']==x['expected'] for x in raw if x['mode']==m),incorrect_positive=sum(x['got']=='SHIP' and x['expected']!='SHIP' for x in raw if x['mode']==m)) for m in modes}
  (out/'summary.json').write_text(json.dumps(dict(results=summary,model_sha256=digest,cmd=cmd,subset=('first 14 development cases' if '--dev' in sys.argv else 'first 70 consumed evaluation cases, diagnostic only'),rag='single policy retrieval supplied, no retrieval cost measured',threads='8 fixed from CPU quota; not tuned',energy='unmeasured'),indent=2))
 finally:
  p.terminate();p.wait(timeout=30);log.close()
  (out/'server-resource.json').write_text(json.dumps(dict(child_peak_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,child_cpu_seconds=resource.getrusage(resource.RUSAGE_CHILDREN).ru_utime+resource.getrusage(resource.RUSAGE_CHILDREN).ru_stime)))
if __name__=='__main__':main()
