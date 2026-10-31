"""Actual Rust cap-check; records cryptographically signed by synthetic test key.
Explicit request binding baseline uses typed context, not inferred intent.
Run after fp_evidence.py .local/evidence-reproduction.
"""
import copy,json,pathlib,subprocess,time
R=pathlib.Path(__file__).resolve().parent;ROOT=R.parents[1];LOCAL=ROOT/'.local/evidence-reproduction';BIN=ROOT/'target/release/syntriass'
def cli(*args):return subprocess.check_output([str(BIN),*map(str,args)],text=True)
def run():
 out=R/'results/record-binding';out.mkdir(parents=True,exist_ok=False);cases=[];contexts={}
 originals=[json.loads(s) for s in (LOCAL/'ir.B.jsonl').read_text().splitlines() if 'record' in json.loads(s)]
 for x in originals:
  if x['label']!='PASS':continue
  for kind in ['valid','hypothetical','wrong_asset','stale','cross_tenant','tampered']:
   row=copy.deepcopy(x);row['id']=x['id']+'-'+kind;rec=row['record'];rec['taken_at_ms']=100000;rec['asset_id']='motor-17'
   ctx=dict(tenant='koravi-process',asset='motor-17',now_ms=100500,intent='assess')
   if kind=='hypothetical':row['text']='This is a hypothetical simulation, not an actual assessment: '+row['text'];ctx['intent']='simulate'
   if kind=='wrong_asset':rec['asset_id']='motor-99'
   if kind=='stale':rec['taken_at_ms']=1
   if kind=='cross_tenant':rec['tenant']='other-company'
   unsigned=LOCAL/'probe-unsigned.jsonl';unsigned.write_text(json.dumps(rec)+'\n')
   row['record']=json.loads(cli('record-sign','--key',LOCAL/'instrument.key.json','--in',unsigned))
   if kind=='tampered':row['record']['asset_id']='changed-after-signing'
   row['label']='PASS' if kind=='valid' else 'ABSTAIN';cases.append(row);contexts[row['id']]=dict(kind=kind,**ctx)
 p=LOCAL/'binding-cases.jsonl';p.write_text(''.join(json.dumps(x)+'\n' for x in cases))
 start=time.perf_counter_ns();raw=cli('cap-check','--file',LOCAL/'ir.signed.capability.json','--cases',p,'--instruments',LOCAL/'instruments.json');elapsed=time.perf_counter_ns()-start
 got={x['id']:x for x in map(json.loads,raw.splitlines())};results=[]
 for x in cases:
  ctx=contexts[x['id']];rec=x['record'];v=got[x['id']]['got']
  bound=(ctx['intent']=='assess' and rec['asset_id']==ctx['asset'] and rec['tenant']==ctx['tenant'] and 0<=ctx['now_ms']-rec['taken_at_ms']<=1000)
  results.append(dict(id=x['id'],kind=ctx['kind'],expected=x['label'],runtime=v,bound_baseline=v if bound else 'ABSTAIN'))
 (out/'cases.json').write_text(json.dumps(cases,indent=1)+'\n');(out/'contexts.json').write_text(json.dumps(contexts,indent=1)+'\n');(out/'raw.json').write_text(json.dumps(list(got.values()),indent=1)+'\n');(out/'comparative.json').write_text(json.dumps(results,indent=1)+'\n');(out/'instruments.json').write_bytes((LOCAL/'instruments.json').read_bytes())
 summary={k:{m:sum(x[m]=='PASS' for x in results if x['kind']==k) for m in ['runtime','bound_baseline']}|{'n':sum(x['kind']==k for x in results)} for k in sorted({x['kind'] for x in results})}
 summary['batch_wall_ns']=elapsed;summary['scope']='cap-check only; no tool activation; explicit context trusted externally; timestamps synthetic; baseline is conventional binding, not semantic intelligence'
 (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
if __name__=='__main__':run()
