import hashlib,json,math,pathlib,random,resource,statistics,time,sys
from warehouse_methods import METHODS
R=pathlib.Path(__file__).parent

def wilson(k,n):
 if not n:return None
 z=1.959963984540054;p=k/n;d=1+z*z/n
 center=(p+z*z/(2*n))/d;half=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
 return [max(0,center-half),min(1,center+half)]
def run():
 manifest=json.loads((R/'datasets/manifest.json').read_text())
 for name,h in manifest['sha256'].items():assert hashlib.sha256((R/'datasets'/name).read_bytes()).hexdigest()==h
 rows=json.loads((R/'datasets/heldout.json').read_text());raw=[];summary={};runs={k:[] for k in METHODS}
 for name,fn in METHODS.items():
  for x in rows:
   start=time.perf_counter_ns();got=fn(x);ns=time.perf_counter_ns()-start
   raw.append(dict(id=x['id'],kind=x['kind'],method=name,expected=x['expected'],got=got,latency_ns=ns))
  fn(rows[0]) # explicit warmup before timed repeated batches
 # Rotate method order to reduce ordering confounding. CPU seconds, not energy.
 for rep in range(30):
  names=list(METHODS);names=names[rep%len(names):]+names[:rep%len(names)]
  for name in names:
   start=time.process_time_ns()
   for x in rows:METHODS[name](x)
   runs[name].append(time.process_time_ns()-start)
 for name in METHODS:
  p=[x for x in raw if x['method']==name];correct=sum(x['got']==x['expected'] for x in p);released=[x for x in p if x['got']!='ABSTAIN'];good=sum(x['got']==x['expected'] for x in released)
  summary[name]=dict(n=len(p),correct=correct,accuracy_ci95=wilson(correct,len(p)),released=len(released),correct_releases=good,wrong_releases=len(released)-good,false_ship=sum(x['got']=='SHIP' and x['expected']!='SHIP' for x in p),correct_abstentions=sum(x['got']==x['expected']=='ABSTAIN' for x in p),missed=sum(x['got']=='ABSTAIN' and x['expected']!='ABSTAIN' for x in p),precision_ci95=wilson(good,len(released)),median_batch_cpu_ns=statistics.median(runs[name]),p95_latency_ns=sorted(x['latency_ns'] for x in p)[math.ceil(.95*len(p))-1])
 rng=random.Random(222);ratios=[]
 for _ in range(4000):
  ix=[rng.randrange(30) for _ in range(30)];ratios.append(statistics.mean(runs['exhaustive'][j] for j in ix)/statistics.mean(runs['interval'][j] for j in ix))
 out=R/'results'/(sys.argv[1] if len(sys.argv)>1 else 'logistics');out.mkdir(parents=True,exist_ok=False)
 (out/'raw.json').write_text(json.dumps(raw,indent=1)+'\n');(out/'timing.json').write_text(json.dumps(runs,indent=1)+'\n')
 result=dict(methods=summary,exhaustive_to_interval_cpu_ratio_ci95=[sorted(ratios)[100],sorted(ratios)[3899]],process_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,memory_scope='whole Python process; not per method; Linux ru_maxrss',energy='unmeasured',quality_scope='synthetic typed alternatives, not text understanding',holdout='consumed by this run')
 (out/'summary.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':run()
