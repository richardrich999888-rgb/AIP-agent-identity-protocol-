import os,sys,subprocess,json,time,platform,resource,hashlib
from pathlib import Path
out=Path('/workspace/scratch/d81076ea93b3/p051-5/offline');out.mkdir(exist_ok=False)
cmd=[sys.executable,'research/capability-learning/harness/record_session_scoreboard.py','--binary','target/debug/syntriass','--with-examples','--out',str(out/'replay')]
meta={'source':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'tree':subprocess.check_output(['git','rev-parse','HEAD^{tree}']).decode().strip(),'platform':platform.platform(),'cpus':os.cpu_count(),'cpuinfo':Path('/proc/cpuinfo').read_text(),'meminfo':Path('/proc/meminfo').read_text(),'net_before':Path('/proc/net/dev').read_text(),'routes':Path('/proc/net/route').read_text(),'command':cmd,'binary_sha256':hashlib.sha256(Path('target/debug/syntriass').read_bytes()).hexdigest(),'rehearsal_credit':0,'clean_machine':False}
assert [l.split(':')[0].strip() for l in meta['net_before'].splitlines()[2:]]==['lo']
start=time.monotonic();a=resource.getrusage(resource.RUSAGE_CHILDREN)
with (out/'run.log').open('wb') as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
b=resource.getrusage(resource.RUSAGE_CHILDREN)
meta.update(exit_status=r.returncode,wall_seconds=time.monotonic()-start,child_cpu_seconds=b.ru_utime+b.ru_stime-a.ru_utime-a.ru_stime,child_peak_rss_kib=b.ru_maxrss,net_after=Path('/proc/net/dev').read_text())
(out/'metadata.json').write_text(json.dumps(meta,indent=2)+'\n');assert r.returncode==0
verified=[]
for p in (out/'replay').glob('*/result.json'):
 result=json.loads(p.read_text())
 if 'teaching_review_sha256' not in result: continue
 command=[sys.executable,'research/capability-learning/harness/teaching_review.py',str(p.parent),'--expected-digest',result['teaching_review_sha256']]
 verify=subprocess.run(command,capture_output=True)
 verified.append({'folder':p.parent.name,'digest':result['teaching_review_sha256'],'command':command,'exit_status':verify.returncode,'stdout':verify.stdout.decode(),'stderr':verify.stderr.decode()})
 assert verify.returncode==0
assert len(verified)==2
(out/'verification.json').write_text(json.dumps(verified,indent=2)+'\n')
print(json.dumps({'source':meta['source'],'exit_status':r.returncode,'reviews_verified':len(verified),'wall_seconds':meta['wall_seconds']}))
