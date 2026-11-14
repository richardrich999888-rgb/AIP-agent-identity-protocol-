import json,subprocess,os,platform,time,resource,hashlib
from pathlib import Path
out=Path('/workspace/scratch/d81076ea93b3/p051-4/published-offline');out.mkdir(exist_ok=False)
git=lambda *args:subprocess.check_output(['git',*args]).decode().strip()
meta={'source':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'tracked_diff':git('diff','HEAD','--stat'),'platform':platform.platform(),'cpuinfo':Path('/proc/cpuinfo').read_text(),'meminfo':Path('/proc/meminfo').read_text(),'net_before':Path('/proc/net/dev').read_text(),'interfaces':os.listdir('/sys/class/net'),'routes':Path('/proc/net/route').read_text(),'rehearsal_credit':0,'clean_machine':False}
assert not meta['tracked_diff']
assert meta['interfaces']==['lo']
command=['cargo','test','--locked','--offline','-p','syntriass-runtime','--test','runtime_app','--test','lifecycle_isolation']
env={**os.environ,'SYNTRIASS_LIFECYCLE_EVIDENCE':str(out/'originals')}
t=time.monotonic();c0=resource.getrusage(resource.RUSAGE_CHILDREN)
with (out/'command.log').open('wb') as f:r=subprocess.run(command,env=env,stdout=f,stderr=subprocess.STDOUT)
c1=resource.getrusage(resource.RUSAGE_CHILDREN)
meta.update(command=command,exit_status=r.returncode,wall_seconds=time.monotonic()-t,child_cpu_seconds=c1.ru_utime+c1.ru_stime-c0.ru_utime-c0.ru_stime,child_peak_rss_kib=c1.ru_maxrss,net_after=Path('/proc/net/dev').read_text(),binary_sha256=hashlib.sha256(Path('target/debug/syntriass').read_bytes()).hexdigest())
(out/'metadata.json').write_text(json.dumps(meta,indent=2)+'\n');assert r.returncode==0
print(json.dumps({k:meta[k] for k in ['source','exit_status','wall_seconds','interfaces']}))
