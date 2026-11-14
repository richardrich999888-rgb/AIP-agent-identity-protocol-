import subprocess,os,time,resource,json,platform,hashlib,sys,importlib.metadata
from pathlib import Path
out=Path('/workspace/scratch/d81076ea93b3/p051-6/published-offline');out.mkdir(exist_ok=False)
git=lambda *a:subprocess.check_output(['git',*a]).decode().strip()
meta={'source':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'tracked_diff':git('diff','HEAD','--stat'),'platform':platform.platform(),'cpuinfo':Path('/proc/cpuinfo').read_text(),'meminfo':Path('/proc/meminfo').read_text(),'network_before':Path('/proc/net/dev').read_text(),'routes':Path('/proc/net/route').read_text(),'python':sys.version,'packages':{n:importlib.metadata.version(n) for n in ['pytest','pypdf','python-docx','lxml','pillow']},'binary_sha256':hashlib.sha256(Path('target/debug/syntriass').read_bytes()).hexdigest(),'rehearsal_credit':0,'clean_machine':False}
assert not meta['tracked_diff']
assert [l.split(':')[0].strip() for l in meta['network_before'].splitlines()[2:]]==['lo']
env={**os.environ,'SYNTRIASS_BIN':str(Path('target/debug/syntriass').resolve()),'SYNTRIASS_TEACH_APPROVAL_EVIDENCE':str(out/'signed-originals')}
commands=[['-m','pytest','-q','-rs','research/capability-learning/tests/test_signed_teaching_review.py'],['research/capability-learning/harness/record_session_scoreboard.py','--binary','target/debug/syntriass','--with-examples','--out',str(out/'scoreboard')]]
meta['commands']=[]
for i,cmd in enumerate(commands):
 command=[sys.executable,*cmd];t=time.monotonic();a=resource.getrusage(resource.RUSAGE_CHILDREN)
 with (out/('command-'+str(i)+'.log')).open('wb') as log:r=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT)
 b=resource.getrusage(resource.RUSAGE_CHILDREN)
 meta['commands'].append({'command':command,'exit_status':r.returncode,'wall_seconds':time.monotonic()-t,'child_cpu_seconds':b.ru_utime+b.ru_stime-a.ru_utime-a.ru_stime,'peak_child_rss_kib':b.ru_maxrss})
 meta['network_after']=Path('/proc/net/dev').read_text();(out/'metadata.json').write_text(json.dumps(meta,indent=2)+'\n')
 assert r.returncode==0
print(json.dumps({'source':meta['source'],'commands':meta['commands']}))
