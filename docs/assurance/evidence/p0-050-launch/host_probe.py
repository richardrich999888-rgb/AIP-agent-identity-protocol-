import ctypes, json, os, subprocess
r=subprocess.run(['/usr/bin/unshare','--user','--map-root-user','--net','--pid','--fork','--kill-child','--mount','--mount-proc','--','/bin/true'],capture_output=True)
print(json.dumps(dict(namespace_probe_exit=r.returncode, stderr=r.stderr.decode())),flush=True)
pid=os.fork()
if pid==0:
 c=ctypes.CDLL(None,use_errno=True);ret=c.ptrace(0,0,0,0)
 print(json.dumps(dict(ptrace_traceme=ret,errno=ctypes.get_errno(),uid=os.getuid())),flush=True)
 os._exit(0)
os.waitpid(pid,0)
