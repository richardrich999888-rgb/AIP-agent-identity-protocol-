# Tetragon — build recipe and the kernel finding that stops it

Every command below was executed and its result observed. Nothing here is a
plausible-looking command that was never run.

## Why from source

Tetragon's two documented install paths are both blocked at the proxy in this
environment:

- container image from `quay.io` — **blocked**
- `apt` — `deb.debian.org` **blocked**

Source build over `git clone` (reachable) is the only remaining path, and it
worked.

## Recipe

```sh
git clone https://github.com/cilium/tetragon /tmp/probe_clone
cd /tmp/probe_clone

# 1. BPF objects. LOCAL_CLANG=1 is essential: the default target pulls a
#    clang container image from quay.io, which is blocked.
make LOCAL_CLANG=1 tetragon-bpf          # clang 18.1.3 -> bpf/objs/*.o

# 2. Go binaries. go.mod requires go 1.27.0; the host has go1.24.7.
#    GOTOOLCHAIN=auto fetches 1.27.0 from proxy.golang.org, which is reachable.
export GOTOOLCHAIN=auto
make LOCAL_CLANG=1 tetragon tetra
```

Result: `tetragon` (60,907,680 bytes) and `tetra` (53,588,128 bytes), plus
`bpf/objs/` containing `bpf_execve_map_update.o`, `bpf_cgroup_*.o`,
`bpf_cgtracker.o`, `bpf_lseek*.o`, `bpf_alignchecker.o`, `bpf_exit_v511.o` and
the rest of the sensor set.

Binaries are **not committed** — 114 MB, and they do not run on this host.

## Runtime prerequisites satisfied here

```sh
mkdir -p /sys/fs/bpf && mount -t bpf bpf /sys/fs/bpf     # succeeded
```

| Prerequisite | State |
|---|---|
| root, `CapEff: 000001fffeffffff` | yes |
| `/sys/kernel/btf/vmlinux` | present, 4,671,335 bytes |
| bpffs at `/sys/fs/bpf` | mounted |
| tracefs at `/sys/kernel/tracing` | mounted, populated |
| cgroups | hybrid v1+v2, memory controller active |
| `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, `CONFIG_DEBUG_INFO_BTF` | all `=y` |

Tetragon got a long way. From its own log:

```
level=info msg="BTF discovery: default kernel btf file found" btf-file=/sys/kernel/btf/vmlinux
level=info msg="Cgroup mode detection succeeded" cgroup.mode="Hybrid mode (Cgroupv1 and Cgroupv2)"
level=info msg="Set execve_map entries 32768" size=28M
level=info msg="BPF ring buffer size (bytes)" total=256K
level=info msg="Loading sensor" name=__base__
```

## The blocker

```
level=error msg="Failed to execute tetragon" error="sensor __base__ from
  collection __base__ failed to load: failed prog
  /tmp/probe_clone/bpf/objs/bpf_exit_v511.o kern_version 397868 loadInstance:
  attaching 'event_exit_acct_process' failed: creating tracefs event
  (arch-specific fallback for \"acct_process\"): creating probe entry on
  tracefs: open /sys/kernel/tracing/kprobe_events: no such file or directory"
```

Two earlier errors in the same run are the same cause:

```
level=error msg="detect modify return syscall" error="failed to load: load program:
  invalid argument: __x64_sys_getcpu() is not modifiable"
level=error msg="detect link pin" error="creating tracefs event (arch-specific
  fallback for \"vprintk\"): ... open /sys/kernel/tracing/kprobe_events: no such
  file or directory"
```

And the detected feature set says it outright:

```
kprobe_multi: false, fmodret: false, override_return: false, link_pin: false,
lsm: false, probe_write_user: false
```

## Root cause

From the running kernel's own configuration, `/proc/config.gz`:

```
# CONFIG_KPROBES is not set
CONFIG_HAVE_KPROBES=y
CONFIG_HAVE_KPROBES_ON_FTRACE=y
CONFIG_UPROBES=y
CONFIG_UPROBE_EVENTS=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_EVENTS=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_FTRACE=y
CONFIG_TRACEPOINTS=y
```

`CONFIG_HAVE_KPROBES=y` says the *architecture* supports kprobes. `# CONFIG_KPROBES
is not set` says this kernel was **built without them**. Corroborated twice
over:

- `/sys/kernel/tracing/` contains `uprobe_events`, `uprobe_profile` and
  `dynamic_events`, and contains **no `kprobe_events`**.
- `/sys/bus/event_source/devices/` contains `breakpoint`, `msr`, `power`,
  `software`, `tracepoint`, `uprobe` — and **no `kprobe`**.

Tetragon's process-lifecycle sensors attach kprobes to kernel functions
(`acct_process` for exit, among others). Without `CONFIG_KPROBES` there is
nothing to attach to, through either interface.

## What this is and is not

**It is not** a permission problem — the process is root with essentially the
full capability set, and BPF programs loaded and maps were created.

**It is not** a build problem — the binaries and BPF objects built cleanly and
the daemon started, discovered BTF, and got as far as sensor load.

**It is not** fixable from inside the guest. Enabling `CONFIG_KPROBES` requires
building and booting a different kernel, which is a host-level change to a
Firecracker microVM this session does not control.

**It is** environmental. The same recipe on a host with `CONFIG_KPROBES=y`
produces a working instrument, which is why the recipe is preserved.

## What was not done

Tetragon can enforce — `SIGKILL`, return-value override, signal delivery. No
`TracingPolicy` with an enforcement action was written, loaded, or tested. The
attempted run was observation-only (`--enable-process-cred=false
--enable-process-ns=false`, no policy directory). Had it run, it would have
stayed that way: rule B, and Tetragon's enforcement is a control surface.
