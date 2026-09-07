# Tetragon — re-check

Phase 5 of the real-world validation mandate. `BUILD.md` diagnosed Tetragon as
blocked; this is the re-verification, run again rather than assumed.

## Result: still BLOCKED, same cause, unchanged

```
$ zgrep -E 'CONFIG_KPROBES|CONFIG_BPF_SYSCALL|CONFIG_DEBUG_INFO_BTF' /proc/config.gz
CONFIG_BPF_SYSCALL=y
# CONFIG_KPROBES is not set
CONFIG_DEBUG_INFO_BTF=y
```

BPF and BTF are present; kprobes are not. Tetragon's process sensors attach to
kernel functions through kprobes, so its sensor load fails after the daemon has
otherwise started cleanly. The full diagnosis in `BUILD.md` stands: it is not a
permission problem, not a build problem, and not fixable from inside the guest.
Enabling `CONFIG_KPROBES` means booting a different kernel, which is a change
to a Firecracker microVM this session does not control.

**No attempt was made to work around the kernel restriction**, per the standing
instruction.

## Consequence for the experiment

Tetragon was the instrument `validation/linux/INDEPENDENCE.md` identified as
the one that would have made a comparison evidence about the *event*. It is
still unavailable.

That document's conclusion — that no mechanism-independent observer of process
execution exists in this environment — was nevertheless wrong, because it
surveyed tracing facilities only. The Linux audit subsystem is not one, is
compiled in, and hooks a different point in the syscall path. See
`../../airi/OBSERVER_INDEPENDENCE.md`.

Tetragon would still add something audit does not: a probe on kernel functions
*below* the syscall boundary, which would survive a subject that manipulated
the syscall entry path. That remains out of reach here and is listed as the
first item of the next experiment.
