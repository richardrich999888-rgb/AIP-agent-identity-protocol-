# Full-sensor service profile: review and qualification

Status: **the first live full-sensor run observed all seven sensors and verified
signed evidence, but failed the host-root write negative control. The enforcing
AppArmor candidate below requires a fresh Linux qualification before acceptance.** The user
approved testing this profile on a disposable GitHub Actions Linux runner on
24 November 2026. This authorization does not approve customer deployment or
establish separately administered collector custody.

`review-probe-unit` remains inert. `package.py install` still refuses fanotify by
default. Its new activation path requires the reviewed unit digest, the exact
configuration digest, the exact AppArmor policy digest and an explicit disposable-runner flag. It never starts a
service automatically. The existing capability, seccomp and namespace restrictions remain; an enforcing
AppArmor policy adds filesystem write confinement beyond the mount namespace.

## Filesystem write boundary

The original `ProtectSystem=strict` namespace did not protect a world-writable
host file reached through `/proc/1/root`. Run 45331122159 retained that failure;
its successful sensor and signature checks do not turn the failed privilege
control into a pass. The negative control remains mandatory.

The v2 package includes the exact AppArmor policy. The installed unit names it
without an ignore-errors prefix and incorporates its digest. Installation
requires AppArmor enabled, its parser available, and kernel profile inspection.
It refuses an existing same-named profile, loads only the approved bytes with
cache use disabled, and requires enforce mode. The runner also checks the actual
probe and negative helper process labels, including after a disconnected restart.
A disabled LSM, complain-mode profile, unavailable parser, or missing loaded
profile is a refusal, never a successful qualification.

The policy permits measurement reads, the existing sensor capabilities and
socket types, and fixed inherited execution. Only service-owned paths under
`/var/lib/aip-probe` receive write permission. Atomic spool publication has an
`owner link subset` rule with both the new link and existing target constrained
to that same hierarchy; outside-target hardlinks remain forbidden. It grants no unconfined execution
or profile changes and uses no disconnected-path aliasing flag. Direct writes,
host-root and other-process-root aliases, and a symlink from writable state to
an outside canary, and an outside-file hardlink into state must all fail while normal spool operations and all seven
sensors continue to work. Profile bytes and their digest are retained with the
installation receipt and public qualification evidence. Uninstall stops the
service, unloads only its owned policy, removes software, and preserves state.

This is a candidate until the original exploit and legitimate controls pass
on Linux. Read access remains broad; filesystem write confinement does not
establish independent collector custody or isolation of customer secrets.
Legacy v1 packages still verify and support their default profiles; they cannot
activate the full-sensor profile without the v2 confinement artifact.

## Concrete candidate

Inspect [the complete unit](aip-probe.full-sensor.service.review),
[the enforcing policy](aip-probe.full-sensor.apparmor.review), and
[the sample configuration](full-sensor-pilot.env.review). The sample endpoint
and all-zero transport pin are placeholders, not enrolled trust material.
From an independently verified runtime archive, generate an equivalent review
record for the actual approved configuration:

```sh
python3 package.py review-probe-unit \
  --archive vanian-runtime-x86_64-linux.tar \
  --expected-sha256 "$INDEPENDENTLY_APPROVED_ARCHIVE_SHA256" \
  --config probe.env --output probe-unit-review.json
```

The JSON records the source commit, archive digest, exact proposed unit and
unit digest, exact configuration-byte and AppArmor-policy digests, chosen sensors, mount, interface
and filter path. Generation is not approval or qualification. Existing files
are never replaced.

For the approved disposable validation only, install the probe using digests
from that reviewed record and the independently approved archive digest:

```sh
sudo env GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  python3 package.py install --role probe --config probe.env \
  --archive vanian-runtime-x86_64-linux.tar \
  --expected-sha256 "$INDEPENDENTLY_APPROVED_ARCHIVE_SHA256" \
  --approved-probe-unit-sha256 "$APPROVED_PROBE_UNIT_SHA256" \
  --approved-probe-config-sha256 "$APPROVED_PROBE_CONFIG_SHA256" \
  --approved-probe-apparmor-sha256 "$APPROVED_PROBE_APPARMOR_SHA256" \
  --disposable-runner-validation
```

The workflow must actually be running on the approved disposable GitHub-hosted
Linux VM. The two environment markers prevent accidental context mismatch;
a root operator can supply them, so they are not authentication or hardware
attestation. Do not use this mode for customer deployment. It conflicts with
`--confirm-separate-host`, and its receipt explicitly records that independent
administrative custody has not been established. A staged installation records
that it is not a live host installation.

The supplied configuration must carry the actual enrolled collector Noise key;
an all-zero sample pin is refused. The installer reads configuration bytes once,
checks the approved digest, and installs those exact bytes with the exact
reviewed unit. A changed destination, filter, limit or other configuration byte
invalidates that approval even if it would not change the unit text. The archive
digest and source identity are retained in the same installation receipt.

The candidate uses the dedicated `aip-probe` account, requires an explicit
interface and a dedicated workload mount, retains the current filesystem
namespace directives, restricts namespace creation and mount-changing system
calls, and bounds service resources. Proposed capabilities are:

| Purpose | Capability | Qualification implication |
| --- | --- | --- |
| `sched`, `cgroup`, `sockstate`, `socksend` perf tracepoints | `CAP_PERFMON` | Verify each configured tracepoint opens and its integrity check succeeds. |
| `connector` process events | `CAP_NET_ADMIN` | Must work in the initial network namespace; network-administration permission is broader than observation. |
| `fanotify` mount watch | `CAP_SYS_ADMIN` | Broad privilege; exact original mount and effective syscall restrictions must be tested. |
| `afpacket` interface tap | `CAP_NET_RAW` | Explicit interface must carry the controlled test traffic. |
| Cross-user process/root/namespace inspection | `CAP_SYS_PTRACE` | Verify actual identity measurements for the workload UID, with direct `ptrace` and memory-write calls denied. |
| Executable-content and path reads | `CAP_DAC_READ_SEARCH` | Broad read access; this is not an isolation guarantee for unrelated customer data. |

The kernel recommends `CAP_PERFMON` rather than granting `CAP_SYS_ADMIN` solely
for perf monitoring. This candidate needs the latter for its separate
fanotify operation. [Linux perf security documentation](https://www.kernel.org/doc/html/latest/admin-guide/perf-security.html).

A fanotify mount mark covers the mount containing its path, including its
files and directories; a subdirectory does not narrow it. Mount marks require
`CAP_SYS_ADMIN`. The preflight therefore refuses system trees, ordinary
subdirectories, aliased mounts and filesystems mounted elsewhere.
[Linux fanotify_mark documentation](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html).

Packet sockets require `CAP_NET_RAW`; binding an interface narrows which
interface they observe. The installer requires an explicit interface rather
than silently watching all interfaces.
[Linux packet documentation](https://man7.org/linux/man-pages/man7/packet.7.html).

## Host mount access is an unqualified design assumption

The candidate passes `/proc/1/root` followed by the approved workload path to
fanotify. `/proc/PID/root` exposes that process's filesystem view, including
mounts, subject to a ptrace read-access check. This motivates resolving the
host's mount through PID 1 while the service retains its private mount view.
The conclusion that this produces the required fanotify observations is an
**inference that must be tested**, not an executed result.
[Linux proc_pid_root documentation](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html).

`ProtectSystem`, `ProtectHome` and `PrivateTmp` create filesystem namespace
restrictions. systemd recommends denying mount-changing system calls when
retaining broad privileges. It also documents limitations, including kernel
support and mount propagation. The candidate keeps those directives and
adds the mount syscall restriction; an effective unit must still be inspected
on the actual host. [systemd execution documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).

These directives do **not** establish confinement through another process's
root view. `CAP_DAC_READ_SEARCH` bypasses read/search checks and also permits
additional file-handle operations. The probe's grants remain broader than
its intended observations. Direct syscall restrictions reduce some actions
but do not turn `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE` or `CAP_NET_ADMIN` into
read-only capabilities. Negative access tests and security-owner review are
required before adoption. [Linux capability documentation](https://man7.org/linux/man-pages/man7/capabilities.7.html).

All seven sensors may be requested, but per-agent filtering is a separate
retention boundary. Kernel acquisition can see host data internally.
Unassignable events, including packet events without a measured process
binding, are withheld and counted. A scoped archive does not assert
host-wide coverage or prove that unobserved actions did not happen.

## Required Linux lifecycle qualification

This procedure is an acceptance specification. Use the explicit reviewed
activation path above; manually copying the unit bypasses its digest checks.
Preserve each failed attempt and its original evidence. Do not edit archives,
rewrite queued records, remove continuity files or relax clock checks to make
a step pass.

1. **Identify the deployment.** Retain the exact source and binary digests,
   package digest, approved unit digest, OS/kernel/systemd versions, actual
   tracepoints, cgroup version, clock synchronization result, mount identity
   and interface identity. Record both host identities and their responsible
   administrators. Two processes or two hosted runners under one
   administrator do not establish independent collector custody.
2. **Install without starting.** On clean approved hosts, install only the
   correct role. Retain installation receipts. Confirm the workload host has
   the transport credential only; the collector host generates and retains
   its own wrapped signing key and Noise key. Approve the collector transport
   pin and evidence public key through a channel independent of the captured
   archive. Provision the passphrase through the collector's systemd
   credential. Do not copy private keys into a workflow artifact.
3. **Check enrollment.** Start the controlled workload in a waiting state,
   enroll its actual process incarnation with `aip-probe enroll-filter`, and
   store the file root-owned with exact mode `0640` and the probe group (or
   `0600` only when the eventual service can read it). Rerun host preflight
   after installation. `FILTER_SCHEMA_DEFERRED` is not a passing enrollment;
   `validate-filter` must run successfully using the installed binary. Also
   check access under the actual service identity.
4. **Establish real service operation.** After the approved installation path
   exists, start through systemd. Retain the effective unit, daemon UID,
   effective/bounding capabilities, mount and network namespace identities,
   startup diagnostics and signed observations. Require all seven requested
   sensor opens to succeed. Exercise a selected workload and a different-UID
   unselected workload: only approved process records may enter the spool
   and exported scoped archive. Required selected file/socket/process events
   must bind to the measured incarnation; absent records fail the test.
5. **Qualify the mount boundary.** Produce controlled writes through the host
   workload mount and through a different mount. Establish the expected
   selected host-mount file event and reject attribution to the alternate
   mount. Confirm direct mount/namespace changes and disallowed process-write
   operations are denied. Assess reads and writes through `/proc/1/root`
   explicitly; retained unit directives alone cannot close this gate.
6. **Interrupt delivery and recover.** Disconnect only the approved probe's
   collector route while the workload continues. Retain queued payload
   hashes and show queue growth. Restore connectivity and prove delivery of
   the same payloads, original windows, run IDs and sequence numbers. Lose an
   acknowledgement and reconnect: the collector must return the existing
   receipt rather than sign a duplicate. Repeat across probe and collector
   restarts. Restart coverage must not backfill the collector interruption.
7. **Exercise bounded failure.** Reach the configured queue limit on a
   dedicated test filesystem, then test a storage-write failure and a corrupt
   queued copy. Require explicit refusal/stop, retention of existing records
   and visible loss/coverage uncertainty. Recover from separately preserved
   valid state according to the incident procedure; do not discard the
   damaged original to manufacture uninterrupted history.
8. **Verify independently offline.** Freeze consistent original batch and
   health archives plus an independently held boundary checkpoint. On a
   third verification environment with networking disabled, run the existing
   verifier against the separately approved evidence key. Compare the
   complete report with online verification. Altered payload, signature,
   scope, chain link, missing/extra record and checkpoint cases must be
   rejected by the applicable checks. Preserve `CannotProve`, missing
   coverage and scope exclusions; signatures alone do not prove workload
   semantics or administrative independence.
9. **Uninstall and reinstall.** Stop/disable and uninstall through the approved
   package path. Confirm daemon/unit software is removed and all credentials,
   spool data, evidence, continuity state, trust records and service accounts
   remain. Reinstall reviewed identical configuration, restart and repeat
   strict continuity/offline checks. Record the maintenance coverage gap.

Acceptance requires the actual independently administered collector test,
not only the disposable-runner rehearsal. The collector administrator must
confirm that the workload administrator cannot read, replace or restore the
collector signing key, continuity state or independently retained checkpoint.
Neither an endpoint hostname nor `--confirm-separate-host` proves this.
