# Security disposition — no enterprise approval

At the original P0-057 base `61dd730`, Security run `43168207784` failed Gitleaks
and Trivy. P0-057 does not change scanner rules, exclusions or the Kubernetes
template. This checkpoint fixes the reproduced executable-consistency defect;
it is not a full security audit or release approval.

During execution, P0-048 advanced through `ce7925c` to
`d2883d7d565901a46e134a22f702eb793db72497`. Those commits classify exact immutable
historical findings and pin the qualified compiler. The raw reports remain.
The new P0-048 Security run `43582310104` passed; this is a later separate-source
result, not remediation of the live template. No automatic merge/cherry-pick was
performed. PR #23's synthetic merge tests may contain that newer CI policy;
native qualification deliberately measures the exact P0-057 head.

| Finding | Current opt-in probe behavior | P0-057 disposition |
|---|---|---|
| KSV-0009 | Host networking | Needs approved-host evaluation of sensor/egress coverage under alternatives; not waived |
| KSV-0010 | Host PID access | Needed by current host-wide process profile; scoped process/namespace profile not qualified |
| KSV-0118 | Explicit UID 0 | Lower-privilege capability profile not qualified; not accepted as safe |
| KSV-0121 | Host `/proc` mount | Read-only mount still exposes host process metadata; removal changes coverage and needs actual tests |

The chart drops all capabilities then adds PERFMON/NET_ADMIN, disables privilege
escalation and service-account token mounting, and uses a read-only root FS.
These reduce some permissions; they do not neutralize host namespace/mount risk.
This baseline lacks a qualified seccomp/AppArmor profile. #17 and later #21 are
review inputs; a static RuntimeDefault addition needs live compatibility checks.
Kubernetes admission controls and tenant node separation remain deployment gates.

The newer classification matches historical rule/path/line/hash tuples and
public checksum fingerprints; it is not authorization to deploy an enabled
chart with those privileges. P0-057 does not extend that classification to new
files or suppress fresh findings. An authorised reviewer must approve residual
deployment risk only after a documented least-privilege coverage comparison.
No such external acceptance has been supplied. Security release gate stays open.
