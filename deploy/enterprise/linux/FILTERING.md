# Per-agent retention scope

The pilot filter selects explicitly enrolled Linux process instances before
serialization, durable buffering, or transport. Kernel sensors still collect
within their configured host, mount and interface scopes in memory. This is a
retention/export boundary, not a kernel collection boundary.

The selection pins boot ID, PID, process start ticks and executable content
SHA-256. Enrollment also pins the measured PID, mount and network namespaces
and any measured cgroup ID. A reused PID, a different boot, an executable
change, or a required namespace mismatch does not match. Customer labels are
operator claims, never verified AIP agent attribution.

## Enrollment and lifecycle

1. Start the intended agent in a controlled waiting state under its intended
   identity, executable and namespaces. Do not count work performed before the
   probe is collecting as observed work.
2. From an appropriately authorized Linux administrator session, measure the
   actual process with the installed probe binary:

   ```sh
   umask 077
   aip-probe enroll-filter customer-agent "$AGENT_PID" > scope.json
   aip-probe validate-filter scope.json
   ```

   Enrollment uses a pidfd-anchored measurement and refuses a process that
   exits during measurement or whose namespace identity cannot be read. The
   output contains measured identifiers and an operator label; no private key.
3. Provision the validated scope at `/etc/aip/agent-filter.json`, owned by root
   with group `aip-probe` and mode `0640`. For a probe running as the file owner,
   mode `0600` is also accepted. The runtime refuses other permissions,
   symlinks, nonregular files, oversized files and unknown schema fields.
4. Set `AIP_PROBE_FILTER_PATH=/etc/aip/agent-filter.json` in the probe's reviewed
   configuration. The file is loaded once before sensors start. Replacing the
   file does not silently change a running probe's scope.
5. After the approved probe configuration is running, release the waiting
   workload. Preserve the scope, original signed observations, independent
   collector public anchor and boundary checkpoint with the test report.

A process restart requires new enrollment. An exec that changes executable
content also requires new enrollment. Child processes are not automatically
included: enroll each intended process instance in the `targets` array before
its relevant work. At most 256 unique process instances may be selected in one
scope. The configuration file is limited to 256 KiB.

Multiple logical agents sharing one process cannot be separated by this
filter. They need distinct process instances or separately verified
application-level attribution. A scope label does not provide that attribution.

## What is retained and withheld

A retained execution observation must match a target's full selection. A
retained kernel event must also name that same PID as its subject. An unrelated
payload cannot borrow a selected `bound` identity. Events without a reliable
subject, including device-level packet records and asynchronous socket states,
are withheld. Missing required measurements remain unassigned rather than
being guessed from a PID, socket or agent label.

A retained event may contain metadata about its relationship with another
process, such as the child PID in a selected parent's spawn. It is evidence of
that selected process's event, not enrollment of the related process. No event
is rewritten to remove fields from its original kernel record.

Every filtered batch carries a signed `filter_report` with the exact target
selection and original, excluded and unassigned record counts. Source-reported
loss remains separate in `dropped_events`. Original run IDs, sequence ranges,
clock anchors, event times and claimed collection windows remain unchanged.
Intentional exclusions advance the original stream sequence accounting; they
are not relabelled as source loss or as observed activity.

## Verification and completeness

Protocol 14 includes the complete filter report in the signed canonical bytes.
The collector and offline verifier reject inconsistent counts, out-of-scope
retained records and scope fields injected into legacy protocol versions.
Changes to a signed target, label or count invalidate the signature.

Current signed health has no process-scoped coverage model. Therefore every
filtered batch withdraws aggregate coverage, even if it happened to exclude
zero records. Signed positive measurements remain available; absence,
uninterrupted coverage and unobserved business outcomes remain `CannotProve`.
A passing signature check does not establish that a selected logical agent
completed a business action, or that a compromised host reported the truth.

Without `AIP_PROBE_FILTER_PATH`, the probe retains its existing host-scoped
behavior. The customer must explicitly approve that wider metadata scope.

## Compatibility and upgrades

Original protocol 12 and 13 archives remain verifiable without rewriting any
record. Regression tests verify the original 93 batches and six health records
from the preserved Linux Q&A capture, including their separately retained
controller hashes and batch-chain links.

The collector still accepts newly submitted batches only at its current
protocol version. Before a future protocol upgrade, drain queued batches using
their matching probe/collector version and preserve the resulting checkpoint.
Do not rewrite a durable queued payload to the new version, delete a refused
queue, or relax version checking to clear an upgrade refusal. Scope changes
also leave already buffered original batches and their original signed scope
intact.

Full-sensor service installation and testing on separately administered Linux
hosts have separate acceptance gates. These filter implementation and regression
tests do not close those gates.
