# Durable buffering and replay contract

This implementation adds a bounded, private probe queue and collector replay
receipts. Component tests cover crash/replay boundaries. They do not establish
customer deployment, power-loss durability on a particular filesystem, sustained
throughput, or separately administered collector custody. Those require the
Linux pilot qualification and its independently retained verification results.

## Collection and queue limits

The sensor loop runs separately from blocking network delivery. Every exported
batch is filtered first, serialized once, and committed with file and directory
`fsync` before the sender can read it. A successful send removes the queue entry
only after the pinned Noise session returns the collector's acknowledgement.
The original batch/run identifiers, timestamps, sequence range and loss counts
are never regenerated for a retry. The queue has no signing key.

| Setting | Default / contract |
| --- | --- |
| `AIP_PROBE_BATCH_INTERVAL_MS` | 2000; accepted range100..60000 milliseconds |
| `AIP_PROBE_SPOOL_DIR` | `spool` beside the configured transport key; the installer uses `/var/lib/aip-probe/spool` |
| `AIP_PROBE_SPOOL_MAX_BYTES` | 268435456 payload bytes (256 MiB) |
| `AIP_PROBE_SPOOL_MAX_BATCHES` | 10000 pending batches |
| Largest individual payload | 1048000 bytes; leaves room for authenticated transport framing |
| Permissions | Queue directory owned by the probe user, no group/other access; files likewise private; final path symlinks refused |
| Recipient binding | Persistent probe ID and pinned collector Noise public key; a changed recipient or identity refuses replay |

Both queue limits apply. At the default two-second interval, the batch-count
limit alone permits about 5 hours 33 minutes of outage; at one second, about
2 hours 46 minutes. Byte capacity can be exhausted sooner, depending on event
volume. Size the queue against measured customer load, filesystem overhead and
available disk space. A queue is not an unlimited retention service.

A private, checksummed `.position` file records both the next enqueue sequence
and the highest acknowledged sequence independently of the surviving payload
files. Payload and directory persistence precede the enqueue checkpoint; the
ACK checkpoint precedes payload deletion. Recovery requires every declared
pending sequence, including the first, last or sole record. It can roll forward
one complete next enqueue and clean up payloads already covered by a durable ACK
checkpoint. Complete adjacent checkpoint staging is recoverable; incomplete,
corrupt or nonadjacent staging refuses startup. A missing checkpoint in an
existing queue is never silently reconstructed from whatever files survived.
An empty, drained queue retains its counters across restart.

Queue exhaustion, a torn/corrupt entry, a missing pending sequence, an I/O error
or an oversized batch stops the probe explicitly. It does not evict pending
records. Complete staging files are recoverable; incomplete staging files remain
on disk and refuse startup. An exclusive lock prevents two probe processes from
using one queue. Configurations sharing a transport-key directory must set distinct
spool directories; an identity mismatch refuses startup instead of sharing data.
Sensor ring loss before a batch is persisted remains possible
and keeps the existing loss/uncertainty semantics. Restarting the probe creates a
new run ID, so a collection interruption is not hidden.

An unreadable or malformed sensor read is not a quiet interval. Acquisition
refuses the incomplete batch and permanently stops that sensor run before
serialization or queue insertion. A caller cannot retry the same sensor set to
publish the failed window later. Previously committed queue entries remain
intact; restart creates a new run identity, and existing collector rules refuse
to backfill the interruption. Kernel-reported loss keeps its existing explicit
loss semantics. This does not claim that volatile, uncommitted observations
survive a failed acquisition.

## Collector receipts and replay

A single shared writer serializes attestations, archive append and replay
receipts across connections. The collector persists its chain position, appends
the signed batch, and flushes the file and containing directory before issuing
an ACK. If persistence fails after chain advancement, later writes/ACKs are
refused until strict recovery; the implementation does not invent a replacement
sequence to continue through a damaged archive.

On startup the receipt index is reconstructed only from a complete signed
archive. Every signature must match the configured collector evidence key;
sequence numbers, predecessor hashes and the final persisted position must
agree. A raw JSON index cannot authorize an ACK. A duplicate batch identity
must have the same canonical content after the collector's existing integrity
assessment. Before repeating an ACK, the collector also re-reads and hashes
that exact previously committed signed archive record. A missing or changed
record cannot be acknowledged merely because a receipt remains in memory.
Retries return the original sequence/head without a new attestation, fresh
coverage or clearing an integrity finding. Conflicting content is rejected.

The current pilot index retains at most **1,000,000 receipts** across all probes.
Its entries use a fixed-size hash of the probe identity. At one batch per second
in total this is about **11.6 days**; at the default two seconds for one probe it
is about **23.1 days**. Ten equally active probes consume this allowance ten
times faster. At capacity, the collector explicitly rejects new batches before
signing and continues acknowledging already committed retries. It never evicts
receipts and silently re-attests an old retry. Inspect session logs for the
`replay receipt capacity exhausted` refusal and plan the epoch duration before
deployment; memory/throughput at maximum retention has not been qualified.

## Restart, upgrade and recovery

The daemon establishes a collector-controlled coverage floor at every startup.
Buffered records from before that floor can still be signed as historical
observations, with the actual later collector receipt time. They cannot create
coverage before collector startup. A window crossing the floor can only cover
its post-start portion, and its end remains the original claimed end. A newly
signed backlog is therefore not fresh observation coverage. Filtered streams
continue to withhold host-wide coverage entirely.

Never delete a spool, archive, receipt history or collector checkpoint to make a
failed continuity check pass. Preserve the complete files, independent anchors,
health records and the observed failure for investigation. Restore a consistent
state/archive/key set from an approved backup and verify it against independently
retained checkpoints. Uninstall and retention operations must preserve pending
spool data and collector evidence unless a separately approved retention action
explicitly covers them.

The current daemon signs the current protocol only. Drain queued batches using
their matching probe/collector version before changing protocol versions; do not
rewrite queued v13 records into v14. Offline verification still accepts sealed
v12/v13 evidence. Likewise, the replay loader currently accepts only the
collector's configured evidence-key version. An archive containing previous key
versions needs an explicit multi-key replay migration, which is not implemented.

There is no in-place receipt eviction, automatic archive segmentation or daemon
key-rotation workflow in this implementation. For a pilot that reaches the
retention limit or needs a new signing identity, stop and export the old epoch,
verify its complete evidence against independent checkpoints, drain or preserve
all old recipient-bound queues, and provision a separately identified new epoch
under an approved enrollment/key ceremony. Reusing the old identity with empty
state is not a supported rotation procedure. The new trust anchors and any
custody claim require independent operator approval.

The queue checkpoint detects missing or corrupt queue members under its retained
local accounting; it is not a hardware-backed anti-rollback anchor. A hostile
root administrator who replaces the entire queue, checkpoint and context can
also replace the probe itself. Independent collector archives and separately
retained checkpoints remain necessary for that trust boundary. Existing queues
from the unpublished pre-checkpoint implementation are refused; no automatic
migration assumes their surviving files are a complete inventory.
