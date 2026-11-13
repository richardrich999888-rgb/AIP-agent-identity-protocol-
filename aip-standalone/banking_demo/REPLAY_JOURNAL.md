# AIRON evidence replay journal

## Design

The adapter stores one version 2 JSONL record per accepted EvidencePacket. Records contain a monotonically increasing sequence, packet/decision/action identifiers, the previous record hash, and an HMAC-SHA-256. The HMAC input has a versioned domain prefix and canonical compact JSON field order. The next link is SHA-256 of the complete authenticated record bytes. Loading checks canonical encoding, identifier shape, version, sequence, link, and MAC before reconstructing replay history.

An adjacent `.lock` file is held using an exclusive, nonblocking OS `flock` for the ReplayStore lifetime. A second process fails startup rather than loading stale history. This is advisory locking: all writers must use this adapter. Unix journal, lock, and key files are opened with no-follow flags and mode `0600`; newly created parent directories use `0700`. Existing journal symlinks and non-regular journal files are rejected. These protections are currently implemented for Unix; non-Unix platforms fail closed for secure file operations/locking.

## Recovery and durability

Complete newline-terminated records are retained. A malformed unterminated final fragment is truncated to the last complete record and synced before startup proceeds, but only if the checkpoint still agrees with that recovered head. An unterminated but complete valid JSON record is accepted as a complete authenticated record, terminated with a newline, and synced. Corruption in a terminated/middle record, empty lines, unsupported versions, invalid IDs, invalid links, or invalid MACs fail startup. The checkpoint must agree with recovered sequence and head hash; a journal ahead of or behind the checkpoint fails closed. Every accepted append is synced before the software checkpoint advances, and success is returned only after both durable operations complete. If checkpoint advancement fails after the journal sync, the request errors, the in-process store fail-stops, and the next startup detects the inconsistency; operator recovery is required.

## Key and checkpoint

For the demo, a random 32-byte key is created from `/dev/urandom` in an adjacent `0600` file and never written into the journal. The checkpoint provider is an explicit interface intended to be replaced by trusted external monotonic storage. The current software provider authenticates the local checkpoint with the same local key and atomically replaces it after journal persistence. It detects accidental/inconsistent state changes while its files/key remain trusted; it does **not** prevent an attacker who can modify or roll back the journal, checkpoint, and key together. A hash chain alone likewise cannot detect rollback to an older complete chain.

## Security claims and deployment requirements

- In-process replay: serialized by the Tokio mutex.
- Cross-process replay: serialized among cooperating adapter processes by the OS lock.
- Tamper evidence: record MAC and hash chain detect edits, deletion, and reordering while the software key is protected.
- Rollback resistance: not achieved by this software-only checkpoint.
- Hardware-backed protection: not implemented or claimed.

Enterprise deployment still requires protected key custody and an external monotonic checkpoint, such as an ATECC608B-backed design or trusted remote service. Such integration must define atomic counter/checkpoint update semantics, recovery for a journal durable before a failed counter advance, device provisioning, key rotation, backup/restore behavior, and multi-host ownership. The ATECC608B integration must not treat a software copy of its checkpoint as authoritative. Existing version 1 journals are unauthenticated and are intentionally rejected; migration requires an explicit trusted migration procedure rather than implicit acceptance.

This implementation demonstrates local durable replay-state handling and tamper detection under the stated file/key assumptions. It does not prove protection against root, storage snapshots/rollback, compromised host/kernel, non-cooperating writers, or multi-host deployments.
