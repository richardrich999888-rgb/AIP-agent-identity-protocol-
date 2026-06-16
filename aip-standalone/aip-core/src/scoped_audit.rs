//! NM-A4: Scope-Constrained Audit Trail Binding
//!
//! ## Patent Claim (IDF Element)
//!
//! "An audit logging mechanism configured to, for each action performed under
//! a delegation token, record in an append-only cryptographically-chained log:
//! the unique identifier of the authorizing delegation token, the effective
//! capability scope at time of action, the delegation depth at time of action,
//! and the identity of the root principal, wherein the log entry hash covers
//! all recorded fields such that any modification to the delegation binding
//! is detectable."
//!
//! ## What This Does
//!
//! Standard Chrono entries: `{event, data, previous_hash, timestamp}`
//!
//! NM-A4 Scoped entries add:
//!
//! ```text
//! {event, data, previous_hash, timestamp,
//!  authorizing_jti: [u8; 16],              // which delegation token
//!  effective_scope_at_action: CapabilityScope,  // scope at time of action
//!  chain_depth_at_action: u8,              // delegation depth
//!  root_principal: AgentId}                // original human authorizer
//! ```
//!
//! The entry hash covers ALL fields including the delegation binding.
//! Any modification to the delegation context is therefore detectable.

use aip_crypto::sha256;
use aip_types::*;
use serde::{Deserialize, Serialize};

/// A single entry in the scope-constrained audit trail.
///
/// This is the core NM-A4 data structure. Every action performed under
/// a delegation token produces one of these entries. The hash chain
/// ensures append-only integrity; the delegation binding fields ensure
/// that the audit trail records not just WHAT happened, but under WHAT
/// AUTHORITY and with WHAT SCOPE it was authorized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopedAuditEntry {
    /// Monotonically increasing sequence number within the audit trail.
    pub sequence: u64,

    /// SHA-256 hash of the previous entry's canonical bytes.
    /// For the first entry (genesis), this is `[0u8; 32]`.
    pub previous_hash: [u8; 32],

    /// Unix timestamp (milliseconds) when this action occurred.
    pub timestamp: u64,

    /// The action event being recorded (e.g., "data.read", "model.execute").
    pub event: String,

    /// Opaque event payload (application-specific).
    pub data: Vec<u8>,

    // ─── NM-A4: Delegation Binding Fields ───
    /// The JTI (unique identifier) of the delegation token that authorized
    /// this action. This is the link back to the delegation chain.
    pub authorizing_jti: [u8; 16],

    /// The effective capability scope at the time this action was performed.
    /// This is the leaf scope from `verify_delegation_chain()` — the most
    /// attenuated (most restricted) scope in the chain.
    pub effective_scope_at_action: CapabilityScope,

    /// The delegation chain depth at the time of action.
    /// 0 = root token (no delegation), 1+ = delegated.
    pub chain_depth_at_action: u8,

    /// The AIP-ID of the root principal — the original human or authority
    /// that issued the root token from which this delegation chain descends.
    pub root_principal: String,

    /// SHA-256 hash of the canonical encoding of this entry (computed on creation).
    /// This hash covers ALL fields above, including the delegation binding.
    pub entry_hash: [u8; 32],
}

impl ScopedAuditEntry {
    /// Compute the canonical byte representation for hashing.
    ///
    /// This is the load-bearing function for NM-A4: the canonical encoding
    /// includes the delegation binding fields, so any tampering with the
    /// authorization context invalidates the hash chain.
    pub fn canonical_bytes_without_hash(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Standard Chrono fields
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.extend_from_slice(&self.previous_hash);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(self.event.as_bytes());
        buf.push(0x00); // separator
        buf.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.data);

        // NM-A4 Delegation binding fields
        buf.extend_from_slice(&self.authorizing_jti);
        // Encode effective scope deterministically
        for action in &self.effective_scope_at_action.allowed {
            buf.push(0x01); // allowed marker
            match action {
                ScopeAction::Standard(a) => {
                    buf.push(0x00);
                    buf.push(*a as u8);
                }
                ScopeAction::Custom(s) => {
                    buf.push(0x01);
                    buf.extend_from_slice(s.as_bytes());
                    buf.push(0x00);
                }
            }
        }
        buf.push(0xFF); // separator between allowed and denied
        for action in &self.effective_scope_at_action.denied {
            buf.push(0x02); // denied marker
            match action {
                ScopeAction::Standard(a) => {
                    buf.push(0x00);
                    buf.push(*a as u8);
                }
                ScopeAction::Custom(s) => {
                    buf.push(0x01);
                    buf.extend_from_slice(s.as_bytes());
                    buf.push(0x00);
                }
            }
        }
        buf.push(self.chain_depth_at_action);
        buf.extend_from_slice(self.root_principal.as_bytes());

        buf
    }

    /// Recompute the entry hash from the canonical bytes.
    pub fn compute_hash(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes_without_hash())
    }

    /// Verify that this entry's hash is correct (not tampered).
    pub fn verify_integrity(&self) -> bool {
        self.entry_hash == self.compute_hash()
    }
}

/// The append-only scope-constrained audit log.
///
/// Each entry's hash covers the previous entry's hash AND the delegation
/// binding fields, creating a tamper-evident chain where modifying any
/// delegation context in any historical entry is immediately detectable.
pub struct ScopedAuditLog {
    pub entries: Vec<ScopedAuditEntry>,
}

impl ScopedAuditLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Create and append a scoped audit entry.
    ///
    /// This is the primary API: record an action along with the full
    /// delegation context that authorized it.
    pub fn record_action(
        &mut self,
        event: &str,
        data: &[u8],
        authorizing_jti: [u8; 16],
        effective_scope: CapabilityScope,
        chain_depth: u8,
        root_principal: &str,
    ) -> &ScopedAuditEntry {
        let sequence = self.entries.len() as u64;
        let previous_hash = if let Some(last) = self.entries.last() {
            last.entry_hash
        } else {
            [0u8; 32] // Genesis
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let mut entry = ScopedAuditEntry {
            sequence,
            previous_hash,
            timestamp: now,
            event: event.to_string(),
            data: data.to_vec(),
            authorizing_jti,
            effective_scope_at_action: effective_scope,
            chain_depth_at_action: chain_depth,
            root_principal: root_principal.to_string(),
            entry_hash: [0u8; 32], // placeholder
        };

        // Compute the hash covering ALL fields
        entry.entry_hash = entry.compute_hash();

        self.entries.push(entry);
        self.entries.last().unwrap()
    }

    /// Verify the entire chain integrity.
    ///
    /// Returns `Ok(())` if every entry's hash is valid and every entry's
    /// `previous_hash` matches the prior entry's `entry_hash`.
    ///
    /// This is the full audit trail verification — if any field in any
    /// entry (including delegation binding) has been modified, this fails.
    pub fn verify_chain(&self) -> Result<(), AuditChainError> {
        let mut expected_prev = [0u8; 32]; // Genesis

        for (i, entry) in self.entries.iter().enumerate() {
            // 1. Check previous_hash linkage
            if entry.previous_hash != expected_prev {
                return Err(AuditChainError::BrokenLink {
                    entry_index: i,
                    expected: hex_encode(&expected_prev),
                    actual: hex_encode(&entry.previous_hash),
                });
            }

            // 2. Check entry hash integrity (covers delegation binding)
            if !entry.verify_integrity() {
                return Err(AuditChainError::TamperedEntry {
                    entry_index: i,
                    field: "entry_hash mismatch — delegation binding or data modified".into(),
                });
            }

            // 3. Check sequence monotonicity
            if entry.sequence != i as u64 {
                return Err(AuditChainError::SequenceGap {
                    entry_index: i,
                    expected: i as u64,
                    actual: entry.sequence,
                });
            }

            expected_prev = entry.entry_hash;
        }

        Ok(())
    }

    /// Find all audit entries authorized by a specific delegation token JTI.
    ///
    /// This is the key query for incident response: "What actions were
    /// performed under this delegation chain?"
    pub fn entries_for_jti(&self, jti: &[u8; 16]) -> Vec<&ScopedAuditEntry> {
        self.entries
            .iter()
            .filter(|e| &e.authorizing_jti == jti)
            .collect()
    }

    /// Find all audit entries authorized by a specific root principal.
    ///
    /// For regulatory compliance: "Show all actions traceable to this
    /// original human authorizer."
    pub fn entries_for_principal(&self, principal: &str) -> Vec<&ScopedAuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.root_principal == principal)
            .collect()
    }

    /// Number of entries in the log.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all entries (read-only).
    pub fn entries(&self) -> &[ScopedAuditEntry] {
        &self.entries
    }
}

impl Default for ScopedAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors detected during audit chain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditChainError {
    /// The `previous_hash` of an entry doesn't match the prior entry's hash.
    BrokenLink {
        entry_index: usize,
        expected: String,
        actual: String,
    },
    /// An entry's computed hash doesn't match its stored hash (data modified).
    TamperedEntry { entry_index: usize, field: String },
    /// Sequence numbers are not monotonically increasing.
    SequenceGap {
        entry_index: usize,
        expected: u64,
        actual: u64,
    },
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ═══════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn scope_read_only() -> CapabilityScope {
        CapabilityScope {
            allowed: vec![ScopeAction::Standard(Action::Read)],
            denied: vec![],
        }
    }

    fn scope_read_write() -> CapabilityScope {
        CapabilityScope {
            allowed: vec![
                ScopeAction::Standard(Action::Read),
                ScopeAction::Standard(Action::Write),
            ],
            denied: vec![],
        }
    }

    fn test_jti() -> [u8; 16] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]
    }

    #[test]
    fn test_single_entry_integrity() {
        let mut log = ScopedAuditLog::new();
        let entry = log.record_action(
            "data.read",
            b"payload",
            test_jti(),
            scope_read_only(),
            1,
            "aip1-root-human",
        );

        assert!(entry.verify_integrity());
        assert_eq!(entry.sequence, 0);
        assert_eq!(entry.previous_hash, [0u8; 32]); // Genesis
        assert_eq!(entry.chain_depth_at_action, 1);
        assert_eq!(entry.root_principal, "aip1-root-human");
    }

    #[test]
    fn test_chain_integrity_valid() {
        let mut log = ScopedAuditLog::new();

        log.record_action(
            "data.read",
            b"first",
            test_jti(),
            scope_read_only(),
            1,
            "root-1",
        );
        log.record_action(
            "data.write",
            b"second",
            test_jti(),
            scope_read_write(),
            1,
            "root-1",
        );
        log.record_action(
            "model.execute",
            b"third",
            [0xAA; 16],
            scope_read_only(),
            3,
            "root-2",
        );

        assert!(log.verify_chain().is_ok());
    }

    #[test]
    fn test_tampered_delegation_jti_detected() {
        let mut log = ScopedAuditLog::new();
        log.record_action(
            "data.read",
            b"action",
            test_jti(),
            scope_read_only(),
            1,
            "root",
        );
        log.record_action(
            "data.write",
            b"action2",
            test_jti(),
            scope_read_write(),
            1,
            "root",
        );

        // Tamper: change the authorizing JTI of the first entry
        log.entries[0].authorizing_jti = [0xFF; 16];

        let result = log.verify_chain();
        assert!(result.is_err(), "Tampered JTI must break chain integrity");
        match result {
            Err(AuditChainError::TamperedEntry { entry_index, .. }) => {
                assert_eq!(entry_index, 0);
            }
            other => panic!("Expected TamperedEntry, got {:?}", other),
        }
    }

    #[test]
    fn test_tampered_scope_detected() {
        let mut log = ScopedAuditLog::new();
        log.record_action(
            "data.read",
            b"action",
            test_jti(),
            scope_read_only(),
            1,
            "root",
        );

        // Tamper: change the effective scope to add Write permission
        log.entries[0]
            .effective_scope_at_action
            .allowed
            .push(ScopeAction::Standard(Action::Write));

        let result = log.verify_chain();
        assert!(result.is_err(), "Tampered scope must break chain integrity");
    }

    #[test]
    fn test_tampered_root_principal_detected() {
        let mut log = ScopedAuditLog::new();
        log.record_action(
            "data.read",
            b"action",
            test_jti(),
            scope_read_only(),
            1,
            "root-human",
        );

        // Tamper: change the root principal
        log.entries[0].root_principal = "attacker-id".to_string();

        let result = log.verify_chain();
        assert!(
            result.is_err(),
            "Tampered principal must break chain integrity"
        );
    }

    #[test]
    fn test_tampered_chain_depth_detected() {
        let mut log = ScopedAuditLog::new();
        log.record_action(
            "data.read",
            b"action",
            test_jti(),
            scope_read_only(),
            1,
            "root",
        );

        // Tamper: change depth from 1 to 0 (pretend it was a root token)
        log.entries[0].chain_depth_at_action = 0;

        let result = log.verify_chain();
        assert!(
            result.is_err(),
            "Tampered chain depth must break chain integrity"
        );
    }

    #[test]
    fn test_broken_link_detected() {
        let mut log = ScopedAuditLog::new();
        log.record_action("first", b"a", test_jti(), scope_read_only(), 1, "root");
        log.record_action("second", b"b", test_jti(), scope_read_only(), 1, "root");

        // Tamper: break the previous_hash link of the second entry
        log.entries[1].previous_hash = [0xDE; 32];
        // Recompute hash to hide the link tampering
        log.entries[1].entry_hash = log.entries[1].compute_hash();

        let result = log.verify_chain();
        assert!(result.is_err());
        match result {
            Err(AuditChainError::BrokenLink { entry_index, .. }) => {
                assert_eq!(entry_index, 1);
            }
            other => panic!("Expected BrokenLink, got {:?}", other),
        }
    }

    #[test]
    fn test_query_by_jti() {
        let mut log = ScopedAuditLog::new();
        let jti_a = [0xAA; 16];
        let jti_b = [0xBB; 16];

        log.record_action("a.1", b"", jti_a, scope_read_only(), 1, "root");
        log.record_action("b.1", b"", jti_b, scope_read_only(), 2, "root");
        log.record_action("a.2", b"", jti_a, scope_read_only(), 1, "root");

        let a_entries = log.entries_for_jti(&jti_a);
        assert_eq!(a_entries.len(), 2);
        assert_eq!(a_entries[0].event, "a.1");
        assert_eq!(a_entries[1].event, "a.2");

        let b_entries = log.entries_for_jti(&jti_b);
        assert_eq!(b_entries.len(), 1);
    }

    #[test]
    fn test_query_by_principal() {
        let mut log = ScopedAuditLog::new();
        log.record_action("op1", b"", test_jti(), scope_read_only(), 1, "human-alice");
        log.record_action("op2", b"", test_jti(), scope_read_only(), 2, "human-bob");
        log.record_action("op3", b"", test_jti(), scope_read_only(), 1, "human-alice");

        let alice = log.entries_for_principal("human-alice");
        assert_eq!(alice.len(), 2);

        let bob = log.entries_for_principal("human-bob");
        assert_eq!(bob.len(), 1);
    }

    #[test]
    fn test_deterministic_hash() {
        // Record same action with fixed timestamp
        let mut entry1 = ScopedAuditEntry {
            sequence: 0,
            previous_hash: [0u8; 32],
            timestamp: 1710000000,
            event: "data.read".into(),
            data: b"payload".to_vec(),
            authorizing_jti: test_jti(),
            effective_scope_at_action: scope_read_only(),
            chain_depth_at_action: 1,
            root_principal: "root".into(),
            entry_hash: [0u8; 32],
        };
        entry1.entry_hash = entry1.compute_hash();

        let mut entry2 = entry1.clone();
        entry2.entry_hash = entry2.compute_hash();

        assert_eq!(
            entry1.entry_hash, entry2.entry_hash,
            "Same inputs must produce same hash (deterministic)"
        );
    }

    #[test]
    fn test_large_chain_integrity() {
        let mut log = ScopedAuditLog::new();

        for i in 0u64..1000 {
            log.record_action(
                &format!("action.{}", i),
                &i.to_le_bytes(),
                test_jti(),
                scope_read_only(),
                (i % 8) as u8,
                "root-principal",
            );
        }

        assert_eq!(log.len(), 1000);
        assert!(log.verify_chain().is_ok(), "1000-entry chain must verify");
    }
}
