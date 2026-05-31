//! Nonce Tracker — Prevents signature replay attacks.
//!
//! Tracks seen (signer_id, nonce) tuples and rejects duplicates.
//! Includes configurable timestamp validation window.

use std::collections::{HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use aip_types::{AipError, Signature};

/// Configuration for the nonce tracker.
#[derive(Debug, Clone)]
pub struct NonceTrackerConfig {
    /// Maximum age of a signature in milliseconds before it's rejected.
    /// Default: 5 minutes (300_000 ms).
    pub max_signature_age_ms: u64,
    /// Maximum number of tracked nonces before oldest are evicted.
    /// Default: 100_000.
    pub max_tracked_nonces: usize,
}

impl Default for NonceTrackerConfig {
    fn default() -> Self {
        Self {
            max_signature_age_ms: 300_000, // 5 minutes
            max_tracked_nonces: 100_000,
        }
    }
}

/// A nonce entry combining signer ID and nonce bytes.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct NonceEntry {
    signer_id: String,
    nonce: [u8; 16],
}

/// Tracks used nonces to prevent signature replay attacks.
///
/// Two checks are performed:
/// 1. **Freshness**: The signature timestamp must be within `max_signature_age_ms` of now.
/// 2. **Uniqueness**: The `(signer_id, nonce)` pair must not have been seen before.
pub struct NonceTracker {
    config: NonceTrackerConfig,
    seen: HashSet<NonceEntry>,
    /// Ordered list for eviction (oldest first).
    order: VecDeque<(u64, NonceEntry)>,
}

impl NonceTracker {
    /// Create a new tracker with default configuration.
    pub fn new() -> Self {
        Self::with_config(NonceTrackerConfig::default())
    }

    /// Create a tracker with custom configuration.
    pub fn with_config(config: NonceTrackerConfig) -> Self {
        Self {
            config,
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Get current time in milliseconds.
    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// Validate a signature's freshness and nonce uniqueness.
    ///
    /// Returns `Ok(())` if the signature passes both checks,
    /// or an appropriate `AipError` if it fails.
    ///
    /// On success, the nonce is recorded and cannot be reused.
    pub fn validate_and_record(&mut self, signature: &Signature) -> Result<(), AipError> {
        let now = Self::now_ms();

        // Check 1: Timestamp freshness
        if signature.timestamp > now + 60_000 {
            // Signature from the future (allow 60s clock skew)
            return Err(AipError::SignatureExpired);
        }
        if now.saturating_sub(signature.timestamp) > self.config.max_signature_age_ms {
            return Err(AipError::SignatureExpired);
        }

        // Check 2: Nonce uniqueness
        let entry = NonceEntry {
            signer_id: signature.signer_id.clone(),
            nonce: signature.nonce,
        };

        if self.seen.contains(&entry) {
            return Err(AipError::NonceReuse);
        }

        // Evict old entries if at capacity
        self.evict_if_needed();

        // Record this nonce
        self.order.push_back((signature.timestamp, entry.clone()));
        self.seen.insert(entry);

        Ok(())
    }

    /// Check if a nonce has been seen before (without recording).
    pub fn is_replay(&self, signature: &Signature) -> bool {
        let entry = NonceEntry {
            signer_id: signature.signer_id.clone(),
            nonce: signature.nonce,
        };
        self.seen.contains(&entry)
    }

    /// Number of tracked nonces.
    pub fn tracked_count(&self) -> usize {
        self.seen.len()
    }

    /// Evict oldest entries if we've exceeded capacity.
    fn evict_if_needed(&mut self) {
        let now = Self::now_ms();

        // First, evict expired entries
        let cutoff = now.saturating_sub(self.config.max_signature_age_ms);
        while let Some((ts, _)) = self.order.front() {
            if *ts >= cutoff {
                break;
            }
            if let Some((_, entry)) = self.order.pop_front() {
                self.seen.remove(&entry);
            }
        }

        // If still over capacity, evict oldest
        while self.order.len() >= self.config.max_tracked_nonces {
            if let Some((_, entry)) = self.order.pop_front() {
                self.seen.remove(&entry);
            } else {
                break;
            }
        }
    }

    /// Clear all tracked nonces.
    pub fn clear(&mut self) {
        self.seen.clear();
        self.order.clear();
    }
}

impl Default for NonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_crypto::{generate_ed25519_keypair, sign_ed25519};
    use aip_types::AlgorithmId;

    #[test]
    fn test_nonce_tracker_accepts_fresh_signature() {
        let mut tracker = NonceTracker::new();
        let kp = generate_ed25519_keypair();
        let sig = sign_ed25519(&kp.private_key, "agent1", b"hello").unwrap();
        assert!(tracker.validate_and_record(&sig).is_ok());
    }

    #[test]
    fn test_nonce_tracker_rejects_replay() {
        let mut tracker = NonceTracker::new();
        let kp = generate_ed25519_keypair();
        let sig = sign_ed25519(&kp.private_key, "agent1", b"hello").unwrap();

        // First use: OK
        assert!(tracker.validate_and_record(&sig).is_ok());
        // Replay: REJECTED
        assert_eq!(tracker.validate_and_record(&sig), Err(AipError::NonceReuse));
    }

    #[test]
    fn test_nonce_tracker_rejects_expired_signature() {
        let mut tracker = NonceTracker::with_config(NonceTrackerConfig {
            max_signature_age_ms: 1_000, // 1 second
            max_tracked_nonces: 100,
        });

        let old_sig = Signature {
            algorithm: AlgorithmId::Ed25519,
            signer_id: "old_agent".to_string(),
            timestamp: 1_000_000, // Way in the past
            nonce: [42u8; 16],
            payload_hash: [0u8; 32],
            signature_bytes: vec![0u8; 64],
        };

        assert_eq!(
            tracker.validate_and_record(&old_sig),
            Err(AipError::SignatureExpired)
        );
    }

    #[test]
    fn test_nonce_tracker_rejects_future_signature() {
        let mut tracker = NonceTracker::new();

        let future_sig = Signature {
            algorithm: AlgorithmId::Ed25519,
            signer_id: "future_agent".to_string(),
            timestamp: NonceTracker::now_ms() + 120_000, // 2 min in future
            nonce: [99u8; 16],
            payload_hash: [0u8; 32],
            signature_bytes: vec![0u8; 64],
        };

        assert_eq!(
            tracker.validate_and_record(&future_sig),
            Err(AipError::SignatureExpired)
        );
    }

    #[test]
    fn test_nonce_tracker_different_signers_same_nonce_ok() {
        let mut tracker = NonceTracker::new();
        let kp1 = generate_ed25519_keypair();
        let kp2 = generate_ed25519_keypair();

        let sig1 = sign_ed25519(&kp1.private_key, "agent1", b"hello").unwrap();
        // Create a signature from agent2 with a manually set matching nonce
        let mut sig2 = sign_ed25519(&kp2.private_key, "agent2", b"hello").unwrap();
        sig2.nonce = sig1.nonce; // Same nonce but different signer

        assert!(tracker.validate_and_record(&sig1).is_ok());
        assert!(tracker.validate_and_record(&sig2).is_ok());
    }

    #[test]
    fn test_nonce_tracker_eviction() {
        let mut tracker = NonceTracker::with_config(NonceTrackerConfig {
            max_signature_age_ms: 300_000,
            max_tracked_nonces: 3,
        });

        let kp = generate_ed25519_keypair();
        for i in 0..5 {
            let sig = sign_ed25519(&kp.private_key, &format!("agent{}", i), b"data").unwrap();
            assert!(tracker.validate_and_record(&sig).is_ok());
        }

        // Should have evicted oldest entries
        assert!(tracker.tracked_count() <= 4);
    }

    #[test]
    fn test_is_replay_check() {
        let mut tracker = NonceTracker::new();
        let kp = generate_ed25519_keypair();
        let sig = sign_ed25519(&kp.private_key, "agent1", b"hello").unwrap();

        assert!(!tracker.is_replay(&sig));
        tracker.validate_and_record(&sig).unwrap();
        assert!(tracker.is_replay(&sig));
    }
}
