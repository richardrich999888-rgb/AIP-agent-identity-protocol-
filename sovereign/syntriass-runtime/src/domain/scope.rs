//! Scope-bound reuse of inference cache state.
//!
//! Rust port of `research/compute-memory/cachescope` (validated there:
//! cross-principal timing probe AUC 1.00 with a shared llama.cpp prompt cache,
//! 0.43 with scoping). Pure: no IO, no clock.
//!
//! Rule (fail closed): attention state produced under one [`CacheScope`] may
//! be reused only by a request carrying an identical scope. Any difference in
//! model, tokenizer, policy, knowledge snapshot, authorization scope or
//! security domain is a miss, and the slot is erased before it serves the new
//! scope, so no request can observe whether another scope's prefix is
//! resident in the slot that serves it.

use serde::{Deserialize, Serialize};

/// Separator between key fields; fields may not contain it.
const SEP: u8 = 0x1f;
/// Upper bound on a field's length (bytes).
const MAX_FIELD: usize = 512;

/// Every dependency that makes cached state valid *and* permitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheScope {
    pub model_sha256: String,
    pub tokenizer_sha256: String,
    pub policy_version: String,
    pub knowledge_snapshot: String,
    /// Canonical authorization scope (tenant + clearance), not a user name.
    pub principal_scope: String,
    pub security_domain: String,
}

/// Why a scope was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    Empty(&'static str),
    Invalid(&'static str),
}

impl CacheScope {
    /// Validate and construct. Every field must be non-empty, ≤ 512 bytes and
    /// free of the separator byte.
    pub fn new(
        model_sha256: &str,
        tokenizer_sha256: &str,
        policy_version: &str,
        knowledge_snapshot: &str,
        principal_scope: &str,
        security_domain: &str,
    ) -> Result<Self, ScopeError> {
        let s = Self {
            model_sha256: model_sha256.into(),
            tokenizer_sha256: tokenizer_sha256.into(),
            policy_version: policy_version.into(),
            knowledge_snapshot: knowledge_snapshot.into(),
            principal_scope: principal_scope.into(),
            security_domain: security_domain.into(),
        };
        for (name, v) in s.fields() {
            if v.is_empty() {
                return Err(ScopeError::Empty(name));
            }
            if v.len() > MAX_FIELD || v.as_bytes().contains(&SEP) {
                return Err(ScopeError::Invalid(name));
            }
        }
        Ok(s)
    }

    fn fields(&self) -> [(&'static str, &str); 6] {
        [
            ("model_sha256", &self.model_sha256),
            ("tokenizer_sha256", &self.tokenizer_sha256),
            ("policy_version", &self.policy_version),
            ("knowledge_snapshot", &self.knowledge_snapshot),
            ("principal_scope", &self.principal_scope),
            ("security_domain", &self.security_domain),
        ]
    }

    /// Deterministic 256-bit key (hex). Field order is part of the contract;
    /// the separator prevents concatenation collisions ("ab"+"c" ≠ "a"+"bc").
    pub fn key(&self) -> String {
        let mut b = Vec::new();
        for (i, (_, v)) in self.fields().iter().enumerate() {
            if i > 0 {
                b.push(SEP);
            }
            b.extend_from_slice(v.as_bytes());
        }
        hex::encode(aip_crypto::sha256(&b))
    }
}

/// What the inference adapter must do before sending a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotDecision {
    pub slot: usize,
    /// Erase the slot's KV state before use (it belongs to another scope).
    pub erase_first: bool,
    /// The slot already holds state from this exact scope.
    pub reuse_allowed: bool,
}

/// Which scope key last wrote each slot (`None` = empty or erased).
#[derive(Debug, Clone)]
pub struct SlotTable {
    owner: Vec<Option<String>>,
    last_use: Vec<u64>,
    tick: u64,
}

impl SlotTable {
    /// Table for `n_slots` server slots. Zero slots is a configuration error.
    pub fn new(n_slots: usize) -> Result<Self, ScopeError> {
        if n_slots == 0 {
            return Err(ScopeError::Invalid("n_slots"));
        }
        Ok(Self {
            owner: vec![None; n_slots],
            last_use: vec![0; n_slots],
            tick: 0,
        })
    }

    /// Pick a slot for `scope` and record it as the slot's owner.
    ///
    /// 1. A slot owned by this exact scope → reuse, no erase.
    /// 2. Else an empty slot → use it (nothing resident to leak).
    /// 3. Else the least-recently-used slot → erase first.
    ///
    /// Ties break on the lowest index, so the choice is deterministic.
    pub fn decide(&mut self, scope: &CacheScope) -> SlotDecision {
        let k = scope.key();
        self.tick += 1;
        let d = if let Some(s) = self.owner.iter().position(|o| o.as_deref() == Some(&k)) {
            SlotDecision {
                slot: s,
                erase_first: false,
                reuse_allowed: true,
            }
        } else if let Some(s) = self.owner.iter().position(Option::is_none) {
            SlotDecision {
                slot: s,
                erase_first: false,
                reuse_allowed: false,
            }
        } else {
            let s = (0..self.owner.len())
                .min_by_key(|&i| (self.last_use[i], i))
                .unwrap_or(0);
            SlotDecision {
                slot: s,
                erase_first: true,
                reuse_allowed: false,
            }
        };
        self.owner[d.slot] = Some(k);
        self.last_use[d.slot] = self.tick;
        d
    }

    /// Release every slot whose owner key satisfies `stale` (e.g. a policy or
    /// snapshot changed). Returns the slots the adapter must erase now.
    pub fn invalidate(&mut self, stale: impl Fn(&str) -> bool) -> Vec<usize> {
        let mut out = Vec::new();
        for (i, o) in self.owner.iter_mut().enumerate() {
            if o.as_deref().is_some_and(&stale) {
                *o = None;
                out.push(i);
            }
        }
        out
    }

    /// Mark a slot empty after an erase failed or the server restarted.
    pub fn forget(&mut self, slot: usize) {
        if let Some(o) = self.owner.get_mut(slot) {
            *o = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sc(scope: &str) -> CacheScope {
        CacheScope::new("m", "t", "p1", "s1", scope, "restricted").unwrap()
    }

    #[test]
    fn same_scope_reuses_after_first_use() {
        let mut t = SlotTable::new(1).unwrap();
        assert!(!t.decide(&sc("a")).reuse_allowed);
        let d = t.decide(&sc("a"));
        assert!(d.reuse_allowed && !d.erase_first);
    }

    #[test]
    fn every_field_change_is_a_miss_that_erases() {
        let base = ["m", "t", "p1", "s1", "a", "restricted"];
        for i in 0..6 {
            let mut f = base.map(String::from);
            f[i].push('x');
            let mut t = SlotTable::new(1).unwrap();
            t.decide(&sc("a"));
            let other = CacheScope::new(&f[0], &f[1], &f[2], &f[3], &f[4], &f[5]).unwrap();
            let d = t.decide(&other);
            assert!(d.erase_first && !d.reuse_allowed, "field {i}");
        }
    }

    #[test]
    fn key_has_no_concatenation_collision() {
        let a = CacheScope::new("m", "t", "ab", "c", "x", "d").unwrap();
        let b = CacheScope::new("m", "t", "a", "bc", "x", "d").unwrap();
        assert_ne!(a.key(), b.key());
        assert_eq!(a.key(), a.clone().key());
    }

    #[test]
    fn matches_python_reference_key() {
        // research/compute-memory/cachescope: CacheScope("m","t","p1","snap1",
        // "finance:payroll","restricted").key()
        let k = CacheScope::new("m", "t", "p1", "snap1", "finance:payroll", "restricted")
            .unwrap()
            .key();
        let py = hex::encode(aip_crypto::sha256(
            b"m\x1ft\x1fp1\x1fsnap1\x1ffinance:payroll\x1frestricted",
        ));
        assert_eq!(k, py);
    }

    #[test]
    fn empty_slot_before_eviction_then_lru() {
        let mut t = SlotTable::new(2).unwrap();
        assert_eq!(t.decide(&sc("a")).slot, 0);
        assert_eq!(t.decide(&sc("b")).slot, 1);
        t.decide(&sc("a"));
        let d = t.decide(&sc("c"));
        assert_eq!(d.slot, 1);
        assert!(d.erase_first);
    }

    #[test]
    fn invalidate_forces_recompute() {
        let mut t = SlotTable::new(2).unwrap();
        let s = sc("a");
        t.decide(&s);
        let k = s.key();
        assert_eq!(t.invalidate(|o| o == k), vec![0]);
        assert!(!t.decide(&s).reuse_allowed);
    }

    #[test]
    fn rejects_bad_fields_and_zero_slots() {
        assert_eq!(
            CacheScope::new("", "t", "p", "s", "a", "d"),
            Err(ScopeError::Empty("model_sha256"))
        );
        assert!(CacheScope::new("m", "t", "p", "s", "a\u{1f}b", "d").is_err());
        assert!(CacheScope::new("m", "t", "p", "s", &"x".repeat(513), "d").is_err());
        assert!(SlotTable::new(0).is_err());
    }
}
