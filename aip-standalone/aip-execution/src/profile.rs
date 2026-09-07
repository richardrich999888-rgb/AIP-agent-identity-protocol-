//! `ExecutionProfile` — one execution, across the stage ladder.
//!
//! # What it composes, and what it does not duplicate
//!
//! Nine of the twelve stages already have authoritative types. This profile
//! **references** them and adds only what was missing:
//!
//! | Stage | Carried by | Here |
//! |---|---|---|
//! | ExpectedExecution | `aip-authorize`, DP-signed | `decision_id` reference |
//! | AI claim, model, tool, runtime report | `aip-airi`, agent-signed chain | `airi_chain_head` reference |
//! | Process / container | `aip-types::ExecutionBinding` | inside `SystemExecution` |
//! | Device / platform | `aip-system` | inside `SystemExecution` |
//! | Independent observation | `aip-observe` | referenced by `EffectEvidence` |
//! | Reconciliation, proof | `aip-reconcile`, `aip-nexora` | not referenced — this is their *input* |
//!
//! References rather than copies, because a copy is a second place for the
//! truth to live and a second place for it to drift.
//!
//! # The signed carrier
//!
//! Skill 17's descriptors are unsigned, deliberately. This profile is unsigned
//! too — and it does not need a signer, because
//! [`ExecutionProfile::authorization_parameter`] binds its digest into
//! something already signed: `ActionParameters`, whose digest the decision
//! point signs as `ExpectedExecution.parameter_digest`.
//!
//! No new trust anchor. No wire-format change. The decision point is also the
//! right authority: it decides what an agent may do, and "for this system, on
//! this platform, for this mission" is part of that decision.
//!
//! **What that establishes:** the context was *authorized*, and cannot be
//! swapped afterwards without breaking the DP signature.
//! **What it does not:** that the execution *ran* in that context. Authorized
//! is not attested. Proving where it ran needs hardware attestation
//! (Skill 19) or independent observation (Skill 20), and this type does not
//! stand in for either.

use aip_crypto::sha256;
use aip_system::SystemExecution;
use aip_types::canonical::{put_bytes, put_domain, put_u16, put_u32, put_u8};
use serde::{Deserialize, Serialize};

use crate::effect::EffectOutcome;
use crate::error::ExecutionError;
use crate::runtime::RuntimeDeclaration;

/// Domain tag leading every `ExecutionProfile` canonical encoding.
pub const EXECUTION_PROFILE_DOMAIN: &str = "SYNTRIASS/AUTONOMY/EXECUTION_PROFILE/v1";

/// Structure version. Unknown versions are refused, never guessed.
pub const EXECUTION_PROFILE_VERSION: u16 = 1;

/// The reserved `ActionParameters` key carrying the execution binding.
///
/// Versioned in the key itself: a v2 binding would use a different key, so a
/// decision point that signed a v1 binding can never be read as having signed
/// a v2 one. That is cheaper and safer than versioning inside the value, where
/// a reader has to remember to look.
pub const BINDING_PARAMETER_KEY: &str = "aip.execution_profile.v1";

/// One execution, composed across the stage ladder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionProfile {
    pub version: u16,
    /// Who ran, as what system, on what platform and hardware, for what
    /// mission. Skill 17's record, embedded whole — its canonical bytes go
    /// into this profile's preimage, so none of those identities can be
    /// swapped without changing the digest the decision point signed.
    pub system_execution: SystemExecution,
    /// The `ExpectedExecution.decision_id` this execution claims.
    ///
    /// A reference, not a copy of the expectation: the expectation is
    /// DP-signed and lives in `aip-authorize`. Copying its fields here would
    /// create a second, unsigned account of what was authorized.
    ///
    /// `None` means no authorization was claimed — a statement a verifier can
    /// act on, and more honest than a fabricated id.
    pub decision_id: Option<[u8; 16]>,
    /// Hash of the head event of the AIRI chain for this execution.
    ///
    /// A commitment to the agent's self-reported account, so the account
    /// cannot be exchanged for a different one after the fact. It remains a
    /// self-report; committing to a claim does not promote it.
    pub airi_chain_head: Option<[u8; 32]>,
    /// What is known about the runtime, by source.
    pub runtime: RuntimeDeclaration,
    /// The external effects this execution requested, each with whatever
    /// disposition the available evidence supports.
    pub effects: Vec<EffectOutcome>,
    /// Unix ms this profile was assembled. Context; not a validity window.
    pub assembled_at_ms: u64,
}

impl ExecutionProfile {
    /// A profile for one execution, claiming nothing further.
    ///
    /// Constructing it grants nothing and asserts nothing about occurrence:
    /// there is no effect, no runtime observation and no authorization claim
    /// until one is added, and adding a claim does not make it true.
    pub fn new(system_execution: SystemExecution, assembled_at_ms: u64) -> Self {
        Self {
            version: EXECUTION_PROFILE_VERSION,
            system_execution,
            decision_id: None,
            airi_chain_head: None,
            runtime: RuntimeDeclaration::new(),
            effects: Vec::new(),
            assembled_at_ms,
        }
    }

    pub fn claiming_decision(mut self, decision_id: [u8; 16]) -> Self {
        self.decision_id = Some(decision_id);
        self
    }
    pub fn with_airi_chain_head(mut self, head: [u8; 32]) -> Self {
        self.airi_chain_head = Some(head);
        self
    }
    pub fn with_runtime(mut self, runtime: RuntimeDeclaration) -> Self {
        self.runtime = runtime;
        self
    }
    pub fn with_effect(mut self, effect: EffectOutcome) -> Self {
        self.effects.push(effect);
        self
    }

    /// Refuse a structure whose version this build does not implement.
    ///
    /// Serde will parse a version-2 record into version-1 fields quite
    /// happily; only this stops those fields being read as though their
    /// meaning were known. It also re-checks the embedded `SystemExecution`,
    /// because a profile is only as well formed as what it contains.
    pub fn check_version(&self) -> Result<(), ExecutionError> {
        if self.version != EXECUTION_PROFILE_VERSION {
            return Err(ExecutionError::UnsupportedVersion {
                found: self.version,
                supported: EXECUTION_PROFILE_VERSION,
            });
        }
        self.system_execution
            .check_version()
            .map_err(|_| ExecutionError::MalformedProfile {
                reason: "embedded system execution failed its own version check",
            })
    }

    /// Domain-tagged, injective canonical bytes.
    ///
    /// Every identity that participates in a security decision is inside
    /// these bytes — the whole embedded `SystemExecution` encoding, the
    /// claimed decision, the AIRI chain commitment, all four runtime slots,
    /// and every effect with its disposition. Nothing that affects
    /// authorization or evidence semantics sits outside the preimage.
    ///
    /// Effects are encoded in supplied order and counted, because order is
    /// meaningful for effects in a way it is not for a set of profiles: two
    /// executions that did the same things in a different sequence did
    /// different things.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, EXECUTION_PROFILE_DOMAIN);
        put_u16(&mut buf, self.version);
        // Length-prefixed so the embedded encoding cannot run into the next
        // field, and so a longer inner record is not a valid prefix.
        put_bytes(&mut buf, &self.system_execution.canonical_bytes());
        match &self.decision_id {
            Some(d) => {
                put_u8(&mut buf, 1);
                put_bytes(&mut buf, d);
            }
            None => put_u8(&mut buf, 0),
        }
        match &self.airi_chain_head {
            Some(h) => {
                put_u8(&mut buf, 1);
                put_bytes(&mut buf, h);
            }
            None => put_u8(&mut buf, 0),
        }
        self.runtime.encode(&mut buf);
        put_u32(&mut buf, self.effects.len() as u32);
        for e in &self.effects {
            e.encode(&mut buf);
        }
        put_bytes(&mut buf, &self.assembled_at_ms.to_le_bytes());
        buf
    }

    /// SHA-256 over [`ExecutionProfile::canonical_bytes`].
    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// The `(key, value)` pair to add to `ActionParameters` so a decision
    /// point signs this execution's context.
    ///
    /// # Usage
    ///
    /// ```ignore
    /// let params = ActionParameters::from_pairs(
    ///     action_params.into_iter().chain([profile.authorization_parameter()])
    /// )?;
    /// // params.digest() → ExpectedExecution.parameter_digest, DP-signed
    /// ```
    ///
    /// The value is the profile digest, not the profile: `ActionParameters`
    /// carries byte strings, and a digest is a complete commitment to a
    /// domain-separated, prefix-free encoding — not a bare hash standing in
    /// for one.
    ///
    /// A verifier that holds the profile recomputes the digest and confirms
    /// the decision point signed *this* context. A verifier that does not hold
    /// it learns only that some context was committed to, which is the correct
    /// amount to learn from a commitment alone.
    pub fn authorization_parameter(&self) -> (String, Vec<u8>) {
        (BINDING_PARAMETER_KEY.to_owned(), self.digest().to_vec())
    }

    /// Whether `parameters` commit to this exact profile.
    ///
    /// Takes the key's value as the caller read it from a verified
    /// `ActionParameters`. Returns `false` for a missing key rather than
    /// erroring: a decision point that committed to no context is a fact to
    /// report, not an exception to raise.
    ///
    /// This function verifies **nothing about the signature** — the caller
    /// must already have verified the `ExpectedExecution` that carries the
    /// parameter digest. Comparing a digest against unverified parameters
    /// proves only that two untrusted things agree.
    pub fn is_committed_by(&self, parameter_value: Option<&[u8]>) -> bool {
        match parameter_value {
            Some(v) => v == self.digest(),
            None => false,
        }
    }
}
