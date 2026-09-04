//! Per-connection state: who is calling, on which weights, and what they
//! have read.
//!
//! The context ledger is the interesting half. An agent's context window is
//! normally opaque — the only account of what a model has read is the model's
//! own, which is precisely the thing an injected instruction can lie about.
//! A session here records every piece of content that entered context through
//! the gateway, by URI and digest, with the trust tier the policy assigned it.
//! That record is what [`Session::taint`] reduces, and what gets written into
//! the sealed packet's `contextProvenance`.

use ot_accountability_core::aip::ContextSource;
use ot_accountability_core::authority::TrustTier;
use ot_accountability_core::identity::PrincipalBinding;
use sha2::{Digest, Sha256};

/// Decides how far content from a given origin may be trusted.
pub trait TrustPolicy {
    /// The tier for content read from `uri`.
    fn classify_resource(&self, uri: &str) -> TrustTier;
}

/// A boxed policy is a policy, so a deployment can pick one at runtime
/// without the gateway giving up its static type.
impl<T: TrustPolicy + ?Sized> TrustPolicy for Box<T> {
    fn classify_resource(&self, uri: &str) -> TrustTier {
        (**self).classify_resource(uri)
    }
}

/// Classifies by URI prefix, with everything unmatched falling to
/// [`TrustTier::Untrusted`].
///
/// Fail-closed by construction: a new resource an operator has not thought
/// about is treated as hostile until it is declared otherwise, so forgetting
/// to classify something makes the gateway stricter, never laxer.
#[derive(Debug, Default, Clone)]
pub struct PrefixTrustPolicy {
    rules: Vec<(String, TrustTier)>,
}

impl PrefixTrustPolicy {
    /// A policy that trusts nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Declares that URIs starting with `prefix` carry `tier`. Longer
    /// prefixes win, so a specific rule can carve an exception out of a
    /// broader one regardless of declaration order.
    pub fn declare(mut self, prefix: impl Into<String>, tier: TrustTier) -> Self {
        self.rules.push((prefix.into(), tier));
        self
    }
}

impl TrustPolicy for PrefixTrustPolicy {
    fn classify_resource(&self, uri: &str) -> TrustTier {
        self.rules
            .iter()
            .filter(|(prefix, _)| uri.starts_with(prefix.as_str()))
            .max_by_key(|(prefix, _)| prefix.len())
            .map(|(_, tier)| *tier)
            .unwrap_or(TrustTier::Untrusted)
    }
}

/// The upper bound on retained context entries.
///
/// Long-running sessions must not grow without limit, but a bound must never
/// *lower* the recorded taint — forgetting an untrusted read would hand an
/// attacker a way to launder context by flooding it. So eviction drops the
/// oldest entries while [`Session::high_water_taint`] keeps the maximum tier
/// ever seen, and that is what adjudication uses.
pub const MAX_RETAINED_CONTEXT: usize = 256;

/// One governed connection.
#[derive(Debug, Clone)]
pub struct Session {
    /// The calling agent's DID, from the `initialize` governance envelope.
    pub agent_did: String,
    /// The weights the runtime claims to be executing.
    pub runtime_model_digest: String,
    /// Whether `initialize` has completed.
    pub initialized: bool,
    /// Who the caller was proven to be, once an attestor has established it.
    /// `None` until then, which the gateway refuses to act on.
    pub principal: Option<PrincipalBinding>,
    /// The challenge issued at `initialize`, spent on first successful use.
    challenge: Option<String>,
    context: Vec<ContextSource>,
    high_water: TrustTier,
    evicted: usize,
}

impl Session {
    /// A fresh session for `agent_did` running `runtime_model_digest`.
    pub fn new(agent_did: impl Into<String>, runtime_model_digest: impl Into<String>) -> Self {
        Self {
            agent_did: agent_did.into(),
            runtime_model_digest: runtime_model_digest.into(),
            initialized: false,
            principal: None,
            challenge: None,
            context: Vec::new(),
            high_water: TrustTier::Trusted,
            evicted: 0,
        }
    }

    /// Records content that entered context, returning what was recorded.
    pub fn record_context(
        &mut self,
        uri: impl Into<String>,
        content: &str,
        trust: TrustTier,
    ) -> ContextSource {
        let source = ContextSource {
            uri: uri.into(),
            digest: digest_of(content),
            trust,
        };
        self.high_water = self.high_water.max(trust);
        self.context.push(source.clone());
        if self.context.len() > MAX_RETAINED_CONTEXT {
            let overflow = self.context.len() - MAX_RETAINED_CONTEXT;
            self.context.drain(0..overflow);
            self.evicted += overflow;
        }
        source
    }

    /// Records the challenge this session must answer.
    pub fn set_challenge(&mut self, nonce: Option<String>) {
        self.challenge = nonce;
    }

    /// The outstanding challenge, if any.
    pub fn challenge(&self) -> Option<&str> {
        self.challenge.as_deref()
    }

    /// Consumes the challenge and records the established identity.
    ///
    /// The nonce is spent here rather than at issue: a challenge that
    /// survived a successful authentication would be answerable twice, which
    /// is exactly the replay the nonce exists to prevent.
    pub fn establish(&mut self, principal: PrincipalBinding) {
        self.challenge = None;
        self.principal = Some(principal);
    }

    /// True when the caller has proven who it is.
    pub fn is_authenticated(&self) -> bool {
        self.principal.as_ref().is_some_and(|p| p.is_proven())
    }

    /// The retained context entries, oldest first.
    pub fn context(&self) -> &[ContextSource] {
        &self.context
    }

    /// How many entries were evicted by the retention bound. Non-zero means
    /// `contextProvenance` on later packets is a suffix, not the whole
    /// history — which the seal records rather than hides.
    pub fn evicted_context(&self) -> usize {
        self.evicted
    }

    /// The most-untrusted tier ever recorded on this session.
    ///
    /// Deliberately monotonic: taint does not decay, because there is no way
    /// to establish that a model has forgotten something it read.
    pub fn taint(&self) -> TrustTier {
        self.high_water
    }

    /// Alias for [`Session::taint`], named for the property that matters.
    pub fn high_water_taint(&self) -> TrustTier {
        self.high_water
    }
}

/// Lowercase hex SHA-256 of a string.
pub fn digest_of(content: &str) -> String {
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(content.as_bytes()) {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_for_an_undeclared_origin_is_untrusted() {
        let policy = PrefixTrustPolicy::new()
            .declare("file:///opt/mission/", TrustTier::Trusted)
            .declare("https://intranet.example/", TrustTier::Internal);
        assert_eq!(
            policy.classify_resource("file:///opt/mission/orders.json"),
            TrustTier::Trusted
        );
        assert_eq!(
            policy.classify_resource("https://intranet.example/wiki"),
            TrustTier::Internal
        );
        assert_eq!(
            policy.classify_resource("https://anywhere.else/page"),
            TrustTier::Untrusted
        );
    }

    #[test]
    fn the_longest_matching_prefix_wins_regardless_of_declaration_order() {
        let policy = PrefixTrustPolicy::new()
            // The narrow exception is declared first, the broad rule second.
            .declare("https://intranet.example/uploads/", TrustTier::Untrusted)
            .declare("https://intranet.example/", TrustTier::Internal);
        assert_eq!(
            policy.classify_resource("https://intranet.example/uploads/from-a-vendor.pdf"),
            TrustTier::Untrusted
        );
        assert_eq!(
            policy.classify_resource("https://intranet.example/handbook"),
            TrustTier::Internal
        );
    }

    #[test]
    fn taint_is_monotonic_and_survives_retention_eviction() {
        let mut s = Session::new("did:syntriass:agent:A", "a".repeat(64));
        assert_eq!(s.taint(), TrustTier::Trusted);
        s.record_context("file:///orders", "go", TrustTier::Trusted);
        s.record_context("https://web/page", "hello", TrustTier::Untrusted);
        assert_eq!(s.taint(), TrustTier::Untrusted);
        // Reading something clean afterwards does not launder it.
        s.record_context("file:///orders2", "again", TrustTier::Trusted);
        assert_eq!(s.taint(), TrustTier::Untrusted);

        // Nor does flooding the retention window to push it out.
        for i in 0..MAX_RETAINED_CONTEXT + 10 {
            s.record_context(format!("file:///pad-{i}"), "pad", TrustTier::Trusted);
        }
        assert_eq!(s.context().len(), MAX_RETAINED_CONTEXT);
        assert!(s.evicted_context() > 0);
        assert!(!s.context().iter().any(|c| c.trust == TrustTier::Untrusted));
        // The entry is gone from the retained list, the taint is not.
        assert_eq!(s.taint(), TrustTier::Untrusted);
    }

    #[test]
    fn identical_content_digests_identically() {
        let mut s = Session::new("did:a", "d");
        let a = s.record_context("uri://one", "same bytes", TrustTier::Internal);
        let b = s.record_context("uri://two", "same bytes", TrustTier::Internal);
        assert_eq!(a.digest, b.digest);
        assert_eq!(a.digest.len(), 64);
        assert_ne!(
            a.digest,
            s.record_context("uri://three", "other bytes", TrustTier::Internal)
                .digest
        );
    }
}
