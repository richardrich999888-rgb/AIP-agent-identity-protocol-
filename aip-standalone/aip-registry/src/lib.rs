//! `aip-registry` — the institution's signed map from network endpoints to
//! **named resources** (R1 of `docs/pilot/RBI_REQUIREMENTS_COVERAGE.md`).
//!
//! The observer sees addresses and ports. An auditor, a board and a
//! supervisor need to read "core banking API", "payments switch", "customer
//! data store". This crate is the one place that translation happens, and it
//! is designed so the translation cannot be argued with afterwards:
//!
//! - **Signed by the institution.** A registry is a statement by the
//!   regulated entity about its own estate; it is signed under the entity's
//!   key and verified against an anchor the verifier holds. A verifier that
//!   accepts an unsigned registry lets anyone rename the payments switch
//!   "test system".
//! - **Versioned and time-bounded.** Every registry carries a monotone
//!   `revision` and a `valid_from_ms`; a verdict or ledger names the revision
//!   it resolved against, so a later edit cannot silently re-label past
//!   evidence.
//! - **Unambiguous at load.** Two entries that could both match one endpoint
//!   are refused before the registry is ever used
//!   ([`RegistryError::Overlap`]). Resolution is therefore a total,
//!   deterministic function: exactly one resource, or **unregistered**.
//! - **"Unregistered" is an answer, not a gap.** An endpoint the institution
//!   never named is reported as such; nothing is inferred from a hostname,
//!   a reverse lookup or a port convention. The absence of a name is itself
//!   evidence an auditor wants to see.
//!
//! What this crate deliberately does not do: it does not resolve names
//! behind a shared gateway address (that needs the gateway's cooperation and
//! is documented as a trust assumption), it does not read DNS, and it holds
//! no key — signing is done by the caller with the institution's custodian.
//!
//! Dependency direction: `aip-types` and `aip-crypto` only. The observer,
//! the reconciler and the ledger consume this crate; it consumes none of
//! them, so a registry can never influence what was observed.

use std::collections::{BTreeSet, HashMap};

use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_types::canonical::*;
use aip_types::{CapabilityScope, ScopeAction, Signature};
use serde::{Deserialize, Serialize};

/// Domain tag leading the canonical encoding of a [`ResourceRegistry`].
pub const RESOURCE_REGISTRY_DOMAIN: &str = "GHOST/ResourceRegistry/v1";
/// Wire version of [`ResourceRegistry`].
pub const RESOURCE_REGISTRY_VERSION: u16 = 1;
/// Longest permitted resource id, in bytes. Chosen so that
/// [`RESOURCE_SCOPE_PREFIX`] plus an id fits a `ScopeAction::Custom` (64
/// bytes): a resource grant rides inside the existing signed, attenuating
/// capability scope with no change to any token's wire format.
pub const MAX_RESOURCE_ID_LEN: usize = 60;
/// Prefix that marks a `ScopeAction::Custom` as a **resource grant** rather
/// than an action. `res:core-banking-api` in a token's `allowed` list grants
/// the agent that resource; in `denied` it withholds it, overriding any
/// grant above it in the chain. Grants attenuate down a delegation chain
/// exactly as actions do (`child.allowed ⊆ parent.allowed`), and are covered
/// by the issuer's signature exactly as actions are.
pub const RESOURCE_SCOPE_PREFIX: &str = "res:";
/// Longest permitted display name, in bytes.
pub const MAX_DISPLAY_NAME_LEN: usize = 256;

// ─── Vocabulary ───

/// How much a resource matters to the institution. Carried into verdict
/// presentation and incident bundles; never into evidence strength, which
/// is a property of how something was observed, not of what it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Criticality {
    /// Read-only or informational systems.
    Informational,
    /// Systems whose disruption impairs operations but moves no money.
    Operational,
    /// Systems in or adjacent to the transaction path: core banking,
    /// payment switches, settlement, customer data of record.
    TransactionCritical,
}

impl Criticality {
    pub fn code(&self) -> u8 {
        match self {
            Criticality::Informational => 0x01,
            Criticality::Operational => 0x02,
            Criticality::TransactionCritical => 0x03,
        }
    }
}

/// Transport protocol a resource is reached over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    /// The resource is reached over either protocol; matches both.
    Any,
}

impl Protocol {
    pub fn code(&self) -> u8 {
        match self {
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Any => 0,
        }
    }

    /// Whether an observed transport protocol falls under this entry.
    fn admits(&self, observed: ObservedProtocol) -> bool {
        matches!(
            (self, observed),
            (Protocol::Any, _)
                | (Protocol::Tcp, ObservedProtocol::Tcp)
                | (Protocol::Udp, ObservedProtocol::Udp)
        )
    }

    /// Whether two entries' protocols could both match one endpoint.
    fn intersects(&self, other: &Protocol) -> bool {
        matches!(
            (self, other),
            (Protocol::Any, _)
                | (_, Protocol::Any)
                | (Protocol::Tcp, Protocol::Tcp)
                | (Protocol::Udp, Protocol::Udp)
        )
    }
}

/// The protocol of an observed endpoint. Never `Any`: an observation is
/// always one or the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObservedProtocol {
    Tcp,
    Udp,
}

// ─── Address and port ranges ───

/// A CIDR range. IPv4 addresses occupy the **first** four bytes of `addr`
/// with `is_v6 == false` and `prefix_len <= 32` — the same layout the
/// observer uses for `SocketEndpoint`, so an observed address is compared
/// byte for byte with no re-encoding in between; IPv6 fills all 16 with
/// `prefix_len <= 128`. Host bits below the prefix are ignored on match and
/// must be zero in a well-formed entry, so two spellings of one range have
/// one canonical encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AddressRange {
    pub is_v6: bool,
    pub addr: [u8; 16],
    pub prefix_len: u8,
}

impl AddressRange {
    /// An IPv4 range from dotted octets and a prefix length.
    pub fn v4(octets: [u8; 4], prefix_len: u8) -> Self {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&octets);
        AddressRange {
            is_v6: false,
            addr,
            prefix_len,
        }
    }

    /// A single IPv4 host.
    pub fn v4_host(octets: [u8; 4]) -> Self {
        Self::v4(octets, 32)
    }

    /// An IPv6 range.
    pub fn v6(addr: [u8; 16], prefix_len: u8) -> Self {
        AddressRange {
            is_v6: true,
            addr,
            prefix_len,
        }
    }

    fn address_bits(&self) -> u8 {
        if self.is_v6 {
            128
        } else {
            32
        }
    }

    /// The bytes of the address that carry the family's bits (16 for v6,
    /// the first 4 for v4).
    fn family_bytes(addr: &[u8; 16], is_v6: bool) -> &[u8] {
        if is_v6 {
            &addr[..]
        } else {
            &addr[..4]
        }
    }

    fn well_formed(&self) -> Result<(), RegistryError> {
        if self.prefix_len > self.address_bits() {
            return Err(RegistryError::BadPrefix {
                prefix_len: self.prefix_len,
                is_v6: self.is_v6,
            });
        }
        if !self.is_v6 && self.addr[4..] != [0u8; 12] {
            return Err(RegistryError::V4WithHighBytes);
        }
        // Host bits below the prefix must be zero: one range, one spelling.
        if !host_bits_zero(Self::family_bytes(&self.addr, self.is_v6), self.prefix_len) {
            return Err(RegistryError::HostBitsSet);
        }
        Ok(())
    }

    /// Whether `addr` (same family) lies in this range.
    fn contains(&self, is_v6: bool, addr: &[u8; 16]) -> bool {
        if is_v6 != self.is_v6 {
            return false;
        }
        prefix_equal(
            Self::family_bytes(&self.addr, self.is_v6),
            Self::family_bytes(addr, is_v6),
            self.prefix_len,
        )
    }

    /// Whether two ranges share any address. Same family, and the shorter
    /// prefix contains the other's network address.
    fn intersects(&self, other: &AddressRange) -> bool {
        if self.is_v6 != other.is_v6 {
            return false;
        }
        let shorter = self.prefix_len.min(other.prefix_len);
        prefix_equal(
            Self::family_bytes(&self.addr, self.is_v6),
            Self::family_bytes(&other.addr, other.is_v6),
            shorter,
        )
    }
}

/// True when the first `bits` bits of `a` and `b` agree.
fn prefix_equal(a: &[u8], b: &[u8], bits: u8) -> bool {
    let full = (bits / 8) as usize;
    let rem = bits % 8;
    if a[..full] != b[..full] {
        return false;
    }
    if rem == 0 {
        return true;
    }
    let mask: u8 = 0xFF << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

/// True when every bit below `bits` is zero.
fn host_bits_zero(a: &[u8], bits: u8) -> bool {
    let full = (bits / 8) as usize;
    let rem = bits % 8;
    if rem != 0 {
        let mask: u8 = 0xFF >> rem;
        if a[full] & mask != 0 {
            return false;
        }
        return a[full + 1..].iter().all(|&b| b == 0);
    }
    a[full..].iter().all(|&b| b == 0)
}

/// An inclusive port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortRange {
    pub from: u16,
    pub to: u16,
}

impl PortRange {
    pub fn single(port: u16) -> Self {
        PortRange {
            from: port,
            to: port,
        }
    }

    fn well_formed(&self) -> Result<(), RegistryError> {
        if self.from > self.to {
            return Err(RegistryError::PortRangeInverted {
                from: self.from,
                to: self.to,
            });
        }
        Ok(())
    }

    fn contains(&self, port: u16) -> bool {
        self.from <= port && port <= self.to
    }

    fn intersects(&self, other: &PortRange) -> bool {
        self.from <= other.to && other.from <= self.to
    }
}

// ─── Entries and the registry ───

/// One named resource: an id the ledger and verdicts will carry, a display
/// name for humans, and the endpoint set it occupies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceEntry {
    /// Stable identifier, `[A-Za-z0-9._-]`, 1..=128 bytes. What every
    /// downstream artefact cites.
    pub id: String,
    /// Human-readable name, 1..=256 bytes. Display only; not a key.
    pub display_name: String,
    pub criticality: Criticality,
    pub protocol: Protocol,
    /// At least one range.
    pub addresses: Vec<AddressRange>,
    /// At least one range.
    pub ports: Vec<PortRange>,
}

impl ResourceEntry {
    fn well_formed(&self) -> Result<(), RegistryError> {
        if self.id.is_empty() || self.id.len() > MAX_RESOURCE_ID_LEN {
            return Err(RegistryError::BadId(self.id.clone()));
        }
        if !self
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
        {
            return Err(RegistryError::BadId(self.id.clone()));
        }
        if self.display_name.is_empty() || self.display_name.len() > MAX_DISPLAY_NAME_LEN {
            return Err(RegistryError::BadDisplayName(self.id.clone()));
        }
        if self.addresses.is_empty() {
            return Err(RegistryError::NoAddresses(self.id.clone()));
        }
        if self.ports.is_empty() {
            return Err(RegistryError::NoPorts(self.id.clone()));
        }
        for a in &self.addresses {
            a.well_formed()?;
        }
        for p in &self.ports {
            p.well_formed()?;
        }
        Ok(())
    }

    /// Whether this entry names the endpoint.
    fn matches(&self, protocol: ObservedProtocol, is_v6: bool, addr: &[u8; 16], port: u16) -> bool {
        self.protocol.admits(protocol)
            && self.ports.iter().any(|p| p.contains(port))
            && self.addresses.iter().any(|a| a.contains(is_v6, addr))
    }

    /// Whether some endpoint could match both entries.
    fn could_overlap(&self, other: &ResourceEntry) -> bool {
        self.protocol.intersects(&other.protocol)
            && self
                .ports
                .iter()
                .any(|p| other.ports.iter().any(|q| p.intersects(q)))
            && self
                .addresses
                .iter()
                .any(|a| other.addresses.iter().any(|b| a.intersects(b)))
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        put_str(buf, &self.id);
        put_str(buf, &self.display_name);
        put_u8(buf, self.criticality.code());
        put_u8(buf, self.protocol.code());
        put_u32(buf, self.addresses.len() as u32);
        for a in &self.addresses {
            put_u8(buf, u8::from(a.is_v6));
            buf.extend_from_slice(&a.addr);
            put_u8(buf, a.prefix_len);
        }
        put_u32(buf, self.ports.len() as u32);
        for p in &self.ports {
            put_u16(buf, p.from);
            put_u16(buf, p.to);
        }
    }
}

/// The institution's signed resource registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRegistry {
    pub version: u16,
    /// Names the registry (one institution may keep several: per segment,
    /// per data centre). Downstream artefacts cite `(registry_id, revision)`.
    pub registry_id: String,
    /// The institution identity whose key signs this registry.
    pub issuer_id: String,
    /// Monotone per `registry_id`. A verifier that has seen revision N
    /// refuses a later-presented revision below N for the same id.
    pub revision: u64,
    /// The instant from which this revision describes the estate.
    pub valid_from_ms: u64,
    /// Sorted ascending by `id`, unique, pairwise non-overlapping.
    pub entries: Vec<ResourceEntry>,
    pub signature: Signature,
}

/// Why a registry is refused. Every variant is a refusal to resolve against
/// a registry that could name an endpoint two ways or that the institution
/// did not sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    UnsupportedVersion(u16),
    EmptyRegistryId,
    EmptyIssuerId,
    BadId(String),
    BadDisplayName(String),
    NoAddresses(String),
    NoPorts(String),
    BadPrefix {
        prefix_len: u8,
        is_v6: bool,
    },
    V4WithHighBytes,
    HostBitsSet,
    PortRangeInverted {
        from: u16,
        to: u16,
    },
    EntriesNotSorted,
    DuplicateId(String),
    /// Two entries could both name one endpoint. Refused at load so that
    /// resolution is a function.
    Overlap {
        a: String,
        b: String,
    },
    UntrustedIssuer(String),
    SignerMismatch,
    PayloadHashMismatch,
    SignatureInvalid,
    SigningFailed(String),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RegistryError {}

/// Issuer id → Ed25519 public key. The verifier's own anchors; a registry
/// never carries the key that verifies it.
#[derive(Debug, Clone, Default)]
pub struct RegistryTrustAnchors {
    keys: HashMap<String, Vec<u8>>,
}

impl RegistryTrustAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(mut self, issuer_id: &str, public_key: &[u8]) -> Self {
        self.keys.insert(issuer_id.to_owned(), public_key.to_vec());
        self
    }

    pub fn get(&self, issuer_id: &str) -> Option<&[u8]> {
        self.keys.get(issuer_id).map(Vec::as_slice)
    }
}

/// The outcome of resolving one endpoint. Total: every endpoint resolves to
/// exactly one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution<'a> {
    /// The institution named this endpoint.
    Resource(&'a ResourceEntry),
    /// The institution did not. An answer, not a gap: nothing is inferred.
    Unregistered,
}

impl ResourceRegistry {
    /// Build and sign a registry under the issuer's key. Entries are sorted
    /// by id here so the caller's order never leaks into the signed bytes.
    /// Refuses a registry that is not well-formed: the institution cannot
    /// sign an ambiguous estate.
    pub fn sign(
        registry_id: &str,
        issuer_id: &str,
        issuer_private_key: &[u8],
        revision: u64,
        valid_from_ms: u64,
        mut entries: Vec<ResourceEntry>,
    ) -> Result<Self, RegistryError> {
        entries.sort_by(|a, b| a.id.cmp(&b.id));
        let mut reg = ResourceRegistry {
            version: RESOURCE_REGISTRY_VERSION,
            registry_id: registry_id.to_owned(),
            issuer_id: issuer_id.to_owned(),
            revision,
            valid_from_ms,
            entries,
            signature: placeholder_signature(issuer_id),
        };
        reg.check_well_formed()?;
        reg.signature = sign_ed25519(issuer_private_key, issuer_id, &reg.signing_preimage())
            .map_err(|e| RegistryError::SigningFailed(e.to_string()))?;
        Ok(reg)
    }

    /// The exact bytes hashed into `signature.payload_hash`. Injective: every
    /// field is fixed-width or length-prefixed, and the entry list is
    /// length-prefixed with each entry's own length-prefixed fields.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, RESOURCE_REGISTRY_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.registry_id);
        put_str(&mut buf, &self.issuer_id);
        put_u64(&mut buf, self.revision);
        put_u64(&mut buf, self.valid_from_ms);
        put_u32(&mut buf, self.entries.len() as u32);
        for e in &self.entries {
            let mut inner = Vec::new();
            e.encode(&mut inner);
            put_bytes(&mut buf, &inner);
        }
        buf
    }

    /// Structural checks, independent of any key: version, ids, ranges,
    /// ordering, uniqueness and pairwise non-overlap.
    pub fn check_well_formed(&self) -> Result<(), RegistryError> {
        if self.version != RESOURCE_REGISTRY_VERSION {
            return Err(RegistryError::UnsupportedVersion(self.version));
        }
        if self.registry_id.is_empty() {
            return Err(RegistryError::EmptyRegistryId);
        }
        if self.issuer_id.is_empty() {
            return Err(RegistryError::EmptyIssuerId);
        }
        for e in &self.entries {
            e.well_formed()?;
        }
        for w in self.entries.windows(2) {
            match w[0].id.cmp(&w[1].id) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    return Err(RegistryError::DuplicateId(w[0].id.clone()))
                }
                std::cmp::Ordering::Greater => return Err(RegistryError::EntriesNotSorted),
            }
        }
        // Pairwise: quadratic in the entry count, which is small by nature
        // (an estate has hundreds of named systems, not millions), and run
        // once at load. Deterministic order so the same pair is always
        // reported.
        for i in 0..self.entries.len() {
            for j in (i + 1)..self.entries.len() {
                if self.entries[i].could_overlap(&self.entries[j]) {
                    return Err(RegistryError::Overlap {
                        a: self.entries[i].id.clone(),
                        b: self.entries[j].id.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Verify against the verifier's anchors: well-formedness, an anchored
    /// issuer, a signature that names it, the payload hash over this
    /// struct's own preimage, and the Ed25519 signature — in that order.
    pub fn verify(&self, anchors: &RegistryTrustAnchors) -> Result<(), RegistryError> {
        self.check_well_formed()?;
        let key = anchors
            .get(&self.issuer_id)
            .ok_or_else(|| RegistryError::UntrustedIssuer(self.issuer_id.clone()))?;
        if self.signature.signer_id != self.issuer_id {
            return Err(RegistryError::SignerMismatch);
        }
        if self.signature.payload_hash != sha256(&self.signing_preimage()) {
            return Err(RegistryError::PayloadHashMismatch);
        }
        match verify_ed25519(key, &self.signature) {
            Ok(true) => Ok(()),
            _ => Err(RegistryError::SignatureInvalid),
        }
    }

    /// Resolve one observed endpoint. Total and deterministic: at most one
    /// entry can match a well-formed registry, so the first match is the
    /// only match. Callers must have verified the registry; this function
    /// does not re-check, so a caller that resolves against an unverified
    /// registry has chosen to trust it.
    pub fn resolve(
        &self,
        protocol: ObservedProtocol,
        is_v6: bool,
        addr: &[u8; 16],
        port: u16,
    ) -> Resolution<'_> {
        match self
            .entries
            .iter()
            .find(|e| e.matches(protocol, is_v6, addr, port))
        {
            Some(e) => Resolution::Resource(e),
            None => Resolution::Unregistered,
        }
    }

    /// Look an entry up by id.
    pub fn entry(&self, id: &str) -> Option<&ResourceEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// `(registry_id, revision)`: what downstream artefacts cite so a later
    /// revision cannot re-label past evidence.
    pub fn citation(&self) -> (&str, u64) {
        (&self.registry_id, self.revision)
    }
}

// ─── Resource grants inside capability scopes ───

/// The scope action that grants `id`. Inverse of [`resource_id_of`].
pub fn resource_scope_action(id: &str) -> ScopeAction {
    ScopeAction::Custom(format!("{RESOURCE_SCOPE_PREFIX}{id}"))
}

impl ResourceEntry {
    /// The scope action that grants this resource.
    pub fn scope_action(&self) -> ScopeAction {
        resource_scope_action(&self.id)
    }
}

/// The resource id a scope action grants, if it is a resource grant.
pub fn resource_id_of(action: &ScopeAction) -> Option<&str> {
    match action {
        ScopeAction::Custom(s) => s.strip_prefix(RESOURCE_SCOPE_PREFIX),
        ScopeAction::Standard(_) => None,
    }
}

/// The resources a scope grants: every `res:` entry in `allowed` that is
/// not also in `denied`. Explicit deny overrides allow, as for actions.
pub fn granted_resources(scope: &CapabilityScope) -> BTreeSet<String> {
    let denied: BTreeSet<&str> = scope.denied.iter().filter_map(resource_id_of).collect();
    scope
        .allowed
        .iter()
        .filter_map(resource_id_of)
        .filter(|id| !denied.contains(id))
        .map(str::to_owned)
        .collect()
}

/// A structurally valid, obviously unsigned placeholder used while the
/// preimage is computed. Never leaves [`ResourceRegistry::sign`].
fn placeholder_signature(signer_id: &str) -> Signature {
    Signature {
        algorithm: aip_types::AlgorithmId::Ed25519,
        signer_id: signer_id.to_owned(),
        timestamp: 0,
        nonce: [0u8; 16],
        payload_hash: [0u8; 32],
        signature_bytes: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_equal_handles_partial_bytes() {
        assert!(prefix_equal(&[10, 0, 5, 20], &[10, 0, 5, 200], 24));
        assert!(!prefix_equal(&[10, 0, 5, 20], &[10, 0, 6, 20], 24));
        assert!(prefix_equal(
            &[10, 0, 5, 0b1010_0000],
            &[10, 0, 5, 0b1011_1111],
            27
        ));
        assert!(!prefix_equal(
            &[10, 0, 5, 0b1010_0000],
            &[10, 0, 5, 0b1000_0000],
            27
        ));
        assert!(prefix_equal(&[1, 2, 3, 4], &[9, 9, 9, 9], 0));
    }

    #[test]
    fn host_bits_zero_is_strict() {
        assert!(host_bits_zero(&[10, 0, 5, 0], 24));
        assert!(!host_bits_zero(&[10, 0, 5, 1], 24));
        assert!(host_bits_zero(&[10, 0, 5, 0b1010_0000], 27));
        assert!(!host_bits_zero(&[10, 0, 5, 0b1010_0001], 27));
        assert!(host_bits_zero(&[10, 0, 5, 7], 32));
    }

    #[test]
    fn resource_grants_ride_in_the_scope_and_deny_overrides_allow() {
        let scope = CapabilityScope {
            allowed: vec![
                resource_scope_action("core-banking-api"),
                resource_scope_action("payments-switch"),
                ScopeAction::Custom("ghost.net.connect.v1".into()),
            ],
            denied: vec![resource_scope_action("payments-switch")],
        };
        let g = granted_resources(&scope);
        assert_eq!(
            g.into_iter().collect::<Vec<_>>(),
            vec!["core-banking-api".to_owned()]
        );
        assert_eq!(
            resource_id_of(&ScopeAction::Custom("ghost.net.connect.v1".into())),
            None
        );
        assert_eq!(resource_id_of(&resource_scope_action("x")), Some("x"));
    }

    #[test]
    fn a_v4_range_with_host_bits_set_is_not_well_formed() {
        assert_eq!(
            AddressRange::v4([10, 0, 5, 1], 24).well_formed(),
            Err(RegistryError::HostBitsSet)
        );
        assert_eq!(AddressRange::v4([10, 0, 5, 0], 24).well_formed(), Ok(()));
        assert_eq!(
            AddressRange::v4([10, 0, 5, 0], 33).well_formed(),
            Err(RegistryError::BadPrefix {
                prefix_len: 33,
                is_v6: false
            })
        );
    }
}
