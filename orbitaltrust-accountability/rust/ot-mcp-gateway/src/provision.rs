//! Policy provisioning: signing delegation edges and rotating issuer keys.
//!
//! The logic behind the `ot-provision` binary, in the library so it is
//! unit-testable and so nothing about what gets signed can drift between the
//! tool that signs and the verifier that checks —
//! [`DelegationEdge::canonical_terms`] is the single definition both sides
//! use.
//!
//! # Rotation is one operation, not a sweep
//!
//! A signing key rotation touches three things that must move together:
//! every edge the old key signed needs a fresh signature by the new key, the
//! new key's identity must appear in the policy's `issuers`, and the old
//! key's identity must leave it. Done by hand across a policy file, missing
//! any one of the three either bricks the deployment (edges signed by a key
//! no longer authorised) or defeats the rotation (the compromised key still
//! authorised). [`rotate_issuer`] does all three atomically on the document,
//! and the caller writes the result back in one atomic rename.

use ot_accountability_core::authority::{ClearanceLevel, DelegationEdge, EdgeStatus};
use serde_json::Value;
use std::path::Path;

use crate::trust::{sign_edge, AttestationSigner};

/// Reads a delegation-edge spec out of a policy document's JSON into the
/// typed edge whose canonical terms get signed.
///
/// Strict: an unknown clearance or status is an error, not a default — the
/// tool must never sign terms other than the ones the document states.
fn edge_from_spec(spec: &Value) -> Result<DelegationEdge, String> {
    let text = |key: &str| -> Result<String, String> {
        spec.get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("edge is missing string field {key:?}"))
    };
    let list = |key: &str| -> Vec<String> {
        spec.get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let clearance_text = text("clearanceLevel")?;
    let clearance = ClearanceLevel::parse(&clearance_text)
        .ok_or_else(|| format!("unknown clearance level {clearance_text:?}"))?;
    let status = match spec.get("status").and_then(Value::as_str) {
        None | Some("ACTIVE") => EdgeStatus::Active,
        Some("REVOKED") => EdgeStatus::Revoked,
        Some(other) => return Err(format!("unknown edge status {other:?}")),
    };
    Ok(DelegationEdge {
        edge_id: text("edgeId")?,
        parent_did: text("parentDid")?,
        child_did: text("childDid")?,
        scope: list("scope"),
        multi_sig_tools: list("multiSigTools"),
        clearance_level: clearance,
        valid_from_utc: text("validFromUtc")?,
        expires_at_utc: text("expiresAtUtc")?,
        status,
        signature: None,
    })
}

/// Signs every delegation edge issued by `issuer_did`, in place, and
/// authorises the signing key in the document's `issuers`.
///
/// Returns how many edges were signed. Edges with other parents are left
/// untouched — their issuers sign for themselves.
pub fn sign_policy_edges(
    policy: &mut Value,
    issuer_did: &str,
    signer: &dyn AttestationSigner,
) -> Result<usize, String> {
    let identity = signer.identity_hex();
    let mut signed = 0usize;

    let edges = policy
        .get_mut("delegations")
        .and_then(Value::as_array_mut)
        .ok_or("policy has no `delegations` array")?;
    for spec in edges.iter_mut() {
        if spec.get("parentDid").and_then(Value::as_str) != Some(issuer_did) {
            continue;
        }
        let edge = edge_from_spec(spec)?;
        spec["signature"] = sign_edge(&edge, signer)?;
        signed += 1;
    }

    let issuers = policy
        .as_object_mut()
        .ok_or("policy is not an object")?
        .entry("issuers")
        .or_insert_with(|| Value::Object(Default::default()));
    let keys = issuers
        .as_object_mut()
        .ok_or("`issuers` is not an object")?
        .entry(issuer_did.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let keys = keys.as_array_mut().ok_or("issuer keys are not an array")?;
    if !keys.iter().any(|k| k.as_str() == Some(&identity)) {
        keys.push(Value::String(identity));
    }
    Ok(signed)
}

/// Rotates `issuer_did` from `old_identity` to a new signing key: re-signs
/// every edge the DID issues, authorises the new key, and withdraws the old
/// one — the three moves a rotation is, done together.
///
/// Returns how many edges were re-signed. Refuses when the old identity was
/// not authorised for the DID, because "rotating away" a key that was never
/// there usually means the wrong DID or the wrong key file, and signing
/// anyway would mask that.
pub fn rotate_issuer(
    policy: &mut Value,
    issuer_did: &str,
    old_identity: &str,
    new_signer: &dyn AttestationSigner,
) -> Result<usize, String> {
    let currently_authorised = policy
        .get("issuers")
        .and_then(|i| i.get(issuer_did))
        .and_then(Value::as_array)
        .is_some_and(|keys| keys.iter().any(|k| k.as_str() == Some(old_identity)));
    if !currently_authorised {
        return Err(format!(
            "key {}… is not an authorised issuer for {issuer_did}; nothing to rotate",
            &old_identity[..old_identity.len().min(12)],
        ));
    }

    let signed = sign_policy_edges(policy, issuer_did, new_signer)?;

    let keys = policy
        .get_mut("issuers")
        .and_then(|i| i.get_mut(issuer_did))
        .and_then(Value::as_array_mut)
        .expect("checked above");
    keys.retain(|k| k.as_str() != Some(old_identity));
    Ok(signed)
}

/// Writes a policy document atomically: temp file in the same directory,
/// then rename. A crash mid-write leaves the old policy intact rather than
/// a half-written one that fails to parse — or worse, parses to less than
/// was meant.
pub fn write_policy_atomically(path: impl AsRef<Path>, policy: &Value) -> Result<(), String> {
    let path = path.as_ref();
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let temp = directory.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("policy.json")
    ));
    let text = serde_json::to_string_pretty(policy)
        .map_err(|e| format!("cannot serialize policy: {e}"))?;
    std::fs::write(&temp, text).map_err(|e| format!("cannot write {}: {e}", temp.display()))?;
    std::fs::rename(&temp, path).map_err(|e| format!("cannot replace {}: {e}", path.display()))
}

/// SHA-256 enrolment digest of a DER-encoded credential (e.g. a client
/// certificate), computed exactly the way
/// [`PeerCredential::digest`](crate::identity::PeerCredential) computes it —
/// one definition, so an enrolment printed here always matches what the
/// transport presents.
pub fn credential_digest_of_der(der: &[u8]) -> String {
    use std::fmt::Write;
    let mut hex = String::with_capacity(der.len() * 2);
    for byte in der {
        let _ = write!(hex, "{byte:02x}");
    }
    ot_accountability_core::sha256_hex(&hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::{IssuerRegistry, SignedEdgeVerifier};
    use ot_accountability_core::authority::EdgeVerifier;
    use ot_pqc::{CryptoSuite, SignatureKeyPair};
    use serde_json::json;

    const OFFICER: &str = "did:syntriass:officer:OFF-1";

    fn key(seed: u8) -> SignatureKeyPair {
        SignatureKeyPair::from_seed(CryptoSuite::X25519MlKem1024MlDsa87, &[seed; 32])
            .expect("keygen")
    }

    fn policy() -> Value {
        json!({
            "agent": { "did": "did:syntriass:agent:AGT-1" },
            "delegations": [
                {
                    "edgeId": "edge-1",
                    "parentDid": OFFICER,
                    "childDid": "did:syntriass:agent:AGT-1",
                    "scope": ["read_catalog"],
                    "clearanceLevel": "SECRET",
                    "validFromUtc": "2026-01-01T00:00:00.000Z",
                    "expiresAtUtc": "2027-01-01T00:00:00.000Z"
                },
                {
                    "edgeId": "edge-other",
                    "parentDid": "did:syntriass:officer:SOMEONE-ELSE",
                    "childDid": "did:syntriass:agent:AGT-2",
                    "scope": ["read_catalog"],
                    "clearanceLevel": "SECRET",
                    "validFromUtc": "2026-01-01T00:00:00.000Z",
                    "expiresAtUtc": "2027-01-01T00:00:00.000Z"
                }
            ]
        })
    }

    /// The signed document, read back through the real verifier.
    fn verifies(policy: &Value, edge_index: usize, registry: IssuerRegistry) -> bool {
        let spec = &policy["delegations"][edge_index];
        let mut edge = edge_from_spec(spec).unwrap();
        edge.signature = spec.get("signature").cloned();
        SignedEdgeVerifier::new(registry).verify(&edge)
    }

    #[test]
    fn signing_covers_the_issuers_edges_and_authorises_the_key() {
        let officer = key(1);
        let mut document = policy();
        let signed = sign_policy_edges(&mut document, OFFICER, &officer).unwrap();
        assert_eq!(signed, 1, "only the officer's own edge is signed");
        assert!(document["delegations"][0]["signature"].is_object());
        // Another issuer's edge is not this key's to sign.
        assert!(document["delegations"][1].get("signature").is_none());
        // The key is authorised in the same operation.
        assert_eq!(
            document["issuers"][OFFICER][0],
            json!(officer.verifying_key().identity_hex())
        );
        // And the result verifies under the registry the document now declares.
        let registry =
            IssuerRegistry::new().authorise(OFFICER, officer.verifying_key().identity_hex());
        assert!(verifies(&document, 0, registry));
    }

    #[test]
    fn rotation_reissues_authorises_and_withdraws_in_one_move() {
        let old = key(1);
        let new = key(2);
        let mut document = policy();
        sign_policy_edges(&mut document, OFFICER, &old).unwrap();

        let resigned = rotate_issuer(
            &mut document,
            OFFICER,
            &old.verifying_key().identity_hex(),
            &new,
        )
        .unwrap();
        assert_eq!(resigned, 1);

        // The old key is gone from the document, the new one present.
        let keys = document["issuers"][OFFICER].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], json!(new.verifying_key().identity_hex()));

        // The edge verifies under the new key…
        assert!(verifies(
            &document,
            0,
            IssuerRegistry::new().authorise(OFFICER, new.verifying_key().identity_hex()),
        ));
        // …and no longer under a verifier that still trusts only the old one:
        // the re-signature replaced the old envelope rather than stacking.
        assert!(!verifies(
            &document,
            0,
            IssuerRegistry::new().authorise(OFFICER, old.verifying_key().identity_hex()),
        ));
    }

    #[test]
    fn rotating_a_key_that_was_never_authorised_is_refused() {
        let old = key(1);
        let new = key(2);
        let mut document = policy();
        // Nothing signed, no issuers block at all.
        let err = rotate_issuer(
            &mut document,
            OFFICER,
            &old.verifying_key().identity_hex(),
            &new,
        )
        .unwrap_err();
        assert!(err.contains("nothing to rotate"), "{err}");
        // The document was not half-modified on the way to the refusal.
        assert!(document.get("issuers").is_none());
        assert!(document["delegations"][0].get("signature").is_none());
    }

    #[test]
    fn a_malformed_edge_stops_the_signing_run_rather_than_being_skipped() {
        let officer = key(1);
        let mut document = policy();
        document["delegations"][0]["clearanceLevel"] = json!("SECERT");
        let err = sign_policy_edges(&mut document, OFFICER, &officer).unwrap_err();
        // Signing must never quietly cover fewer edges than the document
        // holds for this issuer — an unsigned edge is a dead edge under a
        // signature-checking verifier, discovered at the worst time.
        assert!(err.contains("SECERT"), "{err}");
    }

    #[test]
    fn atomic_write_replaces_the_file_or_leaves_it_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        std::fs::write(&path, "{\"old\":true}").unwrap();
        write_policy_atomically(&path, &json!({ "new": true })).unwrap();
        let read: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(read, json!({ "new": true }));
        // No temp file left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn the_enrolment_digest_matches_what_the_transport_computes() {
        let der = vec![1u8, 2, 3, 4];
        assert_eq!(
            credential_digest_of_der(&der),
            crate::identity::PeerCredential::ClientCertificate(der)
                .digest()
                .unwrap(),
        );
    }
}
