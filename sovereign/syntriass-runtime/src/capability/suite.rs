//! Expert validation suites: the only evidence that can make a capability pass.
//!
//! Rationale (defect found in iteration 1 of the runtime loop): validation
//! cases used to live inside the capability artifact, with an unauthenticated
//! `author` string. Whoever proposed a capability could therefore write cases
//! labelled `Expert` by someone else and certify their own procedure. A suite
//! is now a separate object, signed with the expert's Ed25519 key over a
//! domain-separated canonical encoding, and checked against an
//! operator-configured trust anchor. Cases inside an artifact are treated as
//! generated: they can fail a capability, never pass it.

use serde::{Deserialize, Serialize};

/// Domain separator for suite signatures (version-tagged).
const DOMAIN: &[u8] = b"syntriass-expert-suite/v1\n";
/// Upper bound on suite size (bounded validation cost).
pub const MAX_SUITE_CASES: usize = 512;

/// One expert-written or expert-verified case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiteCase {
    pub id: String,
    pub text: String,
    pub expected: String,
    /// Designed to break a naive procedure (scope, validity, boundary, missing input).
    pub counterexample: bool,
}

/// A signed set of cases for one task in one tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpertSuite {
    pub suite_id: String,
    pub tenant: String,
    pub task: String,
    pub expert_id: String,
    pub cases: Vec<SuiteCase>,
    pub signature_hex: String,
}

/// The signed content: every field except the signature, in fixed order.
#[derive(Serialize)]
struct Unsigned<'a> {
    suite_id: &'a str,
    tenant: &'a str,
    task: &'a str,
    expert_id: &'a str,
    cases: &'a [SuiteCase],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuiteError {
    Empty,
    TooLarge,
    DuplicateId(String),
    Sign(String),
}

fn canonical(
    suite_id: &str,
    tenant: &str,
    task: &str,
    expert_id: &str,
    cases: &[SuiteCase],
) -> Vec<u8> {
    // serde_json emits struct fields in declaration order; `cases` is a Vec,
    // so the encoding is deterministic for identical content.
    let body = serde_json::to_vec(&Unsigned {
        suite_id,
        tenant,
        task,
        expert_id,
        cases,
    })
    .unwrap_or_default();
    [DOMAIN, body.as_slice()].concat()
}

fn check_cases(cases: &[SuiteCase]) -> Result<(), SuiteError> {
    if cases.is_empty() {
        return Err(SuiteError::Empty);
    }
    if cases.len() > MAX_SUITE_CASES {
        return Err(SuiteError::TooLarge);
    }
    let mut seen = std::collections::BTreeSet::new();
    for c in cases {
        if !seen.insert(c.id.as_str()) {
            return Err(SuiteError::DuplicateId(c.id.clone()));
        }
    }
    Ok(())
}

impl ExpertSuite {
    /// Sign a suite with the expert's private key.
    pub fn sign(
        suite_id: &str,
        tenant: &str,
        task: &str,
        expert_id: &str,
        cases: Vec<SuiteCase>,
        private_key: &[u8],
    ) -> Result<Self, SuiteError> {
        check_cases(&cases)?;
        let sig = aip_crypto::sign_ed25519_raw(
            private_key,
            &canonical(suite_id, tenant, task, expert_id, &cases),
        )
        .map_err(|e| SuiteError::Sign(format!("{e:?}")))?;
        Ok(Self {
            suite_id: suite_id.into(),
            tenant: tenant.into(),
            task: task.into(),
            expert_id: expert_id.into(),
            cases,
            signature_hex: hex::encode(sig),
        })
    }

    /// Bytes covered by the signature.
    pub fn signed_bytes(&self) -> Vec<u8> {
        canonical(
            &self.suite_id,
            &self.tenant,
            &self.task,
            &self.expert_id,
            &self.cases,
        )
    }

    /// Verify against the expert's public key (offline). Fails closed on any
    /// malformed field or structural violation.
    pub fn verify(&self, public_key: &[u8]) -> bool {
        if check_cases(&self.cases).is_err() {
            return false;
        }
        let Ok(raw) = hex::decode(&self.signature_hex) else {
            return false;
        };
        let Ok(sig) = <[u8; 64]>::try_from(raw.as_slice()) else {
            return false;
        };
        aip_crypto::verify_ed25519_raw(public_key, &self.signed_bytes(), &sig)
    }

    /// Content identity (hex SHA-256 of the signed bytes).
    pub fn hash(&self) -> String {
        hex::encode(aip_crypto::sha256(&self.signed_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Edit = Box<dyn Fn(&mut ExpertSuite)>;

    fn case(id: &str) -> SuiteCase {
        SuiteCase {
            id: id.into(),
            text: "M-1 6.6 kV 100 megohm 40 C PI 2.1".into(),
            expected: "PASS".into(),
            counterexample: false,
        }
    }

    fn suite(kp: &aip_types::KeyPair) -> ExpertSuite {
        ExpertSuite::sign(
            "s1",
            "koravi-process",
            "ir",
            "expert:lead",
            vec![case("a"), case("b")],
            &kp.private_key,
        )
        .unwrap()
    }

    #[test]
    fn signed_suite_verifies_and_hash_is_stable() {
        let kp = aip_crypto::generate_ed25519_keypair();
        let s = suite(&kp);
        assert!(s.verify(&kp.public_key));
        assert_eq!(s.hash(), suite(&kp).hash());
    }

    #[test]
    fn any_edit_breaks_the_signature() {
        let kp = aip_crypto::generate_ed25519_keypair();
        let base = suite(&kp);
        let edits: Vec<Edit> = vec![
            Box::new(|s| s.cases[0].expected = "REJECT".into()),
            Box::new(|s| s.cases[1].text.push('!')),
            Box::new(|s| s.expert_id = "expert:other".into()),
            Box::new(|s| s.tenant = "tarvel-grid".into()),
            Box::new(|s| s.cases.push(case("c"))),
            Box::new(|s| s.cases[0].counterexample = true),
        ];
        for e in edits {
            let mut s = base.clone();
            e(&mut s);
            assert!(!s.verify(&kp.public_key));
        }
    }

    #[test]
    fn wrong_key_or_malformed_signature_fails_closed() {
        let kp = aip_crypto::generate_ed25519_keypair();
        let other = aip_crypto::generate_ed25519_keypair();
        let s = suite(&kp);
        assert!(!s.verify(&other.public_key));
        let mut bad = s.clone();
        bad.signature_hex = "zz".into();
        assert!(!bad.verify(&kp.public_key));
        bad.signature_hex = "00".repeat(10);
        assert!(!bad.verify(&kp.public_key));
    }

    #[test]
    fn structural_limits() {
        let kp = aip_crypto::generate_ed25519_keypair();
        assert_eq!(
            ExpertSuite::sign("s", "t", "x", "e", vec![], &kp.private_key),
            Err(SuiteError::Empty)
        );
        assert_eq!(
            ExpertSuite::sign(
                "s",
                "t",
                "x",
                "e",
                vec![case("a"), case("a")],
                &kp.private_key
            ),
            Err(SuiteError::DuplicateId("a".into()))
        );
    }
}
