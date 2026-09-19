//! The tool gateway's countersigned receipt (R4 of
//! `docs/pilot/RBI_REQUIREMENTS_COVERAGE.md`).
//!
//! # Why a third signer at the tool boundary
//!
//! A `ToolInvocation` is the agent's own statement of what it asked a tool
//! to do. The decision point's `ExpectedExecution` is what was authorized.
//! Neither says what the tool **received**. Inside a regulated entity the
//! tool is a payments switch, a core-banking API or a loan ledger, and the
//! question a supervisor asks after a disputed transaction is exactly that
//! one: was the request that reached the system the request that was
//! authorized?
//!
//! The kernel observer cannot answer it. It sees a socket to the gateway's
//! address and never the application payload (invariant I23), so for the
//! `ghost.tool.invoke.v1` action class it produces no action evidence at
//! all. The party that can answer is the gateway itself: it holds the
//! request bytes, it is operated by the institution and not by the agent,
//! and it can recompute the same domain-separated commitment the agent's
//! SDK computed and the decision point sealed.
//!
//! A [`ToolReceipt`] is that statement, signed by the gateway's key. It is
//! not observation and it is not a verdict:
//!
//! - It says what the gateway received and what it did with it. It does not
//!   say the downstream effect occurred (the switch may have acknowledged
//!   and failed) and this crate never treats it as if it did.
//! - It carries **commitments**, never arguments. An amount, a beneficiary,
//!   an account number appear nowhere in a receipt.
//! - A gateway anchored under the agent's own key is refused
//!   ([`ReceiptError::GatewayKeyIsAgentKey`]): a receipt the agent can sign is
//!   the agent's self-report wearing another name, the same rule the
//!   reconciler applies to a decision point (I1) and an observer (I10).

use std::collections::BTreeMap;

use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_types::canonical::{
    put_bytes, put_domain, put_opt_str, put_str, put_u16, put_u32, put_u64, put_u8,
};
use aip_types::{AipError, Signature};
use serde::{Deserialize, Serialize};

use crate::ids::ToolCallId;
use crate::provenance::put_opt_digest;

/// Domain tag leading the canonical encoding. Distinct from the AIRI event
/// domain, so a receipt cannot be presented as an agent event or vice versa.
pub const TOOL_RECEIPT_DOMAIN: &str = "GHOST/AIRI/ToolReceipt/v1";

/// Structure version. A verifier refuses any other value rather than
/// interpreting it.
pub const TOOL_RECEIPT_VERSION: u16 = 1;

/// Upper bound on each free-text field of a receipt.
pub const MAX_RECEIPT_FIELD_LEN: usize = 4096;

/// What the gateway says it did with the request it received. A claim by
/// the gateway about its own behaviour, not evidence of a downstream effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayDisposition {
    /// The gateway forwarded the request to the tool and the tool answered.
    Forwarded,
    /// The gateway refused the request before it reached the tool.
    Refused,
    /// The gateway forwarded the request and the tool did not answer, or
    /// answered with a transport failure.
    Failed,
}

impl GatewayDisposition {
    pub fn code(self) -> u8 {
        match self {
            Self::Forwarded => 0x01,
            Self::Refused => 0x02,
            Self::Failed => 0x03,
        }
    }
}

/// The gateway's statement of one request it received.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolReceipt {
    pub version: u16,
    /// The gateway that signed. A verifier maps `(gateway_id, key_version)`
    /// to an anchor it was provisioned with.
    pub gateway_id: String,
    pub key_version: u32,
    /// The decision the request cited. The gateway copies it from the
    /// request's authorization header; it is a join key to the expectation,
    /// not proof the expectation covers the request.
    pub decision_id: [u8; 16],
    /// The agent the request identified itself as.
    pub agent_id: String,
    /// The tool identifier the gateway resolved the request to, in the same
    /// vocabulary the decision point's `tool_invoke_parameters` uses.
    pub tool_id: String,
    /// The gateway's **own** recomputation of the parameter commitment over
    /// the canonical arguments it received, under the AIRI parameter domain.
    /// Never copied from the request.
    pub parameter_commitment: [u8; 32],
    /// The model's tool-call id, when the request carried one.
    pub tool_call_id: Option<ToolCallId>,
    pub disposition: GatewayDisposition,
    /// Commitment to the response the gateway returned, when it returned one.
    pub response_commitment: Option<[u8; 32]>,
    /// The gateway's clock at receipt. The gateway's own; not an anchor.
    pub received_at_ms: u64,
}

impl ToolReceipt {
    /// Domain-tagged, length-prefixed encoding of every field.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(256);
        put_domain(&mut b, TOOL_RECEIPT_DOMAIN);
        put_u16(&mut b, self.version);
        put_str(&mut b, &self.gateway_id);
        put_u32(&mut b, self.key_version);
        put_bytes(&mut b, &self.decision_id);
        put_str(&mut b, &self.agent_id);
        put_str(&mut b, &self.tool_id);
        put_bytes(&mut b, &self.parameter_commitment);
        put_opt_str(&mut b, &self.tool_call_id.as_ref().map(|x| x.0.clone()));
        put_u8(&mut b, self.disposition.code());
        put_opt_digest(&mut b, &self.response_commitment);
        put_u64(&mut b, self.received_at_ms);
        b
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    fn check_structure(&self) -> Result<(), ReceiptError> {
        if self.version != TOOL_RECEIPT_VERSION {
            return Err(ReceiptError::UnsupportedVersion(self.version));
        }
        for (field, s) in [
            ("gateway_id", &self.gateway_id),
            ("agent_id", &self.agent_id),
            ("tool_id", &self.tool_id),
        ] {
            if s.is_empty() {
                return Err(ReceiptError::MissingField(field));
            }
            if s.len() > MAX_RECEIPT_FIELD_LEN {
                return Err(ReceiptError::FieldTooLong {
                    field,
                    len: s.len(),
                    max: MAX_RECEIPT_FIELD_LEN,
                });
            }
        }
        if let Some(id) = &self.tool_call_id {
            if id.0.len() > MAX_RECEIPT_FIELD_LEN {
                return Err(ReceiptError::FieldTooLong {
                    field: "tool_call_id",
                    len: id.0.len(),
                    max: MAX_RECEIPT_FIELD_LEN,
                });
            }
        }
        Ok(())
    }
}

/// A receipt plus the gateway's signature over its canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedToolReceipt {
    pub receipt: ToolReceipt,
    pub attestation: Signature,
}

/// The gateway's signing identity: an id, a key version and the key.
///
/// Constructed on the gateway, never on the agent host. The public key is
/// kept so `signer_id`'s attribution can be checked at construction.
pub struct GatewaySigner {
    gateway_id: String,
    key_version: u32,
    private_key: Vec<u8>,
}

impl GatewaySigner {
    pub fn new(gateway_id: &str, key_version: u32, private_key: &[u8]) -> Result<Self, AipError> {
        if private_key.len() != 32 {
            return Err(AipError::InvalidPublicKey);
        }
        if gateway_id.is_empty() {
            return Err(AipError::MissingRequiredField);
        }
        Ok(Self {
            gateway_id: gateway_id.to_string(),
            key_version,
            private_key: private_key.to_vec(),
        })
    }

    pub fn gateway_id(&self) -> &str {
        &self.gateway_id
    }

    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    /// Sign a receipt. The receipt's `gateway_id` and `key_version` are set
    /// from the signer, so a receipt cannot be signed in another gateway's
    /// name or under another key version.
    pub fn sign(&self, mut receipt: ToolReceipt) -> Result<SignedToolReceipt, ReceiptError> {
        receipt.gateway_id = self.gateway_id.clone();
        receipt.key_version = self.key_version;
        receipt.version = TOOL_RECEIPT_VERSION;
        receipt.check_structure()?;
        let attestation = sign_ed25519(
            &self.private_key,
            &self.gateway_id,
            &receipt.canonical_bytes(),
        )
        .map_err(ReceiptError::Crypto)?;
        Ok(SignedToolReceipt {
            receipt,
            attestation,
        })
    }
}

/// The verifier's trust decision: which gateways, under which key versions.
/// Supplied by the verifier, never by the receipt.
#[derive(Debug, Clone, Default)]
pub struct GatewayTrustAnchors {
    keys: BTreeMap<(String, u32), Vec<u8>>,
}

impl GatewayTrustAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(mut self, gateway_id: &str, key_version: u32, public_key: &[u8]) -> Self {
        self.keys
            .insert((gateway_id.to_string(), key_version), public_key.to_vec());
        self
    }

    pub fn get(&self, gateway_id: &str, key_version: u32) -> Option<&[u8]> {
        self.keys
            .get(&(gateway_id.to_string(), key_version))
            .map(|k| k.as_slice())
    }
}

/// Why a receipt was refused. Every variant is a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    UnsupportedVersion(u16),
    /// The `(gateway_id, key_version)` pair is not anchored. The verifier
    /// has no opinion about gateways it was not provisioned for.
    GatewayNotAnchored {
        gateway_id: String,
        key_version: u32,
    },
    /// `attestation.signer_id` is not the receipt's `gateway_id`.
    SignerIsNotGateway,
    /// The anchored gateway key is the agent's own key.
    GatewayKeyIsAgentKey,
    PayloadHashMismatch,
    SignatureInvalid,
    MissingField(&'static str),
    FieldTooLong {
        field: &'static str,
        len: usize,
        max: usize,
    },
    Crypto(AipError),
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ReceiptError {}

/// A receipt that verified against the verifier's own anchors.
///
/// The field is private and there is no constructor: the only way to obtain
/// one is [`verify_tool_receipt`], so a comparison cannot be handed a
/// receipt nobody checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedToolReceipt(ToolReceipt);

impl VerifiedToolReceipt {
    pub fn receipt(&self) -> &ToolReceipt {
        &self.0
    }
}

/// Verify a receipt against `anchors`. The verifier's anchors win: a receipt
/// cannot name the key it is judged against.
///
/// `agent_public_key` is the key of the agent the decision concerns, when
/// the verifier knows it. If the gateway anchor *is* that key the receipt is
/// refused.
pub fn verify_tool_receipt(
    signed: &SignedToolReceipt,
    anchors: &GatewayTrustAnchors,
    agent_public_key: Option<&[u8]>,
) -> Result<VerifiedToolReceipt, ReceiptError> {
    let r = &signed.receipt;
    r.check_structure()?;
    let key = anchors.get(&r.gateway_id, r.key_version).ok_or_else(|| {
        ReceiptError::GatewayNotAnchored {
            gateway_id: r.gateway_id.clone(),
            key_version: r.key_version,
        }
    })?;
    if let Some(agent_key) = agent_public_key {
        if key == agent_key {
            return Err(ReceiptError::GatewayKeyIsAgentKey);
        }
    }
    if signed.attestation.signer_id != r.gateway_id {
        return Err(ReceiptError::SignerIsNotGateway);
    }
    if signed.attestation.payload_hash != r.digest() {
        return Err(ReceiptError::PayloadHashMismatch);
    }
    match verify_ed25519(key, &signed.attestation) {
        Ok(true) => Ok(VerifiedToolReceipt(r.clone())),
        Ok(false) => Err(ReceiptError::SignatureInvalid),
        Err(e) => Err(ReceiptError::Crypto(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt() -> ToolReceipt {
        ToolReceipt {
            version: TOOL_RECEIPT_VERSION,
            gateway_id: "gw-payments-1".into(),
            key_version: 1,
            decision_id: [0xD1; 16],
            agent_id: "aip1Agent".into(),
            tool_id: "mcp:payments:transfer".into(),
            parameter_commitment: [0x11; 32],
            tool_call_id: Some(ToolCallId("call_1".into())),
            disposition: GatewayDisposition::Forwarded,
            response_commitment: Some([0x22; 32]),
            received_at_ms: 5_000,
        }
    }

    #[test]
    fn canonical_bytes_lead_with_the_domain_tag_and_cover_every_field() {
        let base = receipt();
        let bytes = base.canonical_bytes();
        let tag = TOOL_RECEIPT_DOMAIN.as_bytes();
        assert_eq!(&bytes[4..4 + tag.len()], tag);

        let mut variants: Vec<ToolReceipt> = vec![base.clone()];
        variants.push(ToolReceipt {
            gateway_id: "gw-payments-2".into(),
            ..base.clone()
        });
        variants.push(ToolReceipt {
            key_version: 2,
            ..base.clone()
        });
        variants.push(ToolReceipt {
            decision_id: [0xD2; 16],
            ..base.clone()
        });
        variants.push(ToolReceipt {
            agent_id: "aip1Other".into(),
            ..base.clone()
        });
        variants.push(ToolReceipt {
            tool_id: "mcp:payments:refund".into(),
            ..base.clone()
        });
        variants.push(ToolReceipt {
            parameter_commitment: [0x12; 32],
            ..base.clone()
        });
        variants.push(ToolReceipt {
            tool_call_id: None,
            ..base.clone()
        });
        variants.push(ToolReceipt {
            disposition: GatewayDisposition::Refused,
            ..base.clone()
        });
        variants.push(ToolReceipt {
            response_commitment: None,
            ..base.clone()
        });
        variants.push(ToolReceipt {
            received_at_ms: 5_001,
            ..base.clone()
        });
        let digests: std::collections::BTreeSet<[u8; 32]> =
            variants.iter().map(|v| v.digest()).collect();
        assert_eq!(
            digests.len(),
            variants.len(),
            "a field outside the preimage"
        );
    }

    #[test]
    fn a_signer_cannot_sign_in_another_gateways_name() {
        let kp = aip_crypto::generate_ed25519_keypair();
        let signer = GatewaySigner::new("gw-1", 3, &kp.private_key).unwrap();
        let signed = signer
            .sign(ToolReceipt {
                gateway_id: "gw-impostor".into(),
                key_version: 99,
                ..receipt()
            })
            .unwrap();
        assert_eq!(signed.receipt.gateway_id, "gw-1");
        assert_eq!(signed.receipt.key_version, 3);
        assert_eq!(signed.attestation.signer_id, "gw-1");
        let anchors = GatewayTrustAnchors::new().trust("gw-1", 3, &kp.public_key);
        assert!(verify_tool_receipt(&signed, &anchors, None).is_ok());
    }

    #[test]
    fn a_receipt_with_empty_or_oversized_fields_is_refused_at_signing() {
        let kp = aip_crypto::generate_ed25519_keypair();
        let signer = GatewaySigner::new("gw-1", 1, &kp.private_key).unwrap();
        assert_eq!(
            signer.sign(ToolReceipt {
                tool_id: String::new(),
                ..receipt()
            }),
            Err(ReceiptError::MissingField("tool_id"))
        );
        assert!(matches!(
            signer.sign(ToolReceipt {
                agent_id: "a".repeat(MAX_RECEIPT_FIELD_LEN + 1),
                ..receipt()
            }),
            Err(ReceiptError::FieldTooLong {
                field: "agent_id",
                ..
            })
        ));
    }

    #[test]
    fn the_receipt_round_trips_through_json_and_still_verifies() {
        let kp = aip_crypto::generate_ed25519_keypair();
        let signer = GatewaySigner::new("gw-1", 1, &kp.private_key).unwrap();
        let signed = signer.sign(receipt()).unwrap();
        let json = serde_json::to_string(&signed).unwrap();
        let back: SignedToolReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(back, signed);
        let anchors = GatewayTrustAnchors::new().trust("gw-1", 1, &kp.public_key);
        assert!(verify_tool_receipt(&back, &anchors, None).is_ok());
    }
}
