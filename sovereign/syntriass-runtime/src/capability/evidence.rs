//! S1 — evidence-bound execution. Pure.
//!
//! Round-1 finding: a capability that reads its numbers from free text
//! releases equipment on "if we were to test it, we might expect …" (58 of
//! 172 hypothetical or planned probes), and ≤ 1.5B models cannot tell
//! actual from hypothetical wording. The structural fix: a capability whose
//! policy is [`EvidencePolicy::SignedRecord`] decides only on numbers carried
//! in a [`MeasurementRecord`] signed by a registered instrument (or test
//! set) key for the caller's tenant. Text may still select the capability
//! and trigger its scope guards; it can never supply a number.
//!
//! The record states what was measured, on which asset, when, by which
//! instrument. Whether a reading is real is then a signature check, not a
//! language judgement.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::artifact::Capability;
use super::quantity::{quantities, Kind};

/// Domain separator for record signatures.
pub const RECORD_DOMAIN: &str = "syntriass-measurement-record/v1\n";
/// Bounds on hostile input.
pub const MAX_RECORD_QUANTITIES: usize = 32;
pub const MAX_FIELD_CHARS: usize = 128;

/// How a capability may obtain its input values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidencePolicy {
    /// Numbers are read from the request text (v0.1 behaviour).
    #[default]
    Text,
    /// Numbers come only from a verified, signed measurement record.
    SignedRecord,
}

impl EvidencePolicy {
    /// Serde helper: the default is omitted so existing content hashes are unchanged.
    pub fn is_text(&self) -> bool {
        *self == EvidencePolicy::Text
    }
}

/// One measured quantity. Physical quantities carry the reading as the
/// instrument printed it ("1.1 GΩ", "28 °C"), converted by the same parser
/// the text path uses; dimensionless values carry the cue they belong to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordQuantity {
    Physical { reading: String },
    Cued { cue: String, value: f64 },
}

/// A signed measurement record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeasurementRecord {
    pub record_id: String,
    pub tenant: String,
    pub asset_id: String,
    pub instrument_id: String,
    pub taken_at_ms: u64,
    pub quantities: Vec<RecordQuantity>,
    pub signature_hex: String,
}

/// Why a record cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    Malformed(&'static str),
    UnknownInstrument,
    BadSignature,
    WrongTenant,
    /// Two different values for one input.
    Conflict(String),
    /// A reading the parser does not recognise as a physical quantity.
    Unreadable(String),
}

impl MeasurementRecord {
    /// Bytes covered by the signature: domain separator + canonical JSON of
    /// the record with an empty signature (fixed struct field order).
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut u = self.clone();
        u.signature_hex.clear();
        let mut b = RECORD_DOMAIN.as_bytes().to_vec();
        b.extend(serde_json::to_vec(&u).unwrap_or_default());
        b
    }

    /// Sign with the instrument's private key.
    pub fn sign(mut self, private_key: &[u8]) -> Result<Self, String> {
        self.signature_hex.clear();
        let sig = aip_crypto::sign_ed25519_raw(private_key, &self.signed_bytes())
            .map_err(|e| format!("{e:?}"))?;
        self.signature_hex = hex::encode(sig);
        Ok(self)
    }

    fn well_formed(&self) -> Result<(), RecordError> {
        let short = |s: &str| !s.trim().is_empty() && s.chars().count() <= MAX_FIELD_CHARS;
        if !(short(&self.record_id)
            && short(&self.tenant)
            && short(&self.asset_id)
            && short(&self.instrument_id))
        {
            return Err(RecordError::Malformed("identifier empty or too long"));
        }
        if self.quantities.is_empty() || self.quantities.len() > MAX_RECORD_QUANTITIES {
            return Err(RecordError::Malformed("quantity count"));
        }
        for q in &self.quantities {
            match q {
                RecordQuantity::Physical { reading } if !short(reading) => {
                    return Err(RecordError::Malformed("reading"))
                }
                RecordQuantity::Cued { cue, value } if !short(cue) || !value.is_finite() => {
                    return Err(RecordError::Malformed("cued value"))
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Verify for use by `caller_tenant`, with the operator's instrument
    /// trust anchors (instrument id → Ed25519 public key). Fails closed.
    pub fn verify(
        &self,
        caller_tenant: &str,
        instruments: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), RecordError> {
        self.well_formed()?;
        let key = instruments
            .get(&self.instrument_id)
            .ok_or(RecordError::UnknownInstrument)?;
        let raw = hex::decode(&self.signature_hex).map_err(|_| RecordError::BadSignature)?;
        let sig = <[u8; 64]>::try_from(raw.as_slice()).map_err(|_| RecordError::BadSignature)?;
        if !aip_crypto::verify_ed25519_raw(key, &self.signed_bytes(), &sig) {
            return Err(RecordError::BadSignature);
        }
        if self.tenant != caller_tenant {
            return Err(RecordError::WrongTenant);
        }
        Ok(())
    }
}

/// Map a (verified) record onto a capability's declared inputs, in the
/// runtime's canonical units. Physical inputs match by kind, cued inputs by
/// cue (case-insensitive). A record value that matches no input is ignored;
/// two different values for one input is a conflict (never averaged).
pub fn values_from_record(
    cap: &Capability,
    rec: &MeasurementRecord,
) -> Result<BTreeMap<String, f64>, RecordError> {
    let mut typed: Vec<(Kind, f64)> = vec![];
    let mut cued: Vec<(String, f64)> = vec![];
    for q in &rec.quantities {
        match q {
            RecordQuantity::Physical { reading } => {
                let qs = quantities(reading);
                if qs.len() != 1 {
                    return Err(RecordError::Unreadable(reading.clone()));
                }
                typed.push((qs[0].kind, qs[0].value));
            }
            RecordQuantity::Cued { cue, value } => cued.push((cue.to_lowercase(), *value)),
        }
    }
    let mut out = BTreeMap::new();
    for i in &cap.procedure.inputs {
        let mut vals: Vec<f64> = if i.kind == Kind::Cued {
            let cues: Vec<String> = i.cues.iter().map(|c| c.to_lowercase()).collect();
            cued.iter()
                .filter(|(c, _)| cues.contains(c))
                .map(|(_, v)| *v)
                .collect()
        } else {
            typed
                .iter()
                .filter(|(k, _)| *k == i.kind)
                .map(|(_, v)| *v)
                .collect()
        };
        vals.dedup_by(|a, b| a == b);
        let mut uniq: Vec<f64> = vec![];
        for v in vals {
            if !uniq.contains(&v) {
                uniq.push(v);
            }
        }
        match uniq.len() {
            0 => {}
            1 => {
                out.insert(i.name.clone(), uniq[0]);
            }
            _ => return Err(RecordError::Conflict(i.name.clone())),
        }
    }
    Ok(out)
}
