use std::collections::{HashMap, HashSet};
use aip_protocol::VerificationContext;
use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct VerificationContextInput {
    #[serde(alias = "trusted_issuers")]
    pub issuer_public_keys: Option<HashMap<String, serde_json::Value>>,
    #[serde(alias = "trusted_counterparties")]
    pub counterparty_public_keys: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub revoked_jtis: Vec<serde_json::Value>,
    #[serde(default)]
    pub trace_data: Option<serde_json::Value>,
    #[serde(default)]
    pub receipt_data: Option<serde_json::Value>,
}

fn parse_key_value(val: &serde_json::Value) -> Result<Vec<u8>, String> {
    match val {
        serde_json::Value::String(s) => {
            let clean = s.trim();
            if let Ok(b) = hex::decode(clean) {
                Ok(b)
            } else if let Ok(b) = bs58::decode(clean).into_vec() {
                Ok(b)
            } else {
                Ok(clean.as_bytes().to_vec())
            }
        }
        serde_json::Value::Array(arr) => {
            let mut bytes = Vec::with_capacity(arr.len());
            for v in arr {
                if let Some(n) = v.as_u64() {
                    bytes.push(n as u8);
                } else {
                    return Err("Key array must contain byte integers".into());
                }
            }
            Ok(bytes)
        }
        _ => Err("Invalid key format; expected hex/base58 string or byte array".into()),
    }
}

pub fn parse_verification_context(json_str: &str) -> Result<VerificationContext, String> {
    let trimmed = json_str.trim();
    if trimmed.is_empty() || trimmed == "{}" {
        return Ok(VerificationContext::new());
    }

    let input: VerificationContextInput = serde_json::from_str(trimmed)
        .map_err(|e| format!("VerificationContext JSON parse error: {e}"))?;

    let mut ctx = VerificationContext::new();

    if let Some(issuers) = input.issuer_public_keys {
        for (id, val) in issuers {
            let pk = parse_key_value(&val)
                .map_err(|e| format!("Invalid public key for issuer {id}: {e}"))?;
            ctx.issuer_public_keys.insert(id, pk);
        }
    }

    if let Some(counterparties) = input.counterparty_public_keys {
        for (id, val) in counterparties {
            let pk = parse_key_value(&val)
                .map_err(|e| format!("Invalid public key for counterparty {id}: {e}"))?;
            ctx.counterparty_public_keys.insert(id, pk);
        }
    }

    let mut revoked = HashSet::new();
    for item in input.revoked_jtis {
        let bytes = match item {
            serde_json::Value::String(s) => {
                let clean = s.replace('-', "").trim().to_string();
                hex::decode(&clean).map_err(|e| format!("Invalid revoked JTI hex '{s}': {e}"))?
            }
            serde_json::Value::Array(arr) => {
                let mut b = Vec::with_capacity(arr.len());
                for v in arr {
                    b.push(v.as_u64().unwrap_or(0) as u8);
                }
                b
            }
            _ => return Err("Invalid revoked JTI format; expected hex string or array".into()),
        };
        if bytes.len() != 16 {
            return Err(format!("Revoked JTI must be exactly 16 bytes, got {}", bytes.len()));
        }
        let mut jti = [0u8; 16];
        jti.copy_from_slice(&bytes);
        revoked.insert(jti);
    }
    ctx.revoked_jtis = revoked;

    if let Some(t) = input.trace_data {
        ctx.trace_data = match t {
            serde_json::Value::String(s) => Some(s.into_bytes()),
            serde_json::Value::Array(arr) => {
                Some(arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect())
            }
            _ => None,
        };
    }

    if let Some(r) = input.receipt_data {
        ctx.receipt_data = match r {
            serde_json::Value::String(s) => Some(s.into_bytes()),
            serde_json::Value::Array(arr) => {
                Some(arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect())
            }
            _ => None,
        };
    }

    Ok(ctx)
}
