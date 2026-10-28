//! Public-only enrollment bootstrap. No sensor, network or evidence signer.
use std::path::Path;

use crate::keyfile::TransportKey;

pub fn enroll(probe_id: &str, key_path: &Path) -> Result<serde_json::Value, String> {
    if probe_id.is_empty()
        || probe_id.len() > 128
        || !probe_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        || !key_path.is_absolute()
        || key_path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(
            "explicit bounded probe ID and absolute, traversal-free key path required".into(),
        );
    }
    let key = TransportKey::load_or_generate(key_path)?;
    Ok(serde_json::json!({
        "schema": "vanian.probe-enrollment.v1", "probe_id": probe_id,
        "transport_pubkey_hex": hex::encode(key.public),
        "status": "PUBLIC_KEY_READY", "observation": "NOT_STARTED",
        "workload_identity_binding": "NOT_ESTABLISHED"
    }))
}
