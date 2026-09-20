//! What SPIRE asserted, as the workload received it.
//!
//! Parsed from the JSON the `aip-spiffe-workload` sidecar emits, which is
//! produced with SPIRE's own client library rather than by parsing X.509 or the
//! Workload API ourselves — a disagreement must never be blamable on our parser.

use serde::Deserialize;

/// One SVID as a workload received it, reduced to the facts the comparison uses.
///
/// `pid` is self-reported by the workload. That is acceptable here and nowhere
/// else: a workload that lied about its pid would send the comparison to a
/// different process, where AIP's independent measurement would produce a
/// divergence or a refusal — never a false agreement. It is a pointer into
/// AIP's evidence, never itself evidence.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
pub struct WorkloadIdentityAssertion {
    pub spiffe_id: String,
    pub pid: u32,
    pub not_before_ms: i64,
    pub not_after_ms: i64,
    pub observed_at_ms: i64,
    #[serde(default)]
    pub serial: String,
    #[serde(default)]
    pub trust_domain: String,
    /// The SVID chain as PEM, carried so an auditor can re-verify it offline
    /// against the trust bundle instead of taking this summary's word.
    #[serde(default)]
    pub svid_chain_pem: String,
    #[serde(default)]
    pub bundle_pem: String,
}

/// Parse the sidecar's JSON output.
pub fn parse_assertion(json: &str) -> Result<WorkloadIdentityAssertion, String> {
    serde_json::from_str(json).map_err(|e| format!("cannot parse SVID json: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const J: &str = r#"{
      "pid": 17478, "exe_path": "/x",
      "spiffe_id": "spiffe://aip.local/workload/demo",
      "trust_domain": "aip.local", "serial": "177720",
      "not_before_ms": 1789929670000, "not_after_ms": 1789933280000,
      "svid_chain_pem": "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n",
      "bundle_pem": "-----BEGIN CERTIFICATE-----\nBB\n-----END CERTIFICATE-----\n",
      "dns_names": null, "observed_at_ms": 1789929682147 }"#;

    #[test]
    fn a_real_sidecar_document_parses() {
        let a = parse_assertion(J).unwrap();
        assert_eq!(a.spiffe_id, "spiffe://aip.local/workload/demo");
        assert_eq!(a.pid, 17478);
        assert_eq!(a.not_before_ms, 1789929670000);
        assert!(a.svid_chain_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn unknown_fields_do_not_break_the_parse() {
        let j = J.replace("\"dns_names\": null", "\"dns_names\": null, \"future\": 1");
        assert!(parse_assertion(&j).is_ok());
    }

    #[test]
    fn a_document_missing_required_fields_is_refused() {
        assert!(parse_assertion(r#"{"pid": 1}"#).is_err());
    }
}
