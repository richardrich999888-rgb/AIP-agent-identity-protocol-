//! C9 security controls and C10 cryptographic posture.

use super::{Inputs, Sheet};
use crate::finding::FindingKind;
use crate::model::Component;
use crate::standing::{NonEstablishment, Standing, Verifier};
use aip_types::AgentIdentityDocument;

pub(super) fn run(i: &Inputs<'_>, doc: Option<&AgentIdentityDocument>, sheet: &mut Sheet) {
    let m = i.manifest;
    for k in 0..m.security_controls.len() {
        let path = format!("$.security_controls[{k}]");
        sheet.finding(
            Component::SecurityControls,
            path.clone(),
            FindingKind::ControlNotEvidenced,
        );
        sheet.field(Component::SecurityControls, path, Standing::SelfReported);
    }

    if let Some(declared) = m.crypto.identity_key_algorithm {
        let standing = match doc {
            Some(d) if d.primary_key.algorithm == declared => Standing::Verified {
                verifier: Verifier::IdentityDocument,
            },
            Some(d) => Standing::Contradicted {
                reason: format!(
                    "the validated identity key is {:?}, not {declared:?}",
                    d.primary_key.algorithm
                ),
            },
            None => Standing::SelfReported,
        };
        sheet.field(
            Component::Cryptography,
            "$.crypto.identity_key_algorithm",
            standing,
        );
    }
    for k in 0..m.crypto.signing.len() {
        sheet.field(
            Component::Cryptography,
            format!("$.crypto.signing[{k}]"),
            Standing::SelfReported,
        );
    }
    if m.crypto.post_quantum {
        sheet.field(
            Component::Cryptography,
            "$.crypto.post_quantum",
            Standing::Unknowable {
                non_establishment: NonEstablishment::N10,
            },
        );
    }
}
