//! C13 — the manifest's own window.
//!
//! The authority windows are C5's, read from signed tokens. This is the
//! author's statement of when the inventory is a true description.

use super::{Inputs, Sheet};
use crate::finding::FindingKind;
use crate::model::Component;
use crate::standing::{Lapse, Standing};

pub(super) fn run(i: &Inputs<'_>, sheet: &mut Sheet) {
    let v = &i.manifest.validity;
    let now = i.context.present_time_ms;
    let standing = match v.valid_until_ms {
        Some(until) if now > until => Standing::Lapsed {
            lapse: Lapse::Expired {
                valid_until_ms: until,
            },
        },
        _ if now < v.issued_at_ms => Standing::Lapsed {
            lapse: Lapse::NotYetValid {
                valid_from_ms: v.issued_at_ms,
            },
        },
        _ => Standing::SelfReported,
    };
    if v.valid_until_ms.is_none() {
        sheet.finding(
            Component::Validity,
            "$.validity",
            FindingKind::ManifestNeverExpires,
        );
    }
    sheet.field(Component::Validity, "$.validity", standing);
}
