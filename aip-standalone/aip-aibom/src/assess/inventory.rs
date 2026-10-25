//! C2 models, C3 frameworks, C11 supply chain, C12 governance.
//!
//! Most of these can never be independently verified here, and the report
//! says exactly which can't and why. A hosted model's identity is
//! `Unknowable(N-3)`; that local weights were loaded is `Unknowable(N-4)`.

use super::{Inputs, Sheet};
use crate::model::{Component, Hosting};
use crate::standing::{NonEstablishment, Standing};

pub(super) fn run(i: &Inputs<'_>, sheet: &mut Sheet) {
    models(i, sheet);
    let m = i.manifest;
    for k in 0..m.frameworks.len() {
        sheet.field(
            Component::Frameworks,
            format!("$.frameworks[{k}]"),
            Standing::SelfReported,
        );
    }
    for k in 0..m.supply_chain.len() {
        sheet.field(
            Component::SupplyChain,
            format!("$.supply_chain[{k}]"),
            Standing::SelfReported,
        );
    }
    sheet.field(
        Component::Governance,
        "$.governance",
        Standing::SelfReported,
    );
}

fn models(i: &Inputs<'_>, sheet: &mut Sheet) {
    for (k, model) in i.manifest.models.iter().enumerate() {
        let non_establishment = match model.hosting {
            Hosting::Hosted => NonEstablishment::N3,
            Hosting::Local => NonEstablishment::N4,
        };
        sheet.field(
            Component::Models,
            format!("$.models[{k}]"),
            Standing::Unknowable { non_establishment },
        );
        if model.weight_sha256.is_some() {
            sheet.field(
                Component::Models,
                format!("$.models[{k}].weight_sha256"),
                Standing::SelfReported,
            );
        }
    }
}
