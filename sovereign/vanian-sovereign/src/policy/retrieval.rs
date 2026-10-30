//! Retrieval authorization.
//!
//! The rule is evaluated twice by design: once inside the storage query (so
//! unauthorized rows are never read into process memory for ranking) and
//! once here over the returned rows (so a storage adapter bug cannot leak).
//! The second check is the one tests pin; the first is the one that keeps
//! unauthorized text out of memory.

use crate::domain::corpus::{Classification, Ident, Passage, Principal};

/// May `principal` read a document of `tenant` at `classification`?
pub fn may_read(principal: &Principal, tenant: &Ident, classification: Classification) -> bool {
    principal.tenant == *tenant && classification <= principal.clearance
}

/// Defence-in-depth filter. Returns the passages the principal may read and
/// the count that were dropped. A non-zero drop count means the storage
/// layer violated its contract; callers treat it as a fault, not a filter.
pub fn enforce(
    principal: &Principal,
    tenant_of_rows: &Ident,
    rows: Vec<Passage>,
) -> (Vec<Passage>, usize) {
    let before = rows.len();
    let kept: Vec<Passage> = rows
        .into_iter()
        .filter(|p| may_read(principal, tenant_of_rows, p.classification))
        .collect();
    let dropped = before - kept.len();
    (kept, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(t: &str, c: Classification) -> Principal {
        Principal {
            tenant: Ident::new(t).unwrap(),
            clearance: c,
        }
    }

    #[test]
    fn same_tenant_at_or_below_clearance() {
        let t = Ident::new("acme").unwrap();
        let pr = p("acme", Classification::Internal);
        assert!(may_read(&pr, &t, Classification::Public));
        assert!(may_read(&pr, &t, Classification::Internal));
        assert!(!may_read(&pr, &t, Classification::Restricted));
    }

    #[test]
    fn cross_tenant_always_denied_even_at_max_clearance() {
        let other = Ident::new("globex").unwrap();
        assert!(!may_read(
            &p("acme", Classification::Restricted),
            &other,
            Classification::Public
        ));
    }

    #[test]
    fn enforce_reports_contract_violations() {
        let t = Ident::new("acme").unwrap();
        let row = |c| Passage {
            doc_id: Ident::new("d").unwrap(),
            title: String::new(),
            classification: c,
            text: String::new(),
            bm25: 0.0,
        };
        let (kept, dropped) = enforce(
            &p("acme", Classification::Public),
            &t,
            vec![row(Classification::Public), row(Classification::Restricted)],
        );
        assert_eq!(kept.len(), 1);
        assert_eq!(dropped, 1);
    }
}
