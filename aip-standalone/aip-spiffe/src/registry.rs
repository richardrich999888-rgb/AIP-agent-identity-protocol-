//! SPIRE's own record of what a workload must be, parsed from its own output.
//!
//! The registry is **SPIRE's**, not ours. It is parsed from `spire-server entry
//! show` / `entry create`, so the digest a SPIFFE ID is required to have comes
//! from the party that enforces it. Supplying our own expectations here and
//! then "confirming" them against AIP would be a closed loop proving nothing.

use std::collections::BTreeMap;

/// One registration entry as SPIRE reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredWorkload {
    pub entry_id: String,
    pub spiffe_id: String,
    pub parent_id: String,
    /// Every `unix:sha256:` selector on the entry, decoded.
    pub digest_selectors: Vec<[u8; 32]>,
    /// Selectors AIP has no way to check (uid, gid, path, ...). Kept so the
    /// report can say what the identity actually rested on.
    pub other_selectors: Vec<String>,
}

impl RegisteredWorkload {
    /// The single digest this entry requires, if there is exactly one.
    ///
    /// Zero means the identity does not rest on the workload's code at all.
    /// More than one distinct digest means the entry can never be satisfied,
    /// since SPIRE requires every selector to match. Both are refusals, not
    /// agreement — see [`crate::NotComparableReason`].
    pub fn required_digest(&self) -> Option<[u8; 32]> {
        let mut distinct: Vec<&[u8; 32]> = Vec::new();
        for d in &self.digest_selectors {
            if !distinct.contains(&d) {
                distinct.push(d);
            }
        }
        match distinct.len() {
            1 => Some(*distinct[0]),
            _ => None,
        }
    }

    pub fn distinct_digest_count(&self) -> usize {
        let mut distinct: Vec<&[u8; 32]> = Vec::new();
        for d in &self.digest_selectors {
            if !distinct.contains(&d) {
                distinct.push(d);
            }
        }
        distinct.len()
    }
}

/// Every entry SPIRE reported, indexed by SPIFFE ID.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registry {
    by_id: BTreeMap<String, RegisteredWorkload>,
}

impl Registry {
    pub fn lookup(&self, spiffe_id: &str) -> Option<&RegisteredWorkload> {
        self.by_id.get(spiffe_id)
    }
    pub fn len(&self) -> usize {
        self.by_id.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

/// Decode 64 lowercase-or-uppercase hex characters into a digest.
pub fn parse_digest(hex: &str) -> Option<[u8; 32]> {
    let h = hex.trim();
    if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Parse `spire-server entry show` (or `entry create`) output.
///
/// The format is `Key : Value` lines, entries separated by blank lines. An
/// entry whose SPIFFE ID is missing is skipped rather than half-recorded: a
/// partially parsed entry could silently lose the digest selector, and a lost
/// digest selector reads as "the identity did not rest on code", which is a
/// materially different and much weaker statement.
pub fn parse_entry_show(text: &str) -> Registry {
    let mut by_id = BTreeMap::new();
    let mut cur = RegisteredWorkload {
        entry_id: String::new(),
        spiffe_id: String::new(),
        parent_id: String::new(),
        digest_selectors: Vec::new(),
        other_selectors: Vec::new(),
    };
    let flush = |cur: &mut RegisteredWorkload, map: &mut BTreeMap<String, RegisteredWorkload>| {
        if !cur.spiffe_id.is_empty() {
            map.insert(cur.spiffe_id.clone(), cur.clone());
        }
        *cur = RegisteredWorkload {
            entry_id: String::new(),
            spiffe_id: String::new(),
            parent_id: String::new(),
            digest_selectors: Vec::new(),
            other_selectors: Vec::new(),
        };
    };

    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() {
            flush(&mut cur, &mut by_id);
            continue;
        }
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim();
        match key {
            "Entry ID" => cur.entry_id = val.to_string(),
            "SPIFFE ID" => cur.spiffe_id = val.to_string(),
            "Parent ID" => cur.parent_id = val.to_string(),
            "Selector" => {
                // `Selector : unix:sha256:<hex>` — split_once above already ate
                // the first colon, so `val` is e.g. `unix:sha256:<hex>`.
                if let Some(hex) = val.strip_prefix("unix:sha256:") {
                    match parse_digest(hex) {
                        Some(d) => cur.digest_selectors.push(d),
                        // A malformed digest is recorded as an uncheckable
                        // selector, never dropped: dropping it would make the
                        // entry look like it had no code requirement.
                        None => cur.other_selectors.push(val.to_string()),
                    }
                } else {
                    cur.other_selectors.push(val.to_string());
                }
            }
            _ => {}
        }
    }
    flush(&mut cur, &mut by_id);
    Registry { by_id }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHOW: &str = "\
Entry ID                : c8214b2f
SPIFFE ID               : spiffe://aip.local/workload/demo
Parent ID               : spiffe://aip.local/spire/agent/join_token/de9e
Revision                : 0
Selector                : unix:sha256:7783aa692dad5544756825efbda0a2c48f760077e56d7b58f21287f1e564091c
Selector                : unix:uid:0
";

    #[test]
    fn a_real_entry_parses_with_its_digest_and_other_selectors() {
        let r = parse_entry_show(SHOW);
        let e = r.lookup("spiffe://aip.local/workload/demo").unwrap();
        assert_eq!(e.entry_id, "c8214b2f");
        assert_eq!(e.digest_selectors.len(), 1);
        assert_eq!(e.other_selectors, vec!["unix:uid:0"]);
        assert!(e.required_digest().is_some());
    }

    #[test]
    fn an_entry_with_no_digest_selector_has_no_required_digest() {
        let r = parse_entry_show("Entry ID : x\nSPIFFE ID : spiffe://t/w\nSelector : unix:uid:0\n");
        let e = r.lookup("spiffe://t/w").unwrap();
        assert!(
            e.required_digest().is_none(),
            "uid alone is not a code requirement"
        );
        assert_eq!(e.distinct_digest_count(), 0);
    }

    /// SPIRE requires every selector to match, so two different digests can
    /// never both hold. Such an entry must not yield a digest to compare.
    #[test]
    fn two_different_digests_yield_no_required_digest() {
        let show = format!(
            "Entry ID : x\nSPIFFE ID : spiffe://t/w\nSelector : unix:sha256:{}\nSelector : unix:sha256:{}\n",
            "aa".repeat(32),
            "bb".repeat(32)
        );
        let e = parse_entry_show(&show);
        let w = e.lookup("spiffe://t/w").unwrap();
        assert_eq!(w.distinct_digest_count(), 2);
        assert!(w.required_digest().is_none());
    }

    #[test]
    fn a_repeated_identical_digest_is_still_one_requirement() {
        let show = format!(
            "Entry ID : x\nSPIFFE ID : spiffe://t/w\nSelector : unix:sha256:{h}\nSelector : unix:sha256:{h}\n",
            h = "cc".repeat(32)
        );
        let w = parse_entry_show(&show);
        assert!(w
            .lookup("spiffe://t/w")
            .unwrap()
            .required_digest()
            .is_some());
    }

    #[test]
    fn a_malformed_digest_is_kept_as_uncheckable_not_dropped() {
        let w = parse_entry_show(
            "Entry ID : x\nSPIFFE ID : spiffe://t/w\nSelector : unix:sha256:nothex\n",
        );
        let e = w.lookup("spiffe://t/w").unwrap();
        assert_eq!(e.digest_selectors.len(), 0);
        assert_eq!(e.other_selectors.len(), 1, "must not vanish");
        assert!(e.required_digest().is_none());
    }

    #[test]
    fn multiple_entries_separated_by_blank_lines_all_parse() {
        let two = format!("{SHOW}\nEntry ID : b\nSPIFFE ID : spiffe://aip.local/workload/other\nSelector : unix:uid:1\n");
        let r = parse_entry_show(&two);
        assert_eq!(r.len(), 2);
        assert!(r.lookup("spiffe://aip.local/workload/other").is_some());
    }

    #[test]
    fn digest_hex_is_case_insensitive_and_length_checked() {
        assert!(parse_digest(&"AB".repeat(32)).is_some());
        assert!(parse_digest(&"ab".repeat(32)).is_some());
        assert_eq!(
            parse_digest(&"AB".repeat(32)),
            parse_digest(&"ab".repeat(32))
        );
        assert!(parse_digest("abc").is_none(), "short hex must be refused");
        assert!(
            parse_digest(&"zz".repeat(32)).is_none(),
            "non-hex must be refused"
        );
    }
}
