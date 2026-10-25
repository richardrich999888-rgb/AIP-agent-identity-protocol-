//! The cgroup name a decision id determines.
//!
//! A decision cgroup is named by its `decision_id` as 32 lowercase hex
//! digits — nothing else, so the name can always be read back to exactly one
//! id and no id has two names. The name is a **label**: attribution is by the
//! kernel's cgroup id, never by this string (ADR-019 §4). The name only lets
//! the reconciler recover which decision a creator meant.

/// Length of a decision cgroup name: 16 bytes as hex.
pub const NAME_LEN: usize = 32;

/// The cgroup name for `decision_id`.
pub fn decision_cgroup_name(decision_id: &[u8; 16]) -> String {
    let mut s = String::with_capacity(NAME_LEN);
    for b in decision_id {
        s.push(nibble(b >> 4));
        s.push(nibble(b & 0x0f));
    }
    s
}

fn nibble(n: u8) -> char {
    char::from(if n < 10 { b'0' + n } else { b'a' + n - 10 })
}

/// The decision id a cgroup name encodes, if it is exactly a decision cgroup
/// name. Uppercase, short, long or non-hex names are refused: two spellings
/// of one id would be two placements claiming one decision.
pub fn parse_decision_cgroup_name(name: &str) -> Option<[u8; 16]> {
    let b = name.as_bytes();
    if b.len() != NAME_LEN {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in b.chunks_exact(2).enumerate() {
        out[i] = (hex(pair[0])? << 4) | hex(pair[1])?;
    }
    Some(out)
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_round_trips_to_exactly_its_decision() {
        let id = [
            0x00, 0x01, 0x7f, 0x80, 0xab, 0xcd, 0xef, 0xff, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        let n = decision_cgroup_name(&id);
        assert_eq!(n, "00017f80abcdefff0102030405060708");
        assert_eq!(parse_decision_cgroup_name(&n), Some(id));
    }

    #[test]
    fn only_the_one_canonical_spelling_is_a_decision_name() {
        let n = decision_cgroup_name(&[0xab; 16]);
        assert!(parse_decision_cgroup_name(&n.to_uppercase()).is_none());
        assert!(parse_decision_cgroup_name(&n[..31]).is_none());
        assert!(parse_decision_cgroup_name(&format!("{n}0")).is_none());
        assert!(parse_decision_cgroup_name(&format!("g{}", &n[1..])).is_none());
        assert!(parse_decision_cgroup_name("").is_none());
    }
}
