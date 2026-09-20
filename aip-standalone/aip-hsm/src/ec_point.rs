//! Decoding `CKA_EC_POINT` for an Ed25519 public key.
//!
//! PKCS#11 v3 says `CKA_EC_POINT` for an Edwards key is the public key as a
//! DER **OCTET STRING**: for Ed25519 that is the tag `0x04`, the length
//! `0x20` (32), then the 32 key bytes — 34 bytes in all. Some modules
//! return the bare 32 bytes instead. Both are accepted; nothing else is.
//!
//! The decoder is deliberately strict about the wrapped form. A 34-byte
//! value whose tag or length byte is wrong is not "probably a key with a
//! bad header" — it is an unknown encoding, and treating it as a key would
//! mean publishing 32 bytes this crate cannot vouch for as the identity a
//! whole deployment anchors on.

use crate::error::HsmError;

const OCTET_STRING_TAG: u8 = 0x04;
const ED25519_KEY_LEN: usize = 32;

/// Extract the 32-byte Ed25519 public key from a `CKA_EC_POINT` value.
pub fn ed25519_public_key(point: &[u8]) -> Result<[u8; ED25519_KEY_LEN], HsmError> {
    let raw: &[u8] = match point.len() {
        ED25519_KEY_LEN => point,
        n if n == ED25519_KEY_LEN + 2 => {
            if point[0] != OCTET_STRING_TAG {
                return Err(HsmError::EcPoint(format!(
                    "expected DER OCTET STRING tag 0x04, got 0x{:02x}",
                    point[0]
                )));
            }
            if point[1] as usize != ED25519_KEY_LEN {
                return Err(HsmError::EcPoint(format!(
                    "OCTET STRING length byte is {}, expected {ED25519_KEY_LEN}",
                    point[1]
                )));
            }
            &point[2..]
        }
        n => {
            return Err(HsmError::EcPoint(format!(
                "{n} bytes; expected {ED25519_KEY_LEN} (bare) or {} (DER OCTET STRING)",
                ED25519_KEY_LEN + 2
            )))
        }
    };
    let mut out = [0u8; ED25519_KEY_LEN];
    out.copy_from_slice(raw);
    Ok(out)
}

/// The DER-encoded object identifier for Ed25519 (`1.3.101.112`), which is
/// what `CKA_EC_PARAMS` carries for key generation.
pub const ED25519_OID_DER: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn a_der_wrapped_point_decodes() {
        let mut p = vec![0x04, 0x20];
        p.extend_from_slice(&key());
        assert_eq!(ed25519_public_key(&p).unwrap(), key());
    }

    #[test]
    fn a_bare_point_decodes() {
        assert_eq!(ed25519_public_key(&key()).unwrap(), key());
    }

    #[test]
    fn a_wrong_tag_is_refused_not_stripped() {
        let mut p = vec![0x03, 0x20];
        p.extend_from_slice(&key());
        let err = ed25519_public_key(&p).unwrap_err();
        assert!(err.to_string().contains("0x03"), "{err}");
    }

    #[test]
    fn a_wrong_length_byte_is_refused() {
        let mut p = vec![0x04, 0x21];
        p.extend_from_slice(&key());
        assert!(ed25519_public_key(&p).is_err());
    }

    #[test]
    fn other_lengths_are_refused() {
        for n in [0usize, 1, 31, 33, 35, 65] {
            assert!(ed25519_public_key(&vec![0x04; n]).is_err(), "{n}");
        }
    }

    /// `06 03 2B 65 70` is the textbook encoding of 1.3.101.112.
    #[test]
    fn the_ed25519_oid_is_the_rfc_8410_one() {
        assert_eq!(ED25519_OID_DER, [0x06, 0x03, 0x2b, 0x65, 0x70]);
    }
}
