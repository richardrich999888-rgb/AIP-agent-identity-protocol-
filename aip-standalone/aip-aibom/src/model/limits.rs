//! Bounds on every externally supplied value.
//!
//! A manifest is untrusted input, so every string and every collection has a
//! ceiling. Each bound is named here once; nothing else in the crate writes a
//! bare number for one.

/// Longest free-text value accepted (names, descriptions, versions).
pub const MAX_TEXT_LEN: usize = 256;

/// Longest identifier accepted (agent ids, tool ids, resource names).
pub const MAX_ID_LEN: usize = 128;

/// Most entries accepted in any one collection.
pub const MAX_ITEMS: usize = 512;

/// `aip_types::ScopeAction::Custom` documents a 64-byte maximum; the manifest
/// enforces the same bound so a declared action is always one the core can
/// carry.
pub const MAX_CUSTOM_ACTION_LEN: usize = 64;

/// A SHA-256 digest written as lowercase hexadecimal.
pub const SHA256_HEX_LEN: usize = 64;

/// ISO 4217 alphabetic currency codes are three letters.
pub const CURRENCY_CODE_LEN: usize = 3;

/// Largest decimal exponent accepted for an amount's minor unit. ISO 4217
/// minor units are 0–4 for every currency in use; 9 leaves room for
/// non-currency units without admitting nonsense.
pub const MAX_AMOUNT_EXPONENT: u8 = 9;

/// Largest evidence bundle or discovery source the CLI will read, in bytes.
pub const MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024;
