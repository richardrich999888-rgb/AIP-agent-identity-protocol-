//! Bounds on every value a policy or record carries. Named once.

/// Longest identifier accepted (policy, issuer, agent, parameter names).
pub const MAX_ID_LEN: usize = 128;

/// Most rules one policy may carry.
pub const MAX_RULES: usize = 256;

/// ISO 4217 alphabetic currency codes are three letters.
pub const CURRENCY_CODE_LEN: usize = 3;

/// Largest decimal exponent accepted for a minor unit.
pub const MAX_AMOUNT_EXPONENT: u8 = 9;

/// Longest decimal string accepted as an amount. `u64::MAX` has 20 digits;
/// anything longer cannot be a valid amount and is refused before parsing.
pub const MAX_AMOUNT_DIGITS: usize = 20;
