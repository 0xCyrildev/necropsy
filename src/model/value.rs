//! Value types with exact 256-bit semantics.
//!
//! Two rules drive every choice here:
//!   * amounts never narrow. A parsed `U256` is summed into a `U256` and netted
//!     by comparing magnitudes, so there is no `as i128` anywhere near a total.
//!   * serialization is decimal *strings*, never JSON numbers. `U256` does not
//!     fit an IEEE-754 double, and a JSON number would silently corrupt the
//!     exact figures this tool exists to produce.

use ruint::aliases::U256;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// An unsigned EVM quantity (token base units, wei, a token id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Amount(pub U256);

impl Amount {
    pub const ZERO: Amount = Amount(U256::ZERO);

    pub fn new(v: U256) -> Self {
        Amount(v)
    }

    /// Parse a bare decimal string, as it appears in a decoded trace line.
    pub fn from_decimal(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty()
            || s.starts_with('-')
            || s.starts_with("0x")
            || s.starts_with("0X")
            || !s.chars().all(|c| c.is_ascii_digit())
        {
            return None;
        }
        s.parse::<U256>().ok().map(Amount)
    }

    /// Parse `0x…`-prefixed hex, as it appears in RPC fields. A bare decimal
    /// string is accepted too, because ABI data sometimes arrives decoded.
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.trim();
        let digits = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            Some(d) => d,
            None => return Amount::from_decimal(s),
        };
        if digits.is_empty() {
            return Some(Amount::ZERO);
        }
        if digits.len() > 64 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        // Right-align into a 32-byte word and decode big-endian. Done by hand so
        // that "more than 32 bytes" is an explicit rejection rather than a silent
        // truncation, and so no padding helper's name is load-bearing.
        let normalized = if digits.len() % 2 == 1 {
            format!("0{digits}")
        } else {
            digits.to_string()
        };
        let bytes = hex::decode(&normalized).ok()?;
        if bytes.len() > 32 {
            return None;
        }
        let mut word = [0u8; 32];
        word[32 - bytes.len()..].copy_from_slice(&bytes);
        Some(Amount(U256::from_be_slice(&word)))
    }

    /// Decode a full 32-byte big-endian word, e.g. an indexed `uint256` topic.
    pub fn from_be_word(bytes: &[u8; 32]) -> Amount {
        Amount(U256::from_be_slice(bytes))
    }

    /// Decode a right-aligned ABI `uint256` log word.
    pub fn from_abi_word(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let mut w = [0u8; 32];
        w.copy_from_slice(bytes);
        Some(Amount::from_be_word(&w))
    }

    pub fn checked_add(self, other: Amount) -> Option<Amount> {
        self.0.checked_add(other.0).map(Amount)
    }

    pub fn checked_sub(self, other: Amount) -> Option<Amount> {
        self.0.checked_sub(other.0).map(Amount)
    }

    pub fn is_zero(self) -> bool {
        self.0.is_zero()
    }

    pub fn to_decimal_string(self) -> String {
        self.0.to_string()
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for Amount {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_decimal_string())
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Amount::from_hex(&raw)
            .ok_or_else(|| D::Error::custom(format!("not a decimal or 0x amount: {raw:?}")))
    }
}

/// Net movement for one (asset, address) pair: a sign plus a magnitude, so the
/// arithmetic is a comparison and cannot wrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Net {
    Positive(Amount),
    Negative(Amount),
    Zero,
}

impl Net {
    pub fn net_of(inflows: Amount, outflows: Amount) -> Net {
        match inflows.cmp(&outflows) {
            std::cmp::Ordering::Equal => Net::Zero,
            std::cmp::Ordering::Greater => Net::Positive(
                inflows
                    .checked_sub(outflows)
                    .expect("inflows > outflows, so the subtraction cannot overflow"),
            ),
            std::cmp::Ordering::Less => Net::Negative(
                outflows
                    .checked_sub(inflows)
                    .expect("outflows > inflows, so the subtraction cannot overflow"),
            ),
        }
    }

    pub fn is_receiver(self) -> bool {
        matches!(self, Net::Positive(a) if !a.is_zero())
    }

    pub fn magnitude(self) -> Amount {
        match self {
            Net::Positive(a) | Net::Negative(a) => a,
            Net::Zero => Amount::ZERO,
        }
    }
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Net::Zero => write!(f, "0"),
            Net::Positive(a) => write!(f, "+{a}"),
            Net::Negative(a) => write!(f, "-{a}"),
        }
    }
}

impl Serialize for Net {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

/// `10^decimals` as a U256 by repeated checked multiplication. Not `pow()`:
/// a checked loop makes an absurd decimal count a `None` rather than a wrapped
/// divisor that would silently rescale every figure in the report.
fn ten_to(decimals: u8) -> Option<U256> {
    let mut acc = U256::from(1u64);
    let ten = U256::from(10u64);
    for _ in 0..decimals {
        acc = acc.checked_mul(ten)?;
    }
    Some(acc)
}

/// Human-scale a decimal amount for *display only*. Never used for equality or
/// summation: rounding is precisely what makes a token ledger untrustworthy if
/// arithmetic were performed on it.
pub fn format_units(raw: &str, decimals: u8) -> Option<String> {
    let value = raw.parse::<U256>().ok()?;
    let div = ten_to(decimals)?;
    let whole = value / div;
    if decimals == 0 {
        return Some(whole.to_string());
    }
    let frac = value % div;
    let digits = format!("{frac:0>width$}", width = decimals as usize);
    let trimmed = digits.trim_end_matches('0');
    if trimmed.is_empty() {
        Some(whole.to_string())
    } else {
        Some(format!("{whole}.{trimmed}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimal_and_hex_exactly() {
        // 2^200: far beyond u128, which the previous implementation skipped silently.
        let big = "1606938044258990275508728116553337797815401967162919801968804860825600";
        let a = Amount::from_decimal(big).expect("2^200 must parse");
        assert_eq!(a.to_decimal_string(), big);

        let hexed = Amount::from_hex("0x0de0b6b3a7640000").unwrap();
        assert_eq!(hexed.to_decimal_string(), "1000000000000000000");
    }

    #[test]
    fn rejects_negative_and_malformed() {
        assert_eq!(Amount::from_decimal("-5"), None);
        assert_eq!(Amount::from_decimal(""), None);
        assert_eq!(Amount::from_decimal("0x1"), None);
        assert_eq!(Amount::from_decimal("1e17"), None);
        assert_eq!(Amount::from_hex("0xzz"), None);
        // 33 bytes cannot be a uint256; truncating would corrupt the ledger.
        assert_eq!(Amount::from_hex(&format!("0x{}", "ff".repeat(33))), None);
    }

    #[test]
    fn netting_never_wraps_where_the_old_code_did() {
        // The bug being replaced: an inflow between i128::MAX and u128::MAX cast
        // to i128 goes negative, so `net -= amount` ADDS, and the row is then
        // filtered out by `net > 0` — the largest inflow vanishes.
        let huge = Amount::new(U256::MAX / U256::from(2u64));
        let net = Net::net_of(huge, Amount::ZERO);
        assert!(net.is_receiver(), "a sole inflow must rank as a receiver");
        assert_eq!(net.magnitude(), huge);
    }

    #[test]
    fn serializes_as_decimal_string_not_json_number() {
        let a = Amount::new(U256::from(u128::MAX));
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, "\"340282366920938463463374607431768211455\"");
        let back: Amount = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn formats_units_with_trailing_zeros_stripped() {
        assert_eq!(format_units("150000000000", 6).unwrap(), "150000");
        assert_eq!(format_units("1000000000000000000", 18).unwrap(), "1");
        assert_eq!(format_units("1000001000000000000", 18).unwrap(), "1.000001");
        assert_eq!(format_units("1000000", 0).unwrap(), "1000000");
        // An absurd decimal count must fail, not divide by a wrapped divisor.
        assert!(format_units("1000000", 78).is_none());
    }
}
