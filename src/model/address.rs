//! Address, topic and selector values.
//!
//! Addresses are compared and keyed by **bytes**, never by string. The traces
//! this tool reads arrive checksummed from `cast` and lowercase from JSON-RPC,
//! and the previous implementation compared raw strings — which split one
//! address into two ledger rows and made a cross-collector baseline diff report
//! every single node as changed.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(input);
    k.finalize(&mut out);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("expected 0x-prefixed hex")]
    MissingPrefix,
    #[error("expected {expected} hex characters, found {found}")]
    WrongLength { expected: usize, found: usize },
    #[error("contains a non-hex character")]
    NotHex,
    #[error("mixed-case address fails its EIP-55 checksum (likely a typo)")]
    BadChecksum,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Address(pub [u8; 20]);

impl Address {
    pub const ZERO: Address = Address([0u8; 20]);

    pub fn as_bytes(self) -> [u8; 20] {
        self.0
    }

    pub fn from_slice(b: &[u8]) -> Option<Address> {
        if b.len() == 20 {
            Some(Address(b.try_into().unwrap()))
        } else {
            None
        }
    }

    /// An ABI-encoded address occupies the low 20 bytes of a 32-byte word.
    pub fn from_topic(t: &Topic32) -> Address {
        let mut a = [0u8; 20];
        a.copy_from_slice(&t.0[12..32]);
        Address(a)
    }

    /// `0x01`–`0x09`. Classification is by address range rather than by the
    /// renderer's label, so it does not depend on a text format we have not
    /// captured.
    pub fn is_precompile(self) -> bool {
        self.0[..19].iter().all(|&b| b == 0) && (0x01..=0x09).contains(&self.0[19])
    }

    pub fn is_zero(self) -> bool {
        self == Address::ZERO
    }

    /// Lowercase hex — the stable form, used for serialization and file keys.
    pub fn to_hex(self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// EIP-55 mixed-case checksum — for humans only. Never compared.
    pub fn to_checksum(self) -> String {
        let hex_addr = hex::encode(self.0);
        let hash = keccak256(hex_addr.as_bytes());
        let mut out = String::with_capacity(42);
        out.push_str("0x");
        for (i, c) in hex_addr.chars().enumerate() {
            if c.is_ascii_digit() {
                out.push(c);
            } else {
                let nibble = if i % 2 == 0 {
                    hash[i / 2] >> 4
                } else {
                    hash[i / 2] & 0x0f
                };
                out.push(if nibble >= 8 {
                    c.to_ascii_uppercase()
                } else {
                    c
                });
            }
        }
        out
    }

    /// Truncated middle form for tables: `0x3fC9…7FAD`.
    pub fn short(self) -> String {
        let c = self.to_checksum();
        format!("{}…{}", &c[..6], &c[c.len() - 4..])
    }
}

impl FromStr for Address {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let digits = s
            .trim()
            .strip_prefix("0x")
            .ok_or(ParseError::MissingPrefix)?;
        if digits.len() != 40 {
            return Err(ParseError::WrongLength {
                expected: 40,
                found: digits.len(),
            });
        }
        if !digits.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ParseError::NotHex);
        }
        // Mixed case is only meaningful as a checksum, so when it is used it must
        // be correct. All-lower and all-upper are accepted unvalidated.
        let has_upper = digits.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = digits.chars().any(|c| c.is_ascii_lowercase());
        let bytes = hex::decode(digits).map_err(|_| ParseError::NotHex)?;
        let addr = Address::from_slice(&bytes).ok_or(ParseError::NotHex)?;
        // `digits` has the 0x stripped; `to_checksum` re-adds it. Comparing the
        // two without normalizing that is how every real trace address — which
        // arrives checksummed — gets rejected as a typo.
        if has_upper && has_lower && addr.to_checksum() != format!("0x{digits}") {
            return Err(ParseError::BadChecksum);
        }
        Ok(addr)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_checksum())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.to_checksum())
    }
}

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Address::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Topic32(pub [u8; 32]);

impl Topic32 {
    pub fn from_slice(b: &[u8]) -> Option<Topic32> {
        if b.len() == 32 {
            Some(Topic32(b.try_into().unwrap()))
        } else {
            None
        }
    }

    /// keccak256 of a canonical event signature, e.g.
    /// `Transfer(address,address,uint256)`. Matching on a computed topic0 makes
    /// argument *names* irrelevant, which is the whole point: `cast` prints
    /// `from:`/`to:`/`amount:` when it resolved an ABI and `param0:`/`:` when it
    /// did not, so a name-based matcher silently loses transfers depending on
    /// whether an Etherscan/Sourcify lookup happened to succeed.
    pub fn of_signature(sig: &str) -> Topic32 {
        Topic32(keccak256(sig.as_bytes()))
    }

    pub fn to_hex(self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    pub fn first4(self) -> [u8; 4] {
        let mut a = [0u8; 4];
        a.copy_from_slice(&self.0[..4]);
        a
    }
}

impl fmt::Display for Topic32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Topic32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Topic({})", self.to_hex())
    }
}

impl Serialize for Topic32 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Topic32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        let digits = raw.strip_prefix("0x").unwrap_or(&raw);
        let bytes = hex::decode(digits).map_err(serde::de::Error::custom)?;
        Topic32::from_slice(&bytes).ok_or_else(|| {
            serde::de::Error::custom(format!("expected 32-byte topic, got {} bytes", bytes.len()))
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Selector(pub [u8; 4]);

impl Selector {
    /// First four bytes of calldata. Short input (a bare value transfer, a
    /// zero-length delegatecall) legitimately has no selector.
    pub fn from_calldata(input: &[u8]) -> Option<Selector> {
        if input.len() < 4 {
            None
        } else {
            Some(Selector(input[..4].try_into().unwrap()))
        }
    }

    pub fn of_signature(sig: &str) -> Selector {
        Selector(keccak256(sig.as_bytes())[..4].try_into().unwrap())
    }

    pub fn to_hex(self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Selector({})", self.to_hex())
    }
}

impl Serialize for Selector {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

/// A validated transaction hash: `0x` plus exactly 64 hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxHash(pub [u8; 32]);

impl TxHash {
    pub fn to_hex(self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

impl FromStr for TxHash {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let digits = s
            .trim()
            .strip_prefix("0x")
            .ok_or(ParseError::MissingPrefix)?;
        if digits.len() != 64 {
            return Err(ParseError::WrongLength {
                expected: 64,
                found: digits.len(),
            });
        }
        if !digits.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ParseError::NotHex);
        }
        let bytes = hex::decode(digits).map_err(|_| ParseError::NotHex)?;
        let word: [u8; 32] = bytes.try_into().map_err(|_| ParseError::NotHex)?;
        Ok(TxHash(word))
    }
}

impl fmt::Display for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxHash({})", self.to_hex())
    }
}

impl Serialize for TxHash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

pub fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let digits = s
        .trim()
        .strip_prefix("0x")
        .or(s.trim().strip_prefix("0X"))?;
    if digits.is_empty() {
        return Some(Vec::new());
    }
    let padded = if digits.len() % 2 == 1 {
        format!("0{digits}")
    } else {
        digits.to_string()
    };
    hex::decode(padded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_topic0_is_the_canonical_digest() {
        // Pinned to the topic0 read out of a real receipt
        // (0x5b515946… on eth.drpc.org), not to a transcription: a keccak
        // dependency change would otherwise silently reclassify every transfer.
        let t = Topic32::of_signature("Transfer(address,address,uint256)");
        assert_eq!(
            t.to_hex(),
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        );
    }

    #[test]
    fn known_selectors() {
        assert_eq!(
            Selector::of_signature("transfer(address,uint256)").to_hex(),
            "0xa9059cbb"
        );
        assert_eq!(Selector::of_signature("decimals()").to_hex(), "0x313ce567");
    }

    #[test]
    fn checksum_matches_foundrys_implementation() {
        // Vectors produced by `cast to-checksum` (Foundry 1.8.1) on 2026-09-30,
        // not transcribed from memory: what has to agree is the renderer whose
        // output we parse, and every real trace line carries these forms.
        for (lower, want) in [
            (
                "0x5aaeb6053f3e94c9b9080f63252e255d18c08fe9",
                "0x5aaEB6053f3e94c9b9080f63252e255d18c08fE9",
            ),
            (
                "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359",
                "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            ),
            (
                "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb",
                "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            ),
            (
                "0xd1220a0cf47c7b9be7a2e6ba89f47297b603fd1c",
                "0xD1220A0Cf47C7b9be7A2E6Ba89F47297b603fd1c",
            ),
            (
                "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad",
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
            ),
            (
                "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            ),
        ] {
            let a: Address = lower.parse().unwrap();
            assert_eq!(a.to_checksum(), want, "checksum of {lower}");
        }
    }

    #[test]
    fn checksum_is_idempotent_over_the_vectors() {
        // Re-checksumming an already-checksummed address must be a fixed point,
        // otherwise parsing a value out of a trace and printing it again changes
        // the identifier the analyst searched for.
        for s in [
            "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        ] {
            let a: Address = s.parse().unwrap_or_else(|e| panic!("{s} must parse: {e}"));
            assert_eq!(a.to_checksum(), s);
        }
    }

    #[test]
    fn mixed_case_with_bad_checksum_is_rejected() {
        // Take a known-good checksummed form and flip one letter's case: that is
        // a typo an analyst would actually paste, and accepting it silently would
        // key the ledger on the wrong address.
        let broken = "0xA0b86991c6218b36c1d19D4a2e9eb0cE3606eB48";
        assert!(
            matches!(broken.parse::<Address>(), Err(ParseError::BadChecksum)),
            "{broken} must not be accepted as USDC"
        );
        // All-lowercase is accepted without checksum validation, because that is
        // the form JSON-RPC hands us.
        assert!(
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
                .parse::<Address>()
                .is_ok()
        );
    }

    #[test]
    fn same_address_from_both_casings_is_one_key() {
        let upper: Address = "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"
            .parse()
            .unwrap();
        let lower: Address = "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad"
            .parse()
            .unwrap();
        assert_eq!(upper, lower);
        let mut set = std::collections::HashSet::new();
        set.insert(upper);
        set.insert(lower);
        assert_eq!(
            set.len(),
            1,
            "casing must not split one address into two rows"
        );
    }

    #[test]
    fn precompiles_are_classified_by_range() {
        for n in 1u8..=9 {
            let mut b = [0u8; 20];
            b[19] = n;
            assert!(Address(b).is_precompile(), "0x0{n} should be a precompile");
        }
        assert!(
            !Address::ZERO.is_precompile(),
            "0x0 is the null address, not a precompile"
        );
        let mut ten = [0u8; 20];
        ten[19] = 10;
        assert!(!Address(ten).is_precompile());
        assert!(
            !"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
                .parse::<Address>()
                .unwrap()
                .is_precompile()
        );
    }

    #[test]
    fn tx_hash_shape_is_enforced() {
        assert!("0x{}".parse::<TxHash>().is_err());
        assert!("deadbeef".parse::<TxHash>().is_err());
        assert!("0x-abc".parse::<TxHash>().is_err());
        let ok = "0x5b515946dc1177149f140777ac90879312b182117e3392e8e2703ed3cd697153"
            .parse::<TxHash>()
            .unwrap();
        assert_eq!(
            ok.to_hex(),
            "0x5b515946dc1177149f140777ac90879312b182117e3392e8e2703ed3cd697153"
        );
    }

    #[test]
    fn address_from_topic_takes_the_low_20_bytes() {
        let mut raw = [0u8; 32];
        raw[12] = 0xa0;
        raw[31] = 0x48;
        let a = Address::from_topic(&Topic32(raw));
        assert_eq!(a.to_hex(), "0xa000000000000000000000000000000000000048");
    }
}
