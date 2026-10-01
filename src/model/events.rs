//! Log classification: which events move value, and in whose units.
//!
//! Matching is on **computed topic0 plus topic/data arity**, never on printed
//! argument names. That is not pedantry: `cast` renders `Transfer(from:, to:,
//! amount:)` when it resolved an ABI and `Transfer(param0:, param1:, param2:)`
//! or `Sync(: 1.27e26, : 1.56e19)` when it did not, so a name-based matcher
//! silently changes which transfers this tool can see depending on whether an
//! external label lookup happened to succeed.

use super::address::{Address, Topic32};
use super::value::Amount;
use serde::Serialize;
use std::fmt;

/// What a value can be denominated in. The ledger key is `(AssetId, Address)`,
/// never `Address` alone — summing a 6-decimal stablecoin with an 18-decimal
/// token produces a ranking ordered by decimal places rather than by value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AssetId {
    Native,
    Erc20(Address),
}

impl AssetId {
    pub fn token(addr: Address) -> AssetId {
        AssetId::Erc20(addr)
    }

    pub fn label(&self) -> String {
        match self {
            AssetId::Native => "native ETH".to_string(),
            AssetId::Erc20(a) => a.to_checksum(),
        }
    }
}

impl fmt::Display for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssetId::Native => write!(f, "native"),
            AssetId::Erc20(a) => write!(f, "{}", a.to_hex()),
        }
    }
}

impl Serialize for AssetId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawLog {
    pub address: Address,
    pub topics: Vec<Topic32>,
    pub data: Vec<u8>,
    pub log_index: u32,
}

/// The set of events, classified. `Unclassified` is a real variant, not a
/// leftover: a log nobody recognised must be counted so the report can say how
/// much of the value it did not account for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum TokenEvent {
    /// `Transfer(address,address,uint256)`: 3 topics, 32-byte amount in data.
    Erc20Transfer {
        token: Address,
        from: Address,
        to: Address,
        amount: Amount,
        log_index: u32,
    },
    /// Same signature, but the third parameter is indexed and data is empty —
    /// which is exactly how ERC-721 distinguishes itself. Never fungible.
    Erc721Transfer {
        token: Address,
        from: Address,
        to: Address,
        token_id: Amount,
        log_index: u32,
    },
    Erc1155Single {
        token: Address,
        operator: Address,
        from: Address,
        to: Address,
        id: Amount,
        value: Amount,
        log_index: u32,
    },
    Erc1155Batch {
        token: Address,
        operator: Address,
        from: Address,
        to: Address,
        ids: Vec<Amount>,
        values: Vec<Amount>,
        log_index: u32,
    },
    /// WETH9 `Deposit(address,uint256)`: the owner's ETH became WETH. Not a
    /// transfer between parties, but it is the reason a raw-ETH drain shows up
    /// as an ERC-20 inflow and must be tracked as the same movement.
    WethDeposit {
        weth: Address,
        owner: Address,
        amount: Amount,
        log_index: u32,
    },
    WethWithdrawal {
        weth: Address,
        owner: Address,
        amount: Amount,
        log_index: u32,
    },
    /// Recognised but not value-bearing (`Approval`, `Sync`, `Swap`, vault
    /// `Deposit`). Kept so the counts add up.
    NonValue {
        token: Address,
        topic0: Topic32,
        log_index: u32,
    },
    Unclassified {
        address: Address,
        topic0: Option<Topic32>,
        n_topics: usize,
        data_len: usize,
        log_index: u32,
        why: &'static str,
    },
}

mod sig {
    use super::Topic32;
    use std::sync::LazyLock;

    pub static ERC20_TRANSFER: LazyLock<Topic32> =
        LazyLock::new(|| Topic32::of_signature("Transfer(address,address,uint256)"));
    pub static TRANSFER_SINGLE: LazyLock<Topic32> = LazyLock::new(|| {
        Topic32::of_signature("TransferSingle(address,address,address,uint256,uint256)")
    });
    pub static TRANSFER_BATCH: LazyLock<Topic32> = LazyLock::new(|| {
        Topic32::of_signature("TransferBatch(address,address,address,uint256[],uint256[])")
    });
    pub static WETH_DEPOSIT: LazyLock<Topic32> =
        LazyLock::new(|| Topic32::of_signature("Deposit(address,uint256)"));
    pub static WETH_WITHDRAWAL: LazyLock<Topic32> =
        LazyLock::new(|| Topic32::of_signature("Withdrawal(address,uint256)"));
    pub static APPROVAL: LazyLock<Topic32> =
        LazyLock::new(|| Topic32::of_signature("Approval(address,address,uint256)"));
}

fn word(data: &[u8], i: usize) -> Option<Amount> {
    let start = i.checked_mul(32)?;
    Amount::from_abi_word(data.get(start..start + 32)?)
}

/// Decode a dynamic `uint256[]` at `offset`, with every bound checked. A
/// malformed length is refused rather than trusted, because inventing array
/// elements is how a ledger gets numbers that were never on chain.
fn decode_u256_array(data: &[u8], offset: usize) -> Option<Vec<Amount>> {
    let len_raw = word(data, offset / 32)?;
    let len: usize = len_raw.0.try_into().ok()?;
    if len == 0 || len > 4096 {
        return None;
    }
    let mut out = Vec::with_capacity(len.min(64));
    for i in 0..len {
        out.push(word(data, offset / 32 + 1 + i)?);
    }
    Some(out)
}

pub fn classify(log: &RawLog) -> TokenEvent {
    let topic0 = log.topics.first().copied();
    let n = log.topics.len();

    let Some(t0) = topic0 else {
        return TokenEvent::Unclassified {
            address: log.address,
            topic0: None,
            n_topics: n,
            data_len: log.data.len(),
            log_index: log.log_index,
            why: "log carries no topic0, so its signature cannot be identified",
        };
    };

    if t0 == *sig::ERC20_TRANSFER {
        if n == 3 {
            let from = Address::from_topic(&log.topics[1]);
            let to = Address::from_topic(&log.topics[2]);
            return match word(&log.data, 0) {
                Some(amount) if log.data.len() == 32 => TokenEvent::Erc20Transfer {
                    token: log.address,
                    from,
                    to,
                    amount,
                    log_index: log.log_index,
                },
                _ => TokenEvent::Unclassified {
                    address: log.address,
                    topic0: Some(t0),
                    n_topics: n,
                    data_len: log.data.len(),
                    log_index: log.log_index,
                    why: "Transfer(address,address,uint256) topics without a single 32-byte amount word",
                },
            };
        }
        if n == 4 && log.data.is_empty() {
            // ERC-721: tokenId is indexed, so it is the fourth topic and data is empty.
            return TokenEvent::Erc721Transfer {
                token: log.address,
                from: Address::from_topic(&log.topics[1]),
                to: Address::from_topic(&log.topics[2]),
                token_id: Amount::from_be_word(&log.topics[3].0),
                log_index: log.log_index,
            };
        }
        return TokenEvent::Unclassified {
            address: log.address,
            topic0: Some(t0),
            n_topics: n,
            data_len: log.data.len(),
            log_index: log.log_index,
            why: "Transfer(address,address,uint256) topic0 with an arity that is neither ERC-20 (3 topics) nor ERC-721 (4 topics, empty data)",
        };
    }

    if t0 == *sig::TRANSFER_SINGLE
        && n == 4
        && let (Some(id), Some(value)) = (word(&log.data, 0), word(&log.data, 1))
        && log.data.len() == 64
    {
        return TokenEvent::Erc1155Single {
            token: log.address,
            operator: Address::from_topic(&log.topics[0]),
            from: Address::from_topic(&log.topics[1]),
            to: Address::from_topic(&log.topics[2]),
            id,
            value,
            log_index: log.log_index,
        };
    }

    if t0 == *sig::TRANSFER_BATCH && n == 4 {
        let operator = Address::from_topic(&log.topics[0]);
        let from = Address::from_topic(&log.topics[1]);
        let to = Address::from_topic(&log.topics[2]);
        let off_ids = word(&log.data, 0).and_then(|a| usize::try_from(a.0).ok());
        let off_vals = word(&log.data, 1).and_then(|a| usize::try_from(a.0).ok());
        if let (Some(oi), Some(ov)) = (off_ids, off_vals)
            && let (Some(ids), Some(values)) = (
                decode_u256_array(&log.data, oi),
                decode_u256_array(&log.data, ov),
            )
        {
            return TokenEvent::Erc1155Batch {
                token: log.address,
                operator,
                from,
                to,
                ids,
                values,
                log_index: log.log_index,
            };
        }
        return TokenEvent::Unclassified {
            address: log.address,
            topic0: Some(t0),
            n_topics: n,
            data_len: log.data.len(),
            log_index: log.log_index,
            why: "TransferBatch with dynamic-array offsets that do not resolve inside the data",
        };
    }

    if t0 == *sig::WETH_DEPOSIT
        && n == 2
        && log.data.len() == 32
        && let (Some(owner), Some(amount)) = (
            log.topics.get(1).copied().map(|t| Address::from_topic(&t)),
            word(&log.data, 0),
        )
    {
        return TokenEvent::WethDeposit {
            weth: log.address,
            owner,
            amount,
            log_index: log.log_index,
        };
    }

    if t0 == *sig::WETH_WITHDRAWAL
        && n == 2
        && log.data.len() == 32
        && let (Some(owner), Some(amount)) = (
            log.topics.get(1).copied().map(|t| Address::from_topic(&t)),
            word(&log.data, 0),
        )
    {
        return TokenEvent::WethWithdrawal {
            weth: log.address,
            owner,
            amount,
            log_index: log.log_index,
        };
    }

    if t0 == *sig::APPROVAL {
        return TokenEvent::NonValue {
            token: log.address,
            topic0: t0,
            log_index: log.log_index,
        };
    }

    // A cToken/vault `Deposit(address,address,uint256,uint256)` lands here: its
    // topic0 differs from WETH9's, so it is never folded into "ETH was wrapped".
    TokenEvent::NonValue {
        token: log.address,
        topic0: t0,
        log_index: log.log_index,
    }
}

/// Whether an event moves fungible value that the ledger should net.
impl TokenEvent {
    pub fn is_fungible_move(&self) -> bool {
        matches!(
            self,
            TokenEvent::Erc20Transfer { .. }
                | TokenEvent::WethDeposit { .. }
                | TokenEvent::WethWithdrawal { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::address::Topic32;

    fn a(n: u8) -> Address {
        let mut b = [0u8; 20];
        b[19] = n;
        Address(b)
    }

    fn topic_addr(addr: Address) -> Topic32 {
        let mut t = [0u8; 32];
        t[12..32].copy_from_slice(&addr.0);
        Topic32(t)
    }

    fn amount_word(n: u64) -> Vec<u8> {
        let mut w = vec![0u8; 32];
        w[24..].copy_from_slice(&n.to_be_bytes());
        w
    }

    #[test]
    fn erc20_transfer_is_attributed_to_the_emitting_log_address() {
        let token = a(0x10);
        let log = RawLog {
            address: token,
            topics: vec![*sig::ERC20_TRANSFER, topic_addr(a(1)), topic_addr(a(2))],
            data: amount_word(150_000),
            log_index: 3,
        };
        match classify(&log) {
            TokenEvent::Erc20Transfer {
                token: t,
                from,
                to,
                amount,
                ..
            } => {
                assert_eq!(t, token);
                assert_eq!((from, to), (a(1), a(2)));
                assert_eq!(amount.to_decimal_string(), "150000");
            }
            other => panic!("expected an ERC-20 transfer, got {other:?}"),
        }
    }

    #[test]
    fn erc721_transfer_never_enters_the_fungible_ledger() {
        // Same signature string, so topic0 is identical. The discriminator is
        // the indexed tokenId plus empty data.
        let mut id_word = [0u8; 32];
        id_word[31] = 7;
        let log = RawLog {
            address: a(0x11),
            topics: vec![
                *sig::ERC20_TRANSFER,
                topic_addr(a(1)),
                topic_addr(a(2)),
                Topic32(id_word),
            ],
            data: vec![],
            log_index: 0,
        };
        let ev = classify(&log);
        assert!(matches!(ev, TokenEvent::Erc721Transfer { .. }));
        assert!(!ev.is_fungible_move());
    }

    #[test]
    fn a_vault_deposit_is_not_weth() {
        // cToken/Euler-style Deposit(address,address,uint256,uint256): different
        // topic0, so it must not be read as "ETH became WETH".
        let t0 = Topic32::of_signature("Deposit(address,address,uint256,uint256)");
        let log = RawLog {
            address: a(0x12),
            topics: vec![t0, topic_addr(a(1)), topic_addr(a(2))],
            data: [amount_word(1), amount_word(2)].concat(),
            log_index: 0,
        };
        assert!(matches!(classify(&log), TokenEvent::NonValue { .. }));
    }

    #[test]
    fn weth_deposit_and_withdrawal_are_matched_by_topic_and_arity() {
        let log = RawLog {
            address: a(0xc0),
            topics: vec![*sig::WETH_DEPOSIT, topic_addr(a(5))],
            data: amount_word(1),
            log_index: 0,
        };
        assert!(matches!(classify(&log), TokenEvent::WethDeposit { owner, .. } if owner == a(5)));
        // Same topics but an extra one: no longer WETH9's shape.
        let bad = RawLog {
            address: a(0xc0),
            topics: vec![*sig::WETH_DEPOSIT, topic_addr(a(5)), topic_addr(a(6))],
            data: amount_word(1),
            log_index: 0,
        };
        assert!(!matches!(classify(&bad), TokenEvent::WethDeposit { .. }));
    }

    #[test]
    fn erc1155_batch_decodes_both_arrays_and_stays_non_fungible() {
        // ABI head is two dynamic-array offsets: ids at 0x40, values at 0x40+96.
        let mut payload = vec![0u8; 64];
        payload[31] = 0x40;
        payload[63] = 0x40 + 3 * 32;
        let len2 = {
            let mut w = vec![0u8; 32];
            w[31] = 2;
            w
        };
        payload.extend_from_slice(&len2);
        payload.extend_from_slice(&amount_word(7));
        payload.extend_from_slice(&amount_word(8));
        payload.extend_from_slice(&len2);
        payload.extend_from_slice(&amount_word(1000));
        payload.extend_from_slice(&amount_word(2000));
        assert_eq!(payload.len(), 64 + 6 * 32);
        let log = RawLog {
            address: a(0x13),
            topics: vec![
                *sig::TRANSFER_BATCH,
                topic_addr(a(1)),
                topic_addr(a(2)),
                topic_addr(a(3)),
            ],
            data: payload,
            log_index: 0,
        };
        match classify(&log) {
            TokenEvent::Erc1155Batch { ids, values, .. } => {
                assert_eq!(ids.len(), 2);
                assert_eq!(values[0].to_decimal_string(), "1000");
            }
            other => panic!("expected a batch, got {other:?}"),
        }
    }

    #[test]
    fn garbage_array_offset_is_refused_not_trusted() {
        let mut payload = vec![0u8; 64];
        payload[31] = 0xff; // offset far beyond the data
        payload[63] = 0xff;
        let log = RawLog {
            address: a(0x13),
            topics: vec![
                *sig::TRANSFER_BATCH,
                topic_addr(a(1)),
                topic_addr(a(2)),
                topic_addr(a(3)),
            ],
            data: payload,
            log_index: 0,
        };
        assert!(matches!(classify(&log), TokenEvent::Unclassified { .. }));
    }

    #[test]
    fn topicless_log_is_unclassified_rather_than_guessed() {
        let log = RawLog {
            address: a(1),
            topics: vec![],
            data: vec![],
            log_index: 0,
        };
        assert!(matches!(classify(&log), TokenEvent::Unclassified { why, .. } if !why.is_empty()));
    }
}
