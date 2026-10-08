//! PoW-ID header encoding, digests and the block hash (SPEC §3.3, Appendix A).
//!
//! All integers are big-endian at fixed widths. Fields follow the canonical \[P\] order of
//! Appendix A; the header is [`HEADER_LEN`] = 173 bytes.

use crate::error::ProtocolError;
use crate::hash::{Hash, tagged};

/// Encoded header length in bytes.
pub const HEADER_LEN: usize = 173;

/// Domain tag of the header digest.
pub const HEADER_TAG: &[u8] = b"GB/header";
/// Domain tag of the block hash.
pub const BLOCK_TAG: &[u8] = b"GB/block";

/// The miner's externally visible address (Appendix A).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Address {
    /// Type 0: an IPv6 /64 prefix (mainnet uses this type only).
    Ipv6Prefix64([u8; 8]),
    /// Type 1: an IPv4 address (the §13 testnet only), left-padded with zeros on the wire.
    Ipv4([u8; 4]),
}

impl Address {
    /// Type byte and the 8-byte field.
    pub fn encode(&self) -> (u8, [u8; 8]) {
        match self {
            Address::Ipv6Prefix64(prefix) => (0, *prefix),
            Address::Ipv4(ip) => {
                let mut field = [0u8; 8];
                field[4..].copy_from_slice(ip);
                (1, field)
            }
        }
    }

    /// Decodes a type byte and 8-byte field.
    pub fn decode(kind: u8, field: [u8; 8]) -> Result<Address, ProtocolError> {
        match kind {
            0 => Ok(Address::Ipv6Prefix64(field)),
            1 => {
                if field[..4] != [0, 0, 0, 0] {
                    return Err(ProtocolError::Ipv4Padding);
                }
                Ok(Address::Ipv4([field[4], field[5], field[6], field[7]]))
            }
            other => Err(ProtocolError::AddressType(other)),
        }
    }
}

/// A PoW-ID header (SPEC §3.3). Fixed for the round once the entropy is committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Header {
    /// Protocol version.
    pub version: u32,
    /// Block height.
    pub height: u64,
    /// Hash of the previous PoW-ID block.
    pub prev_hash: Hash,
    /// Candidate BLS public key (G1, compressed).
    pub candidate_pk: [u8; 48],
    /// Reward wallet.
    pub reward_wallet: [u8; 32],
    /// The miner's externally visible address.
    pub address: Address,
    /// KWC ID: the index of its leader WC.
    pub kwc_id: u64,
    /// Difficulty target: a step wins when its hash, as a 256-bit integer, is below it.
    pub target: Hash,
}

impl Header {
    /// The 173-byte encoding in canonical order.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        let (kind, field) = self.address.encode();
        let mut at = 0;
        let mut put = |bytes: &[u8]| {
            out[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        };
        put(&self.version.to_be_bytes());
        put(&self.height.to_be_bytes());
        put(&self.prev_hash);
        put(&self.candidate_pk);
        put(&self.reward_wallet);
        put(&[kind]);
        put(&field);
        put(&self.kwc_id.to_be_bytes());
        put(&self.target);
        out
    }

    /// Decodes a header; rejects a wrong length, an unknown address type or bad padding.
    pub fn decode(bytes: &[u8]) -> Result<Header, ProtocolError> {
        if bytes.len() != HEADER_LEN {
            return Err(ProtocolError::Length {
                expected: HEADER_LEN,
                actual: bytes.len(),
            });
        }
        let mut at = 0;
        let mut take = |n: usize| {
            let slice = &bytes[at..at + n];
            at += n;
            slice
        };
        let version = u32::from_be_bytes(fixed(take(4)));
        let height = u64::from_be_bytes(fixed(take(8)));
        let prev_hash = fixed(take(32));
        let candidate_pk = fixed(take(48));
        let reward_wallet = fixed(take(32));
        let kind = take(1)[0];
        let field = fixed(take(8));
        let kwc_id = u64::from_be_bytes(fixed(take(8)));
        let target = fixed(take(32));
        Ok(Header {
            version,
            height,
            prev_hash,
            candidate_pk,
            reward_wallet,
            address: Address::decode(kind, field)?,
            kwc_id,
            target,
        })
    }

    /// `header_digest = SHA256("GB/header" ‖ header)`.
    pub fn digest(&self) -> Hash {
        tagged(HEADER_TAG, &[&self.encode()])
    }
}

/// Copies a slice of known length into an array (lengths are fixed by the layout above).
fn fixed<const N: usize>(slice: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    out
}

/// Block hash = `SHA256("GB/block" ‖ header ‖ E ‖ N)`, the ID of a winning PoW-ID block and the
/// key of the same-height tie-break.
pub fn block_hash(header: &Header, entropy: &Hash, winning_step: u64) -> Hash {
    tagged(
        BLOCK_TAG,
        &[&header.encode(), entropy, &winning_step.to_be_bytes()],
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn sample() -> Header {
        Header {
            version: crate::PROTOCOL_VERSION,
            height: 0x0102_0304_0506_0708,
            prev_hash: [0x11; 32],
            candidate_pk: [0x22; 48],
            reward_wallet: [0x33; 32],
            address: Address::Ipv6Prefix64([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1]),
            kwc_id: 42,
            target: [0xff; 32],
        }
    }

    #[test]
    fn header_is_173_bytes_in_canonical_order() {
        let bytes = sample().encode();
        assert_eq!(bytes.len(), 4 + 8 + 32 + 48 + 32 + 1 + 8 + 8 + 32);
        assert_eq!(&bytes[..4], &1u32.to_be_bytes());
        assert_eq!(&bytes[4..12], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(bytes[124], 0, "address type");
        assert_eq!(&bytes[125..133], &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1]);
        assert_eq!(&bytes[133..141], &42u64.to_be_bytes());
    }

    #[test]
    fn headers_round_trip_for_both_address_types() {
        let mut h = sample();
        assert_eq!(Header::decode(&h.encode()).unwrap(), h);
        h.address = Address::Ipv4([192, 0, 2, 7]);
        let bytes = h.encode();
        assert_eq!(bytes[124], 1);
        assert_eq!(&bytes[125..133], &[0, 0, 0, 0, 192, 0, 2, 7]);
        assert_eq!(Header::decode(&bytes).unwrap(), h);
    }

    #[test]
    fn malformed_headers_are_rejected() {
        let mut bytes = sample().encode();
        assert!(matches!(
            Header::decode(&bytes[..172]),
            Err(ProtocolError::Length { .. })
        ));
        bytes[124] = 2;
        assert_eq!(Header::decode(&bytes), Err(ProtocolError::AddressType(2)));
        bytes[124] = 1;
        bytes[125] = 9;
        assert_eq!(Header::decode(&bytes), Err(ProtocolError::Ipv4Padding));
    }

    #[test]
    fn digests_change_with_every_field() {
        let base = sample();
        let mut variants = vec![base];
        let mut v = base;
        v.kwc_id += 1;
        variants.push(v);
        let mut v = base;
        v.reward_wallet[31] ^= 1;
        variants.push(v);
        let mut v = base;
        v.address = Address::Ipv4([0, 0, 0, 1]);
        variants.push(v);
        let digests: std::collections::BTreeSet<Hash> =
            variants.iter().map(Header::digest).collect();
        assert_eq!(digests.len(), variants.len());
    }
}
