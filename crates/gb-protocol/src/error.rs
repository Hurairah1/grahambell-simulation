//! Errors returned by the protocol core.

use thiserror::Error;

/// A malformed input: bytes that cannot be decoded, or a key or signature that is not a valid
/// curve point.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolError {
    /// The byte string has the wrong length.
    #[error("expected {expected} bytes, got {actual}")]
    Length {
        /// Required length.
        expected: usize,
        /// Length received.
        actual: usize,
    },
    /// The address type byte is not 0 (IPv6 /64) or 1 (IPv4).
    #[error("unknown address type {0}")]
    AddressType(u8),
    /// An IPv4 address must be left-padded with four zero bytes.
    #[error("IPv4 address field is not left-padded with zeros")]
    Ipv4Padding,
    /// A BLS key, signature or aggregation was rejected by `blst`.
    #[error("BLS error: {0}")]
    Bls(String),
    /// A bitfield does not match the number of seats.
    #[error("bitfield covers {bits} seats, expected {seats}")]
    Bitfield {
        /// Seats the bitfield covers.
        bits: usize,
        /// Seats expected.
        seats: usize,
    },
    /// An operation needs at least one element.
    #[error("{0}")]
    Empty(&'static str),
}
