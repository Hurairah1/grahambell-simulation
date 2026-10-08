//! Domain-tagged SHA-256 (Appendix A) and 256-bit helpers.

use sha2::{Digest, Sha256};

/// A 32-byte hash.
pub type Hash = [u8; 32];

/// `SHA256(tag ‖ parts…)`: every protocol hash starts with an ASCII domain tag.
pub fn tagged(tag: &[u8], parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(tag);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// The remainder of a 256-bit big-endian integer divided by `modulus` (which must be
/// positive). Used for seat and lottery positions.
pub fn mod_u256(value: &Hash, modulus: u64) -> u64 {
    let m = u128::from(modulus.max(1));
    let mut remainder: u128 = 0;
    for byte in value {
        remainder = (remainder * 256 + u128::from(*byte)) % m;
    }
    remainder as u64
}

/// Lowercase hexadecimal, as used in the test vectors.
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        text.push(DIGITS[usize::from(b >> 4)] as char);
        text.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn mod_u256_matches_big_integer_arithmetic() {
        // Reference: num-bigint.
        for seed in 0u8..20 {
            let value = tagged(b"test", &[&[seed]]);
            for modulus in [1u64, 7, 10, 1_000_003, u64::MAX] {
                let expected = BigUint::from_bytes_be(&value) % BigUint::from(modulus);
                assert_eq!(BigUint::from(mod_u256(&value, modulus)), expected);
            }
        }
    }

    #[test]
    fn tagged_hash_is_sha256_of_the_concatenation() {
        // Reference: the SHA-256 of "abc" (FIPS 180-2 example).
        let h = tagged(b"a", &[b"b", b"c"]);
        assert_eq!(
            to_hex(&h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
