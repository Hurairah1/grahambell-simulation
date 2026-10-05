//! Independent, reproducible random streams derived from one master seed.
//!
//! Each analysis asks for its own stream by label. Stream seeds are
//! `SHA-256("GB/rng-stream" ‖ seed as 8 little-endian bytes ‖ label)`, so adding or reordering
//! analyses never changes the random numbers another analysis receives.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

/// ChaCha20 stream for `label`, derived from the master `seed`.
pub fn rng_stream(seed: u64, label: &str) -> ChaCha20Rng {
    let mut hasher = Sha256::new();
    hasher.update(b"GB/rng-stream");
    hasher.update(seed.to_le_bytes());
    hasher.update(label.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    ChaCha20Rng::from_seed(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::Rng;

    #[test]
    fn same_seed_and_label_give_the_same_stream() {
        let mut a = rng_stream(7, "section-a");
        let mut b = rng_stream(7, "section-a");
        let xs: Vec<u64> = (0..4).map(|_| a.next_u64()).collect();
        let ys: Vec<u64> = (0..4).map(|_| b.next_u64()).collect();
        assert_eq!(xs, ys);
    }

    #[test]
    fn different_labels_give_different_streams() {
        let mut a = rng_stream(7, "section-a");
        let mut b = rng_stream(7, "section-b");
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn different_seeds_give_different_streams() {
        let mut a = rng_stream(7, "section-a");
        let mut b = rng_stream(8, "section-a");
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn stream_values_are_pinned_for_reproducibility() {
        // Pins the derivation so a dependency upgrade that changed ChaCha20 output, or a change
        // to the seed derivation, would be caught. Value recorded from this implementation.
        let mut rng = rng_stream(20_261_005, "pin");
        let first = rng.next_u64();
        let mut again = rng_stream(20_261_005, "pin");
        assert_eq!(first, again.next_u64());
        assert_eq!(first, PINNED_FIRST_VALUE);
    }

    const PINNED_FIRST_VALUE: u64 = 12_777_862_701_499_943_681;
}
