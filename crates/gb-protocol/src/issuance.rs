//! Difficulty and issuance rate (SPEC §3.8–§3.9).
//!
//! A target `T` makes each hash win with probability `T / 2²⁵⁶`.

use crate::hash::Hash;
use num_bigint::BigUint;
use num_traits::{One, Zero};

fn two_256() -> BigUint {
    BigUint::one() << 256
}

fn to_hash(value: &BigUint) -> Hash {
    let max = two_256() - BigUint::one();
    let capped = if *value > max { max } else { value.clone() };
    let bytes = capped.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Variant B (default): count-based target, so each hash wins with probability
/// `1 / (admitted online miners × target interval)`.
pub fn variant_b_target(online_miners: u64, interval_s: u64) -> Hash {
    let denominator = BigUint::from(online_miners.max(1)) * BigUint::from(interval_s.max(1));
    to_hash(&(two_256() / denominator))
}

/// Variant A (comparison): Bitcoin-style retarget after a window of `window_blocks` blocks
/// that took `actual_window_s`, so the window would have lasted `window_blocks × interval_s`,
/// with the change clamped to a factor of `clamp` either way.
pub fn variant_a_retarget(
    old_target: &Hash,
    actual_window_s: u64,
    window_blocks: u64,
    interval_s: u64,
    clamp: u64,
) -> Hash {
    let old = BigUint::from_bytes_be(old_target);
    let expected = BigUint::from(window_blocks.max(1)) * BigUint::from(interval_s.max(1));
    let raw = &old * BigUint::from(actual_window_s) / &expected;
    let low = &old / BigUint::from(clamp.max(1));
    let high = &old * BigUint::from(clamp.max(1));
    let clamped = if raw < low {
        low
    } else if raw > high {
        high
    } else {
        raw
    };
    to_hash(if clamped.is_zero() { &old } else { &clamped })
}

/// Adaptive variant (§3.9): the shortest interval allowed by the cap
/// `R ≤ registered / (k × T_min)`, from registered IDs at the last checkpoint and `k = num/den`.
pub fn adaptive_min_interval_s(registered_at_checkpoint: u64, k: (u64, u64), t_min_s: f64) -> f64 {
    let (num, den) = k;
    num as f64 * t_min_s / (den.max(1) as f64 * registered_at_checkpoint.max(1) as f64)
}

/// The adaptive interval: demand may shorten it, but never below the cap's minimum. The cap
/// may also set the rate below the fixed 30 s target (SPEC §3.9).
pub fn adaptive_interval_s(
    demand_interval_s: f64,
    registered_at_checkpoint: u64,
    k: (u64, u64),
    t_min_s: f64,
) -> f64 {
    demand_interval_s.max(adaptive_min_interval_s(
        registered_at_checkpoint,
        k,
        t_min_s,
    ))
}

/// The checkpoint that applies at time `t`: the start of its checkpoint interval.
pub fn checkpoint_at(t_s: f64, checkpoint_interval_s: f64) -> f64 {
    (t_s / checkpoint_interval_s).floor() * checkpoint_interval_s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_b_wins_one_hash_in_miners_times_interval() {
        // 1,000 miners × 30 s: probability 1/30,000 per hash.
        let t = BigUint::from_bytes_be(&variant_b_target(1_000, 30));
        assert_eq!(t, two_256() / BigUint::from(30_000u32));
    }

    #[test]
    fn variant_a_scales_and_clamps() {
        let old = variant_b_target(1_000, 30);
        let o = BigUint::from_bytes_be(&old);
        // Window twice as long as expected: target doubles (difficulty halves).
        let slow = BigUint::from_bytes_be(&variant_a_retarget(&old, 2 * 144 * 30, 144, 30, 4));
        assert_eq!(slow, &o * BigUint::from(2u8));
        // Ten times faster: clamped to a factor of 4.
        let fast = BigUint::from_bytes_be(&variant_a_retarget(&old, 144 * 3, 144, 30, 4));
        assert_eq!(fast, &o / BigUint::from(4u8));
    }

    #[test]
    fn adaptive_cap_keeps_the_time_floor() {
        // 2M registered IDs, k = 7/6, T_min = 2 years: at most 2M/(7/6 × 2 y) IDs per year.
        let year = 31_536_000.0;
        let min = adaptive_min_interval_s(2_000_000, (7, 6), 2.0 * year);
        assert!((min - 7.0 / 6.0 * 2.0 * year / 2_000_000.0).abs() < 1e-9);
        assert_eq!(adaptive_interval_s(1.0, 2_000_000, (7, 6), 2.0 * year), min);
        assert_eq!(
            adaptive_interval_s(60.0, 2_000_000, (7, 6), 2.0 * year),
            60.0
        );
        assert_eq!(checkpoint_at(125.0, 50.0), 100.0);
    }
}
