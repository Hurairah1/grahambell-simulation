//! Exact rational arithmetic helpers.
//!
//! Tail probabilities in this crate are computed as exact rationals (`BigRational`). Some are
//! smaller than the smallest positive `f64` (for example committee-capture tails near
//! 10⁻⁴⁰⁰), so results are reported as exact scientific-notation strings and as `log10`
//! values, and converted to `f64` only with correct rounding.

use crate::error::{Result, ensure};
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_rational::BigRational;
use num_traits::{One, Signed, ToPrimitive, Zero};

/// Exact rational alias used throughout the crate.
pub type Q = BigRational;

/// Exact value of the shortest decimal that round-trips to `x`.
///
/// Configuration values such as `0.33` are stored as binary floats; this recovers the decimal
/// the user wrote, so `0.33` becomes exactly `33/100` rather than the nearest binary fraction.
pub fn decimal(x: f64) -> Result<Q> {
    ensure(x.is_finite(), "decimal input must be finite")?;
    let text = format!("{x:e}");
    let (mantissa, exponent) = text
        .split_once('e')
        .ok_or_else(|| crate::error::AnalyticError::InvalidInput(text.clone()))?;
    let exponent: i64 = exponent
        .parse()
        .map_err(|_| crate::error::AnalyticError::InvalidInput(text.clone()))?;
    let negative = mantissa.starts_with('-');
    let digits_text = mantissa.trim_start_matches('-');
    let fraction_digits = digits_text
        .split_once('.')
        .map(|(_, fraction)| fraction.len())
        .unwrap_or(0) as i64;
    let digits: BigInt = digits_text
        .replace('.', "")
        .parse()
        .map_err(|_| crate::error::AnalyticError::InvalidInput(text.clone()))?;
    let power = exponent - fraction_digits;
    let magnitude = if power >= 0 {
        Q::from_integer(digits * pow10(power.unsigned_abs()))
    } else {
        Q::new(digits, pow10(power.unsigned_abs()))
    };
    Ok(if negative { -magnitude } else { magnitude })
}

/// Exact rational `numerator / denominator`.
pub fn ratio(numerator: u64, denominator: u64) -> Q {
    Q::new(BigInt::from(numerator), BigInt::from(denominator))
}

/// Exact rational for the integer `n`.
pub fn integer(n: u64) -> Q {
    Q::from_integer(BigInt::from(n))
}

/// `10^exponent` as a big integer.
pub fn pow10(exponent: u64) -> BigInt {
    num_traits::pow(BigInt::from(10u8), exponent as usize)
}

/// Binomial coefficient `C(n, k)`, exactly. Zero when `k > n`.
pub fn binomial_coefficient(n: u64, k: u64) -> BigUint {
    if k > n {
        return BigUint::zero();
    }
    let k = k.min(n - k);
    let mut value = BigUint::one();
    for i in 0..k {
        value = value * (n - i) / (i + 1);
    }
    value
}

/// Correctly rounded `f64` value (round half to even), including subnormal results.
///
/// Values below the smallest subnormal round to zero; use [`log10`] or [`scientific`] for
/// those.
pub fn to_f64(x: &Q) -> f64 {
    if x.is_zero() {
        return 0.0;
    }
    let numerator = x.numer().magnitude();
    let denominator = x.denom().magnitude();
    let magnitude = positive_ratio_to_f64(numerator, denominator);
    if x.is_negative() {
        -magnitude
    } else {
        magnitude
    }
}

/// `floor(numerator × 2^shift / denominator)`, the remainder, and the effective denominator.
fn scaled_quotient(
    numerator: &BigUint,
    denominator: &BigUint,
    shift: i64,
) -> (BigUint, BigUint, BigUint) {
    if shift >= 0 {
        let scaled = numerator << shift.unsigned_abs();
        let (q, r) = scaled.div_rem(denominator);
        (q, r, denominator.clone())
    } else {
        let scaled_denominator = denominator << shift.unsigned_abs();
        let (q, r) = numerator.div_rem(&scaled_denominator);
        (q, r, scaled_denominator)
    }
}

fn round_half_even(quotient: BigUint, remainder: &BigUint, denominator: &BigUint) -> BigUint {
    let twice = remainder << 1u32;
    if twice > *denominator || (twice == *denominator && quotient.is_odd()) {
        quotient + 1u32
    } else {
        quotient
    }
}

fn positive_ratio_to_f64(numerator: &BigUint, denominator: &BigUint) -> f64 {
    const MANTISSA_BITS: u64 = 53;
    const MAX_SHIFT: i64 = 1074; // shift at which the result is the smallest subnormal unit
    let mut shift =
        (MANTISSA_BITS as i64 - 1) - (numerator.bits() as i64 - denominator.bits() as i64);
    let (mut quotient, mut remainder, mut effective) =
        scaled_quotient(numerator, denominator, shift);
    while quotient.bits() != MANTISSA_BITS {
        shift += if quotient.bits() > MANTISSA_BITS {
            -1
        } else {
            1
        };
        (quotient, remainder, effective) = scaled_quotient(numerator, denominator, shift);
    }
    if shift > MAX_SHIFT {
        let (q, r, d) = scaled_quotient(numerator, denominator, MAX_SHIFT);
        let rounded = round_half_even(q, &r, &d);
        return f64::from_bits(rounded.to_u64().unwrap_or(0));
    }
    let mut mantissa = round_half_even(quotient, &remainder, &effective);
    if mantissa.bits() > MANTISSA_BITS {
        mantissa >>= 1u32;
        shift -= 1;
    }
    let exponent = (MANTISSA_BITS as i64 - 1) - shift;
    if exponent > 1023 {
        return f64::INFINITY;
    }
    let fraction = mantissa.to_u64().unwrap_or(0) & ((1u64 << 52) - 1);
    let biased = (exponent + 1023) as u64;
    f64::from_bits((biased << 52) | fraction)
}

/// Decimal digits and power of ten of a positive rational, rounded half-to-even to
/// `significant` digits: `x ≈ digits × 10^(power)` with `digits` having exactly
/// `significant` digits.
fn decimal_parts(x: &Q, significant: u32) -> (BigUint, i64) {
    let numerator = x.numer().magnitude();
    let denominator = x.denom().magnitude();
    let lower = num_traits::pow(BigUint::from(10u8), significant as usize - 1);
    let upper = &lower * 10u8;
    // log10(2) ≈ 0.30103; the estimate is within a few units and corrected below.
    let bits_difference = numerator.bits() as f64 - denominator.bits() as f64;
    let mut exponent = (bits_difference * std::f64::consts::LOG10_2).floor() as i64;
    loop {
        let power = i64::from(significant) - 1 - exponent;
        let (scaled_numerator, scaled_denominator) = if power >= 0 {
            (
                numerator * pow10(power.unsigned_abs()).magnitude(),
                denominator.clone(),
            )
        } else {
            (
                numerator.clone(),
                denominator * pow10(power.unsigned_abs()).magnitude(),
            )
        };
        let (quotient, remainder) = scaled_numerator.div_rem(&scaled_denominator);
        if quotient >= upper {
            exponent += 1;
            continue;
        }
        if quotient < lower {
            exponent -= 1;
            continue;
        }
        let rounded = round_half_even(quotient, &remainder, &scaled_denominator);
        if rounded == upper {
            return (lower, exponent + 1 - (i64::from(significant) - 1));
        }
        return (rounded, exponent - (i64::from(significant) - 1));
    }
}

/// Exact scientific notation with `significant` digits, for example `1.2346e-396`.
///
/// Zero is written `0`.
pub fn scientific(x: &Q, significant: u32) -> String {
    if x.is_zero() {
        return "0".to_string();
    }
    let significant = significant.max(1);
    let (digits, power) = decimal_parts(&x.abs(), significant);
    let text = digits.to_string();
    let exponent = power + i64::from(significant) - 1;
    let sign = if x.is_negative() { "-" } else { "" };
    let (head, tail) = text.split_at(1);
    if tail.is_empty() {
        format!("{sign}{head}e{exponent}")
    } else {
        format!("{sign}{head}.{tail}e{exponent}")
    }
}

/// Base-10 logarithm of a positive rational, accurate to about 1e-15 absolute.
pub fn log10(x: &Q) -> Option<f64> {
    if !x.is_positive() {
        return None;
    }
    let (digits, power) = decimal_parts(x, 17);
    let leading = digits.to_f64()?;
    Some(libm::log10(leading) + power as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_recovers_the_written_value_exactly() {
        assert_eq!(decimal(0.33).unwrap(), ratio(33, 100));
        assert_eq!(decimal(2_100_000.0).unwrap(), integer(2_100_000));
        assert_eq!(decimal(1.0).unwrap(), integer(1));
        assert_eq!(decimal(-0.05).unwrap(), -ratio(5, 100));
        assert_eq!(decimal(1e-30).unwrap(), Q::new(BigInt::one(), pow10(30)));
    }

    #[test]
    fn decimal_rejects_non_finite_values() {
        assert!(decimal(f64::NAN).is_err());
        assert!(decimal(f64::INFINITY).is_err());
    }

    #[test]
    fn binomial_coefficients_match_known_values() {
        assert_eq!(binomial_coefficient(10, 7), BigUint::from(120u32));
        assert_eq!(binomial_coefficient(30, 21), BigUint::from(14_307_150u32));
        assert_eq!(
            binomial_coefficient(40, 27),
            BigUint::from(12_033_222_880u64)
        );
        assert_eq!(binomial_coefficient(5, 6), BigUint::zero());
        assert_eq!(binomial_coefficient(0, 0), BigUint::one());
    }

    #[test]
    fn to_f64_matches_rust_parsing_of_the_same_decimal() {
        // Rust's float parser is correctly rounded, so it is an independent reference.
        for text in [
            "0.1",
            "0.33",
            "97.142857142857142857",
            "1e-300",
            "4.9e-324",
            "2.2250738585072014e-308",
            "123456789.123456789",
            "0.5",
            "1",
        ] {
            let reference: f64 = text.parse().unwrap();
            let exact = parse_decimal_text(text);
            assert_eq!(to_f64(&exact), reference, "{text}");
        }
    }

    #[test]
    fn to_f64_rounds_halfway_cases_to_even() {
        // 1 + 2^-53 is exactly halfway between 1 and 1 + 2^-52; ties go to the even mantissa 1.
        let halfway = Q::new(BigInt::from(1u64 << 53) + 1u8, BigInt::from(1u64 << 53));
        assert_eq!(to_f64(&halfway), 1.0);
        let above = Q::new(BigInt::from(1u64 << 53) + 3u8, BigInt::from(1u64 << 53));
        assert_eq!(to_f64(&above), 1.0 + 2.0 * f64::EPSILON);
    }

    #[test]
    fn values_below_f64_range_are_still_formatted_exactly() {
        let tiny = Q::new(BigInt::from(12_345u32), pow10(400));
        assert_eq!(scientific(&tiny, 3), "1.23e-396");
        assert_eq!(to_f64(&tiny), 0.0);
        // Reference from Python's `Decimal(12345) / 10**400` at 40-digit precision.
        assert!((log10(&tiny).unwrap() - (-395.908_508_905_732_05)).abs() < 1e-12);
    }

    #[test]
    fn scientific_notation_rounds_half_to_even() {
        assert_eq!(scientific(&ratio(680, 7), 6), "9.71429e1");
        assert_eq!(scientific(&ratio(125, 1000), 2), "1.2e-1");
        assert_eq!(scientific(&ratio(135, 1000), 2), "1.4e-1");
        assert_eq!(scientific(&ratio(9_999, 1_000), 3), "1.00e1");
        assert_eq!(scientific(&integer(0), 3), "0");
        assert_eq!(scientific(&-ratio(1, 4), 1), "-2e-1");
    }

    #[test]
    fn log10_of_powers_of_ten_is_exact() {
        assert_eq!(log10(&integer(1000)).unwrap(), 3.0);
        assert_eq!(log10(&ratio(1, 100)).unwrap(), -2.0);
        assert_eq!(log10(&integer(0)), None);
    }

    fn parse_decimal_text(text: &str) -> Q {
        let (mantissa, exponent) = match text.split_once('e') {
            Some((m, e)) => (m, e.parse::<i64>().unwrap()),
            None => (text, 0),
        };
        let fraction_digits = mantissa.split_once('.').map(|(_, f)| f.len()).unwrap_or(0) as i64;
        let digits: BigInt = mantissa.replace('.', "").parse().unwrap();
        let power = exponent - fraction_digits;
        if power >= 0 {
            Q::from_integer(digits * pow10(power as u64))
        } else {
            Q::new(digits, pow10((-power) as u64))
        }
    }
}
