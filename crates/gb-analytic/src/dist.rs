//! Exact binomial and hypergeometric distributions.
//!
//! A distribution is stored as integer numerators over one shared denominator, so any tail or
//! region probability is an exact sum. Two seat models are used throughout M1:
//!
//! - **Binomial**: each seat is the attacker's independently with probability `p` (an
//!   infinite network, or draws with replacement).
//! - **Hypergeometric**: seats are a uniformly random subset of a finite population that
//!   contains exactly `attackers` attacker IDs (draws without replacement).
//!
//! The `*_by_*` functions compute the same distributions by dynamic programming, seat by seat,
//! as an independent cross-check of the closed forms.

use crate::error::{Result, ensure};
use crate::exact::{Q, binomial_coefficient, integer};
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

/// Seat model for a group of seats.
#[derive(Debug, Clone, PartialEq)]
pub enum SeatModel {
    /// Each seat is the attacker's independently with probability `p`.
    Binomial(Q),
    /// Seats are drawn without replacement from `population` IDs, `attackers` of them hostile.
    Hypergeometric {
        /// Total IDs the seats are drawn from.
        population: u64,
        /// Attacker IDs in the population.
        attackers: u64,
    },
}

impl SeatModel {
    /// Checks the model's parameters.
    pub fn validate(&self) -> Result<()> {
        match self {
            SeatModel::Binomial(p) => ensure(
                *p >= Q::zero() && *p <= Q::one(),
                "binomial probability must lie in [0, 1]",
            ),
            SeatModel::Hypergeometric {
                population,
                attackers,
            } => ensure(
                attackers <= population,
                "attackers cannot exceed the population",
            ),
        }
    }
}

/// Distribution of the number of attacker seats in one group, exactly.
#[derive(Debug, Clone, PartialEq)]
pub struct ExactDistribution {
    numerators: Vec<BigUint>,
    denominator: BigUint,
}

impl ExactDistribution {
    /// Distribution of attacker seats among `seats` under `model`.
    pub fn new(seats: u64, model: &SeatModel) -> Result<Self> {
        model.validate()?;
        Ok(match model {
            SeatModel::Binomial(p) => binomial(seats, p),
            SeatModel::Hypergeometric {
                population,
                attackers,
            } => {
                ensure(
                    seats <= *population,
                    "cannot draw more seats than the population",
                )?;
                hypergeometric(*population, *attackers, seats)
            }
        })
    }

    /// Number of seats `n` (the support is `0..=n`).
    pub fn seats(&self) -> u64 {
        self.numerators.len() as u64 - 1
    }

    /// Probability that exactly `k` seats are the attacker's.
    pub fn pmf(&self, k: u64) -> Q {
        self.probability_where(|x| x == k)
    }

    /// Probability that at least `k` seats are the attacker's.
    pub fn at_least(&self, k: u64) -> Q {
        self.probability_where(|x| x >= k)
    }

    /// Probability that at most `k` seats are the attacker's.
    pub fn at_most(&self, k: u64) -> Q {
        self.probability_where(|x| x <= k)
    }

    /// Probability of the set of seat counts for which `predicate` holds.
    pub fn probability_where(&self, predicate: impl Fn(u64) -> bool) -> Q {
        let sum = self
            .numerators
            .iter()
            .enumerate()
            .filter(|(k, _)| predicate(*k as u64))
            .fold(BigUint::zero(), |acc, (_, n)| acc + n);
        Q::new(BigInt::from(sum), BigInt::from(self.denominator.clone()))
    }

    /// The full probability mass function as exact rationals.
    pub fn to_rationals(&self) -> Vec<Q> {
        (0..=self.seats()).map(|k| self.pmf(k)).collect()
    }
}

fn binomial(seats: u64, p: &Q) -> ExactDistribution {
    // p = a/b in lowest terms; P(X = k) = C(n,k) a^k (b-a)^(n-k) / b^n.
    let a = p.numer().magnitude().clone();
    let b = p.denom().magnitude().clone();
    let c = &b - &a;
    let n = seats as usize;
    let mut a_powers = Vec::with_capacity(n + 1);
    let mut c_powers = Vec::with_capacity(n + 1);
    a_powers.push(BigUint::one());
    c_powers.push(BigUint::one());
    for i in 1..=n {
        a_powers.push(&a_powers[i - 1] * &a);
        c_powers.push(&c_powers[i - 1] * &c);
    }
    let mut coefficient = BigUint::one();
    let mut numerators = Vec::with_capacity(n + 1);
    for k in 0..=n {
        numerators.push(&coefficient * &a_powers[k] * &c_powers[n - k]);
        coefficient = coefficient * (seats - k as u64) / (k as u64 + 1);
    }
    ExactDistribution {
        numerators,
        denominator: num_traits::pow(b, n),
    }
}

/// `C(m, j)` for `j = 0..=up_to`, computed iteratively.
fn binomial_row(m: u64, up_to: u64) -> Vec<BigUint> {
    let mut row = Vec::with_capacity(up_to as usize + 1);
    let mut value = BigUint::one();
    for j in 0..=up_to {
        row.push(value.clone());
        value = if j < m {
            value * (m - j) / (j + 1)
        } else {
            BigUint::zero()
        };
    }
    row
}

fn hypergeometric(population: u64, attackers: u64, seats: u64) -> ExactDistribution {
    // P(X = k) = C(K, k) C(M-K, n-k) / C(M, n).
    let attacker_row = binomial_row(attackers, seats);
    let honest_row = binomial_row(population - attackers, seats);
    let numerators = (0..=seats as usize)
        .map(|k| &attacker_row[k] * &honest_row[seats as usize - k])
        .collect();
    ExactDistribution {
        numerators,
        denominator: binomial_coefficient(population, seats),
    }
}

/// Joint distribution of attacker seats in two disjoint groups of one KWC: the leader WC
/// (`first` seats) and the subordinate WCs (`second` seats).
#[derive(Debug, Clone, PartialEq)]
pub struct JointDistribution {
    numerators: Vec<Vec<BigUint>>,
    denominator: BigUint,
}

impl JointDistribution {
    /// Joint distribution of attacker seats in groups of `first` and `second` seats.
    pub fn new(first: u64, second: u64, model: &SeatModel) -> Result<Self> {
        model.validate()?;
        match model {
            SeatModel::Binomial(_) => {
                let a = ExactDistribution::new(first, model)?;
                let b = ExactDistribution::new(second, model)?;
                let numerators = a
                    .numerators
                    .iter()
                    .map(|x| b.numerators.iter().map(|y| x * y).collect())
                    .collect();
                Ok(JointDistribution {
                    numerators,
                    denominator: &a.denominator * &b.denominator,
                })
            }
            SeatModel::Hypergeometric {
                population,
                attackers,
            } => {
                ensure(
                    first + second <= *population,
                    "cannot draw more seats than the population",
                )?;
                Ok(joint_hypergeometric(*population, *attackers, first, second))
            }
        }
    }

    /// Seats in the first and second group.
    pub fn group_sizes(&self) -> (u64, u64) {
        let first = self.numerators.len() as u64 - 1;
        let second = self
            .numerators
            .first()
            .map_or(0, |row| row.len() as u64 - 1);
        (first, second)
    }

    /// Probability that the first group holds exactly `x` attacker seats and the second `y`.
    pub fn pmf(&self, x: u64, y: u64) -> Q {
        let value = self
            .numerators
            .get(x as usize)
            .and_then(|row| row.get(y as usize))
            .cloned()
            .unwrap_or_else(BigUint::zero);
        Q::new(BigInt::from(value), BigInt::from(self.denominator.clone()))
    }

    /// Probability of the seat counts `(x, y)` for which `predicate` holds, where `x` counts
    /// attacker seats in the first group and `y` in the second.
    pub fn probability_where(&self, predicate: impl Fn(u64, u64) -> bool) -> Q {
        let mut sum = BigUint::zero();
        for (x, row) in self.numerators.iter().enumerate() {
            for (y, value) in row.iter().enumerate() {
                if predicate(x as u64, y as u64) {
                    sum += value;
                }
            }
        }
        Q::new(BigInt::from(sum), BigInt::from(self.denominator.clone()))
    }
}

fn joint_hypergeometric(
    population: u64,
    attackers: u64,
    first: u64,
    second: u64,
) -> JointDistribution {
    // Draw the first group, then the second from what remains:
    // P(x, y) = C(K,x) C(M-K, n1-x) C(K-x, y) C(M-K-(n1-x), n2-y) / (C(M,n1) C(M-n1,n2)).
    let honest = population - attackers;
    let first_attacker = binomial_row(attackers, first);
    let first_honest = binomial_row(honest, first);
    let mut numerators = Vec::with_capacity(first as usize + 1);
    for x in 0..=first {
        let first_term = &first_attacker[x as usize] * &first_honest[(first - x) as usize];
        if first_term.is_zero() {
            numerators.push(vec![BigUint::zero(); second as usize + 1]);
            continue;
        }
        let remaining_attackers = attackers - x;
        let remaining_honest = honest - (first - x);
        let second_attacker = binomial_row(remaining_attackers, second);
        let second_honest = binomial_row(remaining_honest, second);
        let row = (0..=second as usize)
            .map(|y| &first_term * &second_attacker[y] * &second_honest[second as usize - y])
            .collect();
        numerators.push(row);
    }
    JointDistribution {
        numerators,
        denominator: binomial_coefficient(population, first)
            * binomial_coefficient(population - first, second),
    }
}

/// Binomial distribution by seat-by-seat convolution (independent of the closed form).
pub fn binomial_by_convolution(seats: u64, p: &Q) -> Vec<Q> {
    let q = Q::one() - p;
    let mut distribution = vec![Q::one()];
    for _ in 0..seats {
        let mut next = vec![Q::zero(); distribution.len() + 1];
        for (k, mass) in distribution.iter().enumerate() {
            next[k] += mass * &q;
            next[k + 1] += mass * p;
        }
        distribution = next;
    }
    distribution
}

/// Hypergeometric distribution by sequential draws without replacement (independent of the
/// closed form).
pub fn hypergeometric_by_sequential_draws(population: u64, attackers: u64, seats: u64) -> Vec<Q> {
    let mut distribution = vec![Q::one()];
    for drawn in 0..seats {
        let remaining = integer(population - drawn);
        let mut next = vec![Q::zero(); distribution.len() + 1];
        for (k, mass) in distribution.iter().enumerate() {
            let attackers_left = attackers.saturating_sub(k as u64);
            let honest_left = (population - attackers).saturating_sub(drawn - k as u64);
            next[k + 1] += mass * integer(attackers_left) / &remaining;
            next[k] += mass * integer(honest_left) / &remaining;
        }
        distribution = next;
    }
    distribution
}

/// Joint two-group hypergeometric distribution by sequential draws: the first group's seats
/// are drawn first, then the second group's (independent of the closed form).
pub fn joint_hypergeometric_by_sequential_draws(
    population: u64,
    attackers: u64,
    first: u64,
    second: u64,
) -> Vec<Vec<Q>> {
    let mut grid = vec![vec![Q::zero(); second as usize + 1]; first as usize + 1];
    let first_group = hypergeometric_by_sequential_draws(population, attackers, first);
    for (x, mass) in first_group.iter().enumerate() {
        let x = x as u64;
        if attackers < x || population - attackers < first - x {
            continue;
        }
        let second_group =
            hypergeometric_by_sequential_draws(population - first, attackers - x, second);
        for (y, conditional) in second_group.iter().enumerate() {
            grid[x as usize][y] = mass * conditional;
        }
    }
    grid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exact::ratio;

    #[test]
    fn binomial_matches_known_small_values() {
        // Bin(10, 1/2): P(X >= 7) = (120 + 45 + 10 + 1) / 1024 = 176/1024.
        let d = ExactDistribution::new(10, &SeatModel::Binomial(ratio(1, 2))).unwrap();
        assert_eq!(d.at_least(7), ratio(176, 1024));
        assert_eq!(d.at_most(10), Q::one());
    }

    #[test]
    fn binomial_closed_form_equals_convolution_exactly() {
        // Reference: seat-by-seat convolution; tolerance: exact equality of rationals.
        for p in [ratio(33, 100), ratio(5, 100), ratio(2, 5)] {
            let closed = ExactDistribution::new(40, &SeatModel::Binomial(p.clone())).unwrap();
            assert_eq!(closed.to_rationals(), binomial_by_convolution(40, &p));
        }
    }

    #[test]
    fn hypergeometric_closed_form_equals_sequential_draws_exactly() {
        // Reference: sequential draws without replacement; tolerance: exact equality.
        let model = SeatModel::Hypergeometric {
            population: 200,
            attackers: 66,
        };
        let closed = ExactDistribution::new(40, &model).unwrap();
        assert_eq!(
            closed.to_rationals(),
            hypergeometric_by_sequential_draws(200, 66, 40)
        );
    }

    #[test]
    fn joint_hypergeometric_equals_sequential_draws_exactly() {
        // Reference: draw the leader group, then the subordinates; tolerance: exact equality.
        let model = SeatModel::Hypergeometric {
            population: 120,
            attackers: 40,
        };
        let joint = JointDistribution::new(10, 30, &model).unwrap();
        let grid = joint_hypergeometric_by_sequential_draws(120, 40, 10, 30);
        for (x, row) in grid.iter().enumerate() {
            for (y, value) in row.iter().enumerate() {
                let cell = joint.probability_where(|a, b| a == x as u64 && b == y as u64);
                assert_eq!(&cell, value, "cell ({x}, {y})");
            }
        }
    }

    #[test]
    fn joint_binomial_is_the_product_of_independent_groups() {
        let p = ratio(1, 4);
        let model = SeatModel::Binomial(p.clone());
        let joint = JointDistribution::new(10, 30, &model).unwrap();
        let leader = ExactDistribution::new(10, &model).unwrap();
        let subs = ExactDistribution::new(30, &model).unwrap();
        assert_eq!(
            joint.probability_where(|x, y| x >= 7 && y >= 21),
            leader.at_least(7) * subs.at_least(21)
        );
        assert_eq!(joint.probability_where(|_, _| true), Q::one());
        assert_eq!(joint.group_sizes(), (10, 30));
        assert_eq!(joint.pmf(3, 9), leader.pmf(3) * subs.pmf(9));
        assert_eq!(joint.pmf(11, 0), Q::zero());
    }

    #[test]
    fn all_seats_probability_is_p_to_the_power_n() {
        let p = ratio(1, 20);
        let d = ExactDistribution::new(40, &SeatModel::Binomial(p.clone())).unwrap();
        assert_eq!(d.pmf(40), num_traits::pow(p, 40));
    }

    #[test]
    fn hypergeometric_all_seats_is_a_ratio_of_binomial_coefficients() {
        let model = SeatModel::Hypergeometric {
            population: 1000,
            attackers: 50,
        };
        let d = ExactDistribution::new(40, &model).unwrap();
        let expected = Q::new(
            BigInt::from(binomial_coefficient(50, 40)),
            BigInt::from(binomial_coefficient(1000, 40)),
        );
        assert_eq!(d.pmf(40), expected);
    }

    #[test]
    fn degenerate_probabilities_put_all_mass_at_one_end() {
        let none = ExactDistribution::new(5, &SeatModel::Binomial(Q::zero())).unwrap();
        assert_eq!(none.pmf(0), Q::one());
        let all = ExactDistribution::new(5, &SeatModel::Binomial(Q::one())).unwrap();
        assert_eq!(all.pmf(5), Q::one());
    }

    #[test]
    fn invalid_models_are_rejected() {
        assert!(ExactDistribution::new(5, &SeatModel::Binomial(ratio(3, 2))).is_err());
        let model = SeatModel::Hypergeometric {
            population: 10,
            attackers: 11,
        };
        assert!(ExactDistribution::new(5, &model).is_err());
        let small = SeatModel::Hypergeometric {
            population: 10,
            attackers: 5,
        };
        assert!(ExactDistribution::new(11, &small).is_err());
        assert!(JointDistribution::new(6, 6, &small).is_err());
    }
}
