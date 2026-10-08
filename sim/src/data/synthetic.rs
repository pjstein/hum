//! A seeded synthetic conversation with recoverable opinion groups, so the
//! simulator runs offline. It stands in for Polis data in `sim-fast` and is
//! labelled as synthetic in every report; thresholds for it are calibrated
//! separately from the research thresholds (see `thresholds.rs`).
//!
//! Shape: a few latent groups of uneven size; statements that are consensus
//! (everyone leans agree), divisive (one group agrees, the others disagree) or
//! noise (coin flips); each participant votes on a subset whose size follows a
//! long-tailed distribution and whose members follow a skewed exposure curve,
//! as in Polis, where the 60 most-voted statements of a large conversation
//! each carry votes from 40–60% of participants.

use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use super::{Vote, VoteMatrix};

/// Parameters of a synthetic conversation.
#[derive(Clone, Debug)]
pub struct SyntheticSpec {
    /// Participants.
    pub n: usize,
    /// Statements.
    pub c: usize,
    /// Relative group sizes.
    pub group_weights: Vec<f64>,
    /// Shares of consensus, divisive and noise statements.
    pub statement_mix: [f64; 3],
    /// Median votes per participant.
    pub median_votes: usize,
    /// Exposure skew: statement `j` is shown with weight `(1 + j)^-skew`.
    pub skew: f64,
    /// How strongly a divisive statement separates groups (0.5 = none, 1 = perfectly).
    pub signal: f64,
}

impl SyntheticSpec {
    /// A conversation sized like the Polis ones at `n` participants: the
    /// statement count grows with size, as it does in the open data.
    pub fn sized(n: usize) -> Self {
        let c = (30 + n / 5).clamp(30, 400);
        Self {
            n,
            c,
            group_weights: vec![0.5, 0.3, 0.2],
            statement_mix: [0.25, 0.45, 0.30],
            median_votes: 45,
            skew: 1.2,
            signal: 0.85,
        }
    }
}

/// Generate the conversation for a spec and seed. Same inputs, same matrix.
pub fn generate(spec: &SyntheticSpec, seed: u64) -> VoteMatrix {
    let mut rng = ChaCha8Rng::seed_from_u64(0x5917_4e71_c000_0000 ^ seed);
    let g = spec.group_weights.len();
    let total_w: f64 = spec.group_weights.iter().sum();

    // Statement kinds and per-group agree probabilities.
    let mut p_agree = vec![vec![0.0; g]; spec.c];
    for row in &mut p_agree {
        let u = rng.random::<f64>();
        if u < spec.statement_mix[0] {
            let base = 0.70 + 0.2 * rng.random::<f64>();
            row.fill(base);
        } else if u < spec.statement_mix[0] + spec.statement_mix[1] {
            let owner = rng.random_range(0..g);
            for (k, pg) in row.iter_mut().enumerate() {
                *pg = if k == owner {
                    spec.signal
                } else {
                    1.0 - spec.signal
                };
            }
        } else {
            for pg in row.iter_mut() {
                *pg = 0.35 + 0.3 * rng.random::<f64>();
            }
        }
    }

    let mut m = VoteMatrix::new(format!("synthetic-{}-seed{seed}", spec.n), spec.n, spec.c);
    for i in 0..spec.n {
        // Group by weight.
        let mut r = rng.random::<f64>() * total_w;
        let mut group = g - 1;
        for (k, w) in spec.group_weights.iter().enumerate() {
            r -= w;
            if r <= 0.0 {
                group = k;
                break;
            }
        }
        m.source_groups[i] = Some(group);
        // Long-tailed vote count: log-normal around the median, at least 7.
        let z: f64 = rand_distr::Distribution::sample(&rand_distr::StandardNormal, &mut rng);
        let k = ((spec.median_votes as f64) * (0.8 * z).exp()).round() as usize;
        let k = k.clamp(7, spec.c);
        // Weighted sampling without replacement (Efraimidis–Spirakis keys).
        let mut keyed: Vec<(f64, usize)> = (0..spec.c)
            .map(|j| {
                let w = (1.0 + j as f64).powf(-spec.skew);
                (rng.random::<f64>().powf(1.0 / w), j)
            })
            .collect();
        keyed.sort_by(|a, b| b.0.total_cmp(&a.0));
        for &(_, j) in keyed.iter().take(k) {
            let p = p_agree[j][group];
            let u = rng.random::<f64>();
            let v = if u < 0.12 {
                Vote::Pass
            } else if rng.random::<f64>() < p {
                Vote::Agree
            } else {
                Vote::Disagree
            };
            m.set(i, j, Some(v));
        }
    }
    m.drop_empty_columns()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_deterministic_per_seed() {
        let a = generate(&SyntheticSpec::sized(120), 3);
        let b = generate(&SyntheticSpec::sized(120), 3);
        let c = generate(&SyntheticSpec::sized(120), 4);
        assert_eq!(a.total_votes(), b.total_votes());
        assert!((0..a.n()).all(|i| a.row(i) == b.row(i)));
        assert_ne!(a.total_votes(), c.total_votes());
    }

    #[test]
    fn every_participant_has_at_least_min_votes() {
        let m = generate(&SyntheticSpec::sized(300), 0);
        assert!((0..m.n()).all(|i| m.votes_in_row(i) >= 7));
        assert_eq!(m.n(), 300);
    }
}
