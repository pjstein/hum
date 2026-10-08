//! A port of `docs/research/dp-polis/polis_dp.py`: zCDP accounting, the
//! non-private baseline, the DP release pipeline, noise-aware rankings and the
//! comparison metrics. This is the oracle the simulator judges releases
//! against. It is a fake in the sense of `docs/specs/simulator.md`: the real
//! release math is `hum-release` (W1 aggregation), which wave 1 plugs in behind
//! the `Aggregator` port and which this port then checks.
//!
//! Noise here is floating-point Gaussian noise from `rand_distr`, exactly as in
//! the research code. That is fine for an oracle and a fake, and forbidden for
//! the product (`CLAUDE.md`, security seams).

pub mod accounting;
pub mod baseline;
pub mod compare;
pub mod dp;
pub mod linalg;
pub mod rank;

use serde::{Deserialize, Serialize};

/// Agree, disagree and pass counts per statement.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Tallies {
    /// Agree count per statement.
    pub agree: Vec<f64>,
    /// Disagree count per statement.
    pub disagree: Vec<f64>,
    /// Pass (unsure) count per statement.
    pub pass: Vec<f64>,
}

impl Tallies {
    /// Number of statements.
    pub fn len(&self) -> usize {
        self.agree.len()
    }

    /// True when there are no statements.
    pub fn is_empty(&self) -> bool {
        self.agree.is_empty()
    }

    /// Total votes per statement.
    pub fn totals(&self) -> Vec<f64> {
        (0..self.len())
            .map(|j| self.agree[j] + self.disagree[j] + self.pass[j])
            .collect()
    }

    /// Share of agree votes per statement (`agree_frac` in the research code).
    pub fn agree_frac(&self) -> Vec<f64> {
        (0..self.len())
            .map(|j| self.agree[j] / (self.agree[j] + self.disagree[j] + self.pass[j]).max(1.0))
            .collect()
    }
}

/// Which way a representative statement leans.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Lean {
    /// The group agrees with it more than everyone else.
    Agree,
    /// The group disagrees with it more than everyone else.
    Disagree,
}

/// One ranked representative statement: statement index and lean.
pub type Rep = (usize, Lean);

/// Published noise levels of one release (`sigmas` in the research code).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Sigmas {
    /// Noise on each tally count.
    pub tally: f64,
    /// Noise on each covariance entry.
    pub cov: f64,
    /// Noise on each map cell.
    pub hist: f64,
    /// Noise on each per-group count.
    pub group: f64,
}

/// What one analysis (baseline or DP) produced. The baseline's `pcs` run over
/// every statement with `sel` = all; the DP pipeline's run over `sel` only.
#[derive(Clone, Debug)]
pub struct Analysis {
    /// Two principal axes, one `[f64; 2]` per selected statement.
    pub pcs: Vec<[f64; 2]>,
    /// Statements the axes were computed over, in order.
    pub sel: Vec<usize>,
    /// Each participant's projection onto the axes (phone-side; never published).
    pub proj: Vec<[f64; 2]>,
    /// Each participant's group (phone-side; never published).
    pub groups: Vec<usize>,
    /// Number of groups.
    pub k: usize,
    /// Public tallies.
    pub tallies: Tallies,
    /// Per-group tallies, one per group.
    pub group_tallies: Vec<Tallies>,
    /// Top 15 representative statements per group.
    pub rep: Vec<Vec<Rep>>,
    /// Top 15 consensus statements.
    pub cons: Vec<usize>,
    /// Noise levels, `None` for the baseline.
    pub sigmas: Option<Sigmas>,
    /// Noised participant count (the true count for the baseline).
    pub n_hat: f64,
    /// Column means used for centring (exact for the baseline, from noised tallies for DP).
    pub mu: Vec<f64>,
    /// Group centroids in projection space.
    pub centroids: Vec<[f64; 2]>,
}
