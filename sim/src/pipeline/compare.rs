//! The comparison metrics (`compare`, `overlap`, `churn`): how much of the
//! non-private analysis survives in a DP release.

use std::collections::HashSet;

use rand::Rng;
use serde::{Deserialize, Serialize};

use super::Analysis;
use super::baseline::baseline;
use super::linalg::{adjusted_rand_index, best_assignment, median, subspace_affinity};
use super::rank::TOP;
use crate::data::VoteMatrix;

/// The metric set carried over from the research code. NaN means "not
/// enough statements in that bin" (as in the CSVs).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Metrics {
    /// Median tally error (pp) over statements with 10–49 votes.
    pub tally_err_10: f64,
    /// … with 50–199 votes.
    pub tally_err_50: f64,
    /// … with 200–999 votes.
    pub tally_err_200: f64,
    /// … with 1,000+ votes.
    pub tally_err_1000: f64,
    /// Median agree-share error in percentage points over statements with 10+ votes.
    pub tally_median_pp: f64,
    /// Share of those statements within 5 pp.
    pub tally_within5pp: f64,
    /// Affinity between the baseline and DP principal subspaces (0–1).
    pub pca_affinity: f64,
    /// 1 when the DP release found the same number of groups.
    pub k_match: f64,
    /// Adjusted Rand index between baseline and DP groups.
    pub ari: f64,
    /// Share of each group's DP top-5 representative statements in the baseline top 5.
    pub repness_overlap: f64,
    /// … in the baseline top 15.
    pub repness_relaxed: f64,
    /// Share of the DP top-5 consensus statements in the baseline top 5.
    pub consensus_overlap: f64,
    /// … in the baseline top 15.
    pub consensus_relaxed: f64,
}

impl Metrics {
    /// Metric names in CSV order.
    pub const NAMES: [&'static str; 13] = [
        "tally_err_10",
        "tally_err_50",
        "tally_err_200",
        "tally_err_1000",
        "tally_median_pp",
        "tally_within5pp",
        "pca_affinity",
        "k_match",
        "ari",
        "repness_overlap",
        "repness_relaxed",
        "consensus_overlap",
        "consensus_relaxed",
    ];

    /// Values in `NAMES` order.
    pub fn values(&self) -> [f64; 13] {
        [
            self.tally_err_10,
            self.tally_err_50,
            self.tally_err_200,
            self.tally_err_1000,
            self.tally_median_pp,
            self.tally_within5pp,
            self.pca_affinity,
            self.k_match,
            self.ari,
            self.repness_overlap,
            self.repness_relaxed,
            self.consensus_overlap,
            self.consensus_relaxed,
        ]
    }

    /// Look a metric up by name.
    pub fn get(&self, name: &str) -> Option<f64> {
        Self::NAMES
            .iter()
            .position(|n| *n == name)
            .map(|i| self.values()[i])
    }

    /// Element-wise mean, ignoring NaNs per field.
    pub fn mean(all: &[Metrics]) -> Metrics {
        let mut out = [0.0f64; 13];
        for (i, o) in out.iter_mut().enumerate() {
            let vals: Vec<f64> = all
                .iter()
                .map(|m| m.values()[i])
                .filter(|v| !v.is_nan())
                .collect();
            *o = if vals.is_empty() {
                f64::NAN
            } else {
                vals.iter().sum::<f64>() / vals.len() as f64
            };
        }
        Metrics {
            tally_err_10: out[0],
            tally_err_50: out[1],
            tally_err_200: out[2],
            tally_err_1000: out[3],
            tally_median_pp: out[4],
            tally_within5pp: out[5],
            pca_affinity: out[6],
            k_match: out[7],
            ari: out[8],
            repness_overlap: out[9],
            repness_relaxed: out[10],
            consensus_overlap: out[11],
            consensus_relaxed: out[12],
        }
    }
}

/// `overlap`: strict = share of the DP top-k in the baseline top-k; relaxed =
/// share of the DP top-k in the baseline top-3k.
pub fn overlap<T: std::hash::Hash + Eq + Copy>(dp: &[T], base: &[T], k: usize) -> (f64, f64) {
    let d: HashSet<T> = dp.iter().take(k).copied().collect();
    let b_strict: HashSet<T> = base.iter().take(k).copied().collect();
    let b_relaxed: HashSet<T> = base.iter().take(3 * k).copied().collect();
    (
        d.intersection(&b_strict).count() as f64 / k as f64,
        d.intersection(&b_relaxed).count() as f64 / k as f64,
    )
}

/// Compare a DP analysis with the baseline. `base_groups` lets a subsample be
/// compared on the participants it shares with the baseline.
pub fn compare(base: &Analysis, dp: &Analysis, base_groups: Option<&[usize]>) -> Metrics {
    let bg: &[usize] = base_groups.unwrap_or(&base.groups);
    let ta = base.tallies.agree_frac();
    let tb = dp.tallies.agree_frac();
    let ns = base.tallies.totals();
    let err: Vec<f64> = ta
        .iter()
        .zip(&tb)
        .map(|(a, b)| (a - b).abs() * 100.0)
        .collect();
    let bin = |lo: f64, hi: f64| -> f64 {
        let v: Vec<f64> = (0..err.len())
            .filter(|&j| ns[j] >= lo && ns[j] < hi)
            .map(|j| err[j])
            .collect();
        if v.len() >= 3 { median(&v) } else { f64::NAN }
    };
    let m10: Vec<f64> = (0..err.len())
        .filter(|&j| ns[j] >= 10.0)
        .map(|j| err[j])
        .collect();
    let within = if m10.is_empty() {
        f64::NAN
    } else {
        m10.iter().filter(|&&e| e <= 5.0).count() as f64 / m10.len() as f64
    };

    let base_pcs_sel: Vec<[f64; 2]> = dp.sel.iter().map(|&j| base.pcs[j]).collect();
    let pca_affinity = subspace_affinity(&base_pcs_sel, &dp.pcs);

    let (kb, kd) = (base.k, dp.k);
    let mut conf = vec![vec![0.0f64; kd]; kb];
    for (&a, &b) in bg.iter().zip(&dp.groups) {
        conf[a][b] += 1.0;
    }
    let mut strict = vec![0.0; kb];
    let mut relaxed = vec![0.0; kb];
    for (a, b) in best_assignment(&conf) {
        let (s, r) = overlap(&dp.rep[b], &base.rep[a], TOP);
        strict[a] = s;
        relaxed[a] = r;
    }
    let (co, cr) = overlap(&dp.cons, &base.cons, TOP);
    Metrics {
        tally_err_10: bin(10.0, 50.0),
        tally_err_50: bin(50.0, 200.0),
        tally_err_200: bin(200.0, 1000.0),
        tally_err_1000: bin(1000.0, 1e9),
        tally_median_pp: median(&m10),
        tally_within5pp: within,
        pca_affinity,
        k_match: f64::from(u8::from(kd == kb)),
        ari: adjusted_rand_index(bg, &dp.groups),
        repness_overlap: strict.iter().sum::<f64>() / kb as f64,
        repness_relaxed: relaxed.iter().sum::<f64>() / kb as f64,
        consensus_overlap: co,
        consensus_relaxed: cr,
    }
}

/// The non-private noise floor: rerun the baseline as if a random 10% of
/// participants never showed up, and compare on the ones who did.
pub fn churn(x: &VoteMatrix, base: &Analysis, frac: f64, rng: &mut impl Rng) -> Metrics {
    let keep: Vec<usize> = (0..x.n()).filter(|_| rng.random::<f64>() < frac).collect();
    let sub = x.subset_rows(&keep);
    // `subset_rows` drops empty columns; keep the statement set aligned with the baseline.
    let sub = if sub.c() == x.c() {
        sub
    } else {
        keep_all_columns(x, &keep)
    };
    let mut b = baseline(&sub, rng);
    b.sel = (0..x.c()).collect();
    let bg: Vec<usize> = keep.iter().map(|&i| base.groups[i]).collect();
    compare(base, &b, Some(&bg))
}

fn keep_all_columns(x: &VoteMatrix, rows: &[usize]) -> VoteMatrix {
    let mut m = VoteMatrix::new(x.name.clone(), rows.len(), x.c());
    for (ni, &i) in rows.iter().enumerate() {
        for j in 0..x.c() {
            m.set(ni, j, x.get(i, j));
        }
        m.source_groups[ni] = x.source_groups[i];
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::synthetic::{SyntheticSpec, generate};
    use crate::pipeline::dp::{DpParams, dp_pipeline};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn overlap_counts_shared_items() {
        let (s, r) = overlap(&[1, 2, 3, 4, 5], &[5, 4, 9, 8, 7, 6, 3, 2, 1], 5);
        assert!((s - 0.4).abs() < 1e-12);
        assert!((r - 1.0).abs() < 1e-12);
    }

    #[test]
    fn comparing_a_release_without_noise_scores_near_perfect_tallies() {
        let m = generate(&SyntheticSpec::sized(200), 5);
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        let b = baseline(&m, &mut rng);
        let d = dp_pipeline(
            &m,
            f64::INFINITY,
            &DpParams {
                cap: None,
                ..DpParams::default()
            },
            &mut rng,
        );
        let met = compare(&b, &d, None);
        assert!(met.tally_median_pp.abs() < 1e-9, "{met:?}");
        assert!((met.tally_within5pp - 1.0).abs() < 1e-12);
        assert!(met.ari > 0.5, "{met:?}");
    }
}
