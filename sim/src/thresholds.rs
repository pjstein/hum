//! Research reference values and the gates the simulator applies.
//!
//! `RESEARCH_E2` is the mean over the research's size sweep (E2 in
//! `docs/research/dp-polis/results/e2.csv`: four large Polis conversations,
//! participants subsampled, 5 seeds × 2 noise draws). Reports print the rows
//! nearest a scenario's size so a reader can compare at a glance.
//!
//! Gates are per source: Polis replays are judged against the research
//! means with slack for seed noise; the synthetic fixture has its own
//! calibrated gates (see `docs/specs/simulator.md`, "Thresholds"). A gate
//! only applies to a tier the design unlocks at that size: tally gates from
//! 100 voters, common ground from 300, map and groups from 800.

use serde::Serialize;

use crate::pipeline::compare::Metrics;

/// One row of the research size sweep.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct ReferenceRow {
    /// Label (`"4"`, `"8"`, `"churn10"`).
    pub eps: &'static str,
    /// Participants.
    pub n: usize,
    /// Mean ARI.
    pub ari: f64,
    /// Mean median tally error in pp.
    pub tally_median_pp: f64,
    /// Mean share within 5 pp.
    pub tally_within5pp: f64,
    /// Mean representative-statement overlap (relaxed).
    pub repness_relaxed: f64,
    /// Mean consensus overlap (relaxed).
    pub consensus_relaxed: f64,
    /// Mean k match.
    pub k_match: f64,
    /// Mean PCA affinity.
    pub pca_affinity: f64,
}

macro_rules! row {
    ($eps:expr, $n:expr, $ari:expr, $tm:expr, $tw:expr, $rr:expr, $cr:expr, $km:expr, $pa:expr) => {
        ReferenceRow {
            eps: $eps,
            n: $n,
            ari: $ari,
            tally_median_pp: $tm,
            tally_within5pp: $tw,
            repness_relaxed: $rr,
            consensus_relaxed: $cr,
            k_match: $km,
            pca_affinity: $pa,
        }
    };
}

/// Means from `e2.csv`, computed on 2026-10-06 (columns: ARI, tally pp,
/// within 5 pp, repness relaxed, consensus relaxed, k match, PCA affinity).
pub const RESEARCH_E2: &[ReferenceRow] = &[
    row!("churn10", 100, 0.77, 1.65, 0.91, 0.78, 0.95, 0.85, 0.91),
    row!("churn10", 200, 0.88, 1.25, 0.94, 0.87, 0.93, 0.75, 0.92),
    row!("churn10", 400, 0.91, 0.98, 0.97, 0.98, 1.00, 0.95, 0.96),
    row!("churn10", 800, 0.97, 0.70, 0.99, 1.00, 0.99, 1.00, 0.99),
    row!("churn10", 1600, 0.96, 0.70, 0.98, 0.99, 1.00, 1.00, 0.99),
    row!("churn10", 3200, 0.96, 0.22, 0.99, 1.00, 1.00, 1.00, 1.00),
    row!("2", 100, 0.00, 31.63, 0.08, 0.04, 0.10, 0.12, 0.04),
    row!("2", 200, 0.00, 28.57, 0.10, 0.08, 0.10, 0.10, 0.09),
    row!("2", 400, 0.07, 22.58, 0.13, 0.11, 0.15, 0.33, 0.23),
    row!("2", 800, 0.40, 16.76, 0.20, 0.39, 0.26, 0.33, 0.45),
    row!("2", 1600, 0.66, 14.98, 0.24, 0.66, 0.27, 0.65, 0.63),
    row!("2", 3200, 0.69, 4.44, 0.54, 0.75, 0.38, 0.90, 0.73),
    row!("4", 100, 0.00, 27.10, 0.10, 0.06, 0.07, 0.20, 0.08),
    row!("4", 200, 0.09, 22.48, 0.13, 0.10, 0.14, 0.20, 0.21),
    row!("4", 400, 0.32, 17.14, 0.19, 0.31, 0.20, 0.28, 0.44),
    row!("4", 800, 0.61, 12.29, 0.30, 0.67, 0.45, 0.70, 0.62),
    row!("4", 1600, 0.74, 10.58, 0.37, 0.80, 0.45, 0.90, 0.78),
    row!("4", 3200, 0.77, 2.54, 0.72, 0.91, 0.60, 1.00, 0.74),
    row!("8", 100, 0.06, 21.35, 0.13, 0.08, 0.15, 0.35, 0.18),
    row!("8", 200, 0.45, 16.97, 0.19, 0.29, 0.24, 0.20, 0.42),
    row!("8", 400, 0.57, 12.61, 0.29, 0.62, 0.40, 0.65, 0.61),
    row!("8", 800, 0.69, 8.54, 0.44, 0.84, 0.59, 0.85, 0.75),
    row!("8", 1600, 0.74, 7.27, 0.49, 0.89, 0.61, 0.90, 0.80),
    row!("8", 3200, 0.67, 1.61, 0.81, 0.89, 0.72, 0.80, 0.77),
    row!("16", 100, 0.30, 15.44, 0.19, 0.24, 0.22, 0.40, 0.39),
    row!("16", 200, 0.59, 12.11, 0.29, 0.61, 0.37, 0.68, 0.55),
    row!("16", 400, 0.63, 8.94, 0.41, 0.77, 0.48, 0.88, 0.70),
    row!("16", 800, 0.80, 5.94, 0.55, 0.90, 0.72, 0.95, 0.81),
    row!("16", 1600, 0.76, 5.14, 0.59, 0.95, 0.78, 0.95, 0.81),
    row!("16", 3200, 0.73, 1.14, 0.88, 0.93, 0.90, 0.90, 0.77),
];

/// Label for an ε as the research CSVs spell it.
pub fn eps_label(eps: f64) -> String {
    if eps.is_infinite() {
        "inf".to_string()
    } else {
        format!("{eps}")
    }
}

/// The research rows that bracket a size at an ε (one row when the size is
/// in the table, two when it falls between rows), plus the churn row.
pub fn reference_for(n: usize, eps: f64) -> Vec<ReferenceRow> {
    let label = eps_label(eps);
    let mut rows: Vec<ReferenceRow> = RESEARCH_E2
        .iter()
        .copied()
        .filter(|r| r.eps == label)
        .collect();
    rows.sort_by_key(|r| r.n);
    let mut out = vec![];
    if let Some(exact) = rows.iter().find(|r| r.n == n) {
        out.push(*exact);
    } else {
        if let Some(below) = rows.iter().rfind(|r| r.n < n) {
            out.push(*below);
        }
        if let Some(above) = rows.iter().find(|r| r.n > n) {
            out.push(*above);
        }
    }
    out
}

/// Where the data came from, which decides the gate table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum SourceKind {
    /// The seeded synthetic fixture.
    Synthetic,
    /// Polis open data.
    Polis,
}

/// A gate: a metric must be at least (or at most) a threshold.
#[derive(Clone, Debug, Serialize)]
pub struct Gate {
    /// Metric name.
    pub metric: &'static str,
    /// True when the metric must be ≥ the threshold, false for ≤.
    pub at_least: bool,
    /// Threshold.
    pub threshold: f64,
    /// Which tier it belongs to.
    pub tier: &'static str,
}

/// A gate's outcome.
#[derive(Clone, Debug, Serialize)]
pub struct GateResult {
    /// The gate.
    pub gate: Gate,
    /// The measured mean.
    pub value: f64,
    /// Whether it passed (a NaN value fails).
    pub pass: bool,
}

/// Gates for a replay at `n` voters and ε, by source. Returns `None` when
/// the pair has no reference and must not be gated (the scenario is then
/// reported as pending, never as a pass).
///
/// Research gates are the E2 mean for the nearest size at or below `n` minus
/// slack for seed-to-seed spread; a gate whose threshold clamps to zero is
/// skipped rather than applied. Synthetic gates were calibrated on the
/// fixture on 2026-10-06 with the tallies blend off (see the spec's table);
/// the tally gate scales with the noise, σ ∝ 1/√ρ, from its ε 4 value, and
/// the ranking and group gates apply from ε 4 up, where a larger ε only
/// makes them easier.
pub fn gates_for(source: SourceKind, n: usize, eps: f64) -> Option<Vec<Gate>> {
    let mut g = vec![];
    let tier_tally = n >= 100;
    let tier_common = n >= 300;
    let tier_map = n >= 800;
    match source {
        SourceKind::Polis => {
            let rows = reference_for(n, eps);
            let r = rows.first()?;
            if r.n > n {
                return None; // no reference at or below this size
            }
            if tier_tally {
                g.push(Gate {
                    metric: "tally_median_pp",
                    at_least: false,
                    threshold: r.tally_median_pp * 1.5 + 2.0,
                    tier: "tallies",
                });
            }
            let floor = |v: f64, slack: f64, metric: &'static str, tier: &'static str| {
                let t = v - slack;
                (t > 0.0).then_some(Gate {
                    metric,
                    at_least: true,
                    threshold: t,
                    tier,
                })
            };
            if tier_common {
                g.extend(floor(
                    r.consensus_relaxed,
                    0.25,
                    "consensus_relaxed",
                    "common-ground",
                ));
            }
            if tier_map {
                // At 800 voters and ε 4 the research's per-run ARI ranged 0.12–0.90 around a mean of 0.61.
                g.extend(floor(r.ari, 0.45, "ari", "map-and-groups"));
                g.extend(floor(
                    r.repness_relaxed,
                    0.35,
                    "repness_relaxed",
                    "map-and-groups",
                ));
            }
        }
        SourceKind::Synthetic => {
            if !(2.0..=16.0).contains(&eps) {
                return None;
            }
            let scale = (crate::pipeline::accounting::eps_to_rho(4.0, 1e-6)
                / crate::pipeline::accounting::eps_to_rho(eps, 1e-6))
            .sqrt();
            if tier_tally {
                let t4 = if n < 300 {
                    32.0
                } else if n < 800 {
                    20.0
                } else {
                    14.0
                };
                g.push(Gate {
                    metric: "tally_median_pp",
                    at_least: false,
                    threshold: t4 * scale,
                    tier: "tallies",
                });
            }
            if eps >= 4.0 {
                if tier_common {
                    g.push(Gate {
                        metric: "consensus_relaxed",
                        at_least: true,
                        threshold: if n < 800 { 0.15 } else { 0.3 },
                        tier: "common-ground",
                    });
                }
                if tier_map {
                    g.push(Gate {
                        metric: "ari",
                        at_least: true,
                        threshold: 0.45,
                        tier: "map-and-groups",
                    });
                    g.push(Gate {
                        metric: "repness_relaxed",
                        at_least: true,
                        threshold: 0.4,
                        tier: "map-and-groups",
                    });
                }
            }
        }
    }
    Some(g)
}

/// Apply gates to a mean metric set.
pub fn apply(gates: Vec<Gate>, mean: &Metrics) -> Vec<GateResult> {
    gates
        .into_iter()
        .map(|gate| {
            let value = mean.get(gate.metric).unwrap_or(f64::NAN);
            let pass = !value.is_nan()
                && if gate.at_least {
                    value >= gate.threshold
                } else {
                    value <= gate.threshold
                };
            GateResult { gate, value, pass }
        })
        .collect()
}
