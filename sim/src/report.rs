//! The report: one JSON file per run plus a text summary on stdout.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use std::fmt::Write as _;

use anyhow::Context;
use serde::Serialize;

use crate::scenario::{ScenarioResult, Status};

/// A whole run.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    /// `fast`, `full` or `replay`.
    pub mode: String,
    /// Unix time the run started.
    pub started: u64,
    /// Wall seconds.
    pub seconds: f64,
    /// Scenario results.
    pub results: Vec<ScenarioResult>,
    /// True when no scenario failed.
    pub passed: bool,
    /// Scenarios by status.
    pub counts: Counts,
}

/// Scenario counts by status.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Counts {
    /// Passed.
    pub pass: usize,
    /// Failed.
    pub fail: usize,
    /// Pending (wave 1 or 2 fills in).
    pub pending: usize,
}

impl Report {
    /// Build from results.
    pub fn new(mode: &str, started: SystemTime, results: Vec<ScenarioResult>) -> Self {
        let mut counts = Counts::default();
        for r in &results {
            match r.status {
                Status::Pass => counts.pass += 1,
                Status::Fail => counts.fail += 1,
                Status::Pending => counts.pending += 1,
            }
        }
        Self {
            mode: mode.to_string(),
            started: started
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            seconds: started.elapsed().map_or(0.0, |d| d.as_secs_f64()),
            results,
            passed: counts.fail == 0,
            counts,
        }
    }

    /// Default output directory: `target/sim/` next to the workspace root.
    pub fn default_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("sim/ has a parent")
            .join("target")
            .join("sim")
    }

    /// Write `<dir>/<mode>.json` and return its path.
    pub fn write(&self, dir: &Path) -> anyhow::Result<PathBuf> {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        let path = dir.join(format!("{}.json", self.mode));
        std::fs::write(&path, serde_json::to_vec_pretty(self)?)
            .with_context(|| format!("write {}", path.display()))?;
        Ok(path)
    }

    /// The text summary.
    pub fn text(&self) -> String {
        let mut s = String::new();
        let f = |v: f64| {
            if v.is_nan() {
                "   -  ".to_string()
            } else {
                format!("{v:6.2}")
            }
        };
        let row = |m: &crate::pipeline::compare::Metrics| {
            format!(
                "{} {} {} {} {} {} {}",
                f(m.ari),
                f(m.tally_median_pp),
                f(m.tally_within5pp),
                f(m.repness_relaxed),
                f(m.consensus_relaxed),
                f(m.k_match),
                f(m.pca_affinity)
            )
        };
        let _ = writeln!(
            s,
            "hum sim · mode {} · {:.1}s · pass {} fail {} pending {}",
            self.mode, self.seconds, self.counts.pass, self.counts.fail, self.counts.pending
        );
        s.push_str("\nscenario                              n     C  eps  ari    tally  <5pp   rep15  cons15 k=   pca    status  secs\n");
        for r in &self.results {
            let metrics = r.mean.as_ref().map_or_else(|| " ".repeat(48), row);
            let _ = writeln!(
                s,
                "{:<36} {:>5} {:>5} {:>4} {} {:<7} {:>5.1}",
                r.name,
                r.size,
                r.statements,
                r.eps.map_or("-".into(), |e| format!("{e}")),
                metrics,
                format!("{:?}", r.status),
                r.seconds
            );
            if let Some(c) = &r.churn {
                let _ = writeln!(
                    s,
                    "{:<36} {:>5} {:>5} {:>4} {}  no-DP churn floor",
                    "  churn10 (no DP, 10% drop out)",
                    "",
                    "",
                    "",
                    row(c)
                );
            }
            for rr in &r.reference {
                let _ = writeln!(
                    s,
                    "{:<36} {:>5} {:>5} {:>4} {} {} {} {} {} {} {}  research E2 mean",
                    format!("  research ε{} n={}", rr.eps, rr.n),
                    "",
                    "",
                    "",
                    f(rr.ari),
                    f(rr.tally_median_pp),
                    f(rr.tally_within5pp),
                    f(rr.repness_relaxed),
                    f(rr.consensus_relaxed),
                    f(rr.k_match),
                    f(rr.pca_affinity)
                );
            }
            for g in &r.gates {
                let _ = writeln!(
                    s,
                    "    gate {:<18} {:>6.2} {} {:<6.2} {}",
                    g.gate.metric,
                    g.value,
                    if g.gate.at_least { ">=" } else { "<=" },
                    g.gate.threshold,
                    if g.pass { "ok" } else { "FAIL" }
                );
            }
            if let Some(l) = &r.leak {
                let per: Vec<String> = l
                    .calls_by_service
                    .iter()
                    .map(|(s, c)| {
                        format!(
                            "{s} {c}/{}",
                            l.records_by_service.get(s).copied().unwrap_or(0)
                        )
                    })
                    .collect();
                let _ = writeln!(
                    s,
                    "    leak check: {} records, {} secrets, {} violations; calls/records per port: {}",
                    l.records,
                    l.secrets,
                    l.violations.len(),
                    per.join(", ")
                );
                for v in l.violations.iter().take(10) {
                    let _ = writeln!(
                        s,
                        "      LEAK {} in {}/{}: {}",
                        v.rule, v.service, v.op, v.detail
                    );
                }
            }
            for v in &r.protocol_violations {
                let _ = writeln!(s, "    VIOLATION {v}");
            }
            for n in &r.notes {
                let _ = writeln!(s, "    note: {n}");
            }
        }
        s
    }
}
