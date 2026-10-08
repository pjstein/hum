//! Noise-aware representative and consensus rankings (`repness`, `consensus`).

use super::{Lean, Rep, Tallies};

/// Rows returned per ranking (the metrics use the top 5 of these 15).
pub const TOP: usize = 5;

/// Polis-style representative statements per group. With `noise_sd > 0` the
/// pseudo-counts scale with the noise and the z-tests use an effective sample
/// size that includes the noise variance.
pub fn repness(group_counts: &[Tallies], noise_sd: f64) -> Vec<Vec<Rep>> {
    let k = group_counts.len();
    let c = group_counts.first().map_or(0, Tallies::len);
    let tot_a: Vec<f64> = (0..c)
        .map(|j| group_counts.iter().map(|g| g.agree[j]).sum())
        .collect();
    let tot_d: Vec<f64> = (0..c)
        .map(|j| group_counts.iter().map(|g| g.disagree[j]).sum())
        .collect();
    let tot_p: Vec<f64> = (0..c)
        .map(|j| group_counts.iter().map(|g| g.pass[j]).sum())
        .collect();
    let lam_in = noise_sd.max(1.0);
    let lam_out = (noise_sd * ((k.max(2) - 1) as f64).sqrt()).max(1.0);
    let mut out = Vec::with_capacity(k);
    for g in group_counts {
        let mut rows: Vec<(usize, Lean, f64, bool)> = Vec::with_capacity(c);
        for j in 0..c {
            let (na, nd, np) = (g.agree[j], g.disagree[j], g.pass[j]);
            let ns = na + nd + np;
            let (oa, od) = (tot_a[j] - na, tot_d[j] - nd);
            let os = (tot_a[j] + tot_d[j] + tot_p[j]) - ns;
            let ne_in = if noise_sd > 0.0 {
                ns * ns / (ns + 3.0 * noise_sd * noise_sd).max(1e-9)
            } else {
                ns
            };
            let ne_out = if noise_sd > 0.0 {
                os * os / (os + 3.0 * (k as f64 - 1.0) * noise_sd * noise_sd).max(1e-9)
            } else {
                os
            };
            let score = |s: f64, o: f64| -> (f64, f64, f64) {
                let p = (s + lam_in) / (ns + 2.0 * lam_in);
                let po = (o + lam_out) / (os + 2.0 * lam_out);
                let r = p / po;
                let pt = 2.0 * (ne_in + 1.0).sqrt() * (p - 0.5);
                let pp = (s + o + 1.0) / (ns + os + 2.0);
                let rt = (p - po)
                    / (pp * (1.0 - pp) * (1.0 / (ne_in + 1.0) + 1.0 / (ne_out + 1.0)))
                        .max(1e-12)
                        .sqrt();
                (r * rt * p * pt, pt, rt)
            };
            let (ma, pta, rta) = score(na, oa);
            let (md, ptd, rtd) = score(nd, od);
            let (metric, pt, rt, lean) = if ma >= md {
                (ma, pta, rta, Lean::Agree)
            } else {
                (md, ptd, rtd, Lean::Disagree)
            };
            let sig = pt > 1.2816 && rt > 1.2816;
            rows.push((j, lean, metric, sig));
        }
        // Significant first, then by metric descending (lexsort in the research code).
        rows.sort_by(|a, b| b.3.cmp(&a.3).then_with(|| b.2.total_cmp(&a.2)));
        out.push(rows.iter().take(3 * TOP).map(|r| (r.0, r.1)).collect());
    }
    out
}

/// Consensus statements: product over groups of smoothed agree shares.
pub fn consensus(group_counts: &[Tallies], noise_sd: f64) -> Vec<usize> {
    let lam = noise_sd.max(1.0);
    let c = group_counts.first().map_or(0, Tallies::len);
    let mut gic = vec![1.0f64; c];
    for g in group_counts {
        for (j, gj) in gic.iter_mut().enumerate() {
            *gj *= (g.agree[j] + lam) / (g.agree[j] + g.disagree[j] + g.pass[j] + 2.0 * lam);
        }
    }
    let mut order: Vec<usize> = (0..c).collect();
    order.sort_by(|&a, &b| gic[b].total_cmp(&gic[a]));
    order.truncate(3 * TOP);
    order
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consensus_ranks_the_statement_everyone_agrees_with_first() {
        let g1 = Tallies {
            agree: vec![90.0, 10.0, 50.0],
            disagree: vec![5.0, 80.0, 40.0],
            pass: vec![5.0, 10.0, 10.0],
        };
        let g2 = Tallies {
            agree: vec![80.0, 70.0, 45.0],
            disagree: vec![10.0, 20.0, 45.0],
            pass: vec![10.0, 10.0, 10.0],
        };
        assert_eq!(consensus(&[g1, g2], 0.0)[0], 0);
    }

    #[test]
    fn repness_finds_the_divisive_statement() {
        let g1 = Tallies {
            agree: vec![90.0, 10.0, 50.0],
            disagree: vec![5.0, 80.0, 40.0],
            pass: vec![5.0, 10.0, 10.0],
        };
        let g2 = Tallies {
            agree: vec![80.0, 70.0, 45.0],
            disagree: vec![10.0, 20.0, 45.0],
            pass: vec![10.0, 10.0, 10.0],
        };
        let r = repness(&[g1, g2], 0.0);
        assert_eq!(r[0][0], (1, Lean::Disagree));
        assert_eq!(r[1][0], (1, Lean::Agree));
    }
}
