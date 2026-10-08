//! The DP release pipeline (`dp_pipeline`): four noised sums (tallies,
//! covariance, map histogram, group tallies) and the post-processing that
//! turns them into axes, groups and rankings.
//!
//! The function also computes the phone-side steps (each participant's
//! projection and group) because it has the whole matrix, exactly as the
//! research code did. `Analysis::proj` and `Analysis::groups` are phone-side
//! facts: the fake aggregator keeps them out of the release it publishes.

use rand::Rng;
use rand_distr::{Distribution, Normal};

use super::accounting::{DELTA, Split, eps_to_rho, gauss_sigma};
use super::baseline::counts;
use super::linalg::{SymMat, blur_noise_factor, choose_kmeans, gaussian_blur, top2_eigen};
use super::rank::{consensus, repness};
use super::{Analysis, Sigmas, Tallies};
use crate::data::VoteMatrix;

/// Pipeline parameters (the research defaults).
#[derive(Clone, Copy, Debug)]
pub struct DpParams {
    /// Contribution cap K: votes counted per person. Sets the sensitivities.
    /// `None` means no cap (sensitivity from the statement count).
    pub cap: Option<usize>,
    /// Apply the cap here by dropping random votes (the research code). A
    /// conforming phone keeps its first K cards instead, so the fake
    /// aggregator sets this false.
    pub bound: bool,
    /// Covariance over the `m` most-voted statements.
    pub m: usize,
    /// Map grid side.
    pub grid: usize,
    /// Budget split.
    pub split: Split,
    /// Gaussian blur σ on the map, in cells.
    pub blur: f64,
    /// Cells below `thresh × σ_eff` are dropped before clustering.
    pub thresh: f64,
    /// Whether rankings know the noise.
    pub noise_aware: bool,
    /// Blend the summed group tallies into the public tallies by inverse
    /// variance, as the research code did. `release.md` ("Dropouts") forbids
    /// it in draft 0.1, so the oracle keeps it off; it is on only when
    /// reproducing the research CSVs.
    pub blend: bool,
    /// Noised voters needed to compute the map tier (`GATE_MAP`). `None`
    /// computes it at any size (the research setting, not a conforming release).
    pub map_gate: Option<f64>,
    /// Noised voters needed for common ground (`GATE_COMMON`) when the map
    /// tier stays locked.
    pub common_gate: Option<f64>,
}

impl Default for DpParams {
    fn default() -> Self {
        Self {
            cap: Some(60),
            bound: true,
            m: 60,
            grid: 24,
            split: super::accounting::DEFAULT_SPLIT,
            blur: 1.0,
            thresh: 1.0,
            noise_aware: true,
            blend: false,
            map_gate: None,
            common_gate: None,
        }
    }
}

fn normal(sigma: f64, rng: &mut impl Rng) -> f64 {
    if sigma <= 0.0 {
        0.0
    } else {
        Normal::new(0.0, sigma).expect("sigma > 0").sample(rng)
    }
}

fn noised(v: &[f64], sigma: f64, rng: &mut impl Rng) -> Vec<f64> {
    v.iter().map(|x| x + normal(sigma, rng)).collect()
}

fn clamp0(v: &[f64]) -> Vec<f64> {
    v.iter().map(|x| x.max(0.0)).collect()
}

/// Run the DP pipeline at `eps` (per release, δ = 10⁻⁶) with the given rng.
pub fn dp_pipeline(x: &VoteMatrix, eps: f64, p: &DpParams, rng: &mut impl Rng) -> Analysis {
    let rho = eps_to_rho(eps, DELTA);
    let r_tally = rho * p.split.tally;
    let r_cov = rho * p.split.cov;
    let r_hist = rho * p.split.hist;
    let r_group = rho * p.split.group;
    let (n, c) = (x.n(), x.c());
    let xb = match p.cap {
        Some(k) if p.bound => x.bound(k, rng),
        _ => x.clone(),
    };
    let sk = (p.cap.unwrap_or(c) as f64).sqrt();

    // (a) tallies, with one extra coordinate for the participant count.
    let sa = gauss_sigma((sk * sk + 1.0).sqrt(), r_tally);
    let exact = counts(&xb, None);
    let ta = Tallies {
        agree: noised(&exact.agree, sa, rng),
        disagree: noised(&exact.disagree, sa, rng),
        pass: noised(&exact.pass, sa, rng),
    };
    let n_hat_raw = n as f64 + normal(sa, rng);
    let n_hat = n_hat_raw.max(1.0);
    let (na, nd, np) = (clamp0(&ta.agree), clamp0(&ta.disagree), clamp0(&ta.pass));
    // Tier decision from the noised count (`release.md` R6), never the raw one.
    if p.map_gate.is_some_and(|g| n_hat_raw < g) {
        let tallies = Tallies {
            agree: na.clone(),
            disagree: nd.clone(),
            pass: np.clone(),
        };
        let mu: Vec<f64> = (0..c)
            .map(|j| ((na[j] - nd[j]) / (na[j] + nd[j] + np[j]).max(1.0)).clamp(-1.0, 1.0))
            .collect();
        let common = p.common_gate.is_none_or(|g| n_hat_raw >= g);
        let cons = if common {
            consensus(
                std::slice::from_ref(&tallies),
                if p.noise_aware { sa } else { 0.0 },
            )
        } else {
            vec![]
        };
        return Analysis {
            pcs: vec![],
            sel: vec![],
            proj: vec![[0.0, 0.0]; n],
            groups: vec![0; n],
            k: 1,
            tallies,
            group_tallies: vec![],
            rep: vec![],
            cons,
            sigmas: Some(Sigmas {
                tally: sa,
                ..Sigmas::default()
            }),
            n_hat: n_hat_raw,
            mu,
            centroids: vec![],
        };
    }
    let mu: Vec<f64> = (0..c)
        .map(|j| ((na[j] - nd[j]) / (na[j] + nd[j] + np[j]).max(1.0)).clamp(-1.0, 1.0))
        .collect();
    let mut sel: Vec<usize> = (0..c).collect();
    sel.sort_by(|&a, &b| (na[b] + nd[b] + np[b]).total_cmp(&(na[a] + nd[a] + np[a])));
    sel.truncate(p.m.min(c));
    let msel = sel.len();

    // (b) Analyze Gauss on unit-normalised, mean-centred full vote vectors over `sel`.
    let z_rows: Vec<Vec<(usize, f64)>> = (0..n)
        .map(|i| {
            sel.iter()
                .enumerate()
                .filter_map(|(t, &j)| x.get(i, j).map(|v| (t, v.value() - mu[j])))
                .collect()
        })
        .collect();
    let u_rows: Vec<Vec<(usize, f64)>> = z_rows
        .iter()
        .map(|r| {
            let nrm = r.iter().map(|(_, z)| z * z).sum::<f64>().sqrt();
            if nrm > 0.0 {
                r.iter().map(|&(t, z)| (t, z / nrm)).collect()
            } else {
                vec![]
            }
        })
        .collect();
    let mut s = SymMat::gram_from_sparse_rows(msel, u_rows.iter().map(Vec::as_slice));
    let sb = gauss_sigma(1.0, r_cov);
    for i in 0..msel {
        for j in i..msel {
            let e = normal(sb, rng);
            s.add(i, j, e);
            if j != i {
                s.add(j, i, e);
            }
        }
    }
    let (lam, pcs) = top2_eigen(&s);

    // (c) phones project themselves; the map is a DP histogram over a box fixed by (a)+(b).
    let proj: Vec<[f64; 2]> = z_rows
        .iter()
        .map(|r| {
            let nv = r.len().max(1) as f64;
            let scale = (msel as f64 / nv).sqrt();
            let mut q = [0.0, 0.0];
            for &(t, z) in r {
                q[0] += z * pcs[t][0];
                q[1] += z * pcs[t][1];
            }
            [q[0] * scale, q[1] * scale]
        })
        .collect();
    let vbar = sel
        .iter()
        .map(|&j| {
            let ns = (na[j] + nd[j] + np[j]).max(1.0);
            ((na[j] + nd[j]) / ns - mu[j] * mu[j]).clamp(0.05, 1.0)
        })
        .sum::<f64>()
        / msel.max(1) as f64;
    let half = [
        3.5 * (lam[0].max(1e-9) / n_hat).sqrt() * (msel as f64 * vbar).sqrt(),
        3.5 * (lam[1].max(1e-9) / n_hat).sqrt() * (msel as f64 * vbar).sqrt(),
    ];
    let grid = p.grid;
    let mut hist = vec![0.0f64; grid * grid];
    for q in &proj {
        let mut idx = [0usize; 2];
        for d in 0..2 {
            let v = q[d].clamp(-half[d], half[d] - 1e-9);
            let cell = ((v + half[d]) / (2.0 * half[d]) * grid as f64).floor();
            idx[d] = (cell.max(0.0) as usize).min(grid - 1);
        }
        hist[idx[0] * grid + idx[1]] += 1.0;
    }
    let sc = gauss_sigma(1.0, r_hist);
    let mut hnoisy = noised(&hist, sc, rng);
    let sc_eff = if p.blur > 0.0 && sc > 0.0 {
        hnoisy = gaussian_blur(&hnoisy, grid, p.blur);
        sc * blur_noise_factor(p.blur)
    } else {
        sc
    };
    let hnoisy = clamp0(&hnoisy);
    let hn: Vec<f64> = hnoisy
        .iter()
        .map(|&v| if v < p.thresh * sc_eff { 0.0 } else { v })
        .collect();
    let centers: Vec<f64> = (0..grid)
        .map(|i| -1.0 + (2.0 * i as f64 + 1.0) / grid as f64)
        .collect();
    let cells: Vec<[f64; 2]> = (0..grid)
        .flat_map(|a| (0..grid).map(move |b| (a, b)))
        .map(|(a, b)| [centers[a] * half[0], centers[b] * half[1]])
        .collect();
    let wts: Vec<f64> = if hn.iter().filter(|&&w| w > 0.0).count() < 6 {
        hnoisy.iter().map(|v| v + 1e-6).collect()
    } else {
        hn
    };
    let km = choose_kmeans(&cells, Some(&wts), rng);
    let groups = km.predict(&proj);
    let k = km.k();

    // (d) per-group tallies.
    let sd = gauss_sigma(sk, r_group);
    let group_tallies: Vec<Tallies> = (0..k)
        .map(|g| {
            let mask: Vec<bool> = groups.iter().map(|&l| l == g).collect();
            let e = counts(&xb, Some(&mask));
            Tallies {
                agree: clamp0(&noised(&e.agree, sd, rng)),
                disagree: clamp0(&noised(&e.disagree, sd, rng)),
                pass: clamp0(&noised(&e.pass, sd, rng)),
            }
        })
        .collect();

    // Public tallies: the tallies part alone (the oracle), or the research
    // code's inverse-variance combination with the summed group tallies.
    let tallies = if rho.is_infinite() {
        counts(&xb, None)
    } else if !p.blend {
        Tallies {
            agree: na.clone(),
            disagree: nd.clone(),
            pass: np.clone(),
        }
    } else {
        let va = sa * sa;
        let vd = k as f64 * sd * sd;
        let wa = (1.0 / va) / (1.0 / va + 1.0 / vd);
        let combine = |a: &[f64], pick: fn(&Tallies) -> &Vec<f64>| -> Vec<f64> {
            (0..c)
                .map(|j| {
                    let sum_g: f64 = group_tallies.iter().map(|g| pick(g)[j]).sum();
                    (wa * a[j] + (1.0 - wa) * sum_g).max(0.0)
                })
                .collect()
        };
        Tallies {
            agree: combine(&ta.agree, |t| &t.agree),
            disagree: combine(&ta.disagree, |t| &t.disagree),
            pass: combine(&ta.pass, |t| &t.pass),
        }
    };
    let na_sd = if p.noise_aware { sd } else { 0.0 };
    Analysis {
        pcs,
        sel,
        proj,
        groups,
        k,
        tallies,
        rep: repness(&group_tallies, na_sd),
        cons: consensus(&group_tallies, na_sd),
        group_tallies,
        sigmas: Some(Sigmas {
            tally: sa,
            cov: sb,
            hist: sc,
            group: sd,
        }),
        n_hat: n_hat_raw,
        centroids: km.centers,
        mu,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::synthetic::{SyntheticSpec, generate};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn infinite_epsilon_reproduces_exact_tallies_under_the_cap() {
        let m = generate(&SyntheticSpec::sized(150), 2);
        let mut rng = ChaCha8Rng::seed_from_u64(9);
        let a = dp_pipeline(
            &m,
            f64::INFINITY,
            &DpParams {
                cap: None,
                ..DpParams::default()
            },
            &mut rng,
        );
        assert_eq!(a.tallies, counts(&m, None));
        assert_eq!(a.sigmas.unwrap(), Sigmas::default());
        assert!(a.k >= 2);
    }

    #[test]
    fn sigmas_follow_the_split() {
        let m = generate(&SyntheticSpec::sized(120), 2);
        let mut rng = ChaCha8Rng::seed_from_u64(9);
        let a = dp_pipeline(&m, 4.0, &DpParams::default(), &mut rng);
        let s = a.sigmas.unwrap();
        let rho = eps_to_rho(4.0, DELTA);
        assert!((s.tally - gauss_sigma(61f64.sqrt(), 0.15 * rho)).abs() < 1e-12);
        assert!((s.group - gauss_sigma(60f64.sqrt(), 0.35 * rho)).abs() < 1e-12);
    }
}

#[cfg(test)]
mod fixture_tests {
    use super::*;
    use crate::data::synthetic::{SyntheticSpec, generate};
    use crate::pipeline::baseline::baseline;
    use crate::pipeline::compare::compare;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    /// Without noise the DP pipeline's post-processing (top-60 covariance,
    /// map histogram, weighted k-means) must land close to the baseline on
    /// the fixture. This guards the port against regressions in the parts
    /// noise does not touch.
    #[test]
    fn noiseless_pipeline_agrees_with_the_baseline_on_the_fixture() {
        let m = generate(&SyntheticSpec::sized(800), 1);
        let b = baseline(&m, &mut ChaCha8Rng::seed_from_u64(0));
        let d = dp_pipeline(
            &m,
            f64::INFINITY,
            &DpParams::default(),
            &mut ChaCha8Rng::seed_from_u64(1000),
        );
        let met = compare(&b, &d, None);
        assert_eq!(d.k, b.k, "{met:?}");
        assert!(met.ari > 0.8, "{met:?}");
        assert!(met.pca_affinity > 0.8, "{met:?}");
        assert!(met.tally_median_pp < 3.0, "{met:?}");
    }
}
