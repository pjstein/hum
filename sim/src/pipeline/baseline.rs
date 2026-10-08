//! The non-private baseline (`baseline` in the research code): PCA over
//! mean-centred votes, Polis-style sparsity-scaled projection, k-means with
//! silhouette selection, then rankings on exact counts.

use rand::Rng;

use super::linalg::{SymMat, choose_kmeans, top2_eigen};
use super::rank::{consensus, repness};
use super::{Analysis, Tallies};
use crate::data::VoteMatrix;

/// Exact agree/disagree/pass counts per statement, optionally over a subset of rows.
pub fn counts(x: &VoteMatrix, mask: Option<&[bool]>) -> Tallies {
    let c = x.c();
    let mut t = Tallies {
        agree: vec![0.0; c],
        disagree: vec![0.0; c],
        pass: vec![0.0; c],
    };
    for i in 0..x.n() {
        if mask.is_some_and(|m| !m[i]) {
            continue;
        }
        for (j, v) in x.row(i).iter().enumerate() {
            match v {
                Some(crate::data::Vote::Agree) => t.agree[j] += 1.0,
                Some(crate::data::Vote::Disagree) => t.disagree[j] += 1.0,
                Some(crate::data::Vote::Pass) => t.pass[j] += 1.0,
                None => {}
            }
        }
    }
    t
}

/// Run the baseline. `rng` only drives k-means and the silhouette sample.
pub fn baseline(x: &VoteMatrix, rng: &mut impl Rng) -> Analysis {
    let (n, c) = (x.n(), x.c());
    let mu = x.column_means();
    let rows: Vec<Vec<(usize, f64)>> = (0..n)
        .map(|i| {
            x.row(i)
                .iter()
                .enumerate()
                .filter_map(|(j, v)| v.map(|v| (j, v.value() - mu[j])))
                .collect()
        })
        .collect();
    let gram = SymMat::gram_from_sparse_rows(c, rows.iter().map(Vec::as_slice));
    let (_, pcs) = top2_eigen(&gram);
    let proj: Vec<[f64; 2]> = rows
        .iter()
        .map(|r| {
            let nv = r.len().max(1) as f64;
            let scale = (c as f64 / nv).sqrt();
            let mut p = [0.0, 0.0];
            for &(j, z) in r {
                p[0] += z * pcs[j][0];
                p[1] += z * pcs[j][1];
            }
            [p[0] * scale, p[1] * scale]
        })
        .collect();
    let km = choose_kmeans(&proj, None, rng);
    let groups = km.labels.clone();
    let k = km.k();
    let group_tallies: Vec<Tallies> = (0..k)
        .map(|g| {
            let mask: Vec<bool> = groups.iter().map(|&l| l == g).collect();
            counts(x, Some(&mask))
        })
        .collect();
    Analysis {
        pcs,
        sel: (0..c).collect(),
        proj,
        groups,
        k,
        tallies: counts(x, None),
        rep: repness(&group_tallies, 0.0),
        cons: consensus(&group_tallies, 0.0),
        group_tallies,
        sigmas: None,
        n_hat: n as f64,
        centroids: km.centers,
        mu,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::synthetic::{SyntheticSpec, generate};
    use crate::pipeline::linalg::adjusted_rand_index;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn baseline_recovers_synthetic_groups() {
        let m = generate(&SyntheticSpec::sized(400), 1);
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let b = baseline(&m, &mut rng);
        let truth: Vec<usize> = m.source_groups.iter().map(|g| g.unwrap()).collect();
        let ari = adjusted_rand_index(&truth, &b.groups);
        assert!(ari > 0.6, "ari = {ari}, k = {}", b.k);
    }
}
