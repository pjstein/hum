//! Small dense linear algebra and clustering helpers the pipeline port needs:
//! symmetric eigenvectors, k-means with silhouette model selection, the
//! Gaussian blur, assignment matching and the adjusted Rand index. Everything
//! is plain `Vec<f64>`; sizes are at most a few thousand points and a few
//! hundred statements.

use rand::seq::index::sample;
use rand::{Rng, RngCore};

/// A dense square symmetric matrix, row-major.
#[derive(Clone, Debug)]
pub struct SymMat {
    /// Dimension.
    pub n: usize,
    /// Row-major entries.
    pub a: Vec<f64>,
}

impl SymMat {
    /// The zero matrix.
    pub fn zeros(n: usize) -> Self {
        Self {
            n,
            a: vec![0.0; n * n],
        }
    }

    /// Entry (i, j).
    pub fn get(&self, i: usize, j: usize) -> f64 {
        self.a[i * self.n + j]
    }

    /// Add `v` to entry (i, j).
    pub fn add(&mut self, i: usize, j: usize, v: f64) {
        self.a[i * self.n + j] += v;
    }

    /// `y = A x`.
    pub fn mul_vec(&self, x: &[f64]) -> Vec<f64> {
        (0..self.n)
            .map(|i| {
                let row = &self.a[i * self.n..(i + 1) * self.n];
                row.iter().zip(x).map(|(a, b)| a * b).sum()
            })
            .collect()
    }

    /// Accumulate `Σ_rows zᵀz` from sparse rows of `(column, value)` pairs.
    pub fn gram_from_sparse_rows<'a>(
        n: usize,
        rows: impl Iterator<Item = &'a [(usize, f64)]>,
    ) -> Self {
        let mut s = Self::zeros(n);
        for row in rows {
            for &(j, zj) in row {
                for &(k, zk) in row {
                    s.add(j, k, zj * zk);
                }
            }
        }
        s
    }
}

/// Top two eigenpairs of a symmetric matrix, eigenvalues descending.
/// Returns `(eigenvalues, vectors)` with `vectors[i] = [v1_i, v2_i]`.
///
/// Uses cyclic Jacobi for small matrices (exact, handles indefinite matrices
/// such as a noised covariance) and subspace iteration for large ones (the
/// baseline Gram matrix, which is positive semi-definite).
pub fn top2_eigen(m: &SymMat) -> ([f64; 2], Vec<[f64; 2]>) {
    if m.n <= 120 {
        jacobi_top2(m)
    } else {
        subspace_top2(m)
    }
}

fn jacobi_top2(m: &SymMat) -> ([f64; 2], Vec<[f64; 2]>) {
    let n = m.n;
    let mut a = m.a.clone();
    let mut v = vec![0.0; n * n];
    for i in 0..n {
        v[i * n + i] = 1.0;
    }
    let scale: f64 = (0..n).map(|i| a[i * n + i].abs()).sum::<f64>().max(1e-300);
    for _sweep in 0..60 {
        let mut off = 0.0;
        for i in 0..n {
            for j in (i + 1)..n {
                off += a[i * n + j] * a[i * n + j];
            }
        }
        if off.sqrt() < 1e-13 * scale {
            break;
        }
        for p in 0..n {
            for q in (p + 1)..n {
                let apq = a[p * n + q];
                if apq.abs() < 1e-300 {
                    continue;
                }
                let theta = (a[q * n + q] - a[p * n + p]) / (2.0 * apq);
                let t = theta.signum() / (theta.abs() + (theta * theta + 1.0).sqrt());
                let t = if theta == 0.0 { 1.0 } else { t };
                let c = 1.0 / (t * t + 1.0).sqrt();
                let s = t * c;
                for k in 0..n {
                    let akp = a[k * n + p];
                    let akq = a[k * n + q];
                    a[k * n + p] = c * akp - s * akq;
                    a[k * n + q] = s * akp + c * akq;
                }
                for k in 0..n {
                    let apk = a[p * n + k];
                    let aqk = a[q * n + k];
                    a[p * n + k] = c * apk - s * aqk;
                    a[q * n + k] = s * apk + c * aqk;
                }
                for k in 0..n {
                    let vkp = v[k * n + p];
                    let vkq = v[k * n + q];
                    v[k * n + p] = c * vkp - s * vkq;
                    v[k * n + q] = s * vkp + c * vkq;
                }
            }
        }
    }
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by(|&i, &j| a[j * n + j].total_cmp(&a[i * n + i]));
    let (i1, i2) = (order[0], order.get(1).copied().unwrap_or(order[0]));
    let vals = [a[i1 * n + i1], a[i2 * n + i2]];
    let vecs = (0..n).map(|k| [v[k * n + i1], v[k * n + i2]]).collect();
    (vals, vecs)
}

fn subspace_top2(m: &SymMat) -> ([f64; 2], Vec<[f64; 2]>) {
    let n = m.n;
    // Deterministic start vectors; the matrix is PSD so the algebraically
    // largest eigenvalues are also the largest in magnitude.
    let mut v1: Vec<f64> = (0..n)
        .map(|i| 1.0 + ((i * 7919) % 13) as f64 * 0.01)
        .collect();
    let mut v2: Vec<f64> = (0..n)
        .map(|i| if i % 2 == 0 { 1.0 } else { -1.0 } + ((i * 104_729) % 11) as f64 * 0.01)
        .collect();
    let mut last = [f64::NAN, f64::NAN];
    let mut vals = [0.0, 0.0];
    for _ in 0..5000 {
        let mut w1 = m.mul_vec(&v1);
        let mut w2 = m.mul_vec(&v2);
        // Gram–Schmidt.
        let n1 = norm(&w1).max(1e-300);
        for x in &mut w1 {
            *x /= n1;
        }
        let d: f64 = dot(&w1, &w2);
        for (x, y) in w2.iter_mut().zip(&w1) {
            *x -= d * y;
        }
        let n2 = norm(&w2).max(1e-300);
        for x in &mut w2 {
            *x /= n2;
        }
        // Rayleigh–Ritz on the 2-d subspace.
        let a11 = dot(&w1, &m.mul_vec(&w1));
        let a22 = dot(&w2, &m.mul_vec(&w2));
        let a12 = dot(&w1, &m.mul_vec(&w2));
        let tr = a11 + a22;
        let det = a11 * a22 - a12 * a12;
        let disc = ((tr * tr) / 4.0 - det).max(0.0).sqrt();
        let (l1, l2) = (tr / 2.0 + disc, tr / 2.0 - disc);
        // Eigenvectors of the 2x2 to rotate the basis.
        let (c, s) = if a12.abs() < 1e-14 {
            if a11 >= a22 { (1.0, 0.0) } else { (0.0, 1.0) }
        } else {
            let x = l1 - a22;
            let nn = (x * x + a12 * a12).sqrt();
            (x / nn, a12 / nn)
        };
        let r1: Vec<f64> = w1.iter().zip(&w2).map(|(a, b)| c * a + s * b).collect();
        let r2: Vec<f64> = w1.iter().zip(&w2).map(|(a, b)| -s * a + c * b).collect();
        v1 = r1;
        v2 = r2;
        vals = [l1, l2];
        let conv = (l1 - last[0]).abs() + (l2 - last[1]).abs();
        if conv <= 1e-10 * (l1.abs() + 1.0) {
            break;
        }
        last = vals;
    }
    (vals, (0..n).map(|i| [v1[i], v2[i]]).collect())
}

fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

fn norm(a: &[f64]) -> f64 {
    dot(a, a).sqrt()
}

/// Squared Euclidean distance of two points in the plane.
fn d2(a: [f64; 2], b: [f64; 2]) -> f64 {
    (a[0] - b[0]).powi(2) + (a[1] - b[1]).powi(2)
}

/// A fitted k-means model.
#[derive(Clone, Debug)]
pub struct KMeans {
    /// Cluster centres.
    pub centers: Vec<[f64; 2]>,
    /// Label per fitted point.
    pub labels: Vec<usize>,
    /// Weighted inertia.
    pub inertia: f64,
}

impl KMeans {
    /// Number of clusters.
    pub fn k(&self) -> usize {
        self.centers.len()
    }

    /// Nearest centre for each point.
    pub fn predict(&self, pts: &[[f64; 2]]) -> Vec<usize> {
        pts.iter().map(|&p| self.nearest(p)).collect()
    }

    fn nearest(&self, p: [f64; 2]) -> usize {
        let mut best = (0usize, f64::INFINITY);
        for (i, &c) in self.centers.iter().enumerate() {
            let d = d2(p, c);
            if d < best.1 {
                best = (i, d);
            }
        }
        best.0
    }
}

/// k-means with k-means++ seeding, `n_init` restarts and optional weights.
pub fn kmeans(
    pts: &[[f64; 2]],
    w: Option<&[f64]>,
    k: usize,
    n_init: usize,
    rng: &mut impl Rng,
) -> KMeans {
    let n = pts.len();
    let wt = |i: usize| w.map_or(1.0, |w| w[i]);
    let mut best: Option<KMeans> = None;
    for _ in 0..n_init {
        // k-means++ seeding.
        let mut centers: Vec<[f64; 2]> = Vec::with_capacity(k);
        let total: f64 = (0..n).map(wt).sum();
        let mut r = rng.random::<f64>() * total;
        let mut first = 0;
        for i in 0..n {
            r -= wt(i);
            if r <= 0.0 {
                first = i;
                break;
            }
        }
        centers.push(pts[first]);
        let mut dist: Vec<f64> = pts.iter().map(|&p| d2(p, pts[first])).collect();
        while centers.len() < k {
            let tot: f64 = (0..n).map(|i| wt(i) * dist[i]).sum();
            let pick = if tot <= 0.0 {
                // Everything sits on a centre already; take any positive-weight point.
                (0..n).find(|&i| wt(i) > 0.0).unwrap_or(0)
            } else {
                let mut r = rng.random::<f64>() * tot;
                let mut pick = n - 1;
                for (i, d) in dist.iter().enumerate() {
                    r -= wt(i) * d;
                    if r <= 0.0 {
                        pick = i;
                        break;
                    }
                }
                pick
            };
            centers.push(pts[pick]);
            for i in 0..n {
                dist[i] = dist[i].min(d2(pts[i], pts[pick]));
            }
        }
        // Lloyd iterations.
        let mut labels = vec![usize::MAX; n];
        for _ in 0..300 {
            let mut changed = false;
            for i in 0..n {
                let mut bi = 0;
                let mut bd = f64::INFINITY;
                for (c, &ce) in centers.iter().enumerate() {
                    let d = d2(pts[i], ce);
                    if d < bd {
                        bd = d;
                        bi = c;
                    }
                }
                if labels[i] != bi {
                    labels[i] = bi;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
            let mut sum = vec![[0.0f64; 2]; k];
            let mut ws = vec![0.0f64; k];
            for i in 0..n {
                let l = labels[i];
                sum[l][0] += wt(i) * pts[i][0];
                sum[l][1] += wt(i) * pts[i][1];
                ws[l] += wt(i);
            }
            for c in 0..k {
                if ws[c] > 0.0 {
                    centers[c] = [sum[c][0] / ws[c], sum[c][1] / ws[c]];
                }
            }
        }
        let inertia: f64 = (0..n).map(|i| wt(i) * d2(pts[i], centers[labels[i]])).sum();
        if best.as_ref().is_none_or(|b| inertia < b.inertia) {
            best = Some(KMeans {
                centers: centers.clone(),
                labels: labels.clone(),
                inertia,
            });
        }
    }
    best.expect("n_init >= 1")
}

/// Mean silhouette on a random sample of at most `sample_size` points.
pub fn silhouette(
    pts: &[[f64; 2]],
    labels: &[usize],
    sample_size: usize,
    rng: &mut impl RngCore,
) -> f64 {
    let n = pts.len();
    let idx: Vec<usize> = if n > sample_size {
        sample(rng, n, sample_size).into_vec()
    } else {
        (0..n).collect()
    };
    let ks: Vec<usize> = {
        let mut v: Vec<usize> = idx.iter().map(|&i| labels[i]).collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    if ks.len() < 2 {
        return -1.0;
    }
    let m = idx.len();
    let mut total = 0.0;
    for &i in &idx {
        let mut sums = vec![0.0f64; ks.len()];
        let mut cnt = vec![0usize; ks.len()];
        for &j in &idx {
            let kj = ks.binary_search(&labels[j]).expect("label present");
            sums[kj] += d2(pts[i], pts[j]).sqrt();
            cnt[kj] += 1;
        }
        let own = ks.binary_search(&labels[i]).expect("label present");
        if cnt[own] <= 1 {
            continue; // sklearn: silhouette 0 for singletons
        }
        let a = sums[own] / (cnt[own] - 1) as f64;
        let b = (0..ks.len())
            .filter(|&k| k != own && cnt[k] > 0)
            .map(|k| sums[k] / cnt[k] as f64)
            .fold(f64::INFINITY, f64::min);
        total += (b - a) / a.max(b).max(1e-12);
    }
    total / m as f64
}

/// Weighted silhouette, a port of `weighted_silhouette` (self included in the
/// own-cluster mean, as in the research code).
pub fn weighted_silhouette(pts: &[[f64; 2]], w: &[f64], labels: &[usize]) -> f64 {
    let ks: Vec<usize> = {
        let mut v = labels.to_vec();
        v.sort_unstable();
        v.dedup();
        v
    };
    if ks.len() < 2 {
        return -1.0;
    }
    let n = pts.len();
    let wsum: Vec<f64> = ks
        .iter()
        .map(|&k| {
            (0..n)
                .filter(|&j| labels[j] == k)
                .map(|j| w[j])
                .sum::<f64>()
                .max(1e-9)
        })
        .collect();
    let mut num = 0.0;
    let mut den = 0.0;
    for i in 0..n {
        let mut mean_d = vec![0.0f64; ks.len()];
        for j in 0..n {
            let kj = ks.binary_search(&labels[j]).expect("label present");
            mean_d[kj] += d2(pts[i], pts[j]).sqrt() * w[j];
        }
        for (k, md) in mean_d.iter_mut().enumerate() {
            *md /= wsum[k];
        }
        let own = ks.binary_search(&labels[i]).expect("label present");
        let a = mean_d[own];
        let b = (0..ks.len())
            .filter(|&k| k != own)
            .map(|k| mean_d[k])
            .fold(f64::INFINITY, f64::min);
        let s = (b - a) / a.max(b).max(1e-12);
        num += s * w[i];
        den += w[i];
    }
    num / den
}

/// `choose_kmeans`: fit k in 2..=5 and keep the best silhouette. With weights,
/// zero-weight points are dropped first and the weighted silhouette is used.
/// Falls back to one cluster when there are too few points for any k.
pub fn choose_kmeans(pts: &[[f64; 2]], w: Option<&[f64]>, rng: &mut impl Rng) -> KMeans {
    let (p, wv): (Vec<[f64; 2]>, Option<Vec<f64>>) = match w {
        Some(w) => {
            let keep: Vec<usize> = (0..pts.len()).filter(|&i| w[i] > 0.0).collect();
            (
                keep.iter().map(|&i| pts[i]).collect(),
                Some(keep.iter().map(|&i| w[i]).collect()),
            )
        }
        None => (pts.to_vec(), None),
    };
    let mut best: Option<(f64, KMeans)> = None;
    for k in 2..=5 {
        if p.len() <= k {
            continue;
        }
        let km = kmeans(&p, wv.as_deref(), k, 10, rng);
        let s = match &wv {
            None => silhouette(&p, &km.labels, 3000.min(p.len()), rng),
            Some(wv) => weighted_silhouette(&p, wv, &km.labels),
        };
        if best.as_ref().is_none_or(|b| s > b.0) {
            best = Some((s, km));
        }
    }
    if let Some((_, km)) = best {
        km
    } else {
        let c = if p.is_empty() { [0.0, 0.0] } else { p[0] };
        KMeans {
            centers: vec![c],
            labels: vec![0; p.len()],
            inertia: 0.0,
        }
    }
}

/// `scipy.ndimage.gaussian_filter(x, sigma, mode="constant")` on a square
/// grid: separable, truncated at 4σ, zero padding.
pub fn gaussian_blur(grid: &[f64], n: usize, sigma: f64) -> Vec<f64> {
    let radius = (4.0 * sigma + 0.5) as isize;
    let kernel: Vec<f64> = {
        let k: Vec<f64> = (-radius..=radius)
            .map(|x| (-(x * x) as f64 / (2.0 * sigma * sigma)).exp())
            .collect();
        let s: f64 = k.iter().sum();
        k.into_iter().map(|v| v / s).collect()
    };
    let pass = |src: &[f64], along_rows: bool| -> Vec<f64> {
        let mut out = vec![0.0; n * n];
        for i in 0..n {
            for j in 0..n {
                let mut acc = 0.0;
                for (t, kv) in kernel.iter().enumerate() {
                    let off = t as isize - radius;
                    let (si, sj) = if along_rows {
                        (i as isize, j as isize + off)
                    } else {
                        (i as isize + off, j as isize)
                    };
                    if si >= 0 && sj >= 0 && (si as usize) < n && (sj as usize) < n {
                        acc += kv * src[si as usize * n + sj as usize];
                    }
                }
                out[i * n + j] = acc;
            }
        }
        out
    };
    pass(&pass(grid, true), false)
}

/// L2 norm of the blur's impulse response: how much blurring shrinks the
/// per-cell noise (`sc_eff / sc` in the research code).
pub fn blur_noise_factor(sigma: f64) -> f64 {
    let n = 13;
    let mut delta = vec![0.0; n * n];
    delta[6 * n + 6] = 1.0;
    gaussian_blur(&delta, n, sigma)
        .iter()
        .map(|v| v * v)
        .sum::<f64>()
        .sqrt()
}

/// Best one-to-one matching between two labelings of at most a handful of
/// clusters, maximising the summed confusion count. Returns `(row, col)` pairs.
pub fn best_assignment(conf: &[Vec<f64>]) -> Vec<(usize, usize)> {
    fn rec(
        a: usize,
        kb: usize,
        kd: usize,
        conf: &[Vec<f64>],
        used: &mut Vec<bool>,
        cur: &mut Vec<(usize, usize)>,
        best: &mut (f64, Vec<(usize, usize)>),
    ) {
        if a == kb || cur.len() == kd.min(kb) {
            let score: f64 = cur.iter().map(|&(i, j)| conf[i][j]).sum();
            if score > best.0 {
                *best = (score, cur.clone());
            }
            return;
        }
        // Either skip base row `a` (only useful when kb > kd) or match it.
        if kb > kd {
            rec(a + 1, kb, kd, conf, used, cur, best);
        }
        for j in 0..kd {
            if !used[j] {
                used[j] = true;
                cur.push((a, j));
                rec(a + 1, kb, kd, conf, used, cur, best);
                cur.pop();
                used[j] = false;
            }
        }
    }
    let kb = conf.len();
    let kd = conf.first().map_or(0, Vec::len);
    if kb == 0 || kd == 0 {
        return vec![];
    }
    let mut best = (f64::NEG_INFINITY, vec![]);
    let mut used = vec![false; kd];
    let mut cur: Vec<(usize, usize)> = vec![];
    rec(0, kb, kd, conf, &mut used, &mut cur, &mut best);
    best.1
}

/// Adjusted Rand index between two labelings.
pub fn adjusted_rand_index(a: &[usize], b: &[usize]) -> f64 {
    assert_eq!(a.len(), b.len());
    let ka = a.iter().copied().max().map_or(0, |m| m + 1);
    let kb = b.iter().copied().max().map_or(0, |m| m + 1);
    let mut conf = vec![vec![0u64; kb]; ka];
    for (&x, &y) in a.iter().zip(b) {
        conf[x][y] += 1;
    }
    let c2 = |x: u64| (x * x.saturating_sub(1)) as f64 / 2.0;
    let sum_ij: f64 = conf.iter().flatten().map(|&x| c2(x)).sum();
    let sum_a: f64 = conf.iter().map(|r| c2(r.iter().sum())).sum();
    let sum_b: f64 = (0..kb).map(|j| c2(conf.iter().map(|r| r[j]).sum())).sum();
    let n2 = c2(a.len() as u64);
    if n2 == 0.0 {
        return 1.0;
    }
    let expected = sum_a * sum_b / n2;
    let max = f64::midpoint(sum_a, sum_b);
    if (max - expected).abs() < 1e-12 {
        return 1.0;
    }
    (sum_ij - expected) / (max - expected)
}

/// Thin QR (Gram–Schmidt) of an m×2 matrix, returning the orthonormal columns.
fn orthonormal2(a: &[[f64; 2]]) -> Vec<[f64; 2]> {
    let mut c0: Vec<f64> = a.iter().map(|r| r[0]).collect();
    let n0 = norm(&c0).max(1e-300);
    for x in &mut c0 {
        *x /= n0;
    }
    let mut c1: Vec<f64> = a.iter().map(|r| r[1]).collect();
    let d = dot(&c0, &c1);
    for (x, y) in c1.iter_mut().zip(&c0) {
        *x -= d * y;
    }
    let n1 = norm(&c1).max(1e-300);
    for x in &mut c1 {
        *x /= n1;
    }
    c0.iter().zip(&c1).map(|(&x, &y)| [x, y]).collect()
}

/// `subspace_affinity`: ‖`QaᵀQb‖²_F` / 2 for two m×2 bases.
pub fn subspace_affinity(a: &[[f64; 2]], b: &[[f64; 2]]) -> f64 {
    let qa = orthonormal2(a);
    let qb = orthonormal2(b);
    let mut s = 0.0;
    for i in 0..2 {
        for j in 0..2 {
            let v: f64 = qa.iter().zip(&qb).map(|(x, y)| x[i] * y[j]).sum();
            s += v * v;
        }
    }
    s / 2.0
}

/// Median of a slice (empty → NaN).
pub fn median(v: &[f64]) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    let mut s = v.to_vec();
    s.sort_by(f64::total_cmp);
    let m = s.len() / 2;
    if s.len() % 2 == 1 {
        s[m]
    } else {
        f64::midpoint(s[m - 1], s[m])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn diag3() -> SymMat {
        let mut m = SymMat::zeros(3);
        m.add(0, 0, 1.0);
        m.add(1, 1, 5.0);
        m.add(2, 2, 3.0);
        m.add(0, 2, 0.5);
        m.add(2, 0, 0.5);
        m
    }

    #[test]
    fn jacobi_finds_top_two() {
        let (vals, vecs) = jacobi_top2(&diag3());
        assert!((vals[0] - 5.0).abs() < 1e-9);
        assert!((vals[1] - 3.1180).abs() < 1e-3, "{vals:?}");
        assert!((vecs[1][0].abs() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn subspace_iteration_matches_jacobi_on_psd() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let n = 130;
        let mut rows: Vec<Vec<(usize, f64)>> = vec![];
        for _ in 0..400 {
            let mut row = vec![];
            for j in 0..n {
                if rng.random::<f64>() < 0.2 {
                    row.push((j, rng.random::<f64>() - 0.5));
                }
            }
            rows.push(row);
        }
        let m = SymMat::gram_from_sparse_rows(n, rows.iter().map(Vec::as_slice));
        let (a, _) = jacobi_top2(&m);
        let (b, _) = subspace_top2(&m);
        assert!((a[0] - b[0]).abs() < 1e-6 * a[0], "{a:?} vs {b:?}");
        assert!((a[1] - b[1]).abs() < 1e-6 * a[0], "{a:?} vs {b:?}");
    }

    #[test]
    fn kmeans_separates_two_blobs() {
        let mut rng = ChaCha8Rng::seed_from_u64(2);
        let mut pts = vec![];
        for i in 0..200 {
            let c = if i < 100 { [0.0, 0.0] } else { [10.0, 10.0] };
            pts.push([c[0] + rng.random::<f64>(), c[1] + rng.random::<f64>()]);
        }
        let km = choose_kmeans(&pts, None, &mut rng);
        assert_eq!(km.k(), 2);
        let truth: Vec<usize> = (0..200).map(|i| usize::from(i >= 100)).collect();
        assert!((adjusted_rand_index(&truth, &km.labels) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn ari_of_identical_and_independent() {
        assert!((adjusted_rand_index(&[0, 0, 1, 1], &[1, 1, 0, 0]) - 1.0).abs() < 1e-12);
        // sklearn: adjusted_rand_score([0,0,1,1],[0,1,0,1]) == -0.5
        assert!((adjusted_rand_index(&[0, 0, 1, 1], &[0, 1, 0, 1]) + 0.5).abs() < 1e-9);
    }

    #[test]
    fn blur_factor_matches_scipy() {
        // sum of squares of scipy's gaussian_filter impulse response, sigma 1.
        let f = blur_noise_factor(1.0);
        assert!((f - 0.2821).abs() < 0.002, "{f}");
    }

    #[test]
    fn assignment_prefers_diagonal() {
        let conf = vec![vec![10.0, 1.0], vec![2.0, 8.0]];
        assert_eq!(best_assignment(&conf), vec![(0, 0), (1, 1)]);
    }

    #[test]
    fn affinity_of_same_subspace_is_one() {
        let a: Vec<[f64; 2]> = (0..10).map(|i| [f64::from(i), f64::from(i * i)]).collect();
        let b: Vec<[f64; 2]> = a.iter().map(|r| [r[0] + r[1], r[0] - r[1]]).collect();
        assert!((subspace_affinity(&a, &b) - 1.0).abs() < 1e-9);
    }
}
