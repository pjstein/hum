"""Polis-style analysis, non-private baseline vs. a differentially private (zCDP) pipeline.

Every DP output is a noised sum over participants, matching the "make every analytic a sum"
design: (a) per-comment tallies, (b) covariance (Analyze Gauss), (c) a 2D map histogram,
(d) per-group tallies. Clustering, representativeness and consensus are post-processing.
"""
import math
import numpy as np
import pandas as pd
from scipy.optimize import linear_sum_assignment
from scipy.ndimage import gaussian_filter
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score, adjusted_rand_score

DELTA = 1e-6


# ---------------------------------------------------------------- accounting
def eps_to_rho(eps, delta=DELTA):
    """Largest rho such that rho-zCDP implies (eps, delta)-DP: eps = rho + 2 sqrt(rho ln(1/delta))."""
    if math.isinf(eps):
        return math.inf
    L = math.log(1 / delta)
    s = (-2 * math.sqrt(L) + math.sqrt(4 * L + 4 * eps)) / 2
    return s * s


def rho_to_eps(rho, delta=DELTA):
    return rho + 2 * math.sqrt(rho * math.log(1 / delta))


def gauss_sigma(l2_sens, rho):
    return 0.0 if math.isinf(rho) else l2_sens / math.sqrt(2 * rho)


# ---------------------------------------------------------------- data
def load(path, min_votes=7):
    v = pd.read_csv(f"{path}/votes.csv")
    c = pd.read_csv(f"{path}/comments.csv")
    v = v.sort_values("timestamp").drop_duplicates(["comment-id", "voter-id"], keep="last")
    keep = sorted(set(c.loc[c.moderated >= 0, "comment-id"]))
    v = v[v["comment-id"].isin(keep)]
    per = v.groupby("voter-id").size()
    voters = sorted(per[per >= min_votes].index)
    v = v[v["voter-id"].isin(voters)]
    vi = {p: i for i, p in enumerate(voters)}
    ci = {k: j for j, k in enumerate(keep)}
    X = np.full((len(voters), len(keep)), np.nan)
    X[v["voter-id"].map(vi).values, v["comment-id"].map(ci).values] = v["vote"].values
    used = ~np.all(np.isnan(X), axis=0)
    X = X[:, used]
    pv = pd.read_csv(f"{path}/participants-votes.csv", usecols=["participant", "group-id"])
    gmap = dict(zip(pv["participant"], pv["group-id"]))
    polis_groups = np.array([gmap.get(p, np.nan) for p in voters], dtype=float)
    return X, polis_groups


# ---------------------------------------------------------------- shared pieces
def counts(X, mask=None):
    """Return (n_agree, n_disagree, n_pass) per comment."""
    if mask is not None:
        X = X[mask]
    return (np.sum(X == 1, 0).astype(float), np.sum(X == -1, 0).astype(float),
            np.sum(X == 0, 0).astype(float))


def weighted_silhouette(P, w, labels):
    D = np.sqrt(((P[:, None, :] - P[None, :, :]) ** 2).sum(-1))
    ks = np.unique(labels)
    if len(ks) < 2:
        return -1
    mean_d = np.stack([(D[:, labels == k] * w[labels == k]).sum(1) / max(w[labels == k].sum(), 1e-9)
                       for k in ks], 1)
    own = np.searchsorted(ks, labels)
    a = mean_d[np.arange(len(P)), own]
    mean_d[np.arange(len(P)), own] = np.inf
    b = mean_d.min(1)
    s = (b - a) / np.maximum(np.maximum(a, b), 1e-12)
    return float((s * w).sum() / w.sum())


def choose_kmeans(P, w=None, ks=(2, 3, 4, 5), seed=0):
    if w is not None:
        P, w = P[w > 0], w[w > 0]
    best = None
    for k in ks:
        if (w is None and len(P) <= k) or (w is not None and (w > 0).sum() <= k):
            continue
        km = KMeans(k, n_init=10, random_state=seed).fit(P, sample_weight=w)
        if w is None:
            s = silhouette_score(P, km.labels_, sample_size=min(len(P), 3000), random_state=seed)
        else:
            s = weighted_silhouette(P, w, km.labels_)
        if best is None or s > best[0]:
            best = (s, k, km)
    return best[2]


def z_test_prop(succ, n):
    return 2 * np.sqrt(n + 1) * ((succ + 1) / (n + 1) - 0.5)


def two_prop_z(s1, n1, s2, n2):
    p1, p2 = (s1 + 1) / (n1 + 2), (s2 + 1) / (n2 + 2)
    pp = (s1 + s2 + 1) / (n1 + n2 + 2)
    return (p1 - p2) / np.sqrt(np.maximum(pp * (1 - pp) * (1 / (n1 + 1) + 1 / (n2 + 1)), 1e-12))


def repness(group_counts, top=5, noise_sd=0.0):  # returns top 15 ranked; metrics use top 5
    """Polis-style representative comments per group. group_counts: list of (na, nd, np).

    noise_sd > 0 makes it noise-aware: pseudo-counts scale with the DP noise and the z-tests use an
    effective sample size that includes the noise variance, so low-vote statements stop winning by luck.
    """
    k = len(group_counts)
    tot = [sum(gc[i] for gc in group_counts) for i in range(3)]
    out = []
    for na, nd, npass in group_counts:
        ns = na + nd + npass
        oa, od = tot[0] - na, tot[1] - nd
        os_ = (tot[0] + tot[1] + tot[2]) - ns
        lam_in, lam_out = max(1.0, noise_sd), max(1.0, noise_sd * math.sqrt(max(k - 1, 1)))
        ne_in = ns ** 2 / np.maximum(ns + 3 * noise_sd ** 2, 1e-9) if noise_sd else ns
        ne_out = os_ ** 2 / np.maximum(os_ + 3 * (k - 1) * noise_sd ** 2, 1e-9) if noise_sd else os_
        res = {}
        for direction, s, o in (("agree", na, oa), ("disagree", nd, od)):
            p = (s + lam_in) / (ns + 2 * lam_in)
            po = (o + lam_out) / (os_ + 2 * lam_out)
            r = p / po
            pt = 2 * np.sqrt(ne_in + 1) * (p - 0.5)
            pp = (s + o + 1) / (ns + os_ + 2)
            rt = (p - po) / np.sqrt(np.maximum(pp * (1 - pp) * (1 / (ne_in + 1) + 1 / (ne_out + 1)), 1e-12))
            res[direction] = (r * rt * p * pt, pt, rt)
        m_a, m_d = res["agree"][0], res["disagree"][0]
        use_agree = m_a >= m_d
        metric = np.where(use_agree, m_a, m_d)
        pt = np.where(use_agree, res["agree"][1], res["disagree"][1])
        rt = np.where(use_agree, res["agree"][2], res["disagree"][2])
        sig = (pt > 1.2816) & (rt > 1.2816)
        order = np.lexsort((-metric, ~sig))  # significant first, then by metric
        out.append([(int(j), "A" if use_agree[j] else "D") for j in order[: 3 * top]])
    return out


def consensus(group_counts, top=5, noise_sd=0.0):  # returns top 15 ranked; metrics use top 5
    lam = max(1.0, noise_sd)
    gic = np.ones_like(group_counts[0][0])
    for na, nd, npass in group_counts:
        gic = gic * (na + lam) / (na + nd + npass + 2 * lam)
    return np.argsort(-gic)[: 3 * top].tolist()


def agree_frac(na, nd, npass):
    return na / np.maximum(na + nd + npass, 1)


# ---------------------------------------------------------------- baseline
def baseline(X, seed=0):
    voted = ~np.isnan(X)
    mu = np.array([X[voted[:, j], j].mean() for j in range(X.shape[1])])
    Z = np.where(voted, X - mu, 0.0)
    w, V = np.linalg.eigh(Z.T @ Z)
    pcs = V[:, ::-1][:, :2]
    nv = voted.sum(1)
    proj = (Z @ pcs) * np.sqrt(X.shape[1] / nv)[:, None]
    km = choose_kmeans(proj, seed=seed)
    g = km.labels_
    gc = [counts(X, g == k) for k in range(km.n_clusters)]
    return dict(pcs=pcs, proj=proj, groups=g, k=km.n_clusters, tallies=counts(X),
                rep=repness(gc), cons=consensus(gc))


# ---------------------------------------------------------------- DP pipeline
DEFAULT_SPLIT = dict(tally=0.15, cov=0.35, hist=0.15, group=0.35)


def bound(X, K, rng):
    """Keep at most K randomly chosen votes per participant (contribution bounding)."""
    Xb = X.copy()
    for i in range(len(X)):
        idx = np.flatnonzero(~np.isnan(X[i]))
        if len(idx) > K:
            drop = rng.choice(idx, len(idx) - K, replace=False)
            Xb[i, drop] = np.nan
    return Xb


def dp_pipeline(X, eps, rng, K=60, M=60, grid=24, split=DEFAULT_SPLIT, proj="polis", blur=1.0, thresh=1.0,
                noise_aware=True):
    rho = eps_to_rho(eps)
    r = {k: rho * v for k, v in split.items()}
    n, C = X.shape
    Xb = bound(X, K, rng) if K else X
    voted = ~np.isnan(Xb)
    sK = math.sqrt(K if K else C)

    # (a) tallies -> column means + comment selection
    # one extra coordinate counts participants, so L2 sensitivity is sqrt(K + 1)
    sa = gauss_sigma(math.sqrt(sK ** 2 + 1), r["tally"])
    ta = [c + rng.normal(0, sa, C) for c in counts(Xb)]
    n_hat = max(n + rng.normal(0, sa), 1.0)
    na, nd, npass = (np.maximum(t, 0) for t in ta)
    mu = np.clip((na - nd) / np.maximum(na + nd + npass, 1), -1, 1)
    sel = np.argsort(-(na + nd + npass))[: min(M, C)]

    # (b) Analyze Gauss on unit-normalised, mean-centred vote vectors (selected comments)
    # bounding only matters for count releases; covariance rows are unit-normalised and the map
    # releases one cell per person, so devices use their full vote vectors here
    vfull = ~np.isnan(X)
    Z = np.where(vfull[:, sel], np.nan_to_num(X[:, sel]) - mu[sel], 0.0)
    norms = np.linalg.norm(Z, axis=1)
    ok = norms > 0
    U = np.zeros_like(Z)
    U[ok] = Z[ok] / norms[ok, None]
    S = U.T @ U
    sb = gauss_sigma(1.0, r["cov"])
    E = np.triu(rng.normal(0, sb, S.shape))
    S = S + E + np.triu(E, 1).T
    w, V = np.linalg.eigh(S)
    pcs, lam = V[:, ::-1][:, :2], w[::-1][:2]

    # (c) devices project themselves; DP histogram over a box fixed by post-processing of (a)+(b)
    if proj == "unit":
        P = U @ pcs
        half = np.minimum(1.0, 3 * np.sqrt(np.maximum(lam, 1e-9) / n_hat))
    else:  # Polis-style sparsity-scaled projection of the un-normalised vector
        nv = np.maximum(vfull[:, sel].sum(1), 1)
        P = (Z @ pcs) * np.sqrt(len(sel) / nv)[:, None]
        ns_sel = np.maximum((na + nd + npass)[sel], 1)
        vbar = np.mean(np.clip((na + nd)[sel] / ns_sel - mu[sel] ** 2, 0.05, 1.0))
        half = 3.5 * np.sqrt(np.maximum(lam, 1e-9) / n_hat) * np.sqrt(len(sel) * vbar)
    Pc = np.clip(P, -half, half - 1e-9)
    if grid == "auto":  # coarser grid for small conversations (post-processing of n_hat)
        grid = int(np.clip(round(math.sqrt(n_hat) / 1.5), 8, 24))
    edges = [np.linspace(-h, h, grid + 1) for h in half]
    H, _, _ = np.histogram2d(Pc[:, 0], Pc[:, 1], bins=edges)
    sc = gauss_sigma(1.0, r["hist"])
    Hnoisy = H + rng.normal(0, sc, H.shape)
    if blur and sc > 0:  # smoothing is post-processing: free
        Hnoisy = gaussian_filter(Hnoisy, blur, mode="constant")
        sc_eff = sc * np.sqrt(np.sum(gaussian_filter(np.pad([[1.0]], 6), blur, mode="constant") ** 2))
    else:
        sc_eff = sc
    Hnoisy = np.maximum(Hnoisy, 0)
    Hn = np.where(Hnoisy < thresh * sc_eff, 0, Hnoisy)  # drop cells indistinguishable from noise
    cx = [(e[:-1] + e[1:]) / 2 for e in edges]
    cells = np.array([(a, b) for a in cx[0] for b in cx[1]])
    wts = Hn.ravel()
    if (wts > 0).sum() < 6:
        wts = Hnoisy.ravel() + 1e-6  # noise swamped everything; fall back to unthresholded release
    km = choose_kmeans(cells, wts)
    g = km.predict(P)  # each device assigns itself locally

    # (d) per-group tallies
    sd = gauss_sigma(sK, r["group"])
    gc = []
    for k in range(km.n_clusters):
        gc.append(tuple(np.maximum(c + rng.normal(0, sd, C), 0) for c in counts(Xb, g == k)))

    # public tallies: inverse-variance combine (a) with sum of (d)
    if math.isinf(rho):
        tallies = counts(Xb)
    else:
        va, vd = sa ** 2, km.n_clusters * sd ** 2
        wa = (1 / va) / (1 / va + 1 / vd)
        tallies = tuple(wa * a + (1 - wa) * sum(x[i] for x in gc) for i, a in enumerate(ta))
        tallies = tuple(np.maximum(t, 0) for t in tallies)
    na_sd = sd if noise_aware else 0.0
    return dict(pcs_sel=pcs, sel=sel, proj=P, groups=g, k=km.n_clusters, tallies=tallies,
                rep=repness(gc, noise_sd=na_sd), cons=consensus(gc, noise_sd=na_sd),
                sigmas=dict(tally=sa, cov=sb, hist=sc, group=sd))


# ---------------------------------------------------------------- comparison
def subspace_affinity(A, B):
    qa, _ = np.linalg.qr(A)
    qb, _ = np.linalg.qr(B)
    return float(np.linalg.norm(qa.T @ qb) ** 2 / A.shape[1])


def overlap(dp_list, base_list, k=5):
    """strict: share of DP top-k in baseline top-k; relaxed: share of DP top-k in baseline top-3k."""
    d = set(dp_list[:k])
    return len(d & set(base_list[:k])) / k, len(d & set(base_list[: 3 * k])) / k


def compare(base, dp, X=None, base_groups=None, sel=None):
    """base_groups lets a subsample be compared on the participants it shares with the baseline."""
    out = {}
    bg = base["groups"] if base_groups is None else base_groups
    ta = agree_frac(*base["tallies"])
    tb = agree_frac(*dp["tallies"])
    ns = sum(base["tallies"])
    err = np.abs(ta - tb) * 100
    for lo, hi in [(10, 50), (50, 200), (200, 1000), (1000, 1e9)]:
        m = (ns >= lo) & (ns < hi)
        out[f"tally_err_{lo}"] = float(np.median(err[m])) if m.sum() >= 3 else np.nan
    m = ns >= 10
    out["tally_median_pp"] = float(np.median(err[m]))
    out["tally_within5pp"] = float(np.mean(err[m] <= 5))
    sel = dp.get("sel") if sel is None else sel
    out["pca_affinity"] = subspace_affinity(base["pcs"][sel], dp.get("pcs_sel", dp["pcs"][sel] if "pcs" in dp else None))
    out["k_match"] = float(dp["k"] == base["k"])
    out["ari"] = float(adjusted_rand_score(bg, dp["groups"]))
    kb, kd = base["k"], dp["k"]
    conf = np.zeros((kb, kd))
    for a, b in zip(bg, dp["groups"]):
        conf[a, b] += 1
    ri, ci = linear_sum_assignment(-conf)
    strict, relaxed = np.zeros(kb), np.zeros(kb)
    for a, b in zip(ri, ci):
        strict[a], relaxed[a] = overlap(dp["rep"][b], base["rep"][a])
    out["repness_overlap"], out["repness_relaxed"] = float(strict.mean()), float(relaxed.mean())
    out["consensus_overlap"], out["consensus_relaxed"] = overlap(dp["cons"], base["cons"])
    return out


def churn(X, base, rng, frac=0.9):
    """Non-private noise floor: rerun the baseline as if a random 10% of participants never showed up."""
    keep = rng.random(len(X)) < frac
    sub = baseline(X[keep])
    return compare(base, sub, base_groups=base["groups"][keep], sel=np.arange(X.shape[1]))
