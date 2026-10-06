"""E1: every open Polis conversation at its real size. E2: participant-subsampled size sweep."""
import sys, os, itertools, warnings
import numpy as np, pandas as pd
from multiprocessing import Pool
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from polis_dp import load, baseline, dp_pipeline, compare, churn

warnings.filterwarnings("ignore")
ROOT, OUT = sys.argv[1], sys.argv[2]
EPS = [1, 2, 4, 8, 16, np.inf]
SKIP = {"bg2050-volunteers", "london.youth.policing"}


def e1(d):
    X, _ = load(f"{ROOT}/{d}")
    b = baseline(X)
    rows = []
    for s in range(5):
        rows.append(dict(exp="E1", d=d, n=len(X), C=X.shape[1], eps="churn10", seed=s,
                         **churn(X, b, np.random.default_rng(500 + s))))
    for eps in EPS:
        for s in range(2 if np.isinf(eps) else 8):
            r = dp_pipeline(X, eps, np.random.default_rng(1000 + s))
            rows.append(dict(exp="E1", d=d, n=len(X), C=X.shape[1], eps=eps, seed=s, k_base=b["k"], k_dp=r["k"],
                             **compare(b, r)))
    for eps in [4, 8]:  # ablation: ranking that ignores the noise
        for s in range(4):
            r = dp_pipeline(X, eps, np.random.default_rng(1000 + s), noise_aware=False)
            rows.append(dict(exp="E1", d=d, n=len(X), C=X.shape[1], eps=f"{eps}-naive", seed=s, k_base=b["k"],
                             k_dp=r["k"], **compare(b, r)))
    print("done", d, len(X), flush=True)
    return rows


def e2(args):
    d, n = args
    X, _ = load(f"{ROOT}/{d}")
    rows = []
    for s in range(5):
        rng = np.random.default_rng(10_000 + s)
        idx = rng.choice(len(X), n, replace=False)
        Xs = X[idx]
        Xs = Xs[:, ~np.all(np.isnan(Xs), 0)]
        b = baseline(Xs)
        rows.append(dict(exp="E2", d=d, n=n, eps="churn10", seed=s, **churn(Xs, b, rng)))
        for eps in [2, 4, 8, 16]:
            for t in range(2):
                r = dp_pipeline(Xs, eps, np.random.default_rng(20_000 + 10 * s + t))
                rows.append(dict(exp="E2", d=d, n=n, eps=eps, seed=s, **compare(b, r)))
    print("done", d, n, flush=True)
    return rows


if __name__ == "__main__":
    ds = sorted(x for x in os.listdir(ROOT) if os.path.isfile(f"{ROOT}/{x}/votes.csv") and x not in SKIP)
    big = ["march-on.operation-marchin-orders", "austria-climate.9xnndurbfm.2022-07-07",
           "american-assembly.bowling-green", "vtaiwan.uberx"]
    sizes = {d: len(load(f"{ROOT}/{d}")[0]) for d in big}
    jobs2 = [(d, n) for d in big for n in [100, 200, 400, 800, 1600, 3200] if n <= 0.85 * sizes[d]]
    with Pool(2) as p:
        r1 = p.map(e1, ds, chunksize=1)
        pd.DataFrame([r for rs in r1 for r in rs]).to_csv(f"{OUT}/e1.csv", index=False)
        r2 = p.map(e2, jobs2, chunksize=1)
        pd.DataFrame([r for rs in r2 for r in rs]).to_csv(f"{OUT}/e2.csv", index=False)
