import sys, os, math, numpy as np, pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from polis_dp import eps_to_rho, gauss_sigma, DEFAULT_SPLIT

RES, OUT = sys.argv[1], sys.argv[2]
pd.set_option("display.width", 250); pd.set_option("display.max_columns", 30); pd.set_option("display.max_rows", 300)
M = ["ari", "k_match", "pca_affinity", "tally_median_pp", "tally_within5pp", "repness_overlap", "repness_relaxed",
     "consensus_overlap", "consensus_relaxed"]

def norm(x):
    try:
        return str(float(x))
    except ValueError:
        return x


# ------------------------------------------------------------------ E1
e1 = pd.read_csv(f"{RES}/e1.csv")
e1["eps"] = e1["eps"].astype(str).map(norm)
per = e1.groupby(["d", "n", "eps"])[M].mean().reset_index()
print("=== E1 per conversation: ARI / tally pp / repness relaxed / consensus relaxed ===")
for m in ["ari", "tally_median_pp", "repness_relaxed", "consensus_relaxed"]:
    t = per.pivot_table(index=["n", "d"], columns="eps", values=m)[["churn10", "inf", "16.0", "8.0", "4.0", "2.0", "1.0"]]
    print(f"\n-- {m}"); print(t.round(2))

bins = [0, 300, 1000, 2000, 10_000]
labels = ["<300", "300-1k", "1k-2k", "2k+"]
per["size"] = pd.cut(per["n"], bins, labels=labels)
print("\n=== E1 by size bucket (mean over conversations) ===")
print(per.groupby(["size", "eps"], observed=True)[M].mean().round(2))
print(per.groupby("size", observed=True)["d"].nunique())

# ------------------------------------------------------------------ E2
e2 = pd.read_csv(f"{RES}/e2.csv")
e2["eps"] = e2["eps"].astype(str).map(norm)
agg = e2.groupby(["eps", "n"])[M].mean().reset_index()
print("\n=== E2 size sweep (mean over 4 source conversations) ===")
for m in ["ari", "tally_median_pp", "repness_relaxed", "consensus_relaxed", "k_match", "pca_affinity"]:
    print(f"\n-- {m}"); print(agg.pivot_table(index="n", columns="eps", values=m)[["churn10", "16.0", "8.0", "4.0", "2.0"]].round(2))
print("\n-- ARI per source conversation")
print(e2.pivot_table(index=["d", "n"], columns="eps", values="ari")[["churn10", "16.0", "8.0", "4.0", "2.0"]].round(2))

# ------------------------------------------------------------------ analytic: votes per statement for +/-5pp
print("\n=== Noise per count and votes needed per statement for +/-5pp (90%), K=60, k=2 groups ===")
rows = []
for eps in [1, 2, 4, 8, 16]:
    rho = eps_to_rho(eps)
    sa = gauss_sigma(math.sqrt(61), DEFAULT_SPLIT["tally"] * rho)
    sd = gauss_sigma(math.sqrt(60), DEFAULT_SPLIT["group"] * rho)
    v = 1 / (1 / sa ** 2 + 1 / (2 * sd ** 2))
    need = 1.645 * math.sqrt(0.75 * v) / 0.05
    rows.append(dict(eps=eps, rho=round(rho, 3), sigma_count=round(math.sqrt(v), 1), votes_needed_5pp=round(need)))
print(pd.DataFrame(rows))
print("plain sampling error: respondents for +/-5pp at 90%, p=0.5:", round((1.645 * 0.5 / 0.05) ** 2))

# ------------------------------------------------------------------ chart
ink, ink2, muted, grid, axis, surf = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#fcfcfb"
ramp = {"2.0": "#86b6ef", "4.0": "#3987e5", "8.0": "#1c5cab", "16.0": "#0d366b"}
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.edgecolor": axis, "axes.labelcolor": ink2,
                     "xtick.color": muted, "ytick.color": muted, "axes.titlecolor": ink})
fig, axes = plt.subplots(1, 4, figsize=(16, 4.6), facecolor=surf)
a2 = agg[agg["n"] <= 1600]
ns = sorted(a2["n"].unique())
cols = ["tally_err_10", "tally_err_50", "tally_err_200", "tally_err_1000"]
tb = e1.groupby(["d", "eps"])[cols].mean().reset_index().groupby("eps")[cols].mean()
panels = [("ari", "Opinion groups", "Agreement with non-private groups (ARI)"),
          ("repness_relaxed", "Representative statements", "Share of each group's top 5 in true top 15"),
          ("consensus_relaxed", "Consensus statements", "Share of top 5 in true top 15"),
          ("tally", "Agree share per statement", "Median error, percentage points")]
for ax, (m, title, ylab) in zip(axes, panels):
    ax.set_facecolor(surf)
    for side in ["top", "right"]:
        ax.spines[side].set_visible(False)
    ax.grid(axis="y", color=grid, linewidth=0.8); ax.set_axisbelow(True)
    ax.set_title(title, loc="left", fontsize=11.5, fontweight="bold", pad=18)
    ax.text(0, 1.02, ylab, transform=ax.transAxes, fontsize=9, color=ink2)
    if m == "tally":
        x = np.arange(4)
        ax.plot(x, tb.loc["churn10", cols], color=muted, lw=2, ls=(0, (4, 3)))
        for e, c in ramp.items():
            ax.plot(x, tb.loc[e, cols], color=c, lw=2, marker="o", ms=5, mec=surf, mew=1.5)
        ax.set_xticks(x); ax.set_xticklabels(["10-49", "50-199", "200-999", "1,000+"])
        ax.set_xlabel("Votes on the statement (all 18 conversations)")
        ax.set_ylim(0, None)
        continue
    fl = a2[a2.eps == "churn10"].sort_values("n")
    ax.plot(fl["n"], fl[m], color=muted, lw=2, ls=(0, (4, 3)), label="No DP, 10% of people drop out")
    for e, c in ramp.items():
        sub = a2[a2.eps == e].sort_values("n")
        ax.plot(sub["n"], sub[m], color=c, lw=2, marker="o", ms=5, mec=surf, mew=1.5, label=f"ε = {e[:-2]}")
    ax.set_xscale("log", base=2); ax.set_xticks(ns); ax.set_xticklabels([f"{x:,}" for x in ns]); ax.minorticks_off()
    ax.set_xlabel("Participants (subsampled)")
    ax.set_ylim(-0.03, 1.03)
h, l = axes[0].get_legend_handles_labels()
fig.legend(h[1:] + h[:1], l[1:] + l[:1], loc="lower center", ncol=5, frameon=False, fontsize=10, labelcolor=ink2,
           bbox_to_anchor=(0.5, 0.0))
fig.suptitle("What survives differential privacy in Polis-style analysis (one release, δ = 10⁻⁶)", x=0.01, ha="left",
             fontsize=13, fontweight="bold", color=ink)
fig.text(0.01, 0.905, "First three panels: participants subsampled from 4 open conversations (2 at 1,600). "
         "Last panel: all 18 conversations at full size.", fontsize=9, color=ink2)
fig.tight_layout(rect=(0, 0.08, 1, 0.9))
fig.savefig(f"{OUT}/dp_polis_results.png", dpi=160, facecolor=surf)
print("saved chart")
