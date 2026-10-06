# DP feasibility study on Polis open data

This is the experiment behind the "Evidence from real conversations" section of `docs/design.md`. It runs a Polis-style analysis twice on real conversations, once without privacy and once through the differentially private release pipeline, and measures what survives.

In the build it has a second job: **it's the oracle for the release math.** The aggregation workstream ports this pipeline to Rust, and the simulator compares every release against the non-private baseline using the metrics defined here.

## Files

| File | What it is |
| --- | --- |
| `polis_dp.py` | The pipeline: zCDP accounting (`eps_to_rho`, `rho_to_eps`, `gauss_sigma`), the non-private `baseline`, `dp_pipeline` (tallies, Analyze Gauss covariance, 24×24 map histogram, group tallies), noise-aware `repness` and `consensus`, and the comparison metrics (`compare`, `churn`) |
| `run_experiments.py` | E1: every open conversation with 100+ participants at its real size, ε in {1, 2, 4, 8, 16, ∞}, plus a naive-ranking ablation. E2: a participant-subsampled size sweep |
| `analyze.py` | Builds the summary tables and the chart |
| `results/e1.csv`, `results/e2.csv` | Raw results from the run on 2026-10-06 |
| `results/dp_polis_results.png` | The chart |

## Running it

```bash
git clone https://github.com/compdemocracy/openData /tmp/polis-open   # CC BY 4.0
pip install numpy pandas scipy scikit-learn matplotlib
OMP_NUM_THREADS=1 python -I run_experiments.py /tmp/polis-open results/
python -I analyze.py results/ results/
```

Set `OMP_NUM_THREADS=1`; the script parallelizes across conversations and oversubscribes the CPU otherwise.

## Defaults worth carrying into the specs

- δ = 10⁻⁶. ε 4 ≈ ρ 0.254 and ε 8 ≈ ρ 0.91, from ε = ρ + 2√(ρ ln(1/δ)).
- Budget split (`DEFAULT_SPLIT`): tallies 0.15, covariance 0.35, map histogram 0.15, group tallies 0.35.
- Contribution cap K = 60 votes per person; covariance over the M = 60 most-voted statements; map grid 24 × 24 with a Gaussian blur of 1 cell.
- Ranking must be noise-aware: pseudo-counts λ = max(1, σ) and an effective sample size n_eff = n² / (n + 3σ²) in the z-tests, where n is a statement's noised vote count and σ the published noise level (see `repness` and `consensus`). Naive ranking collapsed on large conversations (representative statements 0.98 vs 0.69 found; common ground 0.72 vs 0.40, at 1,000–2,000 voters, ε 8).
- Size gates the evidence supports: tallies at 100 voters, common ground at 300, map and groups at 800, breakdown cells at 300, real-data checks at 5,000.
- Rule of thumb: privacy noise on a statement ≈ 200·√S / n percentage points at ε 4 (90% interval), with S statements and n voters each voting on the whole deck.

## Things learned the hard way

- Unit-normalizing vote vectors before projection scrambled groups even at ε = ∞. The Polis-style sparsity-scaled projection over full vote vectors fixed it.
- Four releases at ε 4 compose to about ε 8.5 in total under zCDP, not 16.
