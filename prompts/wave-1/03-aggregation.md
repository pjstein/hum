# W1-03 · Ballots, aggregation and the DP release

**Owns:** `core/crates/hum-ballot`, `core/crates/hum-release`, `services/aggregator`
**Implements:** `docs/specs/ballot.md`, `release.md`, `shield.md` (the phone-side accounting), the release plan in `deck.md`, and the aggregator part of `services.md`

## Build

- **`hum-ballot` (phone side):** ballot encoding per release round, capped at K, sent through OHTTP; re-vote movement; receipts; the shield, charged before anything leaves the phone; projection onto published axes and self-assignment to a group for the later rounds.
- **`hum-release`:** the full release, every part a sum of bounded per-person contributions:
  - noise from OpenDP's Gaussian mechanism with zCDP accounting (no hand-rolled sampling; use its exact or discrete samplers);
  - tallies, the covariance (Analyze Gauss) and its axes, the 24 × 24 map histogram with blur, clustering with k chosen by silhouette, centroids and group tallies;
  - noise-aware representative statements and common ground;
  - size gates by noised voter count;
  - Parquet tables as `release.md` defines them.

  Put the "sum" behind a trait so the phase 2 DAP/Prio3 backend can replace central DP without touching the math.
- **`services/aggregator`:** opening a deck after verifying it and its context; ballot intake per round with deduplication by nullifier; floor checks; the noised daily count; producing and signing the release manifest; submitting it to the ledger.

## Oracle

`docs/research/dp-polis/polis_dp.py` is the reference for the math. On the Polis replay scenarios, your releases must land within the research results' ranges (`results/e1.csv`, `e2.csv`) at matching ε and size. Add statistical tests for the noise: the empirical variance matches σ² for each part.

## Seams

Ballot encoding, the cap, the shield, noise sampling, budget accounting, floor checks and tier gating.

## Done when

The simulator runs Polis replays at 100 to 5,000 voters through real ballots and a real aggregator, the metrics match the research, every floor-violation scenario is refused by the phone, the aggregator and the ledger, and the `seam-reviewer` subagent is satisfied.
