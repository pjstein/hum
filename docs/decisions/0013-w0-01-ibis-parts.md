# 0013 · Movement and argument ratings as release parts with small caps

**Status:** proposed (W0-01, 2026-10-06) · `seam:` DP budget accounting, release tiers

## Context

The design doc wants two IBIS measurements: how re-votes move after the card flips, per argument, and "does this move you?" per argument broken down by group. Both are sums of per-person vectors, but a re-vote reveals more than a vote.

## Decision

- **Movement (part 5):** per card, a 3 × 3 transition matrix (first vote → re-vote, diagonal included) plus a "this moved me" bit for at most one of the two shown arguments. Each person contributes up to two ones per re-voted card, capped at `capMovement` = K_m cards, so the sensitivity is √(2·K_m). Recommended K_m = 10. The tallies count the final vote. People who flipped the card before voting, or never flipped it, are in the tallies but not in movement.
- **Ratings (part 6):** per argument, moves · neutral · against; each person rates a uniformly random `capRatings` = K_r of the deck's argument refs. Sensitivity √K_r; recommended K_r = 10. By group, ratings ride in the round-3 group vector, so part 3's sensitivity becomes √(K + K_r + 1).
- Both unlock at 300 noised voters (`GATE_COMMON`).
- Recommended split with both parts: tallies 0.13 · covariance 0.30 · map 0.13 · groups 0.30 · movement 0.08 · ratings 0.06 of the plan's ρ. The total is unchanged because `RHO_MAX` is fixed; IBIS parts cost the other parts noise.
- Why movement costs more: at equal cap its vector has √2 times the norm of a tally vector, so at equal ρ its noise is √2 times larger. The cap and its own share of ρ keep it usable.

## Consequences

- The simulator should test these caps and shares on Polis replays with synthetic re-votes before wave 1 builds them; the numbers come from the sensitivities, not from an experiment.
- `ballot.md` must encode the movement and ratings vectors and apply the random sampling of K_r arguments on the phone.
- `issue-map.md`'s annotations ("moved toward / away", "fair to A · B") read the `movement`, `moved`, `ratings` and `group_ratings` tables.
