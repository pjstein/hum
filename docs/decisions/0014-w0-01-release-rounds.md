# 0014 · A release is one lineage with one version per post-close round

**Status:** proposed (W0-01, 2026-10-06) · `seam:` DP budget accounting, release tiers, what leaves the phone

## Context

The map and groups need phones to act after close on published numbers: axes to project onto, centroids to assign to. The oracle also centers each vote vector on the noised column means before unit-normalizing it, which means the covariance cannot be summed until the tallies are published. The design doc describes two post-close rounds; `services.md` assumed two rounds and unlogged interim blobs signed `round-publish/1`.

## Decision

1. **Three post-close rounds:** covariance (needs tallies), map cell (needs axes), group tallies (needs centroids). Each is a sum of bounded per-person vectors with the sensitivities in `deck.md`.
2. **Each round's publication is a version of the release lineage,** signed by both aggregators and logged: version 1 tallies, 2 axes, 3 centroids, 4 final. Parts already published are frozen; a version may be final early when a round's noised total falls below the map gate. One release per deck means one lineage per deck lineage.
3. **Dropouts** reduce a round's own total, recorded per part as `n`. Downstream numbers use each part's own total; the oracle's blend of tallies with summed group tallies is not done.
4. **Noise** is the discrete Gaussian on integer sums with the exact rational σ² = Δ²·den/(2·num); the Leader draws all of it in phase 1 and the Helper attests parameters, floors, one-release-per-deck, the referenced bytes and a sane `issued`.
5. **Receipt trees are padded** with dummy leaves to a noised size, paid for by a `receipts` part (id 8, sensitivity √(R+1), default ρ 1/200), so a round's exact ballot count is never published beside the noised `nHat`.

## Why versions rather than interim blobs

Versions give frozen-field enforcement for free (parts noised once, never re-noised) and reuse the proof-before-action rule: a phone projects itself only onto axes it holds a log proof for, so a Leader cannot show different axes to different phones without a visible fork. The yearly floor does not depend on them: R14 charges the whole plan at version 1.

The cost is log latency between rounds (seconds) and four log entries per deck instead of one.

## Open

- **One round fewer.** If a normalize-then-center covariance (sum of `u uᵀ` and of `u` with `u` the unit raw vote vector, centered after the fact) matches the oracle's groups in the simulator, round 1 folds into the vote ballot and the design doc's two rounds are restored. The aggregation workstream should run this on the Polis replays.
- **Split noise in phase 1.** The Helper could add half the variance so that one honest aggregator still gives 2ρ-zCDP. Deferred until the Helper is a separate organization; with one operator it is theatre.
- **`services.md` alignment.** `GET .../rounds/{n}/published` should return the release version bundle; `GET .../receipts` should be per round; the `round-publish/1` signature is unnecessary. For W0-10.
