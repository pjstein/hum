# 0043 · Take ratings are rating decks at ρ 0.05

**Status:** proposed (W0-04, 2026-10-06); the deck shape is accepted by W0-01 in `0015-w0-01-rating-decks.md`. The parameters need the owner together with the privacy targets.

## Context

The gallery ranks takes by whether every opinion group calls them a fair reading. A rating is a vote: it reveals how a person reads a political claim, by group. It must be collected and released with the same guarantees as a vote. The design doc fixes the gesture (the same left and right swipe) and says ratings are private and noised, but not how they are collected or what they cost.

## Decision

A rating round is a deck. The context authority deals a `deck` with `kind` = 1 whose cards are take versions pinning one source release of that context. Right is fair, left is misleading, up is can't say. Phones encode it as an ordinary card ballot with a group slot, and the aggregators produce one final release with the `tallies` and `groups` parts, the groups being the source release's, which each phone already knows for itself. No post-close rounds.

Parameters in draft 0.1, all of them deck fields rather than constants:

| Parameter | Value |
| --- | --- |
| ρ per rating deck | at most 0.05 (split 0.4 tallies, 0.6 groups) |
| Contribution cap K | 20 takes per rater |
| Cards | at most 60, earliest-logged eligible takes first |
| Rounds | at most 2 per source release per year |
| Raters | people who voted in the source release |
| Floors | 100 noised raters to publish overall; 300 per group cell |

With K = 20 (sensitivity √21) and ρ 0.03 on the groups part, σ per cell is about 19. At 400 raters in a group a fair share sits at ±6 points (90%); at 1,000, ±2. Each round adds 0.05 to the context's yearly ρ: four releases alone compose to about ε 8.5, with one rating round each to about ε 9.4, with two each to about ε 10.3.

## Why a deck

Every property a rating needs already exists in the deck pipeline: membership proof, contribution cap, planned noise charged to the shield before sending, one release per deck, floors checked at phone, aggregator and ledger, receipts. Reusing it means ratings can't end up with a weaker guarantee than votes through a separate code path. It also means no gallery server ever sees a rating. The gallery index only reads rating releases, and every phone can recompute the ranking from them.

## Consequences

- `deck.md` carries this as `kind` 1 with rule D15; `release.md` as R5 (one final version) and R10 (two per source per year).
- `ballot.md` must carry the group slot in a rating deck's round-0 ballot. In phase 1 the aggregator then learns each rating pseudonym's source-release group. It could already compute that from the same pseudonym's source-deck ballot, so this adds nothing, but W0-02 should confirm when it writes `ballot.md`.
- The shield spec charges rating decks like any deck. The yearly shield placeholder (ε 20) absorbs them at these rates.
- Ratings pool across take versions with the same query and chart (`queryHash`); a changed chart resets the pool.
- Only voters of the source release can rate. Non-voting members have no group; whether to add an "ungrouped" cell is an open question in `take.md`.
- The owner may lower ρ or R, or cap rounds at one per release, when the privacy targets are set. The ranking still works at lower precision; it only needs to separate "fair to both" from "misleading to one".
