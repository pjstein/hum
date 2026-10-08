# 0015 · Rating decks are `deck` kind 1

**Status:** proposed (W0-01, 2026-10-06); parameters need the owner with the privacy targets (see ADR 0043)

## Context

`take.md` and ADR 0043 (W0-04) propose that gallery ratings are collected as a deck whose cards are takes, with groups fixed from a source release, and ask `deck.md` for a `kind` field, a `source` ref, take cards, a two-part plan and a cap, or else a separate `rating-deck` type.

## Decision

Accept the request inside `deck.md`:

- `kind` = 1 marks a rating deck; `refs["source"]` names a final release of the same context whose groups unlocked; cards are `take` versions (card `kind` = 2) that pin that source; at most 60 cards; one topic; no argument refs.
- Plan: parts 0 (`tallies`) and 3 (`groups`) only, ρ ≤ 1/20, cap ≤ 20. Sensitivities as for a vote deck.
- No post-close rounds: the phone already knows its group from the source release, so the group slot travels in the round-0 ballot and the release is one final version with `groupsK` from the source.
- At most two rating releases per source per year, enforced by the ledger (`release.md`, R10).
- Only phones that voted in the source deck take part; others have no group.

## Consequences

- No new manifest type, no new code path for what leaves the phone.
- `ballot.md` carries a group slot in a rating deck's round-0 ballot.
- The ρ, cap and rounds-per-year are W0-04's numbers and are not relitigated here.
