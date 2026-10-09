# 0103 · What may be published below the voter minimum, and when `closes` may move

**Status:** accepted by the owner 2026-10-08, applied; seam, the diff still gets the owner's read before merge · `seam:` release tiers and floor checks · invariant 3

*2026-10-08:* The owner said to apply every recommended item. All four are applied; see `cross-spec.md` section 12.9. `CLAUDE.md` invariant 3 now names the daily count exception (edited by the orchestrator on 2026-10-08); that follow-up is done.

## Context

Four places where a floor in `CLAUDE.md` invariant 3 has a path around it or a rule that cannot be met.

1. **Two outputs have no voter minimum.** The floor says at least 100 noised voters to publish. The organizer's daily count is served every day while the deck is open, with no gate (`context.md`, "The noised daily count"; `deck.md` Parts, gate "none"). The padded receipt tree of round 0 is published even when the release is below the minimum, because `release.md` R13 requires a receipt root and pages for every completed round, while R6 says part 8 is unlocked only with part 0. Its leaf count is a noised voter count. Both outputs are differentially private and inside `plan.rho`. Neither is named as an exception to the floor, and R6 and R13 disagree about part 8.
2. **`closes` may be extended after it has passed.** `deck.md` D12 only requires `closes ≥ prev.closes`. `services.md` says the aggregator "accepts a version that only extends `closes`". No rule says the extension must arrive before the close. After the close the last daily bucket is already noised, the `absorb` decision is taken, and version 1 of the release may be logged. An extension then reopens round 0 for a release that can no longer change. Phones charge shields and send hands that are never counted, and `release.md` R2 ("the highest version logged before `deck.closes`") no longer names one deck version.
3. **A rating deck cannot meet a tightened context floor.** `deck.md` D15 fixes a rating deck's `minVoters` at `GATE_TALLIES` (100). D10 requires `minVoters ≥ ctx.floors.minVoters`. A context that raised its minimum to 300 cannot deal a rating deck.
4. **One release per deck is checked per log.** `services.md` checks R10 and R14 against each log's own history. A context that names two logs can have one release lineage in each for the same deck if both aggregators sign both. At launch one operator may run both aggregators.

## Decision (proposed)

1. **Name the exceptions or remove them.** Recommended: keep the daily count as a declared exception ("the daily count is the one output with no voter minimum; it is noised, capped at `COUNT_RHO_MAX` and seen by organizers only until release"), and stop publishing receipt pages for a release that is below the minimum. Below the minimum nothing was published, so there is nothing for a receipt to confirm. R13 gains "except when `unlocked` is empty", R6 keeps part 8 locked, and part 8's noise is not drawn. `CLAUDE.md` invariant 3 and `manifest.md` "Privacy floors" name the daily count.
2. **An extension must be logged before the close it replaces.** New rule in `deck.md`: a version greater than 1 is valid only if no release version that pins this deck lineage has a lower log index, and aggregators refuse an extension they first see at or after the `closes` they hold. The ledger checks the first half; the aggregators check the second with their own clocks. `release.md` R2 then reads "the highest version of the lineage in the log".
3. **Rating decks take the context's minimum.** D15 becomes `plan.minVoters` = max(`GATE_TALLIES`, `ctx.floors.minVoters`).
4. **A release names the log that counts.** For R10 and R14 the first log in the context's `logs` array is the ledger of record; a release must be in it, and phones apply R10 and R14 against it.

## Consequences

- After review (2026-10-08): below the minimum only parts 0 and 4 are noised; phones check R10 against the ledger of record and R14 stays with the ledger and aggregators; a context version that changes its first log restarts R10 and R14, which is filed as an owner choice in `docs/DECISIONS.md`.

- `release.md` R6, R13 and the `release-valid-below-minimum` vector change with item 1. `services.md` AG-4 and the receipts endpoint answer `404` for a below-minimum round.
- `deck.md` D12 or a new D16, `services.md` "Opening a deck", `release.md` R2 and the `deck-valid-v2-extend` vector change with item 2.
- Items 3 and 4 are one sentence each in `deck.md`, `take.md`, `release.md` and `services.md`.
