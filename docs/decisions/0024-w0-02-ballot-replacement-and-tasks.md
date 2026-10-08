# 0024 · Round-0 replacement until close, one DAP task per (round, part), fixed-size ballots

**Status:** proposed, revised after review (W0-02, 2026-10-06) · `seam:` ballot construction, domain-separation strings

## Context

The `Swipe-End` board says a person can re-sort any card until the deck closes. `services.md` AG-2 said two contributions with one nullifier in one round yield one counted contribution. `services.md` defined one DAP task per round. The review found that an undefined selection time let replacements reveal dropped cards, that a round-1 ballot could exceed 64 KiB, and that "identical" was undefined and a retry after `closes` would be refused.

## Decision

1. **Replacement.** A round-0 ballot with a known primary nullifier and a different body, received before `closes`, replaces the earlier one: the last accepted ballot counts, the earlier payload is deleted at once, and only the new receipt's leaf enters the tree. A ballot with the same body (keys 0–4; the presentation may be re-proved, the nonce is reused) is a retry and gets the original receipt at any time until the nullifier set is deleted, including after `closes`. Rounds 1 to 3 do not replace. The replacement carries the same set of nullifiers.
2. **Counted hand.** The first K cards cast, in cast order, never shrinking; the first `K_m` re-voted cards likewise. A replacement therefore never removes a card from the Leader's view. Rating decks already used this rule; vote decks now do too.
3. **Send schedule.** First ballot when the person leaves the deck; then at most one replacement per random 2 to 6 hours when the hand changed, and one before `closes`.
4. **Fixed size.** Every ballot is padded to `BALLOT_BYTES` = 48 KiB; `cov` is fixed-width 32-bit integers; `deck.md` caps `covStatements` at 128 so every valid deck fits.
5. **Tasks per part.** `taskId(round, part) = SHA-256("hum/dap-task/1" ‖ deck lineage CID ‖ uint8(round) ‖ uint8(part))`; `report_id` = first 16 bytes of `SHA-256(nonce ‖ uint8(part))`.
6. **Receipts.** A round-0 receipt proves acceptance, not inclusion; a dispute is the ballot against a later valid ballot under the same nullifier. Receipt pages are fetched on fresh relay connections at random delays.

## Why

- Without replacement a phone must send once, either immediately (no re-sorting) or at close (lost if offline). The cost is that the phase-1 Leader sees the diff between a person's successive hands, pseudonymous and inside the same release.
- A first-K counted hand is the only rule under which a growing hand never reveals a dropped card.
- One fixed bucket means the relay cannot tell rounds, deck sizes or presentation sizes apart.
- One combined vector per round would enforce only the total weight; per-part tasks keep each part's bound what `deck.md` declares.

## Consequences

- `services.md`: AG-2, intake check order (identical-retry lookup before `closed`), AG-5 (replaced payloads), O-3 (48 KiB bucket for ballots), O-4 (receipt pages), `taskId` and `report_id`, lineage CID. Confirmed by W0-07 for the first set; the rest raised.
- `deck.md`: `covStatements ≤ 128`; "first K cast". `release.md`: what a round-0 receipt proves.
- Phase 2: the Leader keeps the last accepted round-0 report set per nullifier; the Helper cannot check it.
- Open: the 2 to 6 hour cadence and the Leader's intake load are for the simulator.
