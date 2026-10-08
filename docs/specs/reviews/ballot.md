# Review: `docs/specs/ballot.md` (Draft 0.1, W0-02)

Reviewed 2026-10-06, as on disk, against `CLAUDE.md`, `docs/design.md`, ADR 0024, and `credentials.md`, `shield.md`, `deck.md`, `release.md`, `services.md`, `context.md`, `take.md`, `agent-sponsor.md`.

## Verdict

**First review: approve with fixes, three blockers.** **Re-review (see the end of this file): approve with fixes; no blocker of this spec's own remains.** One blocker in `reviews/credentials.md` (R2, the ballot window under a `closes` extension) changes rule B2 here.

First-review verdict text: three blockers, all with small fixes. The vector layouts and weight bounds match `deck.md`'s Parts table. The receipt leaf meets `release.md` and `services.md`: fixed length, no nullifier, dummies indistinguishable. Findings in `reviews/credentials.md` B1 to B3 also decide whether one person can be counted twice here.

## Blockers

**B1 (blocker) — "The K selection", "The movement selection", "Replacement in round 0": when the selection is drawn is undefined, and replacement shows the Leader which cards were dropped.**
The selection is drawn "if the person voted on more than K cards" and "once". A phone now sends after the first sorted card and again after every change. Consider a person who has sorted 10 cards at the first send and ends with K + 5:
- If the phone draws when the count first passes K, cards that were in earlier ballots drop out of later ones. The Leader sees exactly which cards were dropped, which the "Never sent" column and "What the Leader never learns" both deny.
- If it draws over all voted cards at each send, the selection is not drawn once.

Two implementers will differ, and one reading leaks. `deck.md`'s rating-deck row and `take.md` use a different rule again: "the phone counts its first R cards in its own order".

Fix: one rule for all decks. The counted hand is the first K cards the person votes on, in the order they voted. It never shrinks or swaps, so a replacement never removes a card. With random card order it is a random K-subset. Apply the same rule to the movement selection (the first `K_m` re-voted cards). Say whether a vote can be withdrawn; if not, delete "unless the person's voted set shrank". Add client vectors for a hand that grows past K across three sends.

**B2 (blocker) — "The ballot" size limit and "Rounds 1 to 3": a round-1 ballot for a deck `deck.md` allows exceeds 64 KiB.**
`cov` has `M(M+1)/2` integers. `deck.md` D11 allows `covStatements` up to the card count, which is at most 256, and its vector list includes `(256, 2²⁴)`. At M = 256 that is 32,896 entries of 3 to 5 bytes each, about 100 to 165 KiB. B1 rejects every such ballot, so the map tier of a valid deck can never run. Fix: either `deck.md` caps `covStatements` (about 110 keeps the worst case under 64 KiB), or `cov` becomes one byte string of fixed-width big-endian integers with its own limit. Add the boundary vector.

Related: `services.md` O-3 requires every ballot request to land in the 4 KiB relay bucket. A round-0 ballot with a 2.7 KiB presentation is borderline, and a round-1 ballot at M = 60 is about 9 KiB. State the padded size per round here and ask W0-07 to change the check. One fixed bucket for all ballots is best, so the relay cannot tell rounds or presentation sizes apart.

**B3 (blocker) — "Replacement in round 0", B7, B8: what "identical" means and what happens after `closes`.**
- The bound message is over "the ballot with key 5 removed" and the idempotence rule is over "a byte-identical body". BBS proofs are randomized. If "body" includes the presentation, a phone must store and resend the exact bytes. If it does not, the phone may make a fresh proof. Define "body" as the ballot without key 5, and require the retry to reuse the stored `nonce`.
- `services.md` intake check 1 answers `closed` before it looks at the ballot. B7 says an identical resubmission gets the original receipt, with no time condition. A phone whose response was lost at 23:59 retries at 00:01, is told `closed`, and by `shield.md` refunds a charge for a ballot that is in the sum. Fix: an identical resubmission is answered with the original receipt until the nullifier set is deleted. `services.md` check order and check 6 (`conflict` with the receipt, or 200) must match.
- B8 names `conflict`; `services.md` check 4 names `forbidden` for a nullifier with no round-0 ballot. Put the error code beside each B rule.

## Should fix

**S1 — "Receipts": a replaced ballot's receipt looks like proof of a dropped ballot.**
The aggregator signs a receipt for every accepted round-0 ballot, and replaced leaves are left out of the tree. So a signed receipt whose leaf is missing is normal, and "shown as not counted with the signed receipt as evidence" proves nothing. An aggregator can answer any true complaint with "it was replaced", and anyone can raise a false one with an old receipt. Fix: say what a round-0 receipt proves, and define the dispute: the complainant shows the ballot, and the aggregator rebuts only by showing a later valid ballot under the same nullifier. State that this reveals the complainant's ballot to whoever judges it. Rounds 1 to 3 are unaffected.

**S2 — "Receipts", step 2, and B13: receipt-page fetches on one relay connection identify the leaf in large decks.**
`services.md` O-4 gives one relay connection per request class, not per request. A phone that checks rounds 0 to 3 of a deck on one connection reveals four `k`-bit prefixes together. With 100,000 leaves and `k` = 5 the four prefixes select about 0.1 leaves, which is one person. Until the Leader deletes its nullifier set (final plus 24 hours), it can map that leaf to a pseudonym and to every other lookup on the connection. Fix: each receipt-page fetch uses its own fresh relay connection, carries nothing else, and is delayed by a random time; or the phone waits until 24 hours after the final version. For `k` = 0 there is nothing to hide.

**S3 — "Replacement in round 0": the send schedule gives a timing trace.**
A send per minute while the person plays gives the Leader a per-pseudonym activity trace, and gives the relay a matching trace by client address. One correlated event becomes dozens. Fix: send the first ballot when the person leaves the deck, and at most one replacement per deck per random interval of some hours, plus one shortly before `closes`. Also state that the Leader MUST delete a replaced payload at once, and add that to AG-5.

**S4 — "What leaves the phone" and "What the aggregator learns": the tables understate phase 1.**
- Round 1 uses the full hand over `sel`. The Leader therefore learns every vote on a `sel` card, including cards the K selection dropped. The text "What it never learns: … the dropped cards" is false whenever the plan has the map tier.
- Replacement sends earlier votes, so "first votes on cards not re-voted" are sent whenever a person re-sorts.
- The table omits what the presentation shows on every ballot: issuer authority, `kid`, `len`, `branches`, and whether a breakdown was consented to. See `reviews/credentials.md` S4.
- In phase 2 the `hum-authorization` extension is public, so the Helper can link one person's reports across rounds by the round-0 leaf, and by the shared `report_id` across parts. Say so in the Helper column.

**S5 — "Phase 2", part 4: the daily count is not a clean sum under DAP.**
"Time-interval batches give the per-day counts" needs one batch per day. `services.md` says one batch per task with minimum size `minVoters`. A day with fewer reports cannot be collected, and per-day batches would also give both aggregators exact per-day tallies. Fix: make part 4 a client measurement, a `Prio3Histogram` over day buckets sent with the first ballot, which the Leader checks against arrival time. Phase 2 is out of scope for draft 0.1, but invariant 5 asks that the move need no change.

**S6 — "The vectors the payload stands for": part 3 in round 3 has no layout when part 6 is present.**
The table gives only the rating-deck layout. With ratings, the group vector is `groupsK × (3C + 1 + 3A)`. Add the row and its index formula.

**S7 — "Phase 2", task IDs and the receipt signature.**
- `deckCid` in `taskId` is not said to be the lineage CID. If it is the version CID, a `closes` extension splits a deck's reports across two tasks.
- The receipt signature is over `taskId(round)`, which no longer exists. ADR 0024 says to use `taskId(round, 0)` for round 0 and the round's first part otherwise; the spec does not say it. `services.md`'s open response returns one task ID per round.

**S8 — B5: a check the Leader can make is missing, and "first vote" is ambiguous.**
When `votes[i]` is non-zero, `second` must equal it. Add that to B5. With re-sorting allowed, define `first` as the vote standing when the card was flipped.

**S9 — "Phase 1 and phase 2", breakdown in phase 2.**
With the cell chosen inside the share, nothing shows the person holds the attribute at all, not only that one cell is used. A breakdown by a verified attribute becomes a breakdown by a claimed one. State this plainly for the owner beside the phase-1 question.

**S10 — Breakdown in phase 1 needs the owner's decision before wave 1.**
The Leader holds the ward beside the pseudonymous votes until final plus 24 hours. `deck.md` and `services.md` both leave this open. Recommended default: aggregators refuse decks with part 7 in phase 1 until the owner decides, and the consent screen says who sees the value and for how long.

## Notes

- **N1 — Sums.** Parts 0, 5, 6, 7, 3 and 8 are 0/1 vectors with the Hamming weights `deck.md` states. Part 2 is a one-hot. Part 1 is bounded by `Δ_cov` at intake. `Prio3MultihotCountVec` and `Prio3Histogram` fit without changing what is measured. Part 1 has no draft type, which is filed.
- **N2 — Counting twice.** Replacement is keyed by nullifier, so one card counts once. A person is counted twice only through two valid cards (`reviews/credentials.md` B1, B2). Add a client rule and vector: after a renewal, a phone never sends a round-0 ballot for a deck it already has a ledger entry for.
- **N3 — Agents.** B3 covers no credential and an agent-class credential. Add `ballot-invalid-B1-agent-signature`: a ballot with an added key holding an `agentKey` signature, rejected as an unknown key.
- **N4 — Phase-2 admission.** The presentation is publicly verifiable. Forwarding it to the Helper would let both aggregators check membership, at the cost of the Helper seeing nullifiers. Worth an open question.
- **N5 — Restore.** Say that a phone with no hand for the source deck sits a rating deck out.
- **N6 — DAP minimum batch size** conflicts with `release.md` R6, which logs a version below the floor. Phase 2 only.
- **N7 — Domain strings.** `hum/ballot/1` and `hum/receipt-leaf/1` are missing from `services.md`'s registry.

## Testability

One failing vector per rule B1 to B11 is listed, and B12 and B13 are simulator scenarios. Missing:
- `ballot-rejected-keeps-nullifier`, which `services.md` names as this spec's vector for AG-8.
- An identical resubmission after `closes`.
- The 64 KiB boundary for round 1.
- The growing-hand selection vectors from B1.
- A replacement that changes the non-primary credential or the breakdown value.
- B5's `second` ≠ `votes[i]`.

## Changes this forces on sibling specs

- `services.md`: AG-2 and intake check 6 (replacement); check 1 order for identical resubmission; `taskId` per part, the open response and the receipt signature; O-3's 4 KiB check; O-4 for receipt pages; AG-5 for replaced payloads; registry rows.
- `deck.md`: cap on `covStatements` or a new `cov` encoding; the rating-deck cap rule.
- `take.md`: the same cap wording.
- `release.md`: what a round-0 receipt proves.

---

# Re-review (2026-10-06, revised spec, 284 lines)

Re-read in full with ADR 0024, and checked `services.md`, `deck.md` and `release.md` on disk for the matching changes.

## Verdict

**Approve with fixes. No blocker of this spec's own remains.** Rule B2 inherits `reviews/credentials.md` R2: the ballot window follows the deck version in force, so a `closes` extension can admit an old card and its successor. The fix is in `credentials.md`; B2's wording and one vector change here.

## First-review blockers

| Blocker | Status | Evidence |
| --- | --- | --- |
| B1 selection timing | **Fixed.** The counted hand is the first K cards cast, in cast order; it never shrinks or swaps. "Cast" is defined, with undo before casting. The movement selection follows the same rule. `deck.md` says "first K cast" and the client vectors cover a hand that grows across three sends | "Casting and the hand", "The counted hand" |
| B2 round-1 size | **Fixed.** `cov` is one byte string of signed 32-bit integers; every ballot is padded to `BALLOT_BYTES` = 49,152; `deck.md` caps `covStatements` at 128 in the field table, D11 and a failing vector. Two edge cases remain (RS1) | "The ballot", "Rounds 1 to 3" |
| B3 "identical" and `closes` | **Fixed.** The body is keys 0 to 4; a retry may re-prove and must reuse the nonce; an identical retry gets the original receipt until the nullifier set is deleted. `services.md` intake check 2 does the lookup before the `closed` check. Each B rule names its error | "The ballot", "Replacement in round 0", B7, B8 |

First-review should-fixes S1 to S10 are all addressed: what a receipt proves and the dispute rule (also in `release.md`), one fresh relay connection per receipt page with a random delay (also in `services.md` O-4), the 2 to 6 hour send schedule, the corrected phase-1 table including the cohort tuple and the uncounted `sel` votes, part 4 as a client histogram in phase 2, the round-3 layout with ratings, `taskId` over the lineage CID and `firstPart`, `second = votes[i]`, the phase-2 breakdown statement, and part 7 refused in phase 1.

## Remaining should-fixes

**RS1 — "The ballot", Size: two cases where the fixed size cannot be met.**
- `pad` is a CBOR byte string, so its header is 1, 2 or 3 bytes depending on length. Some totals are unreachable: a ballot that is 25 bytes, or 258 bytes, short of `BALLOT_BYTES` before padding cannot be brought to exactly 49,152 with a canonical `pad`, and a ballot fewer than 2 bytes short cannot hold key 6 at all. Fix: pad outside the CBOR. Send the canonical ballot followed by zero bytes up to `BALLOT_BYTES`, with a 4-byte length prefix, and drop key 6. Add vectors at the three boundaries.
- At M = 128, `cov` is 33,024 bytes. P1 allows a 16 KiB presentation. Together they exceed 49,152. The spec says the phone refuses such a deck, which makes round 1 depend on how many cards a person holds. Fix: cap a ballot's presentation at 8 KiB (eight cards at about 0.6 KiB fit), or cap `covStatements` at 120.

**RS2 — "The ballot", Policy, and B2: "valid now" is not what the window checks after `closes`.**
The window is `p_closes − V + 1 ≤ p ≤ min(p_now, p_closes)`. In rounds 1 to 3 it admits a card that was valid at `closes` and has since expired. That is the right behavior, because otherwise people drop out of later rounds. The text says "valid now and valid through `closes`". Say "valid at `closes`, and already issued".

**RS3 — "Replacement in round 0", send schedule: the first send must wait for a card that fits.**
A member whose card dies before `closes` cannot vote until their successor is valid (`reviews/credentials.md` RS3). The schedule sends "when the person leaves the deck". State that the phone holds the ballot until its card satisfies the window, and that the shield entry stays `reserved` meanwhile.

**RS4 — "Receipts", dispute: there is a deadline the spec does not state.**
The Leader can rebut only while it holds the later ballot, which AG-5 deletes 24 hours after the final version. State that a round-0 dispute must be raised before then, or that the Leader keeps nothing and an unanswered dispute proves nothing. Also say that the rebuttal shows the judge the person's later hand.

**RS5 — B9: error code.** `floor` with detail `breakdown_deferred` is not a floor failure. `rejected` with rule B9 reads more truthfully. Minor; `services.md` uses the same code, so change both or neither.

## Notes

- The every-nullifier rule holds in round 0 and for replacements. B8 checks only the primary nullifier in rounds 1 to 3, which is enough.
- The Leader still sees the first send at the moment a person leaves a deck. One event per deck is acceptable.
- Vectors now include `ballot-rejected-keeps-nullifier`, the identical retry after `closes`, the M = 128 boundary, the growing hand, a pooled presentation, a replacement with a different second nullifier, and the added-key agent case. Add the padding boundaries from RS1 and, after `reviews/credentials.md` R2, an extended deck where the successor card is refused.

## Forced sibling changes: what has landed

| Spec | Landed | Not landed |
| --- | --- | --- |
| `services.md` | AG-2; AG-5 with replaced payloads; intake checks reordered (retry lookup before `closed`); check 7 holds every nullifier; `taskId(round, part)` over `deckLineageCid`; `taskIds[round][partIndex]`; receipt signature over `taskId(n, firstPart)`; O-3 states `BALLOT_BYTES` and the 64 KiB bucket; O-4 one connection per receipt page; registry rows for `hum/ballot/1`, `hum/ballot-bound/1`, `hum/receipt-leaf/1`; part 7 refused at open | Intake text still says "under the context's entry policy" (it is `[1, [entry, vote]]`) and "one nullifier per (context, deck)" |
| `deck.md` | `covStatements ≤ 128`; "first K cast"; phase-1 breakdown deferral | — |
| `take.md` | Not re-read; rating decks have no round 1 and already used the first-R rule | — |
| `release.md` | "What a receipt proves" and the dispute rule under "Receipts" | The dispute deadline (RS4) |
