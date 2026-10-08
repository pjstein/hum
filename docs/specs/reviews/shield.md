# Review: `docs/specs/shield.md` (Draft 0.1, W0-02)

Reviewed 2026-10-06, as on disk, against `CLAUDE.md`, `docs/design.md`, ADRs 0023 and 0025, and `credentials.md`, `ballot.md`, `deck.md`, `release.md`, `context.md`, `take.md`, `services.md`, `simulator.md`.

## Verdict

**First review: approve with fixes, two blockers.** **Re-review (see the end of this file): approve with fixes; both blockers are fixed and none remains.** Two items stay with the owner.

First-review verdict text: two blockers. The unit, the constant, charging the plan's total before sending, and the composition argument are correct. I checked the arithmetic: `rho_to_eps(2201/500, 10⁻⁶)` is 19.999 and at 4.403 it is 20.002; the board figures 6.2 and +1.4 reproduce; four releases at ε 4 give 8.5.

## Blockers

**B1 (blocker) — "Charging", Refunds: a server can make a phone refund a charge for a ballot that was counted.**
An entry is refunded when "every attempt … is rejected and the phone stops trying, or the deck closes before any send succeeded". Both conditions rest on what the server says or fails to say:
- A Leader or gateway that accepts a ballot and drops the response leaves the phone with no receipt. At `closes` the phone refunds. The ballot is in the sum.
- A Leader that answers `rejected` and counts the ballot anyway has the same effect. Nothing in phase 1 ties the sums to the receipt tree.
- An honest case does it too: a retry that arrives just after `closes` is answered `closed` (`reviews/ballot.md` B3).

So an operator can keep a person's shield from ever filling, which removes the yearly floor for exactly the adversary the design doc names. "A phone's budget cannot be overdrawn by anything a server does later" is not true as written, and invariant 6 says nothing trusts a server.

Fix: once any round-0 ballot bytes for the deck have been handed to the network, the entry is never refunded. Refund only an entry for which nothing was sent. An honest rejection then costs budget, which is acceptable because B12 has the phone check everything locally first. Change S7 and the `shield-states` vector to match, and add a simulator scenario with a Leader that drops responses.

**B2 (blocker) — "Restore": the rebuilt ledger is not an upper bound, and a conforming app lets the person clear it.**
Step 3 claims spent is at least what the lost ledger held. Four cases break it:
- The backup lists contexts the person "is in" and is rewritten when they leave one. A context left in the last year, where they voted, is missing.
- `chargedAt` is set to the deck's `opens`. The real charge was at the first ballot, later. The estimated entry drops out of the window before the real one would have.
- Step 1 lists releases and open decks. A deck that has closed and has no version 1 yet, and an abandoned deck with no release, are in neither list.
- A release whose version 1 is older than 365 days can belong to a deck whose `closes`, and so whose charge, is inside the window after a `closes` extension. Enumerate by deck, not by release.

Fix: the backup keeps each context for 365 days after the person leaves it. The phone lists every deck of those contexts whose latest `closes` is within 365 days or in the future, whatever its release state, and sets `chargedAt` to that `closes`.

The second half: the board lets the person remove an `estimated` entry by confirming "I did not vote in this deck". Wipe, restore and untick resets the shield on an unmodified app. An organizer who wants an eighteenth deck counted can ask members to do it. Invariant 3 says floors only get stricter, and ADR 0025 does not mention this control. Fix: remove it from draft 0.1, or record it in ADR 0025 as an owner decision with the reason. The team lead asked whether a wipe can reset the budget: with the four cases fixed and no removal control, it cannot; today it can.

## Should fix

**S1 — "Charging", step 2, and "When the shield runs out": the fit check and the "not counting" notice happen at different times.**
The notice must appear before the first card. The charge happens at the first send, after the person leaves the deck. With two decks open, both fit when shown; the first to send takes the budget and the second no longer fits after its cards were sorted. Fix: reserve the charge, as a `pending` entry, when the person opens the deck, and release it only if they leave without sorting a card and nothing was sent.

**S2 — "Restore" and "Per person, not per device": a second restored device roughly doubles the spend.**
Each phone's ledger misses the other's entries. The duplicate-nullifier rule stops a double count in one deck, but the two phones together can spend up to twice the remaining budget across different decks, and each further restore adds more. The spec and ADR 0023 record this as residual risk. It is a floor an unmodified app can exceed, so it needs the owner's explicit acceptance, not only a note. Also fix the route that makes it likely by accident: a chat-only second device currently gets the chat key through the full backup, which carries the cards (`reviews/credentials.md` S7).

**S3 — "The ledger": an `estimated` entry has no transition.**
After a restore the person may vote in an open deck that already has an `estimated` entry. Say the entry is reused and moves to `pending`, so the deck is not charged twice. Add it to `shield-states`.

**S4 — S1 and the constant.**
S1 tests `2202/500`, which is 4.404. The claim is "largest to three decimals", so the test must be `4403/1000`.

**S5 — "Composition": wrong figure.**
`SHIELD_RHO` holds 88 rating decks at ρ 1/20, not "about 65".

**S6 — `shield-compose-board`: the vector contradicts the rule.**
It lists a pending entry and "69% remaining". The spec says pending counts as spent, which gives 62%. 69% is the figure without the pending entry. Say which the bar shows and make the vector carry both numbers.

**S7 — "Restore" and renewal: an honest phone can contribute twice to one release.**
If a card is renewed while a deck the person voted in is open, a later replacement carries a new nullifier and counts as a second voter. That person's sensitivity in the release doubles, so the real cost is four times the ρ the ledger holds. `credentials.md` says phones defer renewal. Make it a rule here with a simulator check: a phone never sends a round-0 ballot for a deck whose entry was charged under a different card. `reviews/credentials.md` B1 covers the attack form.

## Notes

- **N1 — Composition.** Each release is `plan.rho`-zCDP per person, including adaptively chosen later decks and rating decks that reuse the source group, because every part bounds one person's whole contribution. Summing ρ across contexts in one ledger is correct. The sliding window is stricter than a calendar year and I agree with it.
- **N2 — Rating decks and IBIS parts.** Both are charged through `plan.rho`, once, whatever the person does. Correct, and the reason given (a behavior-dependent charge would record behavior) is right.
- **N3 — Exhaustion.** Sitting out sends nothing and keeps no entry. Correct.
- **N4 — Clock.** Say that an entry with `chargedAt` in the future counts as spent.
- **N5 — Arithmetic.** Sums of rationals with 64-bit parts can pass 64 bits. Require arbitrary precision.
- **N6 — New card, no backup.** A person who loses the phone and the phrase starts with an empty ledger once dedup lets them get a card. Votes from the lost phone inside the window are not counted. State it as accepted.
- **N7 — Restore cost.** A person in a busy context, such as Global, may be shown as fully spent for a year after a restore. The spec says so; the owner should see it beside the direct-transfer decision.
- **N8 — δ.** The receipt-padding term is below 10⁻⁷ per year and is ignored consistently with `release.md`. Fine once the outside review confirms.

## Testability

S1 to S10 each have a vector or a simulator scenario. Missing after the fixes above:
- A Leader that drops responses, and one that rejects and counts (B1).
- Restore with a left context, a closed-unreleased deck and an extended `closes` (B2).
- Two decks open at once that each fit alone (S1).
- `estimated` to `pending` (S3).
- `simulator.md` still models a per-context pseudonym and a device switch that "resubmits"; W0-09 needs the per-deck nullifier and the one-voting-device rule.

## Changes this forces on sibling specs

- `credentials.md`: the backup's context list keeps left contexts for 365 days (B2); chat-only transfer (S2).
- `ballot.md`: B7 and the resubmission order (B1).
- `simulator.md`: the scenarios above.
- `docs/ux`: the `P-Budget` wording (already in ADR 0025) and removal of the "I did not vote" control if the owner agrees.

---

# Re-review (2026-10-06, revised spec, 169 lines)

Re-read in full with ADRs 0023 and 0025, and checked `credentials.md` "Storage and backup", `ballot.md` B7 and B12, `chat.md` §2.3 and `simulator.md` on disk.

## Verdict

**Approve with fixes. No blocker remains.** Two items are correctly left with the owner: the two-phone residual risk (ADR 0023) and whether to restore the "I did not vote" control (ADR 0025).

## First-review blockers

| Blocker | Status | Evidence |
| --- | --- | --- |
| B1 refunds trust the server | **Fixed.** An entry is `reserved` at open, `pending` before the first round-0 bytes leave, and permanent from then on whatever the response. Only a `reserved` entry with no send can be dropped, and no server has seen such a deck. S6 tests a Leader that drops responses and one that rejects and counts. `ballot.md` honors an identical retry after `closes`, so a lost response is recovered | "Reserving and charging", S6, S7 |
| B2 restore not an upper bound; removal control | **Fixed.** The backup keeps left contexts for 365 days (`credentials.md`, "The sealed backup"). Restore lists every deck of those contexts whose latest `closes` is within 365 days or in the future, in any release state, with `chargedAt = closes`. No control removes an `estimated` entry; the alternative is filed in ADR 0025. A wipe and restore can no longer lower the total | "Restore", S9 |

First-review should-fixes: S1 (reserve at open, with `shield-fit` and S4 covering two decks), S3 (`estimated` reused as `pending`), S4 (`4403/1000`), S5 (88), S6 (69% settled, 62% with pending, both in the vector) and S7 (one card per entry, S11) are done. S2 is recorded for the owner's explicit acceptance, and the chat-only export removes the accidental route.

I checked the restore argument step by step. A real charge for a deck happened no later than that deck's `closes`, so an estimated entry never leaves the window before the real one would. A context left more than 365 days ago can hold no charge inside the window. An open deck gets a future `chargedAt`, which counts.

## Remaining should-fixes

**RS1 — "Restore", step 3: a context joined since the last backup write is missing.**
`credentials.md` now writes the backup once a day at a random time, and the platform uploads it later still. A person who joins a context, votes, and loses the phone before that backup reaches the platform restores a context list without it. The estimate is then below the lost ledger for that context's decks. Fix: a phone does not send a first round-0 ballot in a context until a backup that lists the context has been written locally. State that the platform's own upload delay is a residual the spec cannot close.

**RS2 — "The ledger", `card`: pin every card, not only the primary.**
`ballot.md` B7 refuses a replacement whose nullifier set differs. The entry records only the primary card. If the phone's deterministic choice of a second card changes while the deck is open, its replacements fail. Record all cards used for the deck and reuse them (`reviews/credentials.md` RS4).

**RS3 — "Reserving and charging", step 3: a ballot held for a card that does not yet fit.**
A member whose card dies before `closes` cannot vote until the successor is valid (`reviews/credentials.md` RS3). Say that the entry stays `reserved` while the phone holds the ballot, and is dropped at `closes` if nothing was sent.

## Notes

- If `reviews/credentials.md` R1 or R2 is exploited, a modified client contributes twice to one release. That raises only that person's own cost, and an unmodified phone is stopped by S11. The shield's guarantee for honest phones does not depend on those fixes.
- Reserving at open means opening a deck costs budget until the person leaves it. That is the intended conservative behavior; the board should show reserved entries as pending, which it does.

## Forced sibling changes: what has landed

| Spec | Landed | Not landed |
| --- | --- | --- |
| `credentials.md` | Left contexts kept 365 days; chat-only export; no transfer of hand or shield; daily backup writes | The write-before-first-vote rule (RS1) |
| `ballot.md` | B7 identical retry at any time; B12 includes the one-card rule and the shield charge | — |
| `chat.md` | §2.3 names the chat-only export and single-device voting | — |
| `simulator.md` | Scenario names for the dropping Leader, two decks, restore and renewal are listed as wave-1 work | `vp_` is still described as a per-context pseudonym, and the churn scenario still has a device switch that resubmits |
| `docs/ux` | — | `P-Budget` "recharges Jan 1" wording, pending the owner |
