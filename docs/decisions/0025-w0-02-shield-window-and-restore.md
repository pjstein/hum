# 0025 · Shield: sliding 365-day window, charged at the plan's total, never refunded after a send, never backed up

**Status:** proposed, revised after review (W0-02, 2026-10-06). The owner confirmed on 2026-10-07 that the "I did not vote" control is off in draft 0.1 · `seam:` shield accounting, DP budget accounting · **one item needs the owner's decision**

*2026-10-07:* Confirmed off in draft 0.1; the alternative stays open for a later decision. The window anchor in this ADR was later tightened by ADR 0102 item 1. Previous status: proposed, revised after review (W0-02, 2026-10-06).

## Context

The `P-Budget` board shows a shield that "recharges Jan 1", ε used as the composed ε of the person's releases, and a pending charge for a deck not yet released. The design doc says the yearly shield is tracked only on the phone. The review found that the first draft let a server make a phone refund a counted charge, and that its restore estimate was not an upper bound and could be cleared by the person.

## Decision

1. **Unit and constant.** Tracked in ρ; `SHIELD_RHO` = 2201/500 (4.402), the largest three-decimal rational with `rho_to_eps(ρ, 10⁻⁶) ≤ 20`. Displayed as `rho_to_eps(Σρ)` rounded to one decimal, which reproduces the board's ε 6.2 and +1.4; the headline fraction excludes pending (the board's 69%), fit checks include it.
2. **Window.** Sliding 365 days from each entry's `chargedAt`; a future `chargedAt` counts. A calendar year allows about ε 31 over two days at the boundary.
3. **Reserve, then charge.** A `reserved` entry of `plan.rho` is persisted before the first card is shown (so two decks that each fit alone are not both played), becomes `pending` before the first round-0 bytes leave, and `charged` on an accepted receipt. Rounds, replacements and the person's own behavior change nothing.
4. **No refund after a send.** Once any ballot bytes were handed to the network the entry is permanent, whatever the server answers or fails to answer. Only a `reserved` entry with no send can be dropped. An honest rejection costs budget; `ballot.md`'s identical-retry rule, honored after `closes`, keeps a lost response from costing a vote.
5. **Not backed up; restored as an upper bound.** After a restore the phone adds an `estimated` entry for every deck of every backed-up context (including contexts left within 365 days) whose latest `closes` is within 365 days or in the future, whatever its release state, with `chargedAt = closes`. Voting in an estimated open deck reuses the entry. No control lets the person remove an estimated entry in draft 0.1.
6. **One card per entry.** A phone never sends a round-0 ballot for a deck whose entry was charged under a different card.

## Why

- ρ composes additively; ε does not. Enforcing in ρ is exact with rationals.
- Charging the maximum before sending is the only quantity the phone knows at send time, and the only one that is not itself a record of behavior.
- Nothing trusts a server (invariant 6): a Leader that drops responses or rejects and counts must not be able to keep a shield from filling.
- A sliding window is stricter than the board's rule, and floors may only tighten.
- Invariant 1 forbids a shield in any backup. An upper-bound estimate keeps the guarantee and loses only precision.

## For the owner

- **"I did not vote in this deck."** A control that clears an estimated entry on the person's word would let an unmodified app reset its shield by wipe, restore and untick, and an organizer could ask members to do it. It is not in draft 0.1. The cost of leaving it out: a person in a busy context may be shown as fully spent for up to a year after a restore. The owner decides whether that cost or the reset risk is worse; direct transfer (ADR 0023) is the other way out.

## Consequences

- The `P-Budget` board's "recharges Jan 1" becomes "each release stops counting a year after you voted".
- `SHIELD_RHO` moves with the owner's privacy-target decision; everything else stays.
- `simulator.md` gains the dropping-Leader, two-decks, restore and renewal scenarios.
