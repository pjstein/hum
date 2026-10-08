# 0102 · Shield window anchor, and the δ of receipt padding

**Status:** item 1 accepted by the owner 2026-10-07, as applied; the seam diff still gets the owner's read before merge. Items 2 and 3 (the receipt clamp's δ) stay open · `seam:` shield accounting, DP budget accounting, floor checks · invariant 3

*2026-10-07:* The owner accepted item 1. No recommendation was accepted for items 2 and 3. Previous status: item 1 Applied 2026-10-06 on the owner's go-ahead; seam, pending owner review of the diff (W0-10). Items 2 and 3 (the receipt clamp's δ) are not applied and stay open: item 2 changes the reported ε of every release, so it is not a pure tightening.

## Context

Two places where the yearly shield or the δ floor can be exceeded by an unmodified phone or a conforming aggregator.

**The window is anchored at the reservation.** `shield.md` counts an entry while its `chargedAt` is within the last 365 days, and `chargedAt` is when the deck was opened on the phone. `deck.md` D2 allows `closes − opens` up to one year, and the release follows the close by up to 30 days plus the rounds. A person who opens seventeen year-long decks on day 0 has every entry drop out on day 365. The seventeen releases are logged from day 366. The phone then has a full shield and can spend it again on short decks released the same month. About ρ 8.6 is published about one person within weeks, which is roughly ε 30. `shield.md` rejects a calendar-year window for exactly this number.

**The receipt clamp adds δ outside the plan.** `release.md` pads each round's receipt tree with `6·⌈σ_8⌉ + Z_r` dummy leaves, clamped at zero. The clamp adds at most 10⁻⁹ per round to δ, at most 4·10⁻⁹ per release, and the specs ignore it. A plan may set `delta` to `DELTA_MAX` exactly, and every example does. The release is then (ε, 10⁻⁶ + 4·10⁻⁹)-DP, which is above the protocol floor of 10⁻⁶. Over seventeen releases the yearly statement carries 6.8·10⁻⁸ more δ than stated.

## Decision (proposed)

1. **An entry leaves the window 365 days after its release, not after its reservation.** An entry counts from the moment it is reserved until 365 days after the later of: `chargedAt`; the time the phone saw the deck's final release version logged; or, if no final version exists, the deck's `expires`. Restore already uses `closes` as the anchor; it changes to the same rule. The ledger gains two fields (`settledAt`, and the deck's latest `expires`). This only makes the floor stricter. As applied in `shield.md`, `settledAt` is capped at the deck's `expires`, so a restore can use `expires` as an upper bound without knowing when the lost phone saw the release. After the applied-decisions review (AB1, AS1 to AS3): `release.md` R13 forbids any release version issued or logged after the deck's `expires`, `deck.md` D13 bounds `expires` at `closes` + 30 days + (R+1) × `roundWindow` and D12 lets it rise only with `closes`, and `settledAt` is the later of the phone's clock and the final version's `issued`. With those the cap and the restore bound are sound.
2. **The clamp's δ is counted inside the plan's δ.** The reported ε of a release is computed at `δ_eff = plan.delta − (R+1)·10⁻⁹`, and D10 requires `δ_eff > 0`. The release is then (ε, `plan.delta`)-DP as the body says. ε at `RHO_MAX` moves from 4.00054 to about 4.0011. The shield converts its yearly total at `10⁻⁶ − 17·4·10⁻⁹` the same way, or the owner accepts the stated residual in `CLAUDE.md`'s wording of the floor.
3. The 10⁻⁹ tail bound for a discrete Gaussian at six ceilings of σ is a claim for the outside review. The provable sub-Gaussian bound is e⁻¹⁸, about 1.5·10⁻⁸.

## Alternatives

- Cap deck length at 30 days so the reservation anchor is close enough. This removes long decks and still leaves a month of slack.
- Leave δ as it is and reword the floor as "δ at most 10⁻⁶ plus the receipt padding term".

## Consequences

- `shield.md` "Window", "The ledger", S8 and the `shield-window` vector change. `shield.md` S9 (restore) changes its anchor.
- `release.md` "Receipts" and R4, `context.md` "Protocol constants" (the ε at `RHO_MAX`), and the accounting vectors change if item 2 is taken.
- The `P-Budget` board shows an entry as spent for longer when a deck is long.
