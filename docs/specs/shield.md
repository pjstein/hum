# Hum Shield Spec — Draft 0.1

Oct 6, 2026 · W0-02 · revised after review · `seam:` shield accounting, DP budget accounting, what leaves the phone

## Scope

The shield is a person's yearly privacy budget. Only their phone can total it, because their pseudonyms are per deck and nothing links them. This spec defines the budget, how the phone reserves and charges it before a ballot leaves, how charges compose across releases and contexts under zCDP, what happens when it runs out, how re-votes and IBIS parts are charged, and what happens on phone loss.

The plan a deck charges is [`deck.md`](deck.md)'s. The release that spends it is [`release.md`](release.md). The ballot that follows a charge is [`ballot.md`](ballot.md). Backup and the one-voting-device rule are [`credentials.md`](credentials.md), "Storage and backup". The DP accounting matches `docs/research/dp-polis/polis_dp.py` (`eps_to_rho`, `rho_to_eps`).

## The budget

| Constant | Value | Meaning |
| --- | --- | --- |
| `SHIELD_YEAR` | ε 20 at δ 10⁻⁶ | The protocol floor from `context.md`; a placeholder until the owner sets privacy targets |
| `SHIELD_RHO` | 2201/500 (4.402) | `SHIELD_YEAR` in ρ: the largest rational with three decimals such that `rho_to_eps(ρ, 10⁻⁶) ≤ 20` |
| `SHIELD_WINDOW` | 31,536,000 s (365 days) | The window the budget covers |

The shield is tracked in ρ, because releases compose additively in ρ-zCDP and not in ε: the sum of entries in the window must stay at or below `SHIELD_RHO`. It is displayed in ε, because that is what people have been shown: displayed spend is `rho_to_eps(Σρ, 10⁻⁶) = Σρ + 2√(Σρ · ln 10⁶)` in binary64, rounded half to even to one decimal. Three releases at ε 4, 2 and 4 are ρ 0.254 + 0.068 + 0.254 = 0.576, displayed as ε 6.2 (the `P-Budget` board); adding a pending ε 4 deck gives ρ 0.830, ε 7.6, shown as "+1.4 pending".

The board's headline fraction excludes pending entries (`1 − rho_to_eps(Σρ over settled entries) / 20`, the board's 69%) and shows pending as a striped segment; the fraction including pending (62% on the board) is what fit checks use. Enforcement never uses a displayed value.

**Window.** The window is sliding and is anchored to when a deck's release is published, not to when the deck was opened (ADR 0102). An entry counts from the moment it is reserved until 365 days after its **anchor**, then drops off. The anchor is the latest of:

- `chargedAt`;
- `settledAt`: the later of the phone's clock when it verified the deck's final release version in the log and that version's `issued`, then capped at the deck's `expires`. Taking `issued` into the maximum means a phone whose clock was set back at that moment does not record an early `settledAt`. The cap is sound because no release version can be issued or logged after `expires` (`release.md` R13, enforced by the Helper's clock, the ledger's clock and every phone), so a final version first seen after `expires` was published by `expires`;
- when no final version has been seen, the `expires` of the latest deck version the phone has verified. `expires` moves later when `closes` is extended, and the anchor moves with it. Before an unsettled entry is allowed to leave the window, the phone looks up the deck lineage's latest version in the log, through the relay. If `expires` moved, it updates the entry and keeps it. If the lookup fails, it keeps the entry and tries again later. A deck can be extended only while it is open (`deck.md` D16), so one successful lookup after the last version's `closes` is final.

So an entry whose deck is still open or in rounds always counts, and an entry is in the sum for the 365 days after the release that spent it could first be seen. A clock set back never frees budget: the test is `now < anchor + 365 days`, and `settledAt` is never earlier than the final version's `issued`. An earlier draft anchored at `chargedAt` alone: a person could then open seventeen year-long decks on one day, see every entry drop off on day 365 just as the releases were logged, and spend a full shield again that month, which is about ε 30 published within weeks through an unmodified app. The `P-Budget` board says "recharges Jan 1"; a calendar year would let a person spend `SHIELD_RHO` on December 31 and again on January 1, which is about ε 31 over two days. Floors can only get stricter, so this spec takes the sliding window and asks for the board's wording to change ([`0025-w0-02-shield-window-and-restore.md`](../decisions/0025-w0-02-shield-window-and-restore.md)). The context's `rhoYear` (`context.md`) is also a 365-day window, over the context's releases rather than one person's.

**Per person, not per device.** The budget is the person's. Cards and the shield live on one voting device at a time (`credentials.md`, "One voting device").

## The ledger

The phone keeps a ledger of entries, one per deck it has opened to play:

| Field | Meaning |
| --- | --- |
| `deck` | The deck lineage CID |
| `context` | The context lineage CID |
| `rho` | The plan's `rho` as a rational, from the deck version the phone verified |
| `chargedAt` | When the entry was created |
| `settledAt` | max(the phone's clock when it verified the deck's final release version in the log, that version's `issued`), capped at the deck's `expires`. Absent until then, and always absent on an `estimated` entry |
| `expires` | The envelope `expires` of the latest deck version the phone has verified; updated when a later version extends it |
| `cards` | The `issuer ‖ kid ‖ epoch` of every card the deck's presentation uses, pinned when the entry is reserved and reused for every ballot of the deck (`credentials.md`, "What is proven"). A pinned card is kept on the phone until the entry is `released` or `dropped`, even after its epoch ends, so later rounds and extensions still have it |
| `state` | `reserved` (deck opened, nothing sent) · `pending` (a ballot was handed to the network, no accepted receipt yet) · `charged` (an accepted receipt exists) · `released` (a final release version was logged) · `estimated` (added by a restore) · `dropped` (reserved, nothing ever sent, deck left or closed) |
| `receipts` | What `ballot.md` keeps per round, for `charged` and `released` entries |

Spent ρ in the window: `Σ rho` over entries with `now < anchor + 365 days` (anchor as under "Window": the latest of `chargedAt`, `settledAt`, and `expires` when `settledAt` is absent) and whose `state` is one of `reserved`, `pending`, `charged`, `released`, `estimated`. Remaining: `SHIELD_RHO − spent`, never below zero. Arithmetic is exact over arbitrary-precision rationals; no floating point until display.

The ledger never leaves the phone: not to backup, chat, storage, logs, analytics, agents or any other device (`CLAUDE.md` invariant 1). Draft 0.1 has no device-to-device transfer of it; that alternative is filed for the owner in ADR 0023.

## Reserving and charging

`seam:` what leaves the phone.

1. **Verify.** Before showing the first card, the phone checks that the deck, its context and both aggregators' registrations passed every step (`ballot.md` B12). A deck whose plan breaks a protocol or context floor is refused before the shield is consulted; those floors are `deck.md` D8, D10, D11.
2. **Fit and reserve.** If `plan.rho ≤ remaining`, the phone appends a `reserved` entry with `rho = plan.rho` and `chargedAt = now` and persists it before the first card is shown. If not, the deck is sat out (below) and the notice appears before the first card. Reserving at open means two decks that each fit alone cannot both be played and then both be found not to fit when the first one sends. When remaining is below a threshold the person set (default: below 20% displayed), the phone asks before reserving instead of reserving on its own; sitting out is the person's choice, not the phone's.
3. **Send.** When the phone is about to hand the first round-0 ballot's bytes to the network (`ballot.md`, send schedule), the entry becomes `pending` and is persisted before the bytes leave. When a receipt is accepted it becomes `charged`. While the phone holds a ballot because a pinned card has not started yet (the deck's original close falls in that issuer's next epoch), the entry stays `reserved`; it is dropped at `closes` if nothing was ever sent. A phone also does not send the first round-0 ballot in a context until a backup listing that context has been written locally (`credentials.md`, "When it is written"), so a restore can never miss a context the person voted in; the platform's own upload delay is a residual the spec cannot close.
4. **Drop.** A `reserved` entry becomes `dropped`, and stops counting, only if no ballot bytes were ever handed to the network and the person left the deck without casting a card or the deck closed. Nothing a server says or fails to say can cause a drop, because a `reserved` entry has had no contact with any server.

**No refund after sending.** Once any round-0 ballot bytes for a deck have been handed to the network, the entry is never removed or reduced, whatever the response: a lost response, a `rejected`, a `closed` after a retry, an abandoned deck, a release below the floor. The ballot may be in a sum, and nothing in phase 1 lets the phone prove it is not; a Leader that drops responses or rejects and counts anyway must not be able to keep a shield from filling. An honest rejection therefore costs budget. That is acceptable because B12 has the phone check everything locally first, and because `ballot.md` keeps the identical-retry path open so a lost response is recovered rather than refunded.

**What is charged** is the plan's total, `plan.rho`, including every part the plan lists: tallies, the map tier whether or not it unlocks, the daily count, movement, ratings and receipt padding. Not the parts the person's behavior touches, and not what the release later reports as spent. Three reasons:

- The guarantee is user-level over the whole release. Whether a tier unlocks depends on everyone's participation, which the phone cannot know when it votes, and the aggregator draws noise for parts 0, 4 and 8 even below the floor (`release.md` R6).
- A plan that declares ρ is a promise that no release under it costs more; charging the maximum means an unused tier never costs more than declared, and never less than the person was told.
- A charge that depended on behavior (did you re-vote, did you consent) would make the ledger a record of behavior.

So a person who re-votes nothing in an IBIS deck is charged what a person who re-votes everything is charged. Re-votes and IBIS parts "cost more" in the plan, where the organizer gives them ρ out of a fixed total (`deck.md`, "Why movement costs more"); they cost nothing extra per person. Rating decks are decks and charge their `plan.rho` (at most 1/20, `take.md`).

**Rounds and replacements cost nothing.** Rounds 1 to 3 and round-0 replacements are the same release under the same plan (`release.md`, "Budget"); the entry already exists and nothing is added. A phone that drops out of later rounds is not refunded: its round-0 contribution is in the sums.

**One card set per entry.** A phone never sends a ballot, replacement or later round included, for a deck with cards other than the entry's pinned `cards` (`ballot.md` B12). A different card has a different nullifier; a second nullifier in one deck would count the person twice and double their sensitivity in that release, which the ledger could not represent. The ballot window makes such a ballot fail at the aggregator anyway (one card per issuer per epoch, and the epoch is fixed by the deck's original close); this rule keeps an honest phone from trying.

**Pending shows as spent.** `reserved` and `pending` entries count against remaining. The board shows them as pending until the final release version is logged, when the entry becomes `released` and shows the ε the release reports, which can be less than the plan's only in display, never in the ledger.

## Composition

Every release is `plan.rho`-zCDP for one person's whole participation in it (`release.md`, "Noise"). Releases of different decks are independent mechanisms over that person's data, so by the composition theorem for zCDP the person's participation in a set of releases is `(Σ plan.rho)`-zCDP, and `(ε, δ)`-DP for `ε = Σρ + 2√(Σρ · ln(1/δ))` at any δ. The shield enforces `Σρ ≤ SHIELD_RHO` over the window. Because an entry stays in the sum until 365 days after its release could first be seen, the releases a person took part in that are published in any 365-day span sum to at most `SHIELD_RHO`, which gives ε 20 at δ 10⁻⁶ for that span. This rests on one rule outside this spec: every release version of a deck is issued and logged by the deck's `expires` (`release.md` R13), and `expires` is at most `closes` + 30 days + (R+1) × `roundWindow` (`deck.md` D13). With both, the anchor is never earlier than the last publication about the deck, the cap on `settledAt` loses nothing, and the restore estimate below is an upper bound. Anchoring at the reservation did not give this for decks that stay open for months.

This holds across contexts because the phone adds every context's entries into one ledger; no server could, since pseudonyms do not match across decks. It does not depend on contexts being honest with each other, on `rhoYear`, or on the aggregators: a context with loose floors spends a person's shield faster, and the phone sits out sooner. Adaptively chosen decks, and rating decks that reuse a source release's groups, are covered because every part bounds one person's whole contribution.

Four releases at ε 4 are ρ 1.016, ε 8.5 (the design doc's figure). `SHIELD_RHO` holds 17 releases at `RHO_MAX`, or 88 rating decks at ρ 1/20 and no full releases.

## When the shield runs out

A deck whose `plan.rho` exceeds remaining is sat out. The phone:

- still shows the deck and lets the person sort it, with the state "not counting" shown before the first card, never after a swipe;
- creates no ledger entry and sends nothing for any round of that deck;
- shows the results deck when the release lands, matched against the local hand as always;
- says why, with the date the oldest entry in the window drops off and what will then fit.

Nothing is sent about sitting out: no empty ballot, no notification. In the daily count and the receipt tree the person is indistinguishable from someone who never opened the deck. A deck the person is already in is unaffected by the shield running out later; its entry stands and its later rounds still send.

Because entries are charged at the plan's maximum and never reduced after a send, a phone can never find itself over budget by any server's doing. The only way over is a ledger that is missing entries, which is the restore case.

## Restore

The shield is never backed up (`credentials.md`). After a restore from the sealed backup the phone rebuilds the ledger as an upper bound on what the lost one held:

1. For every context in the backup, including contexts the person has left (the backup keeps a left context until 365 days after the latest `expires` of its decks dealt before they left), fetch through the relay every deck of that context whose latest `expires` is within the last 365 days or in the future, whatever its release state: released, in rounds, closed with no version yet, abandoned, or open.
2. For each such deck append an `estimated` entry with `rho = plan.rho`, `chargedAt = closes` and `expires` of the latest deck version, and no `settledAt`. Its anchor is therefore `expires`, which is no earlier than any anchor the lost ledger could have held for it: a real `settledAt` is capped at `expires`, and a real `chargedAt` precedes it.
3. Spent is then at least what the lost ledger held: the person could only have voted in decks of contexts they were in, every such context is in the backup, every such deck is enumerated, and no estimated entry drops out of the window before the real one would have.

An `estimated` entry is treated as spent and cannot be removed by the person in draft 0.1. If the person then votes in an open deck that has an `estimated` entry, that entry is reused: it moves to `pending` with the same `rho`, so the deck is not charged twice. The board labels the total "estimated after restore". A control that lets a person clear an entry by stating they did not vote would let an unmodified app reset the shield by wipe, restore and untick; it is filed as an owner decision in ADR 0025, not specified.

The cost is stated plainly: after a restore a person in a busy context may be shown as fully spent until 365 days after the latest `expires` among the estimated decks. For a deck that had already ended that is under a year. For a deck still open at the restore it can be longer: a deck may stay open a year (`deck.md` D2) and its `expires` may be up to 150 days after `closes` (D13), so the bound is about two years and five months after that deck opened. It is bounded, because `expires` is. A person who loses both the phone and the phrase starts with an empty ledger once dedup lets them get a card, and the lost phone's votes inside the window are not counted; accepted.

A person who restores onto a second phone while still voting from the first has two ledgers, each missing the other's entries: the two phones together can spend up to twice one shield across different decks. The duplicate-nullifier rule means they still count once per deck. The app says so during restore. It is a floor an unmodified app can exceed and needs the owner's explicit acceptance ([`0023-w0-02-backup-and-voting-device.md`](../decisions/0023-w0-02-backup-and-voting-device.md)); the chat-only export in `credentials.md` removes the accidental route to it.

## What the person sees

Everything on the `P-Budget` board comes from the ledger alone: the remaining fraction, ε used, pending, the list of decks with each one's state and displayed ε, the "shield at zero" explanation, and the threshold switch. The board states that the ledger exists only on this phone. No part of it is derived from anything a server knows about the person, because no server knows anything about the person.

## Conformance

The shield is enforced on the phone, so the aggregator cannot test it. The conformance suite tests the arithmetic with vectors and the behavior with the simulator's instrumented phone and leak checker.

| Rule | Check |
| --- | --- |
| S1 | `SHIELD_RHO` = 2201/500 and `rho_to_eps(2201/500, 10⁻⁶) ≤ 20 < rho_to_eps(4403/1000, 10⁻⁶)` |
| S2 | Spent and remaining are computed in exact arbitrary-precision rationals over entries in the window (`now < anchor + 365 days`); display is binary64 `rho_to_eps`, rounded half to even to one decimal |
| S3 | A phone reserves before showing the first card, moves the entry to `pending` and persists it before the first round-0 bytes leave, and never sends a round-0 ballot for a deck with no entry (simulator) |
| S4 | A phone never reserves when `plan.rho > remaining`; it reserves when `plan.rho = remaining`; two decks that each fit alone but not together are not both reserved (simulator) |
| S5 | Rounds 1 to 3 and replacements add no entry and change no `rho` (simulator) |
| S6 | An entry whose ballot bytes were handed to the network is never removed or reduced: after a lost response, a `rejected`, a `closed` on retry, an abandoned deck, a below-floor release (simulator, with a Leader that drops responses and one that rejects and counts) |
| S7 | A `reserved` entry is dropped exactly when no bytes were sent and the person left without casting or the deck closed; never otherwise (simulator) |
| S8 | An entry drops out of the sum exactly 365 days after its anchor, where the anchor is the latest of `chargedAt`, `settledAt` (max of the phone's clock and the final version's `issued`, capped at `expires`) when a final release version was seen, and the latest verified `expires` when none was; never 365 days after `chargedAt` while the deck is unreleased; an extension of `closes` that raises `expires` moves the anchor of an unsettled entry; an unsettled entry is dropped only after a successful lookup of the deck lineage's latest version, and is kept when the lookup fails; a clock set back, before or after settling, frees nothing (vector, and simulator for the long-deck case) |
| S9 | Restore produces `estimated` entries for every deck of every backed-up context, including left contexts and closed-unreleased, abandoned and extended decks, with `chargedAt = closes`, no `settledAt` and the latest `expires` as anchor, and nothing else; the estimate is at least the lost ledger (simulator); voting in an estimated deck reuses the entry (vector) |
| S10 | No message a phone sends to any service, and no file it writes outside its own storage, contains a ledger entry or any value derived from one (simulator's leak checker, with ledger entries registered as a kind allowed nowhere) |
| S11 | A phone never sends any ballot for a deck with cards other than the entry's pinned `cards` (simulator, across an epoch boundary) |
| S12 | A phone never sends a first round-0 ballot in a context before a local backup lists that context (simulator) |

## Vectors (for W0-08)

Directory `vectors/shield/`:

- `shield-eps-rho`: `eps_to_rho` and `rho_to_eps` at δ 10⁻⁶ for ε in {1, 2, 4, 8, 16, 20} as binary64, and the S1 inequality at 2201/500 and 4403/1000.
- `shield-compose-board`: the `P-Budget` ledger (ρ 127/500, 169/2500, 127/500 settled; 127/500 pending) with spent and remaining including pending, displayed ε 6.2, pending +1.4, the headline 69% (settled only) and 62% (including pending).
- `shield-compose-four-at-four`: four entries at 127/500, displayed ε 8.5.
- `shield-fit`: remaining 1/4 against plans of 127/500 (does not fit), 1/4 (fits), 1/20 (fits); two plans of 1/5 each against remaining 1/4 (first fits, second does not after the reservation).
- `shield-window`: entries whose anchors are at days 0, 100, 364, 365, 366 before now and 3 days ahead; which are in the sum. Cases for the anchor itself: reserved 400 days ago, deck still open (in); reserved 400 days ago, final version seen 30 days ago (in); final version seen 366 days ago (out); no final version, `expires` 366 days ago (out); no final version, `expires` extended to 10 days ago by a later deck version (in); final version first seen after `expires` (anchor is `expires`); an unsettled entry voted under deck version 1, 365 days past version 1's `expires`, where the log holds a version 2 with a later `expires` (kept), and the same with the log unreachable (kept); final version verified while the phone's clock reads 200 days before that version's `issued` (`settledAt` is `issued`).
- `shield-long-decks`: seventeen entries at 127/500 reserved on day 0 for decks that close on day 360 and release on day 366; on day 365 and on day 400 remaining is 2201/500 − 17 × 127/500 and an eighteenth deck does not fit (the case ADR 0102 closes).
- `shield-states`: event sequences and the ledger after each: open, leave without casting (dropped); open, cast, send, lost response, retry gets the original receipt (charged); open, send, `rejected` (pending forever, counts); open, send, accepted, final (released); open, send, accepted, abandoned (charged, counts); restore, estimated, then vote (pending, same `rho`).
- `shield-restore`: a backup's context list with one left context, a set of decks (released, in rounds, closed-unreleased, abandoned, open, one with an extended `closes`) with plans and times, and the expected `estimated` entries.
- `shield-display`: `rho_to_eps` rounding cases, including one exactly at a half.

Simulator scenarios (`simulator.md`): `sim-shield-sit-out`, `sim-shield-restore` (the estimate is at least the lost ledger across the four cases), `sim-shield-never-leaves`, `sim-shield-dropping-leader` (responses dropped; the ledger still fills), `sim-shield-two-decks` (S4), `sim-ballot-epoch-boundary` (S11), `sim-shield-backup-before-vote` (S12), `sim-shield-long-decks` (S8: year-long decks do not free the shield before their releases age out; and a late Leader whose version 2 after `expires` is refused by the Helper, the ledger and the phone).

## Security considerations

- The shield protects a person from the sum of many honest releases, not from a dishonest aggregator; floors and the ledger handle the latter. Both are needed.
- Reserving at open and never refunding after a send means a phone's budget cannot be overdrawn by anything a server does, and a sat-out deck leaves no trace.
- The ledger is a list of decks a person played, in the clear, on their phone. It is as sensitive as the hand and protected the same way (`credentials.md`, "On the phone").
- Conservative restore errs toward sitting out, by design.
- The threshold prompt changes nothing about what is sent, only when the person is asked.
- A modified client can ignore its shield. That loosens the floor for that person alone; it cannot make a release cost anyone else more (`manifest.md`, "Privacy floors").
- The receipt-padding clamp adds at most 4·10⁻⁹ to δ per release (`release.md`), below 10⁻⁷ over 17 releases; it is ignored consistently with `release.md`, pending the outside review.

## Open questions

Filed in `docs/decisions/`:

- **Window anchor** ([`0102-w0-10-shield-window-and-padding-delta.md`](../decisions/0102-w0-10-shield-window-and-padding-delta.md)): applied; an entry leaves the window 365 days after its release could first be seen. After review, `deck.md` D13 bounds `expires` above and `release.md` R13 forbids any release version after it, which is what makes the anchor sound. One thing stays open there: counting the receipt clamp's δ inside the plan's δ.
- **Sliding window, no refund after send, conservative restore** ([`0025-w0-02-shield-window-and-restore.md`](../decisions/0025-w0-02-shield-window-and-restore.md)): the board's "recharges Jan 1" wording; the "I did not vote in this deck" control, filed as an owner decision and not in 0.1.
- **Two voting devices and direct transfer** ([`0023-w0-02-backup-and-voting-device.md`](../decisions/0023-w0-02-backup-and-voting-device.md)): both are exceptions a floor or invariant 1 would need the owner to accept; draft 0.1 has neither.
- **The target itself:** ε 20 is the design doc's placeholder; `SHIELD_RHO` follows from whatever the owner sets.
- **Display in ε:** the nonlinear bar is faithful to the board; a linear ρ bar would be simpler to explain. UX question.

Assumptions about sibling specs, checked on disk on 2026-10-06:

- `deck.md`: `plan.rho` is the total including every part; the shield charges it once. Met.
- `release.md`: no version spends more than the plan; rounds add nothing. Met.
- `take.md`: rating decks charge `plan.rho` like any deck. Met.
- `context.md`: `SHIELD_YEAR` ε 20 as a protocol constant; the shield is a per-person floor not in the manifest. Met.
- `ballot.md`: identical retries honored after `closes`; B12 includes the one-card rule. Met in this revision.
- `credentials.md`: the backup keeps a left context until 365 days after the latest `expires` of its decks dealt before the person left; no transfer of the ledger. Met in this revision.
- `simulator.md`: the leak checker's secrets registry and the churn scenario are the hooks; W0-09 has confirmed and lists the scenarios as wave-1 work. The simulator now models the per-deck nullifier and a restore in place of a device switch; issuer epochs, pinned card sets, S11 and S12 are listed there as wave-1 work.
