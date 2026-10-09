# 0104 · Issuer epochs where they meet decks, sessions and admission

**Status:** accepted by the owner 2026-10-08, applied; seam, the diff still gets the owner's read before merge · `seam:` credential issuance and presentation, nullifiers

*2026-10-08:* The owner said to apply every recommended item. All four are applied, with `KEY_TAIL` fixed at 520 days; see `cross-spec.md` section 12.9. `KEY_TAIL` governs ordinary retirement only: an emergency removal is always possible and its cost is stated in `verifier.md`.

## Context

The epoch model (ADR 0026) is consistent across `credentials.md`, `verifier.md`, `verifier-runtime.md`, `ballot.md`, `shield.md`, `deck.md` and `release.md` on: the 28-day period, `V`, the handover, which key signs which epoch, the dedup row, the ballot window anchored to the deck's version-1 `closes`, and keeping a pinned card until the deck is final. Four seams are left.

1. **A pinned card can outlive its issuer key.** `verifier.md` moves a key to `retiredKids` 30 days after its last epoch. `credentials.md` P3 rejects a `kid` that is not in `issuerKeys`. A card of epoch E must still verify for round-0 replacements and rounds 1 to 3 of any deck whose version-1 `closes` fell in E. `deck.md` D2 allows `closes` to be extended to one year after `opens`, and the rounds add up to 120 days. If the issuer changed keys at E + 1, every such ballot is rejected from day 31.
2. **Emergency key removal during an open deck.** Removing a key makes every card under it fail at the next presentation, and a dedup row whose `kid` is gone counts as no row, so everyone re-enrols in the same epoch with a new nym secret. People who had voted keep their round-0 ballot (`release.md` R12) and cannot replace it or answer rounds 1 to 3, because the phone is pinned to the dead card (`shield.md` S11). A modified client can vote again with the new card, since its nullifier is new for the deck. No spec says this.
3. **`services.md` V-2** says a session issues at most one credential and a second `issue` call answers `conflict`. A first session in handover issues two cards, and an identical retry returns the identical response.
4. **Entry-policy presentations have no primary nullifier.** `context.md` C6 designates a nullifier leaf in the effective voting policy only. A join, token or authorship presentation proves `entry` and yields one nullifier per card. `chat.md` §5.17 stores one `nullifier` per `join-record`, and `issue-map.md`'s `authorship` map has one `nullifier` field. `issue-map.md` IM-7 already checks every nullifier. `chat.md` keeps every `join-record` forever, while `credentials.md` says they are held while the identity is a member.

## Decision (proposed)

1. A key stays in `issuerKeys` until no deck can still present its cards: 30 days after the latest `expires` of any deck whose version-1 `closes` fell in one of its epochs is not knowable to a verifier, so use a fixed tail. A key moves to `retiredKids` no sooner than `KEY_TAIL` = 520 days after its last epoch ends (one year of extension, 120 days of rounds, 30 days of margin). Alternative: cap how far `closes` may move past version 1's (for example 56 days) and set the tail to match. The owner picks the trade.
2. State the outcome in `verifier.md` and `ballot.md`: an emergency key removal ends the later rounds for voters under that key in open decks, their round-0 ballots stand, and the organizer should retire and re-deal a deck that has not closed. Record that a modified client can double-count in that deck and that an honest phone cannot.
3. V-2 becomes: a session answers at most one issuance request; the response holds one card, or two in a first session during handover; an identical request gets the identical response; a different request answers `conflict`.
4. For uses that prove `entry`, the unit is the nullifier set. `join-record` key 1 becomes an array of every nullifier in the ticket's proof, and a ticket is refused when any of them is recorded for a live identity. The `authorship` map drops key 4, since the log derives every nullifier from the proof. A greeter deletes a `join-record` when its identity leaves the all-members group, and stamps each record with the day it was written so records older than 396 days can be dropped.

## Consequences

- After the confirming review (2026-10-08): a greeter sends the `join-record` before its Add commit, so a failure between the two leaves an inert record and never a member without one.

- Item 1 changes `verifier.md` "Issuer key", rule 24's prose, and the three-version district vector.
- Item 4 changes bytes in `chat.md` §5.17 and `issue-map.md` "The `authorship` bundle field" before any implementation exists.
- Items 2 and 3 are wording.
