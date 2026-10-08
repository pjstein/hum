# 0100 · Issuer and branch cells: what a presentation shows beside a vote and beside a chat name

**Status:** accepted by the owner 2026-10-07, as applied (option 1, whole context, `context.md` C16); the seam diff still gets the owner's read before merge · `seam:` credential presentation, pseudonyms and nullifiers, what leaves the phone · invariants 1 and 2

*2026-10-07:* The owner accepted this with the lost expressiveness listed in `cross-spec.md` section 12.7. Previous status: Applied 2026-10-06 on the owner's go-ahead; seam, pending owner review of the diff (W0-10). Option 1 was applied to the whole context, `entry` as well as `vote`, as `context.md` rule C16.

## Context

Every presentation in `credentials.md` carries, in the clear, the verifier authority of each card (`issuer`), the `kid`, the message count, the epoch, the `branches` taken at each `any` node, and the number of cards. `credentials.md` shows that `kid`, the count and the epoch are equal for every valid card of one issuer. What still differs between two members of one context is the tuple (issuer of each card, branches, number of cards). This ADR calls one value of that tuple a cell.

The same cell appears in four places for one person:

| Where | Beside what | Who reads it |
| --- | --- | --- |
| Every ballot (`ballot.md`, "What the aggregator learns") | The votes in phase 1, a share in phase 2 | The Leader, until the final version plus 24 hours |
| A signed issue-map object's bundle (`issue-map.md`, "Authority and authorship") | The chat identity key | Anyone, permanently |
| A join ticket (`chat.md` §2.5) | The chat identity key and name | Greeters in the organizers group |
| Token issuance (`storage.md` §6.2, `chat.md` §12.3) | A per-day nullifier | The store's and the delivery service's token issuers |

A context has one cell when its effective voting policy has no `any` node and every leaf's source resolves to exactly one verifier authority. It has more when a trust-list source accepts several verifiers for one attribute (`context.md`, "Entry policy": "any verifier authority the list accepts for `name` counts"), or when a policy has an `any` node. The example in `context.md` has two cells: members on the approved list (branch 0, three cards) and everyone else (branch 1, two cards).

When a cell holds one voter, the party that sees that voter's ballot and their signed object can attribute the hand. In phase 1 the operator is that party by itself: it runs the Leader and can read the public log. An organizer who keeps join tickets and colludes with the Leader is another. `docs/threat-model.md` says the aggregator must never learn who a pseudonym belongs to, and says the issuer name is not presented "where the policy allows any issuer on a list". `credentials.md` always presents it. The threat model says it wins on who may see what.

`credentials.md` records the leak and the author screen warns about it. No spec bounds the cell size, and a phone cannot know it.

## Options

1. **One cell per context in draft 0.1 (recommended).** Add a rule to `context.md`: the effective voting policy `[1, [entry, vote]]` has no `any` node, and each `attr` leaf's source yields rows for exactly one verifier authority at the pinned versions. Phones, aggregators and the ledger check it at step 10. No bytes change. Cost: "approved list or residents" needs two contexts or a verifier that issues the disjunction as one bool, and a trust list with two verifiers for one attribute cannot back a leaf.
2. **One cell on ballots only.** Ballots prove `vote` alone when `vote` is present, and the rule of option 1 applies to `vote` only. `entry` keeps `any` and multi-verifier sources. Cells then show beside chat names (signed objects, join tickets) and not beside votes. Cost: the ballot no longer proves `entry`, so "vote can only narrow membership" becomes the organizer's job, and unsigned authorship is still linkable to a chat name through a small cell.
3. **Hide the issuer and the branch.** A proof that the signature verifies under one of a public set of issuer keys, and a proof over the whole policy formula. Neither is in the CFRG drafts. This belongs with the hidden-predicate question in ADR 0022 and the outside review.
4. **Accept and disclose.** Keep the specs as they are, correct the threat model, and have the app warn before voting in a context with more than one cell.

## Recommendation

Option 1 for draft 0.1, option 3 as a question for the outside cryptography review. Whatever is chosen, `docs/threat-model.md` (the malicious-verifier residual, the "organizer and aggregator" collusion row, and the aggregator row) and `ballot.md` ("Who holds a nullifier") must say the same thing as `credentials.md`.

## Consequences

- **As applied:** `context.md` C16 and its example; `credentials.md` (P6, the identifier table, vectors); `ballot.md`; `issue-map.md`; `chat.md` §2.5; `trust-list.md` step 7; `docs/threat-model.md`. With no `any` node and one verifier per leaf, the number of cards is also fixed: it is the number of distinct authorities the policy names. After the applied-decisions review: an authority has exactly one `verifier` lineage (`verifier.md` rule 31), and a breakdown source must also resolve to one verifier (`deck.md` D9). What remains is the one-hour grace below, and that two context versions with different policies show different fields.

- With option 1, `credentials.md`'s claim becomes true at the level of a context: a presentation's public fields identify the context's one cell and nothing finer.
- The one-hour grace at an epoch boundary still yields two epoch values for token, join and authorship presentations. Ballots are not affected, because the ballot epoch is fixed by the deck's version-1 `closes`.
- `trust-list.md` and `verifier.md` keep multi-verifier lists; they simply cannot back a policy leaf in draft 0.1.
