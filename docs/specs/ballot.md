# Hum Ballot Spec — Draft 0.1

Oct 6, 2026 · W0-02 · revised after review · `seam:` ballot construction, contribution caps, what leaves the phone, domain-separation strings

## Scope

A ballot is the only thing a phone ever sends about how a person voted. This spec defines what a phone submits in each release round, how votes are bounded to the contribution cap and encoded so every release part is a sum of bounded per-person vectors, how re-votes are recorded and capped, the receipt a phone keeps, how the same values travel in phase 1 (central noise) and phase 2 (two-server aggregation), and what the aggregator learns in each.

The deck and its plan are [`deck.md`](deck.md). The rounds, what a phone computes between them, the noise and the receipt trees are [`release.md`](release.md). The presentation a ballot carries is [`credentials.md`](credentials.md). The intake API is [`services.md`](services.md), "Aggregator". The shield charge that precedes every first ballot is [`shield.md`](shield.md).

Phase 2 uses [draft-ietf-ppm-dap](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/) (-19, July 2026) with Prio3 from [draft-irtf-cfrg-vdaf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/) (-22, Aug 2026). Every ballot goes through an Oblivious HTTP relay ([RFC 9458](https://www.rfc-editor.org/rfc/rfc9458.html)).

Domain strings this spec owns: `hum/ballot/1` (scope prefix), `hum/ballot-bound/1` (bound-message prefix), `hum/receipt-leaf/1` (leaf hash prefix). `hum/dap-task/1` and `hum/receipt/1` are `services.md`'s.

## What leaves the phone

| Round | Sent | Never sent |
| --- | --- | --- |
| 0 (vote) | The counted hand (the first K cards cast, with their current votes), re-vote transitions for the first K_m re-voted cards, argument ratings for the K_r sampled arguments, a rating deck's group slot; on a replacement, the same with the current votes | Cards cast after the first K, the card order, which argument the phone sampled for cards it did not rate |
| 1 (axes) | The upper triangle of the unit vote vector's outer product over the M selected cards, from the full hand, fixed-point | The projection; but note that in phase 1 a rank-one matrix is the centered hand over `sel` up to sign, so the Leader sees every vote on a `sel` card, including cards after the first K |
| 2 (map) | One grid cell | The coordinates |
| 3 (groups) | The group index with the same counted hand and ratings as round 0 | — |
| All | The presentation: for each card the issuer, `kid`, `len` and `epoch`, an empty `branches`, and the pseudonyms. Under `context.md` C16 the issuers and the number of cards are the same on every ballot of a context | Who holds a pseudonym, any other deck's pseudonym |

Nothing else about votes leaves: not to chat, storage, logs, analytics, crash reports, agents or backups (`CLAUDE.md` invariant 1). A ballot never carries the chat identity, a device identifier, a card order, a phone-chosen timestamp, or anything from another deck. The simulator's leak checker compares every outbound message of an instrumented phone against this table.

## The ballot

A ballot is one deterministic CBOR map posted to `POST /v1/agg/decks/{cid}/rounds/{n}/ballots` on the Leader (phase 2: the Leader, which forwards the Helper's share as DAP defines).

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | `v` | uint | 1 |
| 1 | `deck` | bytes(33) | CID of the deck version the phone verified and voted under |
| 2 | `round` | uint 0..3 | The round |
| 3 | `nonce` | bytes(32) | The receipt nonce, from the phone's CSPRNG, fixed for this ballot and every retry of it |
| 4 | `payload` | map | The round's contribution (below); in phase 2 the map of DAP reports instead |
| 5 | `presentation` | bytes, ≤ 8,192 | The policy presentation (`credentials.md`), bound as below |

**Body.** Keys 0–4 are the ballot's body. The bound message is `hum/ballot-bound/1 ‖ SHA-256(canonical CBOR of the map with keys 0–4 only)`. The presentation's `ph` therefore commits to the deck version, the round, the nonce and the payload. A retry of a ballot is any ballot with the same body; it may carry a fresh presentation, since proofs are randomized, and it MUST reuse the stored `nonce`. Two ballots are "identical" when their bodies are byte-identical.

**Frame and size.** The request body is the frame `uint32be(len(ballot)) ‖ ballot ‖ zero bytes`, exactly `BALLOT_BYTES` = 49,152 bytes long, where `ballot` is the canonical CBOR map above. Padding sits outside the CBOR, so every length is reachable and no padding key exists. Every ballot of every round is framed this way, so the relay and the gateway cannot tell rounds, presentation sizes or deck sizes apart. The presentation is capped at 8 KiB in a ballot (`credentials.md` P1), and `cov` at M = 128 is 33,024 bytes, so every valid deck fits with room for the envelope. `services.md` O-3's relay buckets are 1, 4, 16, 64 and 256 KiB; a 48 KiB frame plus OHTTP and HTTP overhead lands in the 64 KiB bucket every time, which is the point of the padding (confirmed by W0-07).

**Scope.** `hum/ballot/1 ‖ deck lineage CID`, the deck's version-1 CID. Extending `closes` publishes a new deck version and leaves the scope unchanged.

**Policy.** The presentation proves the effective voting policy `[1, [entry, vote]]` of the context version the deck pins, with `context` set to that version. Every card in it discloses its `epoch`, which must be the epoch of `period(closes)` of the deck lineage's **version 1**, and must have started (`credentials.md`, "Validity"): the card that was valid at the deck's original close, and already issued. A `closes` extension does not move it, so an old card and its successor can never both act in one deck. In rounds 1 to 3 the card may have expired since the close; that is allowed. Its primary nullifier is the deck nullifier that keys replacement, later rounds and the daily count; every other nullifier in it is also checked (B3). The phone pins the cards it used in the deck's shield entry and reuses them (`shield.md`).

## Round 0: the vote

Let `C` be the card count, `K` the plan's `cap`, `K_m` `capMovement`, `K_r` `capRatings`, and `A` the number of argument refs in the deck, indexed 0..A−1 by sorting their ref names bytewise (`card/0/con`, `card/0/pro`, `card/1/con`, …).

### Casting and the hand

A card is **cast** when the person has swiped it and either the next card has been shown or the person has left the deck; until then the swipe can be undone and the card is not cast. A cast card's vote may change later (re-sorting, or a re-vote after the flip) but a cast card never returns to uncast. Votes are `1` agree, `2` disagree, `3` unsure. Rating decks map fair, misleading and can't say onto the same values (`take.md`).

The hand is, per card: the cast order, the current vote, whether the card was flipped before it was cast, the vote standing when the card was flipped (`first`), and, for a re-voted card, which shown argument the person marked as having moved them.

### The counted hand

The counted hand is the **first K cards cast, in cast order**. It is fixed as cards are cast, never shrinks, and never swaps: a card cast after the first K is never counted in parts 0, 3 or 7, however the person later re-sorts. With `order` = 0 the cast order is the phone's random deal, so the counted hand is a uniformly random K-subset of the cards the person would have voted on; with `order` = 1 it is the first K in deck order, which the organizer accepted. With `K ≥ C` nothing is dropped. This is `deck.md`'s rating-deck rule ("the first R cards in its own order") applied to every deck; `deck.md`'s vote-deck wording "a uniformly random K" is the same set under random order and is asked to say "first K cast".

Because the counted hand only grows and a replacement carries its current votes, a replacement never removes a card from the Leader's view and never shows which cards were dropped.

Rounds 1 and 2 use the full hand, because their bounds do not depend on `K` (`deck.md`, Parts).

### The movement selection

Re-voted cards are those the person cast, saw flip, and voted on again (the same way or differently). Cards flipped before being cast are not re-voted cards. The movement selection is the first `K_m` re-voted cards in the order they were re-voted, fixed as they happen, never shrinking. A card may be in the movement selection and not in the counted hand, or the reverse.

### The ratings selection

When the plan has part 6, the phone draws a uniform random `K_r` of the deck's `A` argument indexes when it first shows the deck, asks "does this move you?" only for those, and reports only those. If `A ≤ K_r` it asks for all.

### Payload

| Key | Name | Type | Present when | Meaning |
| --- | --- | --- | --- | --- |
| 0 | `votes` | bytes(C) | always | Byte `i` is the current vote on card `i` if card `i` is in the counted hand, else `0` |
| 1 | `movement` | map uint → `[first, second, moved]` | plan has part 5 | Card index → `first` (the vote standing when the card flipped, 1..3), `second` (the current vote, 1..3), `moved` (0 none, 1 the pro, 2 the con); only cards in the movement selection; a card with no `pro` ref cannot have `moved` = 1, likewise `con` |
| 2 | `ratings` | map uint → uint | plan has part 6 | Argument index → 0 moves me, 1 neutral, 2 against; a subset of the ratings selection (unanswered arguments omitted) |
| 3 | `group` | uint | rating deck | The group the phone computed for the source release (`release.md`, round 3); `< source.groupsK`. A phone with no hand for the source deck (after a restore) sits the rating deck out |

**Breakdown (part 7) in draft 0.1.** In phase 1 a breakdown value would sit beside the pseudonymous votes on the Leader until the final version plus 24 hours. `deck.md` and `services.md` leave that to the owner. Until the owner decides, the draft 0.1 rule is the one that discloses nothing: aggregators refuse to register a deck whose plan has part 7, and phones refuse to vote in one (B9). The phase-2 encoding is defined below so the move needs no change.

### Which vote counts

`votes` carries the current vote at the time of sending: if the card flipped and the person re-voted, the re-vote. `movement` carries one transition per card in the movement selection, diagonal included when the person re-voted the same way, plus at most one "moved me" per such card; `second` equals `votes[i]` whenever card `i` is also counted. A card never flipped, or flipped before being cast, contributes nothing to `movement`. This is `deck.md`'s "Which vote counts" as ballot rules (B5, B6).

### The vectors the payload stands for

The aggregator turns a payload into the per-person integer vectors `deck.md`'s Parts table sums. Every entry is 0 or 1, and the Hamming weight bounds give the L2 sensitivities.

| Part | Vector | Layout | Weight ≤ |
| --- | --- | --- | --- |
| 0 `tallies` | `3C + 1` | For card `i`, entries `3i, 3i+1, 3i+2` are agree, disagree, unsure; entry `3C` is the participant coordinate, always 1 | `K + 1` |
| 5 `movement` | `9C + A` | For card `i`, entry `9i + 3(first−1) + (second−1)`; entry `9C + a` for "moved me" on argument `a` | `2 K_m` |
| 6 `ratings` | `3A` | Entries `3a, 3a+1, 3a+2` | `K_r` |
| 7 `breakdown` | `|values| × (3C + 1)` | The tallies vector placed in the cell of the person's value; not accepted in draft 0.1 | `K + 1` |
| 3 `groups`, rating deck, round 0 | `groupsK × (3C + 1)` | The tallies vector placed in slot `group` | `K + 1` |
| 3 `groups`, vote deck, round 3 | `groupsK × (3C + 1 + 3A)` | Slot `g` starts at `g × (3C + 1 + 3A)`: the tallies vector, then the ratings vector; `3A` is 0 without part 6 | `K + K_r + 1` |
| 4 `count` | one-hot over day buckets | Phase 1: set by the aggregator from arrival time, first ballot per nullifier only. Phase 2: a client measurement, see below | 1 |
| 8 `receipts` | `R + 1` | Entry `round` = 1, set by the aggregator | 1 per round |

## Replacement in round 0

A person may re-sort cards until `closes` (`Swipe-End`). A round-0 ballot whose primary nullifier the Leader already holds:

- **identical** (same body): is the same ballot. The Leader returns the original receipt, whatever the time, until it deletes the deck's nullifier set (`services.md` AG-5). A phone whose response was lost at 23:59 and retries at 00:01 is not told `closed`;
- **different body, before `closes`:** replaces the earlier one. The Leader counts only the last accepted ballot, deletes the earlier payload at once, and issues a new receipt. The earlier receipt's leaf is not in the receipt tree. The daily count still counts the first ballot only. The replacement must carry the same set of nullifiers as the ballot it replaces (B7);
- **different body, at or after `closes`:** `closed`.

Rounds 1 to 3 have no replacement: an identical retry gets the original receipt; a different body under a known nullifier is `conflict`.

**Send schedule.** The phone sends its first round-0 ballot when the person leaves the deck with at least one card cast, provided every card the presentation needs satisfies the ballot window; if one has not started yet (the deck's original close falls in the next epoch of that issuer), the phone holds the ballot, shows "counting starts <date>" on the deck card, and sends when the card has started, while the shield entry stays `reserved` (`shield.md`). After that it sends a replacement only if the hand changed, at most once per deck per random interval drawn uniformly from 2 to 6 hours, plus one final replacement at a random time in the last 2 to 6 hours before `closes` if the hand changed since the last send. A phone that is offline sends at its next opportunity. The schedule exists so that neither the Leader nor the relay gets a per-pseudonym activity trace; a send per edit would give one.

Replacement costs no budget: the release sums one contribution per person, and the shield charged the plan once (`shield.md`). What it reveals to the phase-1 Leader is the difference between a person's successive hands, pseudonymous and inside the same release; the alternative, no replacement, loses the votes of phones that are offline at `closes`.

`services.md` AG-2 and intake checks 2, 3 and 7 follow this section (confirmed by W0-07): the nullifier lookup for an identical retry comes before the `closed` check.

## Rounds 1 to 3

Each later round's ballot has the same envelope, `round` set, a fresh `nonce`, a new presentation under the same scope (so the same nullifiers) and bound to this ballot, and a payload from `release.md`'s "What a phone computes":

| Round | Payload | Bound the aggregator checks |
| --- | --- | --- |
| 1 | `{0: cov}`: one byte string of `M(M+1)/2` signed 32-bit big-endian integers, the upper triangle of `u uᵀ` row-major, each scaled by `covScale` and rounded ties-to-even | integer L2 norm ≤ `Δ_cov`; each entry in `[−covScale, covScale]` |
| 2 | `{0: cell}`: uint | `< grid²`; a one-hot |
| 3 | `{0: group, 1: votes, 2: ratings}`: the group index, the identical `votes` bytes of the last accepted round-0 ballot, and its identical `ratings` map | `group < groupsK`; the group vector's weight ≤ `K + K_r + 1` |

The fixed-width `cov` makes a round-1 body `4 × M(M+1)/2` bytes plus a few. It fits `BALLOT_BYTES` with the presentation only for `M ≤ 128` (33,024 bytes of `cov`). `deck.md` D11 allows `covStatements` up to 256; it is asked to cap it at 128 so every valid deck's map tier can run (raised with W0-01; `take.md` is unaffected because rating decks have no round 1).

A phone that lost its hand (restore, `credentials.md`) sits later rounds out. Only the card of the original close's epoch may act in a later round, even if its epoch has since ended (`credentials.md`, ballot window). Every round's ballot carries a presentation of that card (`services.md` intake check 4), so the phone keeps a card pinned to a deck until the deck's shield entry is `released` or `dropped` (`shield.md`), and deletes it only then. Nothing a phone sends in a later round depends on an earlier round's acceptance except that its primary nullifier must have voted in round 0 (`release.md`, "Who may act"): in phase 1 the Leader checks its nullifier set; in phase 2 the round-0 receipt travels as the report's authorization.

## Receipts

On acceptance the Leader returns `{leaf, signature}` (`services.md`, "Ballot intake"). The leaf is:

```
commitment = SHA-256(canonical CBOR of payload)
leaf       = SHA-256("hum/receipt-leaf/1" ‖ uint8(round) ‖ nonce ‖ commitment)
```

A leaf is a fixed-length hash output and carries neither the nullifier nor the pseudonym, so the public receipt pages link nothing across rounds, and a dummy leaf (the hash of 32 random bytes, `release.md`) is indistinguishable from a real one.

The phone keeps, per deck and round: `nonce`, `commitment`, `leaf`, the Leader's signature over `hum/receipt/1 ‖ taskId(round, firstPart) ‖ leaf` where `firstPart` is the round's first part in plan order (`services.md`), and the deck CID. Nothing in that set identifies the phone to anyone who sees the pages.

**What a receipt proves.** A round-0 receipt proves that the Leader accepted that body at some time, not that it is in the sum: it may have been replaced by a later ballot from the same person. A missing round-0 leaf is therefore evidence only together with the ballot: the complainant shows the ballot and receipt, and the Leader rebuts only by showing a later valid ballot under the same primary nullifier, whose presentation and leaf anyone can check. The Leader can rebut only while it holds that later ballot, which `services.md` AG-5 deletes 24 hours after the final version, so a round-0 dispute must be raised before then; after that the Leader holds nothing and an unanswered dispute proves nothing either way. Raising a dispute reveals the complainant's ballot and nullifier to whoever judges it, and a rebuttal reveals their later hand; the app says so before sending anything. For rounds 1 to 3 there is no replacement, so a missing leaf with a valid receipt is evidence on its own. `release.md` is asked to state this under "Receipts".

**Checking a receipt**, once the release version carrying the round's root is logged and verified:

1. Fetch `GET .../rounds/{n}/receipts` through the relay; read `k` and the page CIDs; check the root blob's CID against `refs["receipts/<n>"]`.
2. Fetch the one page whose index is the first `k` bits of `leaf`. Each page fetch uses its own fresh relay connection carrying nothing else, at a random delay of up to 24 hours after the version was logged, and never on a connection used for another round's page or any other request. Four prefixes on one connection would select one leaf in a large deck. With `k = 0` there is one page and nothing to hide. `services.md` O-4 is asked to say so for receipt pages.
3. Check `leaf` is in the page, the pages hash to `receipts[n]` as `release.md` builds the tree (RFC 9162 over the sorted padded list), and the root equals the release body's.
4. Show "counted" on the results deck, or "not counted" with the dispute path above.

Replaced round-0 ballots: only the last receipt is checkable. The phone discards earlier receipts on receiving a new one.

## Phase 1 and phase 2

### Phase 1

The payload is the plain values above. The Leader verifies the presentation, derives every nullifier, checks the bounds, records the contribution keyed by leaf, and sums at close. Every ballot goes through an OHTTP relay to the Leader's gateway, as `services.md` "OHTTP relay" requires, so the Leader sees no network address and the relay sees fixed-size ciphertext. Phones MUST NOT send a ballot outside the relay (B13). The Helper learns nothing per ballot.

### Phase 2

The same values travel as Prio3 input shares inside DAP reports, so the Leader and Helper each see a share that reveals nothing alone, and the sums come out identical to phase 1.

- **Tasks.** One DAP task per (round, part): `taskId(round, part) = SHA-256("hum/dap-task/1" ‖ deck lineage CID ‖ uint8(round) ‖ uint8(part))`. The lineage CID, not the version CID, so a `closes` extension does not split a deck's reports. Each part has its own weight bound, which one combined vector could not enforce. Task parameters (VDAF type, lengths, weights, time-interval batch mode, minimum batch size `minVoters`) come from the deck manifest, not from a provisioning API.
- **Payload.** `{part: DAP Report bytes}` for every part the round carries. Each report's `report_id` is the first 16 bytes of `SHA-256(nonce ‖ uint8(part))`, so two parts of one ballot do not share an ID. The public extension `hum-authorization` carries, for rounds 1 to 3, the round-0 receipt `{leaf, signature}`, which the Leader checks against round 0's accepted set. The presentation and nullifiers stay outside the report, in the ballot envelope, so the Leader does the membership check and the Helper trusts the Leader's admission as DAP's model already has it.
- **Types.** The flattened vectors map onto draft types with no change to what is measured:

| Part | Prio3 type | Parameters |
| --- | --- | --- |
| 0, 7, 3, 5, 6 | `Prio3MultihotCountVec` | `length` = the vector length above, `max_weight` = the weight bound, `chunk_length` per the draft's guidance |
| 2 | `Prio3Histogram` | `length` = `grid²` |
| 4 | `Prio3Histogram` over day buckets, sent with the person's first round-0 ballot only, with the bucket of that ballot's arrival; the Leader checks the bucket against arrival time before admitting the report | `length` = the deck's day count |
| 8 | Not a client measurement: the Leader counts reports per batch | — |
| 1 | No draft type bounds an L2 norm. `Prio3SumVec` bounds each entry, giving L2 ≤ `covScale · √(M(M+1)/2)`, about 43× `Δ_cov` at M = 60. Phase 2 needs a Prio3 instantiation with an L2 validity circuit (the Prio paper's norm check). Filed; phase 2 is out of scope for draft 0.1 (`release.md`) | — |

`MultihotCountVec` enforces the weight bound and the bit domain. It does not enforce one vote per card, that part 3's votes equal part 0's, or that a part-7 cell matches a verified attribute: in phase 2 a breakdown is by a claimed value, not a proven one. A modified client can break these and still stay inside every bound, which changes data quality and not privacy. The phase-1 Leader enforces them syntactically (B4, B10).

- **Replacement.** DAP reports are immutable. The Leader keeps, per primary nullifier, the last accepted round-0 report set and includes only that one in the aggregation job, which is within its existing power to choose a batch's reports. The Helper cannot check this, as it cannot check anything about admission in DAP.
- **What the Helper can link.** `hum-authorization` is public, so the Helper can link one person's rounds 1 to 3 by the round-0 leaf; `report_id`s of one ballot's parts are unrelated by construction. Forwarding the presentation to the Helper, so both aggregators check membership at the cost of the Helper seeing nullifiers, is an open question.
- **Noise.** Each aggregator adds its share of the discrete Gaussian to its aggregate share (`release.md`, "Noise"; `services.md`, "Phase 2").

## Validation rules

The Leader runs these after `services.md`'s intake parse check and before recording anything. Each is phrased so one vector can test it. A failing rule rejects the ballot with the named error and records no nullifier (`services.md` AG-8).

| Rule | Check | Error |
| --- | --- | --- |
| B1 | The request body is exactly `BALLOT_BYTES`; the length prefix is at most `BALLOT_BYTES − 4`; the bytes after the ballot are all zero; the ballot is canonical CBOR with exactly keys 0–5; `presentation` is at most 8,192 bytes; `round` matches the URL; `nonce` is 32 bytes; `deck` is a version of the deck this endpoint serves | `malformed` |
| B2 | `presentation` verifies under `credentials.md` P1–P8 for the ballot row of its uses table: scope `hum/ballot/1 ‖ deck lineage CID`, bound message `hum/ballot-bound/1 ‖ SHA-256(keys 0–4)`, policy `[1, [entry, vote]]` of the deck's pinned context version as `context`, every card's `epoch` equal to the epoch of the deck lineage's version-1 `closes` and already started | `rejected`, rule P1–P8 |
| B3 | Every card in the presentation is from a `person`-class verifier in the context's accepted set for a leaf it satisfies; a ballot with no card proof, or whose presentation satisfies no leaf, is rejected (the "agents never vote" vector). Every nullifier the presentation yields is new for this deck, except under an identical retry or a replacement by the same person (B7) | `rejected` B3; `conflict`, detail `nullifier` |
| B4 | Round 0: `votes` has length `C`, every byte in 0..3, at most `K` non-zero; in a rating deck `group` is present and `< source.groupsK`, in a vote deck absent | `rejected` B4 |
| B5 | `movement` present iff the plan has part 5; at most `K_m` entries; every key `< C`; `first`, `second` in 1..3; `moved` in 0..2 with the matching argument ref present; for every key `i` with `votes[i] ≠ 0`, `second = votes[i]` | `rejected` B5 |
| B6 | `ratings` present iff the plan has part 6; at most `K_r` entries; keys `< A`; values 0..2 | `rejected` B6 |
| B7 | Round 0 with a known primary nullifier: identical body → the original receipt (200), at any time until the nullifier set is deleted; different body before `closes` and with the same nullifier set → replace (200, new receipt); different body at or after `closes` → `closed`; different nullifier set → `conflict`, detail `nullifiers` | as listed |
| B8 | Rounds 1–3: the primary nullifier is in round 0's accepted set (phase 1) or the report's `hum-authorization` receipt verifies against round 0's set (phase 2), else `forbidden`; a known nullifier with a different body is `conflict`, detail `duplicate`; identical → original receipt | as listed |
| B9 | Draft 0.1: a deck whose plan has part 7 is not registered (`services.md`, opening a deck), and a presentation disclosing any attribute message beyond what a satisfied leaf requires is rejected (`credentials.md` P7) | `rejected` B9 at open (not `floor`: the plan is valid, the part is deferred; W0-07 asked to match); `rejected` P7 |
| B10 | Round 1: `cov` is exactly `4 × M(M+1)/2` bytes of signed 32-bit integers, each in `[−covScale, covScale]`, integer L2 norm ≤ `Δ_cov`. Round 2: `cell < grid²`. Round 3: `group < groupsK`, `votes` and `ratings` byte-identical to the last accepted round-0 payload's | `rejected` B10 |
| B11 | Phase 2: every planned part of the round has a report; each report names `taskId(round, part)`; its `report_id` is derived from `nonce` and the part as above; the Leader's share decrypts; no extra parts | `rejected` B11 |
| B12 | Phone side: a ballot is sent only after the deck, its context and both aggregators' registration passed every verification step (`manifest.md` 1–11, `deck.md` D1–D15, `context.md` C1–C16), the shield was charged (`shield.md`), the deck is open or the round is accepting, and the card satisfies the ballot window; and a phone never sends a round-0 ballot for a deck whose shield entry was charged under a different card | simulator |
| B13 | Phone side: every ballot and receipt fetch goes through the relay, padded as above; a phone never sends a ballot to a hostname it did not reach through the relay's gateway for the aggregator the context names by key | simulator |

B12 and B13 are client conformance rules, tested by the simulator's instrumented phone, not by the aggregator.

## What the aggregator learns

| | Phase 1 Leader | Phase 1 Helper | Phase 2 Leader | Phase 2 Helper |
| --- | --- | --- | --- | --- |
| Deck nullifiers, and every card's public fields (issuer, `kid`, `len`, `epoch`), which are identical on every ballot of the deck (`context.md` C16; `branches` is empty) | Yes, per ballot, until final + 24 h | No | Yes | No |
| Counted hand, transitions, ratings, group, cell | Yes | No | A share | A share |
| Successive hands of one pseudonym (replacements) | Yes, the diff | No | Yes, the diff of the reports it holds | No |
| Round-1 matrix: every vote on a `sel` card, including uncounted ones, up to sign | Yes | No | A share | A share |
| Arrival times | Yes | No | Yes | The batch interval |
| One person's rounds 1–3 linked to each other | Yes, by nullifier | No | Yes | Yes, by the round-0 leaf in `hum-authorization` |
| Which of one person's other decks exist | No | No | No | No |
| Who holds a nullifier | Not from the ballot: every ballot of a deck shows the same public fields, so nothing on it matches a chat name, a join ticket or an authored object (`context.md` C16, ADR 0100). Arrival time is the remaining side channel: the first send happens when a person leaves the deck | No | The same as phase 1, without the votes | No |

## Security considerations

- Nullifiers come from blindly issued secrets under a per-deck scope; two decks' nullifiers are unlinkable, and so are a ballot's and any token, join or authorship nullifier (`credentials.md`). A presentation's public fields are the same for every member of a context (`context.md` C16), so they link no two decks and no ballot to a chat name. Before ADR 0100 a policy with an `any` node or a multi-verifier trust-list source let those fields differ between members; such contexts are now invalid.
- The bound message makes every presentation single-use and the body tamper-evident; an aggregator cannot alter a payload and keep a valid presentation, and a relay cannot splice.
- One person, one counted ballot: every nullifier in a presentation must be new (pooled cards are spent for their owner), one card per issuer is valid through any `closes` (`credentials.md`, renewal and the ballot window), and replacement is keyed by the primary nullifier.
- Caps are enforced on the phone (the counted hand), at intake (weight), and in phase 2 by the VDAF, so a malicious phone's contribution is bounded in every phase. A malicious phone can still misreport inside the bounds; that is data quality, which DP does not promise to protect.
- Fixed-size ballots and the send schedule deny the relay and the Leader a per-pseudonym activity trace beyond a handful of sends per deck.
- Receipt pages leak a `k`-bit prefix per fetch; separate connections and random delays keep the prefixes of one person's rounds apart.
- Nothing in a ballot comes from an agent: a personal agent may sort a deck on the phone, and the ballot code takes no input from it (`agent-sponsor.md`). A ballot has no key for a signature; an added key fails B1.

## Vectors (for W0-08)

Directory `vectors/ballot/`, each case bundled with its deck, context and credential vectors.

Valid:

- `ballot-round0-full`: the `Spring priorities` deck (18 cards, `cap` 18), a hand of 10 agree, 5 disagree, 3 unsure (`Swipe-End`), the canonical body, the bound message, the framed bytes, the leaf, and the part-0 vector of weight 19.
- `ballot-frame-edges`: frames for ballots of `BALLOT_BYTES − 4` bytes (no padding), `BALLOT_BYTES − 5` (one zero byte) and a 300-byte ballot, each exactly `BALLOT_BYTES` long.
- `ballot-round0-capped`: a 100-card deck with `cap` 60 and 80 cast cards; the counted hand is the first 60 cast; the vector has weight 61.
- `ballot-round0-ibis`: part 5 and 6 payloads with `K_m` 10, `K_r` 10, including a same-way re-vote on the diagonal and a `moved` on the con; the part-5 vector of weight ≤ 20.
- `ballot-round0-rating`: a rating deck ballot with `group` 1; the part-3 vector.
- `ballot-round0-replace`: two ballots under one primary nullifier with different hands, the expected aggregator state (second counted, first payload deleted, second leaf only).
- `ballot-round0-identical`: the same body twice with two different presentations, one receipt; and the same after `closes`, still the original receipt.
- `ballot-rejected-keeps-nullifier`: a B4 failure followed by a valid ballot under the same nullifier, accepted (`services.md` AG-8).
- `ballot-round1`, `ballot-round2`, `ballot-round3`: from `release.md`'s round vectors, with `cov` as fixed-width bytes and its integer norm, and round 3 reusing round 0's bytes; `ballot-round1-max`: M = 128 at the size limit, and the part-3 layout with ratings.
- `ballot-receipt-check`: a padded tree with a fixed `Y_r`, a leaf, its page, and the expected result; one with an absent leaf; a dispute rebutted by a later ballot.
- `ballot-dap-report`: the round-0 part-0 vector as a `Prio3MultihotCountVec` measurement with fixed shares, task ID and `report_id`; the part-4 histogram report.
- `ballot-task-ids`: `taskId(round, part)` for a fixed deck lineage CID and a second version of the same deck (same IDs).

Invalid, one per rule, named `ballot-invalid-<rule>-<case>`:

- B1: 48 KiB + 1; a non-zero byte after the ballot; a length prefix larger than the frame; a 9 KiB presentation; `round` 4; `nonce` 31 bytes; unknown key 6; a key holding an `agentKey` signature; a different deck.
- B2: presentation under another deck's scope; bound to another body; against the wrong context version; a card of the epoch before the original close; a card of the epoch after it, in a deck whose `closes` was extended into that epoch (the extension vector); a post-dated card that has not started.
- B3: no card proof (the "agents never vote" vector); an agent-class card; a presentation satisfying `entry` but not `vote`; a pooled presentation whose second nullifier is already in the deck.
- B4: `votes` of length `C − 1`; a byte of 4; `K + 1` non-zero bytes; `group` in a vote deck; `group` ≥ `groupsK`.
- B5: `movement` without part 5; `K_m + 1` entries; `moved` = 1 on a card with no `pro`; `first` 0; `second` ≠ `votes[i]`.
- B6: `K_r + 1` ratings; key ≥ `A`; value 3.
- B7: a different body after `closes`; a replacement with a different second nullifier.
- B8: round 2 from a nullifier that never voted; round 1 sent twice with different `cov`.
- B9: a deck with part 7 (refused at open); a gate attribute disclosed.
- B10: `cov` one entry over `covScale`; norm over `Δ_cov`; `cov` of the wrong length; `cell` = `grid²`; round 3 `votes` differing from round 0.
- B11: a report under `taskId(round)` without the part byte; missing part; `report_id` not derived from `nonce` and part.
- B12 and B13: simulator scenarios `sim-ballot-before-proof`, `sim-ballot-off-relay`, `sim-ballot-epoch-boundary`.

Client-side vectors (`ballot-client-*`): the counted hand and movement selection for a hand that grows from 10 to K + 5 cast cards across three sends, showing no card ever leaves; undo before casting; the ratings selection from a fixed seed; the send schedule from a sequence of hand edits with timestamps and a fixed random stream; `ballot-movement-uncounted` (a re-voted card outside the counted hand still appears in `movement`).

## Open questions

Filed in `docs/decisions/`:

- **Replacement, per-part tasks, fixed size** ([`0024-w0-02-ballot-replacement-and-tasks.md`](../decisions/0024-w0-02-ballot-replacement-and-tasks.md)): round-0 replacement until `closes` with identical retries honored after it; `taskId(round, part)` over the lineage CID; `BALLOT_BYTES` 48 KiB and a `covStatements` cap of 128.
- **Breakdown in phase 1:** off in draft 0.1 pending the owner; the consent screen must say who sees the value and for how long if it is turned on. In phase 2 a breakdown is by a claimed value.
- **Phase-2 covariance type:** no L2-bounded Prio3 type; a norm circuit is needed or round 1 must change shape.
- **Phase-2 admission:** forward the presentation to the Helper, or keep the Helper blind to nullifiers.
- **Send schedule:** 2 to 6 hours is a guess; the simulator should check the Leader's load and the trace left.

Assumptions about sibling specs, checked on disk on 2026-10-06, and the changes this revision asks of them:

- `deck.md`: parts, caps, `covScale`, `Δ_cov`, "Which vote counts", one selection reused in parts 0, 3 and 7, the full hand in 1 and 2, the rating-deck group slot. Asked: `covStatements ≤ 128` in D11; "first K cast" wording for the counted hand; part 7 not registrable in phase 1 until the owner decides.
- `release.md`: round contents and bounds, the leaf, RFC 9162 trees, the round-0 receipt as phase-2 authorization, no extra budget for rounds, what a round-0 receipt proves. Asked now: the dispute deadline, final + 24 hours.
- `services.md`: intake order, every-nullifier set, `taskId(round, part)` over the lineage CID, O-3 and O-4, AG-5, registry rows: all confirmed on disk. Asked now: the frame (length prefix plus zero padding, no `pad` key); the 8 KiB presentation cap at intake; `rejected` B9 instead of `floor` for a part-7 deck; the intake text "under the context's entry policy" becomes "`[1, [entry, vote]]`"; the dispute deadline (final + 24 h) beside AG-5.
- `credentials.md`: the ballot window is the epoch of the deck lineage's version-1 `closes`; cards pinned per deck. Met in this revision.
- `take.md`: rating ballots carry the group in round 0; a phone without the source hand sits out. Met.
- `agent-sponsor.md`: the "agents never vote" vector is B3's no-card case and B1's added-key case. Met.
- `issue-map.md`: no ballot scope starts with `hum/author-`. Met.
- `credentials.md`: the ballot row of the uses table, the ballot validity window, every nullifier returned to the use. Met in this revision.
