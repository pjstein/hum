# Cross-spec review — Draft 0.1

Oct 6, 2026 · W0-10 · `seam:` this review touches every seam; it changes no behavior

## What this is

Every spec has had its own review. This pass reads all of them together and looks for faults that sit between two specs.

Read in full: `CLAUDE.md`, `docs/design.md`, `docs/threat-model.md`, `docs/DECISIONS.md`, every file in `docs/specs/`, and the latest re-review section of every file in `docs/specs/reviews/`. The spec files on disk are the source; a review or an ADR that describes an earlier version was not trusted.

Two limits on what follows:

- `conformance.md` was read as it stood at 15:48 on 2026-10-06 (its "first version"). W0-08 is extending it, `reference/` and `vectors/` now. The coverage section is a snapshot.
- `credentials.md` was edited at 17:05 while this review was being written. Every citation below was checked again against the files at 17:20.

**Update, later on 2026-10-06.** The owner approved the fixes for B1, B2 and B3, the rename in S10 and the `manifest.md` edits. They are applied; see "12. Decisions applied after review" at the end. Sections 1 to 11 are kept as written at review time, so they describe the specs before those changes, and each closed finding carries a line saying what closed it.

Severities:

- **Blocker:** an invariant in `CLAUDE.md` can be broken, or two implementations that both follow the specs cannot work together, or a normal flow cannot complete.
- **Should fix:** two specs disagree, a rule cannot be met, or a format is not defined. An implementer would have to guess.
- **Note:** recorded so nobody is surprised. No change is required for draft 0.1.

Findings name the spec and section. Line numbers are left out because they move.

## Summary

| Severity | Count |
| --- | --- |
| Blocker | 3 |
| Should fix | 24 |
| Note | 18 |
| Editorial edits applied by this review | 52, in 13 spec files |
| Owner decisions filed | 8 ADRs, `0100` to `0107` |

The three blockers:

- **B1.** Every presentation shows which verifier issued each card and which policy branch was taken. The same values sit beside the votes on a ballot and beside the chat name on a signed issue-map object. In a context with more than one such combination, a combination held by one voter attributes that voter's hand.
- **B2.** Membership proofs stored in the log are checked against the reader's clock. After an issuer's epoch turns, older issue-map objects fail, and a deck that pins one cannot be verified.
- **B3.** A shield entry leaves the yearly window 365 days after the deck was opened, not after its release. Long decks let an unmodified phone have twice the yearly budget published in one month.

## 1. Blockers

### B1 — The issuer and the branch form cells, and a small cell links a chat name to a ballot

**Closed 2026-10-06** by `context.md` rule C16 (ADR 0100, option 1, applied to `entry` and `vote`): no `any` node, and exactly one verifier authority per policy leaf. Every member of a context now presents the same issuers, the same number of cards and an empty `branches`. Remaining: the one-hour epoch grace on join, token and authorship presentations; different fields between two context versions with different policies; and arrival timing (N17). Pending owner review of the diff.

**Specs:** `credentials.md` ("Format", "What is proven", "Every identifier"); `ballot.md` ("What leaves the phone", "What the aggregator learns"); `issue-map.md` ("Signatures under `hum/author/1`"); `chat.md` §2.5; `context.md` ("Entry policy" and its example); `trust-list.md` ("How a context uses trust lists"); `docs/threat-model.md` ("A malicious verifier", "Colluding servers"). Invariants 1 and 2.

**What the specs say.** A card proof carries `issuer`, `kid`, `len` and the disclosed `epoch` in the clear, and the presentation carries `branches` and the number of cards. `credentials.md` shows that `kid`, `len` and `epoch` are the same for every valid card of one issuer, and concludes that the public fields "identify the issuer and nothing finer". That claim holds. It was checked against `verifier.md` ("Issuer key", "Lifetime"), `verifier-runtime.md` (step 7) and `services.md` ("Issuance"): one key and one layout per epoch, fixed at the start of the handover; a late joiner gets the epoch's key; an emergency removal invalidates every card under the key at once.

**What the claim leaves out.** The issuer itself, the branch and the card count differ between members of one context. Call one combination a cell. A context has more than one cell when:

- a policy leaf's source is a trust list that accepts two or more verifiers for the attribute. `context.md` says "any verifier authority the list accepts for `name` counts";
- a policy has an `any` node. The phone takes the lowest satisfiable child, so the branch also shows that no earlier child was satisfiable;
- one card can satisfy two leaves for some people and not for others, which changes the card count.

The example in `context.md` has two cells. Its `entry` is `any(approved, area = 1)` and a ballot proves `[1, [entry, vote]]`. A member on the approved list presents three cards and branch 0. Everyone else presents two cards and branch 1.

**Where one person's cell appears.**

| Place | Beside | Read by | Kept |
| --- | --- | --- | --- |
| Every ballot, every round | The votes (phase 1) or a share (phase 2), and arrival time | The Leader | Until the final version plus 24 hours |
| A signed issue-map object's bundle | The chat identity key | Anyone | Permanently, in the log and resolvers |
| An unsigned issue-map object's bundle | Nothing else | Anyone | Permanently |
| A join ticket | The chat identity key and name | Greeters, including greeter agents | Transient by rule; nothing stops a greeter keeping it |
| Blob-token and delivery-token issuance | A per-day nullifier | The token issuers | One day |

**The join.** A party that sees a person's cell beside their chat name and a ballot with the same cell has linked the two when the cell holds one voter. In phase 1 the operator can do this alone: it runs the Leader and reads the public log. An organizer who kept a join ticket and the Leader can do it for members who never signed anything. In phase 2 the Leader holds only a share, so the vote is safe, and the Leader still learns that this member voted and when. The same cell links a person's unsigned objects to their chat name.

**Small contexts.** A phone cannot know how many voters share its cell. In a 150-voter context whose trust list accepts three district verifiers and two uniqueness verifiers there are six issuer combinations, and one of them holding a single voter is likely.

**The one-hour grace.** In the first hour of a period a verifier also accepts the previous period's epoch value. At an epoch boundary that gives two epoch values for one hour on join, token and authorship presentations. A presentation with the old value in that hour says its holder had not yet switched to the renewed card. Ballots are not affected: their epoch is fixed by the deck's version-1 `closes`.

**The specs disagree with each other.** `credentials.md` records the leak and `issue-map.md` has the author screen warn about it. `ballot.md` says the Leader does not learn "who holds a nullifier". `docs/threat-model.md` says the aggregator must never see "who a pseudonym belongs to", lists "organizer and aggregator (phase 1)" as "still unlinked", and says the residual from a malicious verifier is "mitigated by presenting only the policy's conditions and not the issuer name where the policy allows any issuer on a list". The issuer is always presented. The threat model says it wins on who may see what.

**Proposed fix.** For draft 0.1, add a rule to `context.md`: the effective voting policy has no `any` node, and each leaf's source yields rows for exactly one verifier authority. Every ballot, ticket and authorship proof in a context then shows the same public fields. No bytes change. Take hiding the issuer and the branch to the outside review with ADR 0022. Correct the threat model and `ballot.md` whichever way the owner decides. Filed as ADR 0100, with three alternatives.

### B2 — Presentations stored in the log are checked against "now"

**Closed 2026-10-06** by the logged-presentation row in `credentials.md` "Validity" (ADR 0101): the log checks `epoch = E_now` and `issued` within 3,600 seconds at submission; every later verifier checks the epoch against `issued` and reads the issuer key at the object's log position, with no clock. Pending owner review of the diff.

**Specs:** `credentials.md` ("Validity", rules P3 and P5, "Where the rules run"); `issue-map.md` ("Validation rules", IM-6); `agent-sponsor.md` (AS-8, "The membership event"); `manifest.md` (verification step 9); `deck.md` (D7); `verifier.md` (closing paragraph of "Validation rules"); `trust-list.md` (step 4).

**The conflict.** `credentials.md` has two epoch checks: the ballot window, and "everything else: `epoch = E_now`" on the verifier's own clock. P3 reads the issuer `kid` from the verifier version in force "when the presentation is verified". That is right for a join ticket or a token request, which is verified once.

Three presentations are stored and verified again later: the membership proof of a signed object, the slot proof of an unsigned object, and the `sponsorProof` of an agent-sponsor manifest. `issue-map.md` says "a phone runs every rule when it syncs", and IM-6 includes the membership proof. `manifest.md` step 9 makes phones and aggregators verify every manifest a deck references, which includes its positions and arguments.

**What breaks.** After the author's issuer turns an epoch, the disclosed epoch of an older object no longer equals `E_now`:

- a phone that syncs a map drops every object written in an earlier epoch;
- a deck that pins a position written in the previous epoch fails step 9 on every phone and at both aggregators, so the deck cannot be voted on;
- a sponsor manifest, valid for up to 90 days, stops verifying at the agent verifier's next epoch boundary;
- once a key moves to `retiredKids`, every object signed under a card of that key fails P3.

A phone that trusts the log's check and a phone that re-checks hold different maps and count rate limits differently. `verifier.md` and `trust-list.md` already say "the verifier version in force at the presentation's log position", which contradicts P3 and is the rule that works.

**Proposed fix.** A third row in the "Validity" table for logged presentations. The log checks `epoch = E_now` at submission with its own clock and requires `issued` to be within one hour of it. Any later verifier uses no clock: it checks the disclosed epoch against `epoch(period(issued))`, and reads `kid`, the layout and the trust-list rows at the object's log position. Filed as ADR 0101.

### B3 — The shield window is anchored at the reservation, so long decks escape the yearly bound

**Closed 2026-10-06** by the anchor rule in `shield.md` "Window" (ADR 0102, item 1): an entry counts until 365 days after the final release version was seen, capped at the deck's `expires`, or after `expires` when there is none. Pending owner review of the diff.

**Specs:** `shield.md` ("The budget", "The ledger", "Composition", S8); `deck.md` (D2, D13); `release.md` (R13). Invariant 3.

**The path.** A shield entry counts while its `chargedAt` is within the last 365 days. `chargedAt` is set when the phone reserves, which is when the person opens the deck. D2 allows a deck to stay open for one year. The release follows the close by up to 30 days and the rounds.

A person opens seventeen year-long decks on day 0. Every entry drops out of the sum on day 365. The seventeen releases are logged from day 366. From day 365 the phone shows a full shield, and it reserves seventeen more decks that close within days. Thirty-four releases about one person, ρ 8.6 in total, are published inside one month. That is about ε 30 at δ 10⁻⁶.

`shield.md` rejects a calendar-year window because it "would let a person spend `SHIELD_RHO` on December 31 and again on January 1, which is about ε 31 over two days". This is the same outcome through an unmodified app. The restore path already anchors estimated entries at `closes`, not at the reservation.

**Proposed fix.** An entry counts from its reservation until 365 days after the later of `chargedAt`, the time the phone saw the final release version logged, or the deck's `expires` when no final version exists. This is stricter and changes one field in the ledger. Filed as ADR 0102.

## 2. Should fix

Each item names the ADR that carries it to the owner.

**S1 — A pinned card can outlive its issuer key.** `verifier.md` ("Issuer key") moves a key to `retiredKids` 30 days after its last epoch. `credentials.md` P3 rejects a `kid` outside `issuerKeys`. `ballot.md` and `shield.md` keep an epoch-E card in use for every replacement and round of a deck whose version-1 `closes` fell in E. `deck.md` D2 lets `closes` move to a year after `opens`, and the rounds add up to 120 days. If the issuer changed keys at E + 1, those ballots are refused from day 31. Fix: a longer fixed tail before retirement, or a cap on how far `closes` may move. ADR 0104.

**S2 — Emergency key removal during an open deck is not described.** `verifier.md` treats a dedup row whose `kid` is gone as no row, so everyone re-enrols in the same epoch with a new pseudonym secret. `release.md` R12 keeps the ballots already accepted. The honest phone is pinned to the dead card (`shield.md` S11) and can neither replace its ballot nor answer rounds 1 to 3. A modified client can vote a second time, because the new card's nullifier is new for the deck. Fix: say so in `verifier.md` and `ballot.md`, and advise re-dealing a deck that has not closed. ADR 0104.

**S3 — `closes` can be extended after it has passed.** `deck.md` D12 requires only `closes ≥ prev.closes`. `services.md` ("Opening a deck") accepts "a version that only extends `closes`". After the close, the last daily bucket is noised, the `absorb` decision is taken and release version 1 may be logged. An extension then reopens round 0 for a release that cannot change. Phones charge shields and send hands that are never counted. `release.md` R2 ("the highest version of its lineage logged before `deck.closes`") stops naming one version. Fix: a deck version above 1 is invalid if a release of the lineage is already in the log, and aggregators refuse an extension first seen at or after the `closes` they hold. ADR 0103.

**S4 — Two outputs ignore the voter minimum, and R6 and R13 disagree.** The floor is "at least 100 noised voters to publish". The daily count is served every day with no gate (`context.md`, `services.md`). The padded receipt tree of round 0 is published for a below-minimum release, because `release.md` R13 requires a root and pages for every completed round, while R6 says part 8 is unlocked only with part 0. The leaf count is a noised voter count, so `nHat` being absent hides nothing. Both outputs are noised and inside `plan.rho`. Neither is named as an exception. Fix: declare the daily count as the one exception and publish no receipt pages below the minimum. ADR 0103.

**S5 — The receipt clamp's δ is outside the plan.** `release.md` ("Receipts") and `shield.md` ("Security considerations") ignore at most 4·10⁻⁹ of δ per release. A plan may set `delta` = `DELTA_MAX`, and every example does, so the release exceeds the δ floor by 0.4%. The 10⁻⁹ per round is asserted, not derived; the provable tail bound for a discrete Gaussian at 6σ is e⁻¹⁸, about 1.5·10⁻⁸. Fix: compute the reported ε at `plan.delta − (R+1)·10⁻⁹`, and give the tail bound to the outside review. ADR 0102.

**S6 — Uses that prove `entry` have no primary nullifier.** `context.md` C6 designates a nullifier leaf in the effective voting policy only. A join ticket, a token request and an authorship proof prove `entry` and yield one nullifier per card. `credentials.md` says a verifier treats a presentation as seen if any of its nullifiers was seen, and `issue-map.md` IM-7 does. `chat.md` §5.17 stores one `nullifier` per `join-record` and §2.5 speaks of "the proof's nullifier". The `authorship` map in `issue-map.md` has one `nullifier` field, which the log recomputes anyway. Retention also differs: `chat.md` keeps every `join-record`; `credentials.md` says they are held while the identity is a member. Fix: `join-record` holds the whole set and is deleted when the identity leaves; the `authorship` map drops the field. ADR 0104.

**S7 — `services.md` V-2 contradicts the handover.** "A session issues at most one credential; a second `issue` call answers `conflict`." A first session in handover issues two cards (`credentials.md`, `verifier-runtime.md` rule 11), and an identical retry gets the identical response. Fix the rule text. ADR 0104.

**S8 — A rating deck cannot meet a tightened context floor.** `deck.md` D15 fixes `plan.minVoters` at `GATE_TALLIES`. D10 requires `minVoters ≥ ctx.floors.minVoters`. A context with a minimum of 300 cannot deal a rating deck. Fix: the larger of the two. ADR 0103.

**S9 — One release per deck is checked per log.** `services.md` ("Step 10 at the log") checks R10 and R14 against each log's own history. A context with two logs can hold one release lineage per log for the same deck if both aggregators sign both, and one operator may run both aggregators at launch. Fix: the first log in the context's `logs` is the ledger of record. ADR 0103.

**S10 — Three domain strings are outside `hum/`.** *Applied 2026-10-06: renamed to `hum/manifest/1`, `hum/keyring/1`, `hum/delivery/1` in every spec; `reference/` and `vectors/` must follow.* `manifest/1`, `keyring/1` and `delivery/1`. Recommendation and cost are in section 5.5 and ADR 0105.

**S11 — COSE signatures place the domain string in two ways.** Manifests and signed requests use `external_aad` with a hash or CID as the payload (ADR 0082, `services.md` A-2). The `roles` signature (`chat.md` §5.8) and the delete order (`storage.md` §8.2) prefix the payload and do not state `external_aad`. `storage.md` says "exactly as manifests are signed", which reads as the other form. The reference uses an empty `external_aad`. Fix: one convention, stated in both specs. ADR 0105.

**S12 — Enumerations are uints in some bodies and text in others.** Uints in `context`, `deck`, `release`, `issue-map`, `take`, `agent-sponsor` and chat bodies. Text in `verifier` (eleven fields), `trust-list` (three) and `service` (`kind`). Three per-spec reviews left this to this pass. Recommendation: keep the three text exceptions for draft 0.1 and write the rule down. ADR 0105.

**S13 — Media types follow no single pattern, and the default store refuses some blobs.** The take text blob is `application/hum-take+cbor`; everything else Hum defines is `application/vnd.hum.*`. Receipt pages, the receipt root blob, a verifier's `code`, `build` and dataset blobs and attestation reports have no declared type. The default `formats.public` in `storage.md` §7 lacks the take type, so a default store answers `415` to a take's text. ADR 0105.

**S14 — `manifest.md` has no key for a retired version or a successor.** *Still open after 2026-10-06: the other `manifest.md` edits were applied, and no keys were proposed for this one.* `deck.md` needs it to withdraw a scheduled deck, `verifier.md` to retire a lineage, `context.md` for both. `take.md` (body key 7) and `agent-sponsor.md` (body key 11) each defined their own `retired`. The full list of manifest edits is in section 10. ADR 0106.

**S15 — `services.md` relies on context fields that do not exist, and the first request cannot be made.** "A client tries the resolvers its context names first" and "a context may name additional relays" have no field in `context.md` (keys 0 to 19). Rule O-2 accepts an OHTTP key configuration only from a logged manifest, and a phone needs one to read the log for the first time. ADR 0107.

**S16 — `services.md` API bodies have names and no keys.** Bodies are "deterministic CBOR" per `manifest.md`, where map keys are integers. The receipt `{ leaf, signature }`, the deck registration response, the log's proof response, the receipt listing, the daily count and the session and evidence bodies are written with names only. The receipt root blob has no encoding, and the receipt signature does not say which key of the keyset made it. ADR 0107.

**S17 — Evidence sealing has no `info`, and a rejection code has no field.** `credentials.md` seals the issuance request "exactly as evidence is" with `info` = `hum/issue/1 ‖ authority`. `verifier.md` and `services.md` give no `info` for evidence. The host's rejection code (0 to 999) has no place in the error map. ADR 0107.

**S18 — The `delivery` service kind has no rules.** `storage.md` has BS-1 to BS-6 for stores. `chat.md` §12.1 lists `limits` names in prose and points at "the same shape as a blob store's" for key 16. Nothing says `issuer.type` must be 1. ADR 0107.

**S19 — Four specs name a scope and not its bound message.** See section 5.2. ADR 0107.

**S20 — `issue-map.md` describes a context field that `context.md` removed.** `unsignedWindow` and `UNSIGNED_WINDOW_MIN` appear in "Membership proofs" and "Rate limits". `context.md` fixes the window as `AUTHOR_WINDOW` and has no such field. The scope bytes agree today (both give 86,400). The log's author counters are kept one window in `services.md` and two in `issue-map.md`. ADR 0107.

**S21 — One error code differs.** `ballot.md` B1 answers `malformed` for a presentation over 8 KiB. `services.md` intake check 1 answers `too_large`. ADR 0107.

**S22 — `release.md` cites a logging rule that does not exist.** "The aggregator's own logs round counts as `services.md` requires." `services.md` lets the aggregator log "counts of ballots accepted and rejected by code" with no rounding. Exact counts in a seven-day log undo the noised counts for anyone who obtains the log. ADR 0107.

**S23 — The simulator's allow table is wider than `chat.md`.** `simulator.md` lets the delivery service see a device key. `chat.md` §12.9 and §12.10 say it sees no credential and no device identifier. The secrets registry has no kind for token-scope nullifiers, join nullifiers, issuance nullifiers or the public card fields, so a leak of any of them would pass. ADR 0107.

**S24 — The threat model disagrees with the specs in three rows.** *Applied 2026-10-06.* The issuer-name sentence and the "organizer and aggregator" row are part of B1. "No service receives two of the three identities in one request" does not cover the log, which receives a chat identity key, a card-derived nullifier and the public card fields in one signed-object bundle. Listed in section 10. ADR 0106.

## 3. Notes

**N1 — The one-hour grace yields two epoch values.** Covered under B1. It doubles a day's token quota and a window's unsigned slots for that hour, which `credentials.md` accepts.

**N2 — "The one place a card-derived value sits beside a chat identity" is two places.** `credentials.md` says this of `join-record`. A signed object's public bundle also holds an `hum/author-once/1` nullifier beside the chat identity key. Neither links to a ballot without the pseudonym secret.

**N3 — The backup phrase unmasks more than authorship.** `credentials.md` notes that whoever holds a card's pseudonym secret can recompute its authorship nullifiers. The same holder can recompute its deck nullifiers. Together with the Leader's intake set for an open deck, that identifies the person's ballot. Cards are deleted when their epoch ends and their decks are final, which bounds it.

**N4 — Handover is undefined for `V` ≤ 2.** "The last two periods of an epoch" is the whole epoch when `V` = 2 and more than the epoch when `V` = 1. The session rules still work if handover means the last min(2, `V`) periods. `credentials.md` should say so. Also, the card choice "bytewise-smallest `issuer ‖ kid`" can pick a card of the next epoch that has not started; the rule should apply among cards the use accepts.

**N5 — Phase 2 gates on an exact count.** `services.md` maps DAP's minimum batch size to `minVoters`. DAP compares it with the exact report count; phase 1 compares the noised `nHat`. Phase 2 is out of scope for draft 0.1.

**N6 — An abandoned deck's daily count never reaches the ledger.** `context.md` records this. It needs both aggregators to stop, since a below-minimum deck still gets a logged version 1. Shields are unaffected.

**N7 — Two uniqueness verifiers on one trust list give one person two deck nullifiers.** `verifier.md` says so. An honest phone uses one. Option 1 of ADR 0100 removes the case.

**N8 — The sponsor row discloses nothing, yet a bool leaf is satisfied by disclosure.** `credentials.md` says the sponsor proof discloses "`epoch` only", and its predicate table satisfies "present" on a bool by disclosing the message. For W0-02.

**N9 — Rule 20e in `verifier.md` binds nothing.** A named profile's `code` must equal its `profile` ref, and any binary can be put in both. What ties a profile name to the reference binary is a trust list's `attested` entry. That is the right place for invariant 6; the rule's wording suggests more.

**N10 — `service` manifests contain hostnames.** `endpoints` are URLs inside a signed body, and `issuer.name` is a Privacy Pass issuer name. A context still names every service by authority CID, so invariant 6 holds if it is read as "a manifest names other services by key". `verifier.md` keeps host locations out of the body entirely. `manifest.md` says location hints are unsigned. The owner should confirm the reading when approving ADR 0072.

**N11 — ADR 0072 is behind `services.md`.** It lists a `gateway` kind and a `stamp` field. The spec has a `relay` kind, no `gateway` kind and no `stamp` field.

**N12 — The witness endpoint does not use the common error map.** It returns the tlog-witness bodies, which is right. The "Errors" section of `services.md` lists witnesses among the services that use the CBOR map.

**N13 — Bundle rule B-4 is by author form, not by type.** An issue-map object written by the context authority and a take written by a person carry `signatures`. `services.md` says "according to the manifest's type". An agent's take carries `authorship` in the map `issue-map.md` defines; `take.md` should say which keys.

**N14 — Some design-doc features have no spec.** Product analytics through private aggregation, competitions and real-data checks, synthetic tables, and rolling a small context's statements up into a parent. None is in draft 0.1. The design doc should mark them as later.

**N15 — Greeter agents hold the join records.** A shared agent with `greeter` sits in the organizers group. It reads reports (stated in `agent-sponsor.md`), opens join tickets and holds the `join-record` set (not stated).

**N16 — An organizer who runs the invite or approved-list verifier can pair a roster entry with a chat name by time.** They see session outcomes for their own verifier and they see who joined. This is inherent in inviting people. The rule in `chat.md` §2.5 is that a KeyPackage handle never passes through a verifier, and it holds.

**N17 — The first ballot is sent when the person leaves the deck.** Later replacements are spread over hours; the first send is immediate. The Leader sees its arrival time beside the votes. Members see when a person is active in chat. Together with a small cell this sharpens B1. The threat model lists timing across services as an open question; this pair should be named there.

**N18 — Two token types.** `services.md` asks whether one Privacy Pass type could serve both the store and the delivery service. Keep two. The store needs public verifiability so the issuer can be a separate party. The delivery service needs a key per channel, which is practical only with a derived VOPRF key.

## 4. Identifier registry

Every identifier, key, nullifier, token, CID and timestamp in the specs: where it is made, where it goes, who can read it. "Phone" means the person's own phone.

| # | Identifier | Made by | Travels to, and kept | Readable by | Joins |
| --- | --- | --- | --- | --- | --- |
| 1 | Pseudonym secret (message 0 of a card) | Phone and host, blind | Phone; sealed backup. Deleted when the epoch has ended and no deck pins the card | Nobody | Every pseudonym of that card |
| 2 | Card: signature, attribute values | Host | Phone; sealed backup | The host at issuance (values and signature); nobody after | Its presentations, only through zero-knowledge proofs |
| 3 | Cell: `issuer`, `kid`, `len`, `epoch`, `branches`, card count | Verifier manifest, policy, phone | Every presentation | Every presentation verifier; the public, for logged objects | Every other presentation of the same person in the context. See B1 |
| 4 | Deck nullifiers, `hum/ballot/1 ‖ deck lineage` | Phone | Leader, until final plus 24 hours | Leader | Rounds and replacements of one deck. Nothing outside the deck |
| 5 | Join nullifiers, `hum/join/1 ‖ context lineage` | Phone | Join ticket (sealed to the greeting key); `join-record` in the organizers group | Organizers, moderators, greeter agents | One card to one chat identity in one context for one issuer epoch |
| 6 | Blob-token nullifier, per token key and day | Phone | Store's token issuer, one day | That issuer | One day's issuance in one context |
| 7 | Delivery-token nullifier, per context token key and day | Phone | Delivery service, one day | Delivery service | One day's context-token issuance |
| 8 | Author-once nullifier, per object | Phone | Log, in the bundle, permanently | Anyone | Beside the chat identity key. Nothing else |
| 9 | Author-slot nullifier, per context, window and slot | Phone | Log, in the bundle, permanently | Anyone | One slot |
| 10 | Sponsor nullifier, per sponsor authority | Agent | Log, in the sponsor manifest | Anyone | One sponsor |
| 11 | Issuance nullifier, per asking verifier | Phone | Asking host, as a keyed hash in a dedup row | That host | Two sessions at that host |
| 12 | Dedup row: keyed hash, `lastEpoch`, `kid`, request hash | Host | Host, until 30 days after `lastEpoch` ends | Host | Sessions at that host. Never a context |
| 13 | Session ID, session day, per-address session counter | Host | Host log; the counter in memory for 24 hours | Host; the verifier's own authority gets outcomes | One session |
| 14 | Evidence | Person | Host, sealed to a host key; kept as declared | Host | The person, by design |
| 15 | Chat identity key; safety code | Phone | MLS trees; signed-object bundles; `roles`, `join-record`, reports; sealed backup; chat-only export | Group members; anyone, for signed objects | Every context the person is in; devices; signed objects |
| 16 | Device ID, leaf key, binding, KeyPackage | Phone | MLS trees; KeyPackages as sealed blobs | Group members | One device, across its groups |
| 17 | KeyPackageRef, Welcome handle | Phone, committer | Delivery service, 14 days | Delivery service | A join event. No identity |
| 18 | Group IDs | Creator | Context manifest (two); channel directory (the rest); delivery service | Public (two); members; delivery service | A channel to its context, at the delivery service |
| 19 | Delivery secret, per group epoch | MLS exporter | Delivery service, 48 hours sliding | Members; delivery service | A channel. No member |
| 20 | Token issuer keys and key IDs; tokens and nonces; fetch cookie | Issuers; phone | Issuer directory, context manifest, channel directory; spent nonces at the service | Public; the service | A context or a channel. Blind to the member |
| 21 | Greeting private key | Organizers | `greeting-key` messages in the organizers group | Organizers, moderators, greeter agents | Join tickets |
| 22 | Message ID, salt, franking key, franking tag, stamp, sequence number, receive time | Phone; delivery service | Inside the message; the tag and stamp at the delivery service; `origin` in a logged signed object | Members; the delivery service sees tag, sequence and time | `origin` joins a signed object to a chat message, for members only |
| 23 | Blob CID, file key, salt, delete secret and commitment, file ID | Phone | Store (CID, commitment); references inside MLS or sealed blobs | Store sees CID and commitment per context; members see the reference | A blob to a context. The same CID in two contexts shows a shared member |
| 24 | Keyring epoch secrets; results key; table keys; keybox | MLS exporter; phone; aggregator | Phones; `keyring-share`; the public key in the context manifest; the keybox as a public blob | Members | Releases and sealed text of one context |
| 25 | Edit root; edit keys | Phone | Edit public key in each logged object; root in the backup and the chat-only export | Anyone sees public keys | Versions of one object |
| 26 | Take authority and its keys; byline | Phone | Log; text blob | Anyone | That author's takes. A sealed take shows the author is a member |
| 27 | Context authority and organizer `sign` keys | Admins | Logged keyset; signed requests to aggregators and the delivery service | Anyone | Organizer actions. Not chat identities, in any manifest |
| 28 | `agentKey`; sponsor authority; instance ID | Sponsor | Sponsor manifest; MLS credential | Anyone | The agent's messages, objects and takes |
| 29 | Receipt nonce, commitment, leaf, signature | Phone; Leader | Phone; leaves in public pages | Anyone sees leaves; only the phone knows its own | Nothing. A page fetch shows a `k`-bit prefix |
| 30 | Ballot arrival time; day bucket | Leader | Leader, until final plus 24 hours; noised in the count | Leader | A pseudonym's activity in one deck. See N17 |
| 31 | DAP `report_id`; `hum-authorization` | Phone | Leader and Helper (phase 2) | Both | The Helper links one person's rounds 1 to 3 |
| 32 | Hand, card order, selections, group, map cell | Phone | Phone. The counted part goes in ballots | Leader, as ballot content | — |
| 33 | Shield ledger: deck lineages, pinned cards, states | Phone | Phone only | Nobody | — |
| 34 | Backup file, salt, phrase; write times | Phone | Platform backup | The platform holds ciphertext and sees write times | Rows 1, 2, 15 and 25, with the phrase |
| 35 | Manifest CIDs, lineage CIDs, log index, `issued` | Authors | Log | Anyone | Structure only |
| 36 | Client address; relay connection | Network | Relay (address, 24 hours); gateway (connection) | Relay; gateway | Nothing, unless relay and gateway collude |

### 4.1 Pairs that could join two identities

| Pair | Who holds both | Result |
| --- | --- | --- |
| Cell on a ballot + cell beside a chat key in a signed object | The operator (Leader and public log) | **B1.** Attributes a hand when the cell has one voter |
| Cell on a ballot + cell on a join ticket | An organizer with the Leader | **B1** |
| Cell on an unsigned object + cell beside a chat key | Anyone | Links unsigned objects to a chat name in a one-person cell |
| Ballot arrival time + chat activity time | The Leader with any member | N17. Sharpens B1; not a join alone |
| Deck nullifier + pseudonym secret | The Leader with whoever holds the backup and phrase | N3. The person's ballot in an open deck |
| Join nullifier + anything card-derived | Organizers with any other party | No join. See 4.2 |
| Author-once nullifier + chat key | Anyone | N2. By design; links nothing further |
| Issuance nullifier or dedup row + any context nullifier | A host with any party | No join: different scope; the request hash covers a hiding commitment |
| Token nullifier + ticket post or put | The delivery service or the store | Timing only; the token is blind and the nullifier lasts a day |
| Receipt page fetch + ballot | The Leader's gateway | A `k`-bit prefix on its own connection at a random delay |
| Rating ballot's group slot + source deck | The Leader | The pseudonym's group in the source release. Recorded in `take.md` |
| Roster entry + join time | An organizer who runs the verifier | N16. A roster name to a chat name; no card value involved |
| Blob CID in two contexts | The store | Two contexts share a member. Recorded in `storage.md` |

### 4.2 The `join-record` trace

The organizers group holds, for each admitted chat identity, the join nullifier or nullifiers of the card that admitted it. The question is whether anyone can join that to another observation.

- **Delivery tokens.** The nullifier at context-token issuance has scope `hum/delivery-tokens/1 ‖ token_key_id ‖ day`. It is unlinkable to the join nullifier without the pseudonym secret. The delivery service sees the issuance, then a blind ticket post, then a commit with Welcome handles. An organizer who also has the delivery service's records can pair a chat identity with a one-day token nullifier by time. That nullifier is useless the next day, and ordinary members request context tokens only when joining.
- **Blob tokens.** The same, at the store, for the KeyPackage uploads that precede a ticket.
- **Author-slot nullifiers.** Public and permanent. Unlinkable to the join nullifier without the pseudonym secret. An organizer cannot test whether an unsigned object came from an admitted identity, except through the cell (B1).
- **The issuer's dedup row.** It holds a keyed hash of evidence, a device hash or an issuance-scope nullifier, and the hash of a request that contains only a hiding commitment. An organizer who runs the context's own verifier holds these and the join records. Nothing in one is computable from the other. What they do share is time (N16).
- **The ballot nullifier.** Different scope, held only by the Leader, deleted 24 hours after the final version. The operator who runs the Leader, the delivery service and the log holds deck nullifiers, token nullifiers and public author nullifiers. None matches a join nullifier, which never leaves the organizers group.

Conclusion: no value links a `join-record` to any other observation. Three things do, and none is specific to `join-record`: the cell (B1), time (N16, N17), and the pseudonym secret from a backup and its phrase (N3). Two repairs to the record itself are in S6: store every nullifier of the proof, and delete a record when its identity leaves.

## 5. Registries

### 5.1 Budget

Every published sum, its sensitivity, its ρ and where it is charged. `K` is `cap`, `K_m` `capMovement`, `K_r` `capRatings`, `R` the number of post-close rounds (0 or 3).

| Part | Sum | L2 sensitivity | Enforced on the ballot by | ρ | Gate | Published in |
| --- | --- | --- | --- | --- | --- | --- |
| 0 `tallies` | Three counts per card, one participant coordinate | √(K+1) | B4: at most K non-zero votes | `plan.parts[0]`; plus the tier's ρ when absorbed | `minVoters` | Version 1 |
| 1 `covariance` | Upper triangle of `u uᵀ`, fixed-point | 1 (integer bound `Δ_cov`) | B10: norm and entry bounds | `plan.parts[1]` | 800, on its own `n` | Version 2 |
| 2 `map` | One cell | 1 | B10: one-hot | `plan.parts[2]` | 800 | Version 3 |
| 3 `groups` | Tallies, and ratings when part 6 is planned, in one group slot | √(K+1), or √(K+K_r+1) | B10: bytes equal to round 0's | `plan.parts[3]` | 800; rating decks 300 per group | Version 4; version 1 for rating decks |
| 4 `count` | First ballot per pseudonym, by day | 1 for the whole series | Set by the Leader from arrival time | `plan.parts[4]` ≤ `ctx.count.rhoMax` ≤ 1/50 | None | Daily to organizers; the `count` table in version 1 |
| 5 `movement` | One transition and at most one "moved me" per re-voted card | √(2·K_m) | B5 | `plan.parts[5]` | 300 | Version 1 |
| 6 `ratings` | Three-way count per rated argument | √K_r | B6 | `plan.parts[6]` | 300 | Version 1 |
| 7 `breakdown` | Tallies per attribute value | √(K+1) | Refused in draft 0.1 (B9) | `plan.parts[7]` | 300 per cell | Not published in draft 0.1 |
| 8 `receipts` | One coordinate per round answered | √(R+1) | Set by the Leader | `plan.parts[8]` | None | The padded leaf count of every round |

What was checked:

- **Each part has a ρ inside the plan.** `deck.md` D8 requires parts 0 and 8, a positive ρ for each part, and the sum equal to `plan.rho`. `release.md` R4 requires each part's ρ to equal the plan's and the total to stay at or below `plan.rho`.
- **The plan is charged once, before sending.** `shield.md` reserves `plan.rho` when the deck is opened and moves the entry to `pending` before the first round-0 bytes leave. Rounds and replacements add nothing. A rating deck is a deck and charges its own `plan.rho`, at most 1/20.
- **The yearly bound composes.** Releases are independent mechanisms over one person's data, each `plan.rho`-zCDP at user level, so the total is the sum. `SHIELD_RHO` = 2201/500 converts to ε 20 at δ 10⁻⁶. The conversion is done once on the total, so per-release δ values do not add. The window that defines "yearly" is wrong for long decks (B3).
- **Ballot replacement does not raise sensitivity.** The sum takes the last accepted round-0 ballot per primary nullifier, the receipt tree holds only its leaf, and the daily count takes the first ballot only. A replacement must carry the same nullifier set (B7).
- **Movement and ratings are bounded independently of the counted hand.** A card may be in the movement selection and not in the counted hand. Ratings are reported twice, in part 6 and inside part 3, each under its own ρ.
- **Three noised views of the voter count exist:** `nHat`, the daily running total and the padded leaf count. Each has its own ρ, and composition covers them.
- **Post-processing is free and is only that.** Gate decisions, `final` flags, the `absorb` decision from the noised daily total, axes, centroids, rankings and each part's `n` are functions of noised values.

What is wrong or loose:

| Item | Finding |
| --- | --- |
| The yearly window anchor | B3 |
| The receipt clamp's δ, at most 4·10⁻⁹ per release, outside `plan.delta` | S5 |
| The daily count and the receipt count are published with no voter minimum | S4 |
| An abandoned deck's daily-count ρ is never on the ledger, so `rhoYear` (R14) misses it | N6. Shields are right, because they charge at the first send |
| Exact accepted and rejected counts in the aggregator's logs | S22 |
| A re-enrolled card after an emergency key removal lets a modified client contribute twice | S2. An honest phone cannot |
| `design.md` gives group tallies a sensitivity of √K; `deck.md` has √(K+1) | Section 10 |

### 5.2 Membership-proof scopes and bound messages

The scope string and bound message of every use, read from `credentials.md` ("The uses") and from each spec that uses it.

| Use | Scope bytes | Bound message | Stated the same in | Result |
| --- | --- | --- | --- | --- |
| Ballot | `hum/ballot/1` ‖ deck lineage CID (33) | `hum/ballot-bound/1` ‖ SHA-256(ballot keys 0 to 4) | `ballot.md`, `services.md`, `simulator.md`, threat model | Identical |
| Join ticket | `hum/join/1` ‖ context lineage CID | SHA-256(canonical CBOR of the handles array) | `chat.md` §2.5 | Identical |
| Blob tokens | `hum/blob-tokens/1` ‖ `token_key_id` (32) ‖ day (uint64 big-endian) | SHA-256(canonical CBOR of the `requests` array) | `storage.md` §6.1, `services.md` | Scope identical. `storage.md` does not state the bound message |
| Delivery tokens | `hum/delivery-tokens/1` ‖ `token_key_id` ‖ day | The same | `chat.md` §12.3, `services.md`, `storage.md` §15 | Scope identical. `chat.md` does not state the bound message |
| Signed authorship | `hum/author-once/1` ‖ object CID | `hum/author/1` ‖ object CID | `issue-map.md` | Identical |
| Unsigned authorship | `hum/author-slot/1` ‖ context lineage CID ‖ window (uint64 BE) ‖ slot (uint16 BE) | `hum/author/1` ‖ object CID | `issue-map.md` | Identical. The window length is described two ways (S20) |
| Sponsor proof | `hum/sponsor/1` ‖ sponsor authority CID | `agentKey` (32) | `agent-sponsor.md` body key 10, AS-8 | Scope identical. `agent-sponsor.md` does not state the bound message |
| Issuance evidence | `hum/issuance/1` ‖ asking verifier's authority CID | SHA-256(issuance request plaintext) | `verifier.md` "Evidence item", `verifier-runtime.md` | Scope identical. Neither states the bound message |

- The eight prefixes are distinct and none is a prefix of another. Checked by program over all 46 registry strings.
- A bound message is not prefixed in five uses. That is safe, because the presentation header binds the scope and the bound message together.
- `hum/author/1` is both an Ed25519 payload prefix and a bound-message prefix. The two are different primitives under different keys.
- A verifier that follows only the using spec would build the presentation header with an empty bound message for four uses and fail against a conforming phone (S19).

### 5.3 Floors

Where each floor of invariant 3 is checked, and the paths around it.

| Floor | Phone | Aggregators | Ledger | Paths that skip it |
| --- | --- | --- | --- | --- |
| ρ ≤ 0.254 per release | C3 and D10 at step 10, before the shield is consulted (`ballot.md` B12) | At registration (AG-3, `floor`); the Helper attests the plan and each σ | C3 on the context, D10 on the deck, R4 on the release | None found |
| δ ≤ 10⁻⁶ | C3, D10 | The same | C3, D10, R4 | The receipt clamp (S5) |
| At least 100 noised voters to publish | D10 on the plan; R6 before display | AG-4; R6 | R6 | The daily count; the receipt count below the minimum (S4). A tightened context floor blocks rating decks (S8) |
| One release per deck | R10 against what it has seen | The Helper's attestation 3; AG-4 | R10 on its own history | Two logs (S9); an extension after the close (S3) |
| A declared contribution cap | D14; the counted hand | B4, B5, B6, B10 at intake; Prio3 in phase 2 | D14; R4 recomputes σ from the caps | None found. Round 1 has no cap by design; its norm is bounded |
| Yearly shield ≤ ε 20 | `shield.md` S1 to S12 | Not checked, by design | `rhoYear` (R14), optional and per context | Long decks (B3); a restore onto a second phone (ADR 0023, with the owner); a modified client |

Other paths checked:

- **Below-minimum releases.** Version 1 is logged, final, with no tables and no `nHat`. Parts 0, 4 and 8 record their ρ. The receipt pages are still required (S4).
- **Extensions of `closes`.** The cards, plan and scope are frozen from version 1, and the ballot window stays on version 1's `closes`. An extension before the close only adds voters. An extension after the close is not ruled out (S3).
- **Rating decks.** D15 caps ρ at 1/20 and the cap at 20, and R10 allows two per source release per year. They count toward `rhoYear` and the shield.
- **Breakdown.** Aggregators refuse to register a deck with part 7 and phones refuse to vote in one (`ballot.md` B9). The ledger does not refuse the deck, because the plan is valid. Two of three edges enforce the deferral, which is enough while both aggregators are required.
- **Floors only tighten.** C10 and C13 hold. A context that tightens `minVoters` after a deck is dealt does not change that deck.

### 5.4 Issuer epochs end to end

| Fact | `credentials` | `verifier` | `verifier-runtime` | `services` | `ballot` | `shield` | `deck` | `release` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Period = 28 days; `V` = floor(`validity` / 28 days); epoch = floor(period / `V`) | Yes | Yes | Yes (step 5) | By reference | — | — | — | — |
| Handover = the last two periods; a first session then issues two cards | Yes | Yes | Yes (step 4, rule 11) | Yes in "Issuance"; **V-2 disagrees** (S7) | — | — | — | — |
| The key of epoch E = largest `fromEpoch ≤ E`, read at the start of E's handover | Yes | Yes | Yes (step 7) | Yes | — | — | — | — |
| Dedup row holds `lastEpoch`, `kid`, request hash; kept 30 days past `lastEpoch` | Yes | Yes | Yes (step 6) | Was "`validity` plus 30 days"; **corrected by this review** | — | — | — | — |
| Ballot epoch = epoch of version 1's `closes`, and the card has started | Yes | — | — | Yes (intake check 4) | Yes (B2) | — | Yes | Yes (R2, "Receipts") |
| A pinned card is kept until the deck is `released` or `dropped` | Yes | — | — | — | Yes | Yes | Yes | — |
| A key stays listed while a pinned card may still be presented | Requires it (P3) | **No: retired after 30 days** (S1) | — | — | — | — | — | — |
| A logged presentation is checked at its log position | **No: "when verified"** (B2) | Yes | — | — | — | — | — | — |

`simulator.md` said cards are re-issued "each 28-day period"; corrected by this review. `chat.md` §2.5 and its open question 16 state the one-identity-per-epoch bound correctly.

### 5.5 Labels and namespaces

*The three strings shown below as `manifest/1`, `keyring/1` and `delivery/1` were renamed under `hum/` after this table was written.*

**Domain-separation strings.** The registry in `services.md` against every spec, after this review's two corrections (one stale entry removed, one missing entry added):

| String | Kind | Owner | Also used in |
| --- | --- | --- | --- |
| `manifest/1` | COSE external AAD | `manifest.md` | `services.md`, `issue-map.md`, `take.md`, `agent-sponsor.md` |
| `hum/service-request/1` | COSE external AAD and hash prefix | `services.md` | `storage.md`, `chat.md`, `release.md` |
| `hum/receipt/1` | Ed25519 payload prefix | `services.md` | `ballot.md` |
| `hum/dap-task/1` | Hash prefix | `services.md` | `ballot.md`, `release.md` |
| `hum/log/`, `hum/witness/` | Name prefixes | `services.md` | — |
| `hum/ballot/1` | Proof scope | `ballot.md` | `credentials.md`, `services.md`, `simulator.md` |
| `hum/ballot-bound/1` | Bound-message prefix | `ballot.md` | `credentials.md` |
| `hum/receipt-leaf/1` | Hash prefix | `ballot.md` | `services.md`, `release.md` |
| `hum/credential/1` | BBS header prefix | `credentials.md` | — |
| `hum/presentation/1` | BBS presentation header prefix | `credentials.md` | — |
| `hum/nullifier/1` | Hash prefix | `credentials.md` | — |
| `hum/nym-share/1` | HKDF salt | `credentials.md` | `verifier-runtime.md`, `services.md` |
| `hum/issue/1` | HPKE info | `credentials.md` | `services.md` |
| `hum/issue-response/1 key`, `… nonce` | HPKE export labels | `credentials.md` | `services.md` |
| `hum/backup/1` | HPKE info | `credentials.md` | — |
| `hum/issuance/1` | Proof scope | `verifier.md` | `credentials.md`, `verifier-runtime.md` |
| `hum/sponsor/1` | Proof scope | `agent-sponsor.md` | `credentials.md` |
| `hum/attest/1` | Hash prefix | `agent-sponsor.md` | `chat.md` |
| `hum/author/1` | Ed25519 payload prefix; bound-message prefix | `issue-map.md` | `take.md`, `agent-sponsor.md`, `chat.md`, `credentials.md` |
| `hum/edit/1` | Ed25519 payload prefix | `issue-map.md` | — |
| `hum/edit-key/1` | HKDF salt | `issue-map.md` | — |
| `hum/author-once/1`, `hum/author-slot/1` | Proof scopes | `issue-map.md` | `credentials.md` |
| `hum/take-query/1` | Hash prefix | `take.md` | `services.md` |
| `hum/sealed/1` | AEAD AAD prefix | `storage.md` | `chat.md` |
| `hum/keyring-blob/1` | HKDF info | `storage.md` | — |
| `hum/delete/1` | Hash prefix | `storage.md` | — |
| `hum/blob-delete/1` | COSE payload prefix | `storage.md` | — |
| `hum/blob-tokens/1` | Proof scope | `storage.md` | `credentials.md`, `services.md` |
| `hum/results-key/1` | HKDF info | `context.md` | `storage.md` |
| `hum/results-keybox/1` | HPKE info | `release.md` | `storage.md` |
| `hum/delivery-tokens/1`, `hum/join/1` | Proof scopes | `chat.md` | `credentials.md`, `services.md` |
| `hum/join-ticket/1` | HPKE info | `chat.md` | — |
| `hum/device/1` | Ed25519 payload prefix | `chat.md` | — |
| `hum/safety/1`, `hum/welcome/1` | Hash prefixes | `chat.md` | — |
| `hum/chat-roles/1` | COSE payload prefix | `chat.md` | — |
| `hum/frank/1`, `hum/commit/1`, `hum/token-request/1` | HMAC prefixes | `chat.md` | — |
| `hum/pp-issuer/1` | HKDF info prefix | `chat.md` | — |
| `hum/stamp/1` | Ed25519 payload prefix | `chat.md` | — |
| `keyring/1`, `delivery/1` | MLS exporter labels | `chat.md` | `storage.md`, `manifest.md` |

No two strings are equal and none is a prefix of another. Every string in a spec is in the registry. `hum/reissue/1` appears only as withdrawn. `hum/predicate-blind/1` was in the registry and in no spec; removed. No string exists for sealing evidence (S17).

**Keys that sign under more than one string.** A chat identity key signs `hum/device/1` and `hum/author/1` payloads. An `agentKey` signs `hum/author/1` payloads and MLS content, which MLS labels itself. A service's `sign` key signs COSE structures, and for a delivery service raw `hum/stamp/1` messages, for an aggregator raw `hum/receipt/1` messages, for a log C2SP notes. A COSE `Sig_structure` begins with a CBOR array header and never with the byte `h`, so the forms cannot collide.

**Namespacing the three bare strings (S10).**

- *What it buys.* One rule that a lint can check. No shared string with another protocol that uses `manifest/1` or `keyring/1` under keys that might be reused.
- *What it costs today.* Three constants in `reference/` (`cose.py`, `storage.py`), one `just vectors` run that changes every signed bundle and the keyring exporter vector, and text edits in `manifest.md` (four places, owner), `chat.md` §1.2 and its table, `storage.md` §4.1 and §4.4, the registry, the "Adopted" line in `DECISIONS.md`, and ADRs 0050, 0060 and 0082. No Rust, Go or app code signs anything yet.
- *What it costs after wave 1.* Every implementation, every vector and every logged manifest.
- *Recommendation.* Rename all three now: `hum/manifest/1`, `hum/keyring/1`, `hum/delivery/1`. If the owner will not reopen an adopted string, rename only the two exporter labels. MLS already prefixes exporter labels internally, so the exporter risk is small; the gain there is the single rule.

**CBOR key ranges.** Each map has its own key space, so no range collides with another.

| Map | Keys | Defined in |
| --- | --- | --- |
| Envelope | 0–9. No key for retired, successor or superseded (S14) | `manifest.md` |
| Bundle; proof | 0–4; 0–3 | `services.md` |
| Error | 0–4 | `services.md` |
| `service` body | 0–11 common, 12–15 reserved, 16 and up per kind. Store: 16–19. Delivery: 16 | `services.md`, `storage.md` §7, `chat.md` §12.1 |
| `context` body | 0–19; `perms` 0–2; `floors` 0–5; log entry 0–1; `storage` 0–5; `chat` 0–4; `count` 0; `map` 1–3; `agents` 0–2 | `context.md` |
| `deck` body | 0–7; card 0–3; plan 0–14; part IDs 0–8 | `deck.md` |
| `release` body | 0–15; part record 0–2 | `release.md` |
| `issue`, `position`, `argument` body | 0–9; `authorship` 0–6 | `issue-map.md` |
| `take` body | 0–7; text blob 0–3; query 0–1; series 0–7; chart 0–5 | `take.md` |
| `agent-sponsor` body | 0–11; `rateLimits` 0–3; `attestation` 0–3 | `agent-sponsor.md` |
| `verifier` body | 0–16; issuer key 0–4; host key 0–2; attribute 0–6; evidence 0–7; dataset 0–4; dedup 0–2; revocation 0–1; code 0–3; build recipe 0–7 | `verifier.md`, `verifier-runtime.md` |
| `trust-list` body | 0–7; scope 0–2; entry 0–5; removal 0–2 | `trust-list.md` |
| Presentation; card proof; issuance request; response; card entry | 0–3; 0–5; 0–4; 0–3; 0–3 | `credentials.md` |
| Backup; chat-only export | 0–5; 0–2 | `credentials.md` |
| Ballot; payload | 0–5; 0–3. Round 3 reuses payload keys 0–2 with other meanings | `ballot.md` |
| Sealed reference | 0–10 | `storage.md` §3 |
| Token request; delete order; order wrapper; folder index; file; version | 0–2; 0–4; 0–1; 0–1; 0–4; 0–3 | `storage.md` |
| MLS credential identity; handle; join ticket; history record | 0–7; 0–1; 0–4; 0–8 | `chat.md` |
| Chat content bodies | Key 0 is the version, except `public-copy` and `keyring-share`, which `storage.md` owns | `chat.md` §5 |
| Delivery-service bodies | Integer keys, per endpoint | `chat.md` §12 |
| Aggregator, log, host, resolver and gallery bodies | **Names only, no keys** (S16) | `services.md` |

`context.md`'s `map` starts at key 1 and key 0 is unused. It looks like the slot of the window field that was removed (S20). Say so, or renumber before vectors exist.

**Type names.** `keyset`, `verifier`, `trust-list`, `context`, `deck`, `release`, `issue`, `position`, `argument`, `take`, `agent-sponsor`, `service`, and `blob-store` (to retire). Service kinds: `log`, `witness`, `aggregator`, `issuer`, `delivery`, `blob-store`, `resolver`, `relay`, `gallery`. No collisions. `manifest.md` lists ten types and lacks `service`.

**Media types.**

| Type | Used for | Defined in |
| --- | --- | --- |
| `application/cbor` | Default for service bodies; token issuance | `services.md`, `storage.md` |
| `application/vnd.hum.bundle+cbor` | Manifest bundles | `services.md` |
| `application/vnd.hum.error+cbor` | Errors | `services.md` |
| `application/vnd.hum.ds+cbor` | Delivery-service bodies | `chat.md` |
| `application/vnd.hum.sealed` | Every sealed blob | `storage.md` |
| `application/vnd.hum.<name>+cbor`, twenty names | Chat content types | `chat.md` §5.2 |
| `application/vnd.hum.folder-index+cbor` | Both the announcement part and the snapshot blob | `chat.md`, `storage.md` |
| `application/vnd.hum.delete-order+cbor` | Delete orders | `storage.md` |
| `application/vnd.hum.keybox+hpke` | Release keybox | `release.md`, `storage.md` |
| `application/vnd.hum.mls-key-package`, `…mls-ratchet-tree`, `…history+cbor-seq` | Sealed plaintext types | `chat.md` |
| `application/hum-take+cbor` | Take text blob. **Not `vnd.hum`, and not in the store's defaults** (S13) | `take.md` |
| `application/vnd.apache.parquet` | Release tables | `release.md` |
| `text/plain; charset=utf-8` | Statements, issue-map text. `chat.md` writes it without the space | `issue-map.md`, `deck.md` |
| `text/markdown;variant=GFM-MIMI`, `application/mimi-content` | Chat text | `chat.md` |
| None declared | Receipt pages, receipt root blob, `code`, `build`, dataset blobs, attestation reports | S13 |

**Other names.**

| Kind | Names |
| --- | --- |
| HTTP headers | `Hum-Authority`, `Hum-Nonce`, `Hum-Issued`, `Hum-Context`, `Hum-Retention`, `Hum-Delete`, `Hum-Delete-Secret`, `Hum-Expires` |
| URI schemes | `hum:member:`, `hum:channel:`, `hum:blob:` |
| MLS | Exporter labels `keyring/1`, `delivery/1`; GroupInfo extension `hum_tree_ref`, type 0xF001 (private use) |
| MIMI | Extension key `hum.frank` |
| DAP | Report extension `hum-authorization` |
| Privacy Pass | Token types 0x0001 and 0x0002; directory member `hum-context` |
| Parquet metadata | `hum.spec` (= `release/1`), `hum.deck`, `hum.part`, `hum.rho`, `hum.sigma`, `hum.noise_sd`, `hum.n_hat`, `hum.n`, `hum.cov_scale`, `hum.attribute`, `hum.lambda1`, `hum.lambda2`, `hum.half_x`, `hum.half_y`, `hum.grid`, `hum.m`, `hum.k`, `hum.blur`, `hum.threshold_sigma` |
| Verifier runtime | Worlds `hum:verifier/module@0.1`, `hum:verifier/host@0.1`; format `wasm-component/1` |
| Algorithm names | `bbs-bls12381-sha256`, `hpke-x25519-sha256-chacha20poly1305` |

## 6. Formats that cross specs

| Format | Specs | Result |
| --- | --- | --- |
| Sealed reference and `ExternalPart` | `storage.md` §3, `chat.md` §5.1 | Agree field for field: `url` = `hum:blob:` plus the CID text, `encAlg` 1, empty `nonce` and `aad`, the reverse rule. `storage.md` §2 named a KeyPackage type without `vnd.hum`; corrected |
| Ballot frame | `ballot.md`, `services.md` | Agree: `uint32be(len) ‖ ballot ‖ zeros`, 49,152 bytes, presentation at most 8,192. The error for an oversized presentation differs (S21) |
| Receipt leaf | `ballot.md`, `services.md`, `release.md` | Agree |
| Receipt signature | `ballot.md`, `services.md` | Agree on the message. The signing key is not identified (S16) |
| Receipt pages and root blob | `release.md`, `services.md`, `ballot.md` | Agree on `k`, sorting and page assignment. The root blob has no encoding (S16). Required below the minimum, against R6 (S4) |
| DAP task ID and `report_id` | `ballot.md`, `services.md`, `release.md` | Agree after this review's edits to two stale sentences |
| Issuance request and response | `credentials.md`, `services.md`, `verifier-runtime.md` | Agree on keys, the per-card `kid`, HPKE info, the export labels and the session ID as AAD. V-2 disagrees (S7). Evidence `info` and the rejection code are undefined (S17) |
| Error format and codes | `services.md`, `storage.md` §6.7, `chat.md` §12.8 | Agree. Every code the two siblings use is in the table |
| Bundle and COSE_Sign | `manifest.md`, `services.md`, ADR 0082 | `services.md` and the reference agree: one COSE_Sign, detached payload = CID, external AAD `manifest/1`. `manifest.md` reads as if the string were part of the payload (section 10). `issue-map.md` said "`signatures` array"; corrected |
| Other COSE signatures | `chat.md` §5.8, `storage.md` §8.2 | A different placement of the domain string, `external_aad` unstated (S11) |
| `service` manifest body | `services.md`, `storage.md` §7, `chat.md` §12.1 | Common keys agree and no kind uses a key below 16, as ADR 0072 asks. The `delivery` kind has no rules (S18) |
| Agent credential and membership event | `agent-sponsor.md`, `chat.md` §2.1, §3.3, §5.12 | Agree on the credential, the attestation binding, runtime codes, the host rule, capability codes and the sponsor-version rule. Both described the name cap wrongly; corrected |
| Results key and keybox | `context.md`, `storage.md` §4.4 and §9.1, `release.md`, `services.md` | Agree on the derivation, the HPKE suite, `info`, `aad`, the byte layout and the media type |
| Token issuance body | `storage.md` §6.2, `chat.md` §12.3, `services.md` | Agree. Bound message unstated in the owners (S19) |
| Authorship field | `issue-map.md`, `services.md`, `take.md` | Agree. One `nullifier` field for several nullifiers (S6); agent takes by reference only (N13) |

## 7. Coverage

Read against `conformance.md` as it stood at 15:48 on 2026-10-06. The reference has since gained body modules for most types, so this list will shrink.

**Covered:** deterministic CBOR; CIDs; the envelope and all eleven verification steps; keysets, rotation and revocation; log leaves, proofs, checkpoints and cosignatures; the bundle's signature form; the sealed format, padding, references, keyring keys and the delete commitment; the release numbers (accounting, σ per part, plan rules D8, D9 in part, D10, D11, D14, floors C3, C4, C10, the cap, gates, phone-side rounds, rankings, the sampler harness).

**Listed there as gaps:**

| Area | Rules with no vector |
| --- | --- |
| `manifest.md` | Retired and successor lineages; frozen fields per type |
| `services.md` | The `authorship` bundle; the `service` body; the witness protocol; A-1 to A-4; task IDs; the receipt signature; error encoding; padding buckets |
| `storage.md` | Folders (§5); delete orders (§8.2); the store API (§6); the store manifest body (§7) |
| `deck.md` | D1 to D7, D9 (refs), D12, D13, D15 |
| `context.md` | C1, C2, C5 to C9, C11 to C15 |
| `release.md` | R1 to R15, tables, rounds, receipts; eigenvectors, blur and k-means |
| `credentials.md`, `ballot.md` | Everything |

**Not in the coverage table at all:**

| Spec | Rules |
| --- | --- |
| `credentials.md` | P1 to P8, issuance checks, epoch edges, nullifier derivation, the backup |
| `ballot.md` | B1 to B13, the frame, receipts, the DAP mapping, client-side selections |
| `shield.md` | S1 to S12. The table's `release/shield/*` "follows the design doc" and predates `shield.md`'s ledger in ρ |
| `chat.md` | All twenty vector sets of §16 |
| `issue-map.md` | IM-1 to IM-15, the `authorship` encodings, the edit-key derivation |
| `take.md` | TK-1 to TK-9, the noise math, ranking |
| `agent-sponsor.md` | AS-1 to AS-9 and the commit cases |
| `verifier.md`, `verifier-runtime.md`, `trust-list.md` | Rules 1 to 28, 1 to 16 and 1 to 13; the disclosure summary; row resolution |
| `context.md` | Policy evaluation, daily-count buckets, the results key |
| `release.md` | The keybox |
| `services.md` | S-5 to S-8 (the table names S-1 to S-4 only), LG-8, O-5, the bootstrap rule, T-1, receipt pages |
| `storage.md` | `external-part-bad-*`, the two `keyring-share` rejections, `range-c-from-size` |

**Stale statements in the snapshot:** "shield.md has not landed"; "`ballot.md` and the credential spec have not landed"; disagreement 1 (COSE_Sign1) and disagreement 2 (ε at `RHO_MAX`), both since settled on disk; "LG-1 to LG-7", where `services.md` has LG-8.

**Findings of this review that need a vector once decided:** B2 (an object verified in a later epoch), B3 (the window for a long deck), S1 (a round-1 ballot under a key past its last epoch), S3 (an extension logged after a release), S4 (receipts below the minimum), S6 (a ticket with two nullifiers).

## 8. Federation and invariant 6

Checked: every place a service is named, discovered or trusted.

**Holds.**

- A context names logs, aggregators, stores, the delivery service and issuers by authority CID. No context, deck, release or trust-list field holds a hostname.
- A phone accepts an OHTTP key configuration only from a logged `service` manifest (O-2), a token issuer key only from the context manifest or the channel directory, and a checkpoint only with the context's own witness threshold.
- `ExternalPart.url` must be `hum:blob:` plus a CID. A message cannot point a phone at a host.
- DAP task parameters come from the deck manifest. There is no provisioning API.
- The bootstrap constants are keys and CIDs: the Global context CID, the reference log's authority, origin and launch witness keys, and the reference relays' authorities. After the first checkpoint, Global's logged witness list governs.
- Core verifiers and the core trust list have no special standing. A context pins a list by CID or names an issuer.

**Gaps.**

| Item | Finding |
| --- | --- |
| Resolvers and extra relays "the context names" have no field | S15 |
| The first request needs an endpoint and a gateway key configuration that only the log can vouch for | S15. Ship the signed bundles with the app |
| One release per deck and `rhoYear` are per log | S9 |
| `service` manifests carry `endpoints` and an issuer name in a signed body | N10 |
| Rule 20e ties a profile to "the reference operator's binary" by nothing but the manifest's own ref | N9 |
| The Global context CID and the reference authorities are not yet written down anywhere | For `DECISIONS.md` when the reference network exists (`deck.md`, `issue-map.md`) |
| A channel lives on one delivery service; moving a context means new channels | Stated in `chat.md` §12.1. The design doc's "can be swapped" should say at what cost |

## 9. Editorial edits applied

Fifty-two edits in thirteen files (fifty-six occurrences, because four rule ranges in `simulator.md` appear more than once). Each fixes a stale cross-reference, a wrong rule number, a status line that a later spec made false, or a restatement that no longer matched the owning spec. None changes a rule.

| File | Section | Edit |
| --- | --- | --- |
| `services.md` | "Services are named by key" | Stamp reference `chat.md` §12.5 → §12.6 |
| `services.md` | "Tokens" table | Context tokens point to `chat.md` §12.3 and list all three uses; channel tokens §12.4 → §12.5 |
| `services.md` | "What services log" | Delivery row `chat.md` §12.8 → §12.9; the simulator pointer now names `simulator.md` |
| `services.md` | "Domain strings and scopes" | `hum/dap-task/1` is "per round and part"; removed `hum/predicate-blind/1`, which no spec defines; added `hum/join-ticket/1` |
| `services.md` | "Rounds, tasks and nullifiers" | "Each round is one DAP task" → "Each release part of a round is one DAP task" |
| `services.md` | "Ballot intake" check 4; "Renewal and revocation" | Two dead anchors to `credentials.md` now point at "Validity" |
| `services.md` | "Issuance" | Dedup retention "for `validity` plus 30 days" → "until 30 days after its `lastEpoch` ends", as `verifier.md` defines |
| `services.md` | "Delivery service and blob store" | `chat.md` §12.8 and §12.9 → §12.9 and §12.10 |
| `services.md` | "Conformance and vectors" | Simulator pointer now names `simulator.md` |
| `chat.md` | §12.1 | Token rules "T-1 to T-3" → "T-1 to T-4" |
| `chat.md` | §17 | `ballot.md` and `shield.md` are no longer "not yet written"; the agent label fits "inside the credential's 256-byte `name` cap" |
| `agent-sponsor.md` | "Body", key 7 | The credential `name` cap is 256 bytes, not 64 |
| `context.md` | "Scope" | `credentials.md` is linked and no longer "not yet written" |
| `context.md` | "Open questions" | `agent-sponsor.md` reads `agents.addRole`; heading "specs not yet written" → "sibling specs" |
| `deck.md` | "Scope"; "Vectors" | `ballot.md` and `shield.md` are linked and no longer "not yet written" |
| `release.md` | "Scope"; "Open questions" | `ballot.md` linked; DAP task IDs "per round and part" over the deck lineage CID; heading as above |
| `release.md` | "Rounds", "Who may act" | The Leader keeps the nullifier set "until 24 hours after the final version", as "Receipts" and AG-5 say |
| `ballot.md` | "Replacement in round 0"; "Rounds 1 to 3" | `services.md` intake checks renumbered: "1 and 6" → "2, 3 and 7"; "check 3" → "check 4" |
| `credentials.md` | "Scopes and nullifiers", rules | "nothing starts with `hum/author-`" → "no ballot scope starts with `hum/author-`" |
| `credentials.md` | "Renewal"; "Open questions" | V-3 named as the former reissue rule; intake check 3 → 4 |
| `simulator.md` | "Adversarial hooks"; "Protocol checks"; plug-in table | Rule ranges match `services.md`: LG-1 to LG-8, AG-1 to AG-8, V-1 to V-3, O-3 to O-5; intake "step 3" → "check 4" |
| `simulator.md` | "Leak checks"; "Assumptions" | The canary is `storage.md` §11; cards are re-issued each issuer epoch, not each period |
| `shield.md` | "Open questions", last bullet | The simulator now models the per-deck nullifier and a restore |
| `storage.md` | §2 | Example type `application/vnd.hum.mls-key-package` |
| `storage.md` | §14 (A6); §15 (question 2) | The membership proof exists in `credentials.md`; the exporter-MAC fallback is not used |
| `issue-map.md` | "The `authorship` bundle field"; "Assumptions" | `signatures` is a field, not an array; merge proposals are `merge-proposal` messages |
| `trust-list.md` | "Example" | The sample policy used a three-value set, which `context.md` C5 rejects; it now uses `area` with one value |

Not edited, and left for their owners: `manifest.md`, `design.md`, `threat-model.md`, `conformance.md`, anything in `reference/`, `vectors/` or `sim/`.

## 10. Edits needed in files this review does not own

### `manifest.md`

| # | Section | Edit |
| --- | --- | --- |
| 1 | "The envelope", "Versions and lineage" | Assign envelope keys for the retired marker, the successor lineage and the superseded lineage. Say what a retired version's body holds. Reconcile with the body-level `retired` in `take.md` and `agent-sponsor.md` |
| 2 | "The envelope", Domain separation; "Verification" step 6; "Security considerations" | State that `manifest/1` is the COSE `external_aad` and the detached payload is the CID (ADR 0082). Rename if ADR 0105 is accepted |
| 3 | "The envelope" | Define the bundle wire format, or point to `services.md` "The bundle" |
| 4 | "Authorities and keys" | A keyset's version 1 has no `authority` field and is signed by its own `rotate` threshold (ADR 0082). List who has authorities today: add take authors, delivery services, blob stores, witnesses, relays, resolvers, issuer hosts |
| 5 | "Type registry" | Add `service` and its kinds; retire `blob-store` (ADR 0072). The count is no longer ten |
| 6 | "Type registry", `release` | The envelope `authority` is the Leader, the body names the Helper, step 6 needs both keysets' thresholds, and no key may be in both (ADR 0010, `release.md` R2, R9) |
| 7 | "Type registry", other rows | `deck`: pins `card/<i>` refs and `source`, not a "statement list". `take`: signed by the author's authority or an agent key. `verifier`: pins `code`, `build`, `profile` and dataset blobs. `agent-sponsor`: pins `verifier` and `report`. Participant-authored types: four author forms, authorship in the bundle |
| 8 | "The envelope", deck example | No `aggregators` or `statements` ref; `rho` as `"127/500"`; `parts` as a map of ρ; add `minVoters` |
| 9 | "Versions and lineage", Frozen fields | A deck is frozen from version 1, not from when it opens |
| 10 | "References and resolution", Pinned | Some refs name a lineage by its version-1 CID (`parent`, `replaces`, `mergedInto` in `issue-map.md`). Body fields may name authorities (trust lists, contexts) |
| 11 | "Verification" | Step 6 variants. Logs run the step-9 reference rule and step 10 for every type. `issued` is load-bearing in `release.md` R10, R13, R14 and in the unsigned-slot window |
| 12 | "Privacy floors" | A below-minimum release is logged with no tables, not refused. Name the daily count per ADR 0103. The shield is a sliding window in ρ |
| 13 | "Blobs and storage" | Two sealed formats, the salt header, the AAD string, the self-delimiting pad; reference forms; point to `storage.md` |
| 14 | "Transparency logs" | Leaf format, C2SP formats, the context's witness threshold, the bootstrap constants; point to `services.md` |
| 15 | "Open questions" | Mark as settled: batching (0041), one log (0071), editing (0042), verifier runtime (0031), re-keying (0062), service types (0072), keyring history |
| 16 | "Scope" | Link `../design.md`, not an external artifact URL |

### `design.md`

| # | Section | Edit |
| --- | --- | --- |
| 1 | "Privacy model and trust", three identities | The voting pseudonym is per deck and comes from a BBS credential. Drop "Semaphore-style" and "per-context nullifier" (ADRs 0020, 0021) |
| 2 | Same | The resident card is issued once per issuer epoch, with evidence at each renewal (ADR 0026) |
| 3 | "Verifiers" table | Issuance: the issuer sees the attributes and the signature, never the pseudonym secret. Presentation: one nullifier per use, per deck for a ballot; the issuing verifier and the policy branch are visible (B1) |
| 4 | Who-sees-what, delivery service | Add: which context a channel belongs to, the message class, the epoch rate, Welcome and ticket counts, token issuance counts (`chat.md` §12.10) |
| 5 | Who-sees-what, other rows | Aggregator phase 1: arrival times, successive hands, the cell. Add rows for the log and the token issuers. Organizer: the join nullifier beside a chat identity |
| 6 | "Differential privacy design" | Three post-close rounds and up to four release versions (ADR 0014). Add the count, receipts, movement and ratings parts. Group tallies sensitivity is √(K+1). The counted hand is the first K cards cast |
| 7 | Unlock table | Movement and ratings unlock at 300. Breakdowns are off in draft 0.1 |
| 8 | "Contexts, permissions and platform rules" | The shield is a sliding 365-day window. "Organizers" for results is reserved. Members always see their groups' MLS trees. "Pseudonyms are per context" → per deck. Rating decks add releases |
| 9 | "Chat layer" table | Channel membership is proven to the delivery service by a per-epoch secret and blind tokens; credentials prove context membership at join and at token issuance |
| 10 | "Vision", "Product and UX" | The chat identity key is a software key in the sealed backup; device keys are in secure hardware (ADR 0023) |
| 11 | "Protocol stack" table | The ledger is a Merkle log with witnesses and is the same log as the manifest log (ADR 0071). Moving a delivery service means new channels |
| 12 | "Open data platform" | Mark product analytics, competitions and synthetic tables as later than draft 0.1 |

### `docs/threat-model.md`

| # | Section | Edit |
| --- | --- | --- |
| 1 | "A malicious verifier", Remains | The issuer is always presented. Rewrite after ADR 0100 |
| 2 | "Colluding servers", organizer and aggregator | Not "still unlinked" when a cell is small. Rewrite after ADR 0100 |
| 3 | "The operator", the identity link | The log receives a chat identity key, a card-derived nullifier and the public card fields in one bundle; the organizers group holds a join nullifier beside a chat identity |
| 4 | Party table, delivery service | The anchor is `chat.md` §12.10, not §12.9 |
| 5 | "Invariants and how they are tested"; "Assumptions about sibling specs" | `simulator.md` and `conformance.md` have landed |
| 6 | "A malicious or compromised agent" | The class rule is `verifier.md` rule 1 and `trust-list.md` step 5, not "verifier.md rule 2" |
| 7 | "Open questions" | Name the first-ballot timing pair (N17) |

### Other

- **ADR 0072** lists a `gateway` kind and a `stamp` field that `services.md` dropped.
- **`credentials.md`**, "Vectors", P3: "a `verify-only` key accepted" names a key state `verifier.md` no longer has. Left for W0-02, who is editing the file.
- **`release.md`**, "Open questions": the sentence about table keys reaching members over MLS describes an older `services.md`.
- **`verifier.md`**, "Issuer key": "If W0-02 recommends a group-proof scheme" is settled by ADR 0020.

## 11. Owner decisions

Each group is one ADR in `docs/decisions/`, with a line in `docs/DECISIONS.md`.

| ADR | Decision needed | Findings |
| --- | --- | --- |
| `0100-w0-10-issuer-and-branch-cells.md` | Whether draft 0.1 restricts a context to one issuer-and-branch cell, restricts ballots only, waits for a hidden-issuer proof, or accepts and discloses | B1, N1, N7, N17 |
| `0101-w0-10-logged-presentations-and-time.md` | Approve the rule for presentations stored in the log: clock at submission, log position afterwards | B2 |
| `0102-w0-10-shield-window-and-padding-delta.md` | Anchor a shield entry to its release; count the receipt clamp's δ inside the plan | B3, S5 |
| `0103-w0-10-floor-exceptions-and-closes.md` | What may be published below the voter minimum; when `closes` may move; the rating-deck minimum; the ledger of record | S3, S4, S8, S9, N6 |
| `0104-w0-10-epochs-across-decks.md` | How long an issuer key stays listed; what an emergency removal does to open decks; V-2; nullifier sets for `entry` uses | S1, S2, S6, S7, N3, N4 |
| `0105-w0-10-names-and-encodings.md` | Namespace the three bare strings; one COSE convention; the enumeration rule; media types | S10, S11, S12, S13 |
| `0106-w0-10-manifest-and-design-edits.md` | Apply the edit lists of section 10 to `manifest.md`, `design.md` and the threat model | S14, S24, N10, N11, N14 |
| `0107-w0-10-discovery-and-wire-gaps.md` | Two context fields, shipped bootstrap bundles, integer keys for `services.md` bodies, and nine smaller alignments | S15 to S23, N12, N13 |

Notes N2, N5, N8, N9, N15, N16 and N18 need no decision. They are recorded here so the next reader does not rediscover them.

## 12. Decisions applied after review

Applied on 2026-10-06 after the owner's go-ahead, relayed by the team lead. Every item touches a seam and is pending the owner's review of the diff. Nothing is committed. `docs/design.md`, `reference/`, `vectors/`, `sim/` and `conformance.md` were not edited.

### 12.1 What closed each blocker

| Blocker | Closed by |
| --- | --- |
| B1 | `context.md` rule C16: in draft 0.1 neither `entry` nor `vote` has an `any` node, and each `attr` leaf's source resolves to exactly one verifier authority. Scope: the whole context, not ballots only |
| B2 | `credentials.md` "Validity", third row, with P3, P5 and the definition of "in force": clock at the log, `issued` and log position afterwards |
| B3 | `shield.md` "Window": the anchor is the final release seen (capped at `expires`), or `expires` |

What remains after B1: for one hour after an issuer's epoch turns, join, token and authorship presentations may show either of two epoch values; two versions of a context with different policies show different fields; and the first ballot's arrival time. The number of cards does not remain: with no `any` node and one verifier per leaf it equals the number of distinct authorities the policy names, for every member.

### 12.2 Files and sections changed

| Item | File | Section |
| --- | --- | --- |
| ADR 0100 | `context.md` | "Body fields" via "Entry policy" (source bullet, new "One cell per context" bullet, the "who can join" table); rule C16; "Where these plug in"; the example and its reading; vectors (C16, policy-evaluation note); "Security considerations" |
| | `credentials.md` | "Three identities, never linked"; "Validity" (anonymity-set sentence); "What is proven" (`any` bullet, card choice, the wards paragraph); P6; "Every identifier" (public card fields, `branches`, fields beside the chat identity); "Security considerations" (new row); vectors (`cred-present-entry-one-cell`, P6 cases); "Open questions" |
| | `ballot.md` | "What leaves the phone" (All row); "What the aggregator learns" (public-fields row, "Who holds a nullifier" row rewritten); "Security considerations" (first bullet); B12 rule range |
| | `issue-map.md` | "Signatures under `hum/author/1`" (both paragraphs); "Posting" step 2; "Security considerations" (public-card-fields row) |
| | `chat.md` | §2.5, the paragraph after the flow |
| | `trust-list.md` | "How a context uses trust lists", new step 7 |
| | `release.md` | "Example", the `assurance` sentence |
| | `services.md` | "Step 10 at the log" and "Opening a deck": C1 to C16 |
| | `docs/threat-model.md` | "A malicious verifier" (Remains); "Colluding servers" (organizer and aggregator row; new aggregator and log row); "The operator" (identity link); three stale references |
| ADR 0101 | `credentials.md` | "Validity" (new row, grace sentence); "Format" (`kid`); P5; "in force"; "Where the rules run"; vectors (logged P3 and P5 cases) |
| | `issue-map.md` | "Validation rules" (log and phone bullets); IM-6; vectors |
| | `agent-sponsor.md` | AS-8; vectors |
| | `manifest.md` | "Verification" step 9 |
| | `deck.md` | D7 |
| | `services.md` | "What the log runs" |
| ADR 0102, item 1 | `shield.md` | "The budget" (Window); "The ledger" (`settledAt`, `expires`, spent ρ); "Composition"; "Restore" steps 1 and 2; S2, S8, S9; vectors (`shield-window`, `shield-long-decks`); simulator scenario list; "Open questions"; assumptions |
| | `credentials.md` | "The sealed backup", Contents: how long a left context stays listed |
| ADR 0105, item 1 | `manifest.md`, `chat.md`, `storage.md`, `services.md`, `issue-map.md`, `take.md`, `agent-sponsor.md`, `docs/threat-model.md` | Every occurrence (32 in the specs). `chat.md` "Domain strings and labels" and `services.md` "Domain strings and scopes" now say every string is under `hum/` |
| | ADRs 0010, 0050, 0051, 0060, 0082; `docs/DECISIONS.md` | Quotations of the three strings |
| `manifest.md` list | `manifest.md` | "Scope"; "The envelope" (bundle pointer, `authority` on keyset version 1, domain separation as `external_aad`, the deck example); "Authorities and keys" (keyset version 1, who has authorities); "Versions and lineage" (frozen fields, retiring); "Verification" step 6 (keyset, release and authorship variants); "Type registry" (`service` added, `blob-store` retired, rows for `verifier`, `deck`, `release`, participant-authored types, `take`, `agent-sponsor`; the two-signer bullet); "Open questions" |
| | `services.md`, `storage.md`, `deck.md` | Sentences that said the registry still needed these edits |
| Status | ADRs 0100, 0101, 0102, 0105, 0106, 0072; `docs/DECISIONS.md` | Status lines; applied items moved under "Adopted in the docs"; what stays open listed under "Open" |

### 12.3 Not applied, and why

- **ADR 0102 items 2 and 3, the receipt clamp's δ.** Computing ε at a reduced δ changes the reported ε of every release (4.00054 becomes about 4.0011 at `RHO_MAX`). That is not a pure tightening, so it stays open.
- **Envelope keys for the retired marker and successor pointers.** The review's list asked for keys and proposed none. `manifest.md` now says plainly that none is assigned and which specs wait on it.
- **ADR 0105 items 2 to 5** (COSE placement for `roles` and delete orders, the enumeration rule, media types): left open as instructed.
- **The rest of the `manifest.md` list** (items 10 and 12 to 16 of section 10: lineage-valued refs, the privacy-floors wording, the storage and log summaries, the remaining open questions, the design-doc link) and all of the **`design.md` list.**
- **`conformance.md`.** It still names `manifest/1` in one coverage row and lists ADRs 0100, 0101, 0102 and 0105 as pending. It tracks what the vectors contain today, and W0-08 is editing it, so it was left for the next vector run.
- **Per-spec reviews** in this directory keep the old string names. They are records of what was reviewed.

### 12.4 New points found while applying

- `deck.md` D13 bounds `expires` from below only. With the new shield anchor, an abandoned deck with a far `expires` holds budget until then. Recorded in ADR 0102.
- The backup must keep a left context for longer than 365 days: until 365 days after the latest `expires` of its decks dealt before the person left. `credentials.md` now says so.
- A context that admitted people "by approved list or by residence" in one policy cannot be written in draft 0.1. `context.md` says to use two contexts or one verifier that issues the disjunction.

### 12.5 What the reference implementation must follow

**Domain strings (bytes change in every signed bundle and two derivations):**

| Old | New | Used as |
| --- | --- | --- |
| `manifest/1` | `hum/manifest/1` | COSE `external_aad` of every manifest signature |
| `keyring/1` | `hum/keyring/1` | MLS exporter label, keyring epoch secret |
| `delivery/1` | `hum/delivery/1` | MLS exporter label, delivery secret |

The `delete-order-wrong-domain` vector signs under `hum/manifest/1`.

**New or changed fields:**

- Shield ledger entry: new `settledAt` and `expires`. Not a wire format; it never leaves the phone.
- No manifest body, ballot, presentation or bundle gains or loses a key. `branches` stays in the presentation and is always `[]`.
- Type registry: `service` is a registered type name and `blob-store` is not.
- The example context in `context.md` changed: `entry` is one `area` leaf and `issuers` is gone. Every vector built on the example (`context-valid-sealed-parent`, the release example's context, `cred-present-ballot-two-cards`) follows.

**New rules that need vectors:**

| Rule | Vectors |
| --- | --- |
| `context.md` C16 | Four rejecting (an `any` in `entry`; an `any` under an `all` in `vote`; two verifiers for a leaf by name; one named entry plus one empty-`attributes` entry) and one accepting (two leaves served by the same single verifier) |
| `credentials.md` P6 | `cred-present-entry-one-cell` (valid); rejecting: non-empty `branches`; the old `any(approved, area = 1)` presentation; a card from a second verifier the list also accepts. `cred-present-entry-any` is withdrawn |
| `credentials.md` P5, logged | An authorship proof verified two epochs later (valid); disclosed epoch not that of `issued` (rejected); `issued` 90 minutes after a boundary with the old epoch (valid) and three hours after (rejected); at the log, `issued` two hours from the log's clock (rejected) |
| `credentials.md` P3, logged | `kid` removed at a log index above the object's (valid) and below it (rejected) |
| `issue-map.md` IM-6 | `im-ok-verified-next-epoch`, `im-ok-kid-removed-after`, `im-bad-proof-epoch-mismatch`, `im-bad-issued-skew`, `im-bad-kid-removed-before` |
| `agent-sponsor.md` AS-8 | `as-ok-proof-after-epoch`, `as-bad-proof-epoch-mismatch`; the sponsor proof's bound message is `agentKey` |
| `services.md`, log submission | `rejected`, rule `P5`, for an authored object or sponsor manifest whose `issued` is more than 3,600 seconds from the log's clock |
| `shield.md` S8, S9 | The extended `shield-window` cases, `shield-long-decks`, and `shield-restore` with `expires` as the anchor and the enumeration by `expires` |
| `manifest.md` step 6 | Already covered by ADR 0082's choices; the `release` two-keyset case needs the R2 and R9 vectors |

### 12.6 Fixes after the review of the applied decisions

`docs/specs/reviews/applied-decisions.md` reviewed the changes above: one blocker (AB1) and fifteen should-fix items (AS1 to AS15). All sixteen are applied. Same status as the rest of this section: seams, pending the owner's review of the diff, nothing committed.

| Finding | File | Section | Change |
| --- | --- | --- | --- |
| AB1 | `release.md` | R13; "Rounds", Deadlines; vectors | Every version's `issued` ≤ the deck lineage's latest `expires`; a non-final version leaves room for its remaining rounds; the ledger refuses by its own clock after `expires`; phones refuse to display a later version |
| AB1, AS1 | `deck.md` | "Body fields" (`expires` paragraph); D12; D13; vectors | `closes` + (R+1) × `roundWindow` ≤ `expires` ≤ `closes` + `PUBLISH_WINDOW` + (R+1) × `roundWindow`; `expires` rises only with `closes`. At the minimum the aggregators have one `roundWindow` of slack in total; the maximum gives version 1 its full 30 days |
| AB1 | `context.md` | "Protocol constants" | `PUBLISH_WINDOW` = 2,592,000 |
| AB1 | `services.md` | "Step 10 at the log", `release` row | The ledger's clock check against `expires` |
| AB1, AS1 to AS3 | `shield.md` | "Window"; "The ledger"; "Composition"; "Restore" (the cost paragraph); S8; vectors; simulator list; "Open questions" | `settledAt` = max(phone clock, final version's `issued`), capped at `expires`; why the cap and the restore bound are sound; the real post-restore bound; S8 states the three-way maximum |
| AS4 | `verifier.md` | "Validation rules", rule 31; vectors | One `verifier` lineage per authority; the log refuses a second |
| AS4 | `trust-list.md`, `credentials.md`, `services.md` | "Refs"; P3; "Step 10 at the log" | State and enforce the same |
| AS5 | `deck.md`, `verifier.md` | "Parts" (breakdown), D9, vectors; "Gate and breakdown attributes" item 5 | A breakdown source resolves to exactly one verifier; the "pools every verifier" sentences are gone |
| AS6 | `docs/threat-model.md` | "A malicious verifier", Denial | No protocol remedy for denial under C16 |
| AS7 | `verifier.md` | Profile notes, Uniqueness | Two uniqueness verifiers as alternatives is not available in draft 0.1 |
| AS8 | `verifier.md`, `credentials.md` | Evidence item `accepts`; "The uses" (issuance evidence), P6, vectors | `accepts` entries are alternatives: exactly one card, lowest-index entry held |
| AS9 | ADR 0101; `credentials.md`; `docs/threat-model.md` | "Consequences" and a new "Open option"; "Security considerations" and the Validity row; "Log and witnesses" row and a new assumptions row | `issued` is bounded only by the log of record's clock; what a lax log admits; the cosignature-timestamp bound is filed, not specified |
| AS10 | `verifier.md`, `credentials.md`, `verifier-runtime.md` | "Attribute" (new key 7 `fromEpoch`), rules 29 and 30, example, vectors; "Message layout", P3; step 7 | The message count of an epoch is 2 plus the attributes with `fromEpoch` ≤ that epoch, with no clock |
| AS11 | `credentials.md`, `issue-map.md`, `services.md` | "in force"; "Several logs" and the log bullet; "What the log runs" | Draft 0.1 uses one log of record (the first entry of the context's `logs`); other logs accept on proof of inclusion there; a stale object is rebuilt |
| AS12 | `services.md`, `issue-map.md`, `credentials.md` | "What the log runs"; the log bullet; Validity row and vectors | "Current, or the previous period's in the first 3,600 seconds"; bounds included; the six edge vectors |
| AS13 | `verifier.md`, `trust-list.md` | Closing paragraph of "Validation rules"; steps 3 and 4 | Both point at `credentials.md`'s two-case definition of "in force" |
| AS14, AS15 | `manifest.md` | "Verification" last paragraph and new table; envelope `issued` row; "Security considerations", clocks row | What a log runs; where `issued` is load-bearing and who bounds it |

The nine notes of that review (AN1 to AN9) are not applied. They are wording and one vector each, and AN9 belongs to ADR 0104.

New byte-level changes and vectors for the reference, beyond 12.5:

| Change | Kind |
| --- | --- |
| `verifier` attribute map gains key 7 `fromEpoch` (uint), required. Every verifier vector and its CID change | Field |
| `deck.md` D13 upper bound and D12 "`expires` rises only with `closes`" | Rules: `deck-invalid-D13-expires-far`, the bound itself (valid), `expires` raised with `closes` unchanged (rejected) |
| `release.md` R13 | A version issued one second after `expires`; a non-final version 1 with no room for three rounds; a submission after `expires` by the ledger's clock; a final version issued exactly at `expires` (valid) |
| `verifier.md` rules 29 to 31 | Missing, decreasing or changed `fromEpoch`; a new attribute joining the current epoch, and the handover case; a second lineage under one authority; the message count for two epochs from one version |
| `credentials.md` | `len` after a mid-epoch append; the three log-of-record cases; the six P5 edges; `accepts` with one card and with two |
| `shield.md` | `settledAt` with a set-back clock; `sim-shield-long-decks` with a late Leader |
| `deck.md` D9 | A breakdown source with two verifiers (rejected) |

### 12.7 What draft 0.1 can no longer express

For the owner. Each item follows from rule C16 or from one verifier per authority.

- **Two ways into one context.** "Approved list or residents", "invite or approved", or any other alternative. Use two contexts, or one verifier that issues the disjunction as a single attribute.
- **A multi-verifier trust list as a leaf source.** A list with two verifiers for an attribute cannot back a policy leaf on it. The Federation list, or one list covering several districts, cannot be a policy source for that attribute. An entry with empty `attributes` counts against every attribute.
- **Fallback issuers.** Each leaf depends on one verifier for issuance, for denial and for key emergencies.
- **Overlap when moving to a new verifier.** A context switches verifier in one context version. Members without the new card wait until they have one.
- **A list publisher adding a second verifier.** Doing so for an attribute makes every context that re-pins the new list version invalid until it names one verifier.
- **Several values in one leaf.** "Wards 1 to 3" needs the verifier to coarsen at issuance. This predates C16 (rule C5).
- **Two uniqueness verifiers as alternatives.**
- **A breakdown pooled across verifiers.** Dormant, since part 7 is off in draft 0.1.

### 12.8 Fixes after the re-review

The re-review appended to `applied-decisions.md` left one blocker (RB1) and six should-fix items (RS1 to RS6), plus one addition on retries. All are applied. Same status: seams, pending the owner's review of the diff, nothing committed.

| Finding | File | Section | Change |
| --- | --- | --- | --- |
| RB1 | `release.md` | R13; vectors | `E` is the `expires` of the deck version in `refs["deck"]`, which R8 freezes. A later deck version cannot move it |
| RB1, the cause | `deck.md` | New rule D16; "Frozen fields"; D2; vectors | The ledger and the aggregators refuse a deck version above 1 once the previous version's `closes` has passed, by their own clocks. D2 is checked on every version. `closes` was chosen over `expires` as the cut-off: it is the tighter of the two, it is the rule ADR 0103 item 2 proposed, and it makes "logged before `closes`" in R2 mean one thing |
| RB1 | `services.md` | "Step 10 at the log" (deck and release rows); "Opening a deck" | The same checks at the log and the aggregator |
| RS1 | `shield.md` | "Window", third bullet; S8; `shield-window` vector | Before an unsettled entry drops, the phone looks up the deck lineage's latest version; it keeps the entry if `expires` moved or the lookup fails |
| RS2 | `context.md` | "Entry policy", after the table | Organizer-run verifiers each use their own authority, never the context's |
| RS3 | `verifier.md` | Rule 30; vectors | A new attribute's `fromEpoch` is at most `E_now + 2`; version 1 has the same ceiling |
| RS4 | `docs/threat-model.md`; `manifest.md` | Assumptions (new row); the load-bearing-clock table | D16, R13 and rule 30 rest on a log's clock; what each failure lets through, including the lock-out |
| RS5 | `context.md`; `issue-map.md` | "Log entries"; "Posting" step 3; "Several logs"; vectors | The first log is the log of record; submit there first; IM-7 and IM-15 count there only |
| RS6 | `credentials.md`; `agent-sponsor.md` | "in force"; AS-8 | A sponsor manifest's log of record is the log whose proof the bundle carries; a context accepts it when that log is any of its `logs` |
| Retry | `credentials.md`; `issue-map.md` | "in force"; "Posting" step 3, "Several logs" | The phone asks the log for the old CID before rebuilding, and treats an IM-7 refusal as "the first one was logged" |
| `verifier.md` rule 31 | `verifier.md` | Rule 31 | The tie-break names the log being read |

ADR 0103 item 2 is now partly applied (the ledger and aggregator half, as D16). The rest of ADR 0103 stays open.

New vectors for the reference; no new field and no byte change:

- `release.md` R13: version 2 issued after the pinned deck version's `expires` and before a later deck version's (rejected).
- `deck.md` D16: version 2 submitted one second after version 1's `closes` (refused) and one second before (accepted).
- `shield.md`: an unsettled entry with a later deck version in the log (kept), and with the log unreachable (kept).
- `verifier.md` rule 30: `fromEpoch = E_now + 3` (rejected); version 1 with `fromEpoch` 500 (rejected).
- `issue-map.md`: `im-ok-lost-response-retry`, `im-bad-rebuilt-after-logged`; `im-ok-two-logs` now counts in the log of record.

