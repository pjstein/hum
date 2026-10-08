# Review: `docs/specs/credentials.md` (Draft 0.1, W0-02)

Reviewed 2026-10-06, as on disk, against `CLAUDE.md`, `docs/design.md`, `prompts/wave-0/02-ballots-and-credentials.md`, ADRs 0020 to 0025, and `manifest.md`, `context.md`, `deck.md`, `release.md`, `services.md`, `verifier.md`, `verifier-runtime.md`, `trust-list.md`, `issue-map.md`, `agent-sponsor.md`, `take.md`, `storage.md` §6 and §11, `chat.md` §2 and §12, `ballot.md`, `shield.md`.

I could not read the IETF drafts at the versions cited. Findings that depend on draft text say so.

## Verdict

**First review: rework.** **Re-review: approve with fixes; four blockers remained (R1 to R4).** **Second re-review (see the end of this file): approve with fixes. R1 to R4 are closed in this spec. One small blocker remains (T1), and the R1 and R4 fixes are not real until `verifier.md` and `verifier-runtime.md` carry the epoch model.**

First-review verdict text: rework, limited to three sections: "Expiry and re-issuance", "Predicates" (the fallback), and "Verification rules" (per-use profiles). The scope table, the presentation header binding, the per-deck ballot scope and the identifier table are sound in outline. Five blockers follow. Each has a concrete fix, but B1 needs a design choice the owner should see.

## Blockers

**B1 (blocker) — "Expiry and re-issuance": re-issuance mints unlimited valid cards from one card.**
The host's only check is that the `hum/reissue/1` nullifier is new for the period (`services.md` V-3). A re-issued card has a new nym secret, so it has a new re-issuance nullifier in the same period. The holder presents card A and gets B, presents B and gets C, and so on without limit. A stays valid until it expires, and so does every card in the chain. Each card yields a different `hum/ballot/1` nullifier, so one person casts as many counted ballots per deck as they have cards. The same chain defeats `verifier.md`'s `credential` dedup method, because each new card has a new `hum/issuance/1` nullifier.

The spec treats the two-nullifier case as an accident an honest phone avoids by deferring renewal. It is an attack a modified client runs on purpose.

Fix, two options:
1. Carry the nym secret across re-issuance. The phone proves the new commitment holds the same prover share as message 0 of the presented card, and the host reuses a zero signer share. Nullifiers then stay stable, the chain is blocked by V-3, and a renewal can never double a vote. This is a second construction outside the drafts and joins ADR 0022's review list. The spec already lists it as a review question.
2. Draft-only stopgap. Allow re-issuance only for a card in its final period, proven by disclosing nothing more than `issuedPeriod = pNow − V` as a one-value predicate. The host sets the new card's `issuedPeriod` to `pNow + 1`, so the new card is not valid until the old one has expired. One card yields one successor and the two are never valid together. A deck that is open across a person's renewal boundary still sees two nullifiers, so `ballot.md` must refuse a round-0 ballot from a card whose first valid period started after the deck's `opens`.

Whichever is chosen, add failing vectors: a re-issuance presented with a card issued this period, and a second re-issuance chained from the first.

**B2 (blocker) — "Expiry and re-issuance": a card outlives the issuer's dedup record.**
With `V = ceil(validity / 28 days)` and acceptance while `p_now − p ≤ V`, a card lives between `28V + 1` and `28(V + 1)` days. That is always longer than `validity`, by up to 55 days. The text says "plus or minus up to 27 days", which is wrong. The `pNow` tolerance adds up to 28 more days. `verifier.md` keeps dedup keys for `validity` plus 30 days. For the district example (`validity` 180 days, so `V` = 7) a card issued on the first day of a period is valid for 224 days and its dedup record expires at day 210. The person gets a second card from the same issuer while the first still verifies, and votes twice.

Fix: make the lifetime never exceed `validity`. Use `V = floor(validity / 28 days)` and accept while `p_now − p ≤ V − 1`, and have `verifier.md` require `validity` to be at least 28 days. Remove the prover-chosen `pNow` tolerance, or limit it to the first 24 hours of a period. State the resulting bound in `verifier.md` and `verifier-runtime.md`, which both repeat "within 27 days". Add vectors at both edges of the window.

**B3 (blocker) — "What is proven", `all` nodes: credentials from two people can be pooled.**
`context.md` says the children of `all` may be satisfied by different credentials "held by the same prover". Nothing enforces "same prover". Each credential has its own nym secret and each proof is independent. A person with only a `unique` card can ask a ward resident to produce the `ward` proof under the same `ph`. The ballot verifies, the nullifier comes from the outsider's `unique` card, and the resident can lend the same `ward` card to any number of outsiders and still vote themselves, because only the primary nullifier is checked. The same pooling works for join tickets and tokens.

Fix that needs no new cryptography: for ballots, every credential's nullifier in the presentation must be new for the deck, not only the primary one, and a replacement ballot must carry the same full set. A lent card is then usable once per deck, which reduces lending to giving away one's own vote. `context.md`'s "they do not produce nullifiers" changes with this. If the owner wants holder binding instead, it is a hidden link secret shared by all cards, which is another item for the outside review.

**B4 (blocker) — "Predicates": the fallback that "needs no extension" cannot be configured, and the construction is not specified precisely enough to implement.**
`CLAUDE.md` says never hand-roll cryptography. The spec's answer is that the set-membership proof is isolated, flagged for outside review, and avoidable. The first two hold. The third does not:
- `V` is `ceil(validity / 2419200)`, so `V = 0` only when `validity` is zero.
- "The validity predicate is always present for every credential", and P5 forbids index 1 in `disclosed`. So even a one-value window needs the predicate proof, which needs the linked commitment.

No context works with the unmodified drafts as written. Fix: define a draft-only profile explicitly. Either let a one-value window be satisfied by disclosing message 1 (it reveals nothing when the window has one value), or adopt ADR 0022's alternative of expiry by issuer-key rotation with no `issuedPeriod` check. Then state that wave 1 builds only that profile until the review clears the extension.

The construction itself leaves these open, and two implementers would produce different bytes:
- Messages are 8-byte strings mapped by `messages_to_scalars`, so the signed scalar is a hash, not the integer. The spec writes `H_j · v_i`. It must say that each set value is mapped the same way before use.
- `Q` is "from `create_generators` with the extra ASCII label". Say exactly which input carries the label and that `Q` is independent of every message generator.
- The order of `C`, the linking commitment, the branch commitments and `S` in the challenge transcript is left to the reference implementation. A seam construction needs the order in the spec, with the vectors as a check, not as the definition.
- `S` is recomputed from the policy and the verifier manifest, but the proof does not say which verifier version the prover used. A value appended to an enum, or a changed `validity`, makes honest proofs fail until both sides hold the same version. Add the verifier version number to the credential proof.

Also record how this will be built without forking a BBS library in a seam. The linking step needs the prover's blinding for message `j`, which the usual library APIs do not expose. Name a library that supports linked statements, or say the review must cover the fork.

**B5 (blocker) — "Issuance": the request and response have no byte format, and the response is not sealed.**
`services.md` says `POST .../issue` carries "the blind issuance request `credentials.md` defines". This spec defines no encoding for the request (commitment with proof, approved attribute indexes) or the response (signature, signer nym entropy, `kid`, `issuedPeriod`, attribute values). The same is true of the re-issuance request. These bytes cross the phone-to-host boundary in a seam. Fix: add CBOR tables for both, and for the re-issuance body.

The request is HPKE-sealed to a host key and the response is not. A TLS terminator in front of the host therefore reads the person's attribute values and the signature for an identified session, which is what `verifier.md`'s host key exists to prevent. Fix: seal the response with a key exported from the request's HPKE context.

## Should fix

**S1 — "Verification rules", P3, P6, P7: the rules fit ballots and break the other uses.**
- P3 requires `class` = `person` for every credential proof. A sponsor proof must come from an `agent`-class verifier (`agent-sponsor.md` AS-8), so a literal P3 rejects every sponsor proof.
- P6 needs a policy walk. Re-issuance, issuance-scope and sponsor presentations have no context policy.
- P7 allows disclosure only for a leaf's predicate or a breakdown. Re-issuance discloses every attribute, and a `credential` evidence item discloses the attributes in `accepts`.
- "Where the rules run" omits the log, which runs AS-8.

Fix: add one table with a row per scope giving the scope bytes, the bound message, whether `context` is present, the policy, the allowed disclosures and the required class. Point P2, P3, P6 and P7 at it.

**S2 — "Format": the bound message is undefined for five of nine scopes.**
"The bound message is never carried; the use defines it." Only ballots, authorship and re-issuance define one. `chat.md` §2.5, `chat.md` §12.3, `storage.md` §6.2, `agent-sponsor.md` and `verifier.md` define none. Fix: state each in the table from S1. Recommended: empty for join (the scope already hashes the handles); the hash of the `TokenRequest` array for both token scopes; `agentKey` for sponsor; the hash of the blind request for issuance.

**S3 — "Scopes and nullifiers": the issuance scope does not say whose authority it names.**
The table says "verifier authority CID". `verifier.md` means the verifier that is asking, not the one that issued the presented card. Say so. For `hum/delivery-tokens/1`, give the byte widths as the blob-token row does.

**S4 — "Every identifier": the cohort tuple is joined to the chat name, and the table does not say so.**
Every presentation shows the issuer authority, `kid`, `len` and `branches` for each credential. Two places bind that tuple to a chat identity:
- A signed map object's public bundle carries the chat identity key beside the `hum/author-once/1` presentation, permanently and for anyone.
- A join ticket shows the greeter the presentation beside the KeyPackage.

The phase-1 Leader sees the same tuple on every ballot. In a small context, or for the one member still on an older `kid`, the tuple can be unique, which joins a chat name to a voting pseudonym for anyone who holds both views. Fix: add both rows to the identifier table, state the anonymity set as the smallest cohort, and have the author screen say that a signed object also publishes which verifier and key issued the card. Ask `verifier.md` to allow one `active` issuing key, not two: a malicious issuer can otherwise place one target alone on the second active key and tag them for every verifier.

**S5 — "Every identifier", closing sentence: the backup contradicts "what never exists".**
The spec says no object holds a nym secret beside a chat identity key. The sealed backup holds the chat identity key, every nym secret and the context list in one file. Reword the claim to exclude the person's own phone and backup, and state the consequence: whoever gets the phrase and the file can recompute every `hum/author-once/1` and `hum/author-slot/1` nullifier, which are public forever, and so unmask every unsigned object the person authored with those cards. Add a rule that expired cards and their nym secrets are deleted from the phone and the next backup.

**S6 — "The sealed backup", "When it is written": write timing leaks to the platform.**
The file is rewritten on every join, leave and renewal. The platform account that holds the backup sees those times, and the delivery service sees a join commit at the same moment. Fix: write on a fixed daily schedule with jitter, never on the event.

**S7 — "One voting device" and "Direct transfer": two gaps.**
- A second device gets the chat identity key "through the backup or transfer", but the backup also holds every credential. Restoring it on a tablet makes a second voting device. Define a chat-only transfer that carries the chat identity key and edit root and nothing else, and reflect it in `chat.md` §2.3.
- Direct transfer moves a hand and a shield off the phone. That is an exception to invariant 1, which says nothing but a ballot carries them. ADR 0023 records the feature but not that it needs the owner's explicit approval as an invariant exception. The channel ("platform APIs, or a QR-bootstrapped Noise channel") has no format, handshake pattern or authentication rule. Specify it or cut it from draft 0.1.

**S8 — "What is proven", `branches`: two readings.**
The walk "reads the next entry" only at `any` nodes it visits. P6 requires "exactly one entry per `any` node". Entries for unvisited nodes would have no defined value and would be a free fingerprint. Fix: one entry per visited `any` node, in walk order. Add a rule for which child and which credential a phone picks when several satisfy, and require the choice to be stable per context so a person's presentations do not vary.

**S9 — "What is proven", breakdown row: how a disclosed value satisfies a set leaf is undefined.**
P6 forbids a message that is both disclosed and under a predicate. With `ward` disclosed for a breakdown, the leaf `ward ∈ {1,2,3}` has no stated way to be satisfied. Fix: a leaf whose message is disclosed is satisfied when the disclosed value meets `pred`. Also, `deck.md` D9 lets a plan name a breakdown attribute that no policy leaf names. P6 then rejects the extra credential as unused. Either D9 requires a matching leaf or P6 admits one breakdown credential.

**S10 — "Scopes and nullifiers", join row: one card admits unlimited chat identities.**
The join scope ends in the hash of the handles, so every ticket has a fresh nullifier and "the greeter checks once" checks nothing. One member can write valid tickets for any number of other people's KeyPackages. If the owner wants one chat identity per card, the scope must be `hum/join/1 ‖ context lineage CID` and greeters must keep the nullifier set. That is a `chat.md` change. At minimum, say here that the entry policy is enforced per ticket and not per person.

**S11 — "Issuance": the phone's checks on a new card are incomplete.**
Add: the `kid` is `active` in the manifest version shown to the person; `issuedPeriod` is the current period; every attribute value is in the manifest's declared set or absent. Without these a host can mark a card. Also say what happens to `verifier-runtime.md`'s `valid-for`, which lets a module shorten validity: this spec takes `V` from the manifest only, so `valid-for` has no effect.

**S12 — "Three identities" and "Issuance": "blind" overstates what the draft gives.**
As I understand the blind-signatures draft, the signer computes and sees the signature value. It does not see message 0. Unlinkability comes from the proof being zero knowledge in the signature, which the spec does say one paragraph later. "Never the finished credential" and "the phone unblinds" should be replaced by that statement. W0-08 should confirm against the pinned draft text, and confirm the function names used here exist at the cited versions.

**S13 — Domain strings.**
`hum/credential/1`, `hum/presentation/1`, `hum/nullifier/1`, `hum/predicate-blind/1`, `hum/reissue/1`, `hum/reissue-request/1` and `hum/backup/1` are not in `services.md`'s registry, which says a string is added there before use. The registry row for `hum/issuance/1` says it covers re-issuance; it no longer does. `hum/ballot/1` is used both as a scope prefix and as a bound-message prefix; give the bound message its own label.

## Notes

- **N1 — Per-deck scope (ADR 0021).** I agree with it. The scope is the deck lineage CID, which `closes` extensions keep, so rounds and versions share a nullifier as `services.md` and `release.md` need. Two decks, and a retired deck and its redeal, are unlinkable by nullifier. The prompt asked for a stable pseudonym per person per context; nothing in any sibling spec uses one, and providing it would only give the phase-1 Leader a cross-deck profile. Residual cross-deck linkage is the cohort tuple of S4. Stale wording to fix elsewhere: `context.md` "Nullifier leaf" still says "per-context pseudonym"; `services.md` says "one nullifier per (context, deck)"; `simulator.md` models one `vp_` per context.
- **N2 — Scope separation.** All nine prefixes end in `/1` and none is a prefix of another. The suffix bytes match `chat.md` §2.5 and §12.3, `storage.md` §6.1, `issue-map.md` and `agent-sponsor.md`. Unlinkability across scopes rests on the pseudonym draft's claim; the review should confirm it still holds with the predicate extension folded into the challenge.
- **N3 — Re-issuance disclosure.** Disclosing every attribute to the host lets it recognize a holder with a unique tuple (a `uint` unit number). It learns only that this person renewed. Accepted, but say it.
- **N4 — Absent value.** `0xFFFFFFFFFFFFFFFF` collides with a `uint` attribute whose `max` is 2⁶⁴ − 1. Ask `verifier.md` to cap `max` below it.
- **N5 — Token versions.** P2 accepts the current or previous context version for tokens. `storage.md` §6.2 accepts the latest only.
- **N6 — Backup size.** Padding buckets still show roughly how many cards and contexts a person has to the platform.

## Testability

The P1 to P8 failing vectors are listed and each names its case. Missing:
- One valid and one failing vector per row of the per-use table (S1), including a sponsor proof from a `person`-class verifier and a re-issuance with an undisclosed attribute.
- `kid` with `since` below a trust list's `minVersion`; a `verify-only` key accepted; `len` above the ceiling.
- Lifetime edges after B2: first and last accepted period.
- Re-issuance failures after B1.
- Issuance request and response bytes, and a response the phone must refuse (wrong `issuedPeriod`, a value outside the declared set, a non-active `kid`).
- Backup: wrong phrase, tampered file, and a plaintext with an unknown key (to pin "nothing else").
- A pooled presentation (B3) rejected.
- Predicate vectors should be marked provisional until the outside review signs the transcript.

## Changes this forces on sibling specs

- `services.md`: registry rows (S13); V-3 after B1; the `issue` and `reissue` bodies (B5).
- `verifier.md`, `verifier-runtime.md`: lifetime wording and minimum `validity` (B2); one active issuing key (S4); `valid-for` (S11); `max` (N4).
- `context.md`: "per-context pseudonym" wording (N1); non-designated credentials and nullifiers (B3).
- `deck.md`: D9 breakdown source must be a policy leaf (S9).
- `chat.md`: §2.3 chat-only transfer (S7); the join scope decision (S10).
- `issue-map.md`: author screen text (S4).
- `docs/design.md`: per-deck wording, and "the issuer never sees the credential" (S12).

---

# Re-review (2026-10-06, revised spec, 412 lines)

Re-read in full: `credentials.md`, `ballot.md`, `shield.md`, ADRs 0022 to 0026, and the changed parts of `services.md`, `context.md`, `deck.md`, `verifier.md`, `verifier-runtime.md`, `chat.md`, `issue-map.md`, `simulator.md`, `release.md`, `trust-list.md`.

## Verdict

**Approve with fixes. Four blockers remain: R1, R2, R3, R4.** R1 and R2 are the two cases where one person still gets two counted nullifiers in one deck. R3 is a byte conflict with `chat.md`. R4 is an invariant 2 question the owner must accept or the spec must fix.

## First-review blockers

| Blocker | Status | Evidence |
| --- | --- | --- |
| B1 renewal chain | **Partly fixed.** The same-period chain is closed: one renewal nullifier per card, renewal only in the last two periods, successor post-dated to `p + V`. A second route to two valid cards remains (R1), and a `closes` extension reopens the double count (R2) | "Re-issuance" |
| B2 lifetime over dedup | **Fixed.** `V = floor(validity / 28 d)`, valid while `0 ≤ p_now − p ≤ V − 1`, lifetime at most `28V` days, which is at most `validity` and so below `validity` + 30. `verifier.md` rule 16 requires at least 28 days. The verifier uses its own clock | "Validity"; `verifier.md` "Lifetime" |
| B3 pooling | **Fixed for ballots.** Every card yields a nullifier, each must be new for the deck, and a replacement carries the same set. `context.md` and `services.md` intake check 7 agree | "The uses", rules; `ballot.md` B3, B7 |
| B4 fallback and predicate | **Fixed.** Draft 0.1 is selective disclosure only. P5 and P6 use disclosed values only. No rule depends on the hidden predicate, and no vector is generated for it. `context.md` C5 rejects multi-valued sets, real ranges and `[0]` on non-bools, and its example now uses `area = 1` | "What is proven"; ADR 0022 |
| B5 issuance bytes | **Fixed.** Request and response tables exist; the response is sealed in the request's HPKE context. Two gaps are listed under RS1 | "Issuance request and response" |

All thirteen first-review should-fixes are addressed in the text, except S10, which is now a conflict (R3).

## Remaining blockers

**R1 (blocker) — "Re-issuance" against `verifier.md` "Dedup item": renewal and fresh issuance together still give one person two valid cards.**
A renewal has no evidence, so the host cannot extend the person's dedup record. That record expires `validity` plus 30 days after the original issuance. The renewal chain is still alive then. District example: card A is issued on day 0 and lives to about day 168. Its successor B is valid from about day 168 to day 336. The dedup record expires on day 210. On day 211 the person opens a fresh session with the same evidence and gets card C. B and C are both valid until day 336, both pass a ballot window, and each has its own renewal chain from then on. The claim "at most one card from an issuer is valid for a person at any time" is false, and a new chain starts every `validity` plus 30 days.

Fix, either:
1. Remove evidence-free renewal from draft 0.1. A person renews by a fresh session with evidence in the card's last two periods. The dedup row stores the card's last valid period, allows a new session only from one period before it, and the new card is post-dated to the period after it. No renewal nullifier exists.
2. Keep renewal and cap the chain. Add a generation message that is disclosed only at renewal, refuse renewal past generation `N`, and have `verifier.md` keep dedup records for `(N + 1) × validity` plus 30 days.

Add a failing vector: a fresh session on day `validity` + 31 from a person whose successor card is valid.

**R2 (blocker) — "Validity", ballot window: a `closes` extension lets an old card and its successor both count.**
The window uses `p_closes` "of the deck version in force". Card A (period `p`) votes while `p_closes ≤ p + V − 1`. The organizer extends `closes` so that `p_closes ≥ p + V`. The spec says A's accepted ballot stands. Successor B now satisfies the new window and sends a round-0 ballot under a new primary nullifier. Both are counted. An honest phone is stopped by `shield.md` S11; a modified client is not, and an organizer can time an extension to a cohort's renewal boundary.

Fix: anchor the window to the lineage, not the version. A ballot's card must be valid in `period(closes)` of the deck's version 1. A and B are never both valid in one period, so no extension can admit both. Cards issued after the original `closes` then cannot vote in an extended deck, which is the cost. Add the vector: an extended deck, A accepted before the extension, B refused after it.

**R3 (blocker) — "The uses", join row: the scope bytes disagree with `chat.md`.**
This spec: scope `hum/join/1 ‖ context lineage CID ‖ SHA-256(handles)`, bound message empty, "one card can admit any number of chat identities". `chat.md` §2.5 on disk: scope `hum/join/1 ‖ context lineage CID`, bound message `SHA-256(canonical CBOR of handles)`, one chat identity per card per context, enforced with `join-record` messages (§5.17). A phone built from one spec fails a greeter built from the other. `chat.md` owns the use. Fix here: adopt its scope and bound message, drop the "any number" rule and open question, and add the identifier-table row: the organizers group holds a stable per-context join nullifier beside a chat identity key for as long as the member stays. It links to no other scope. Tell W0-05 that a renewed card has a new join nullifier, so the one-identity rule lapses at each renewal.

**R4 (blocker until the owner accepts it or it is fixed) — "Validity" and the identifier table: the disclosed `issuedPeriod` makes the cohort tuple small enough to join identities.**
Every presentation now discloses `issuedPeriod` for every card. The tuple per card is issuer, `kid`, `len`, `issuedPeriod`; a two-card policy shows two of them. With `V` = 6 and `V` = 13, a context of 1,000 voters splits into up to 78 cells, about 13 people each on average, with many cells of one. The same tuple appears:
- on every ballot, to the phase-1 Leader, which lets it link one person across decks despite the per-deck nullifier;
- in every signed map object's public bundle, beside the chat identity key, permanently;
- in every unsigned map object's public bundle, permanently, so "nothing links slot 3 to slot 4" (`issue-map.md`) no longer holds in a small cell;
- on join tickets, token requests and `join-record` neighbours.

A public log entry plus the Leader's view joins a chat name to a voting pseudonym wherever the cell has one member. The identifier table states this honestly. It is still a weakening of invariant 2 that a spec cannot accept on the owner's behalf.

Fix inside the drafts: quantize. Every card from an issuer carries the epoch `floor(p / V)` instead of the period, and is valid for that epoch only. All valid cards from an issuer then disclose the same value, and `issuedPeriod` leaves the cohort tuple. A card issued mid-epoch is shorter-lived, and renewal in the last two periods yields the next epoch's card. This also simplifies R2 (the ballot's card must be of the epoch of the original `closes`). If the owner prefers the current design, record the acceptance in ADR 0022 with the cell-size arithmetic.

## Remaining should-fixes

**RS1 — "Issuance request and response" and "Re-issuance": four gaps where bytes or behavior are undefined.**
- The response AAD is the session ID. Renewal goes through the relay with no session, so its AAD is undefined. `services.md` says "exactly like the issue call".
- Step 4's check "`issuedPeriod` equals the phone's current period or the one before" rejects every renewal response, which must carry `p + V`. State the renewal check.
- The issuance-evidence bound message is "SHA-256(the session's issuance request bytes)". Say plaintext CBOR or sealed bytes.
- A lost response locks the person out: the dedup record or renewal nullifier is spent and no card arrived. The host cannot simply re-sign, because a fresh signer nym share would give a second card. Fix: the host derives the signer share from a host secret and the request hash, stores the request hash with the nullifier or session, and answers an identical retry with the same response.

**RS2 — "Validity", first-hour grace.** For non-ballot uses a dying card and its successor are both accepted for one hour. That doubles token quotas and unsigned-authorship slots for that hour. State it as accepted or have the successor's window start one hour late.

**RS3 — "Re-issuance", "Phones" bullet, and ADR 0026 "Cost": the text contradicts the window.** By the formula, a person whose card dies before `closes` cannot vote with the old card at all, and can vote with the successor once it is valid. The text says the deck "is lost … from the period the old card dies". For a 28-day deck with `V` = 6, roughly one member in six must wait for their successor before their first ballot is accepted. Say that, and have `ballot.md` hold the first send until the card fits.

**RS4 — "What is proven", deterministic choice.** The bytewise-smallest card can change when a person gets a new card while a deck is open. The replacement then carries a different nullifier set and is refused (`ballot.md` B7). Fix: the phone pins the cards it used for a deck with the shield entry and reuses them.

**RS5 — Stale text in siblings** (see the table below): `services.md` lines on "(context, deck)" and "`period` equal to `validity`"; `verifier.md` security row and `verifier-runtime.md` "per-period nullifier"; `simulator.md` "`vp_` per-context pseudonym".

## Notes

- Lowest-index branch choice tells a verifier the person does not hold a card for any earlier branch. Accepted leak; say it beside the `branches` row.
- A card issued on the last day of a period with `V` = 1 lives one day. Verifiers with `validity` under 56 days should know.
- `predicate-blind` is in the `services.md` registry though nothing in 0.1 uses it. Harmless.

## Forced sibling changes: what has landed

| Spec | Landed | Not landed |
| --- | --- | --- |
| `services.md` | AG-2, AG-5, intake order with the identical-retry lookup first, every-nullifier set, `taskId(round, part)` over the lineage CID, `taskIds[round][part]`, receipt signature over `firstPart`, O-3 ballot bucket, O-4 receipt pages, V-3, registry rows, sealed issue and reissue bodies, part 7 refused at open | "One nullifier per (context, deck)" wording; "`period` equal to `validity`" and the `period` field of the revocation endpoint; renewal AAD |
| `context.md` | C5 selective-disclosure restriction with vectors; example uses `area = 1`; per-deck and primary-nullifier wording | — |
| `deck.md` | `covStatements ≤ 128` in the field table, D11 and vectors; "first K cast"; part 7 deferred in phase 1 | `deck-valid-breakdown` still lists `ward` with values `[1, 2, 3]`, which is fine for the plan format but cannot be registered in 0.1 |
| `verifier.md` | Exactly one `active` key; `validity ≥ 28 days`; "Lifetime" section; `max` below 2⁶⁴ − 1; `period` removed from revocation | Security row still says the renewal nullifier is "scoped to the verifier and period"; dedup retention does not cover a renewal chain (R1) |
| `verifier-runtime.md` | `valid-for` removed; issuance period rule | "per-period nullifier" in the who-sees-what table |
| `chat.md` | §2.3 chat-only export and single voting device; join scope decision taken (per person per context, `join-record`) | Agreement with `credentials.md` on the join scope bytes (R3) |
| `issue-map.md` | Author screen text; security row on cohort fields | Says nothing of `issuedPeriod` in the tuple, or that unsigned objects are linkable by it (R4) |
| `release.md` | What a round-0 receipt proves, dispute rule | — |
| `simulator.md` | Per-deck oracles and the new scenario names | `vp_` still described as a per-context pseudonym; churn scenario still has a device switch that resubmits |
| `trust-list.md` | No change was needed; the multi-valued rule lives in `context.md` C5 | — |
| `docs/design.md` | Not checked for edits; ADR 0021 leaves the wording to the owner | — |

---

# Second re-review (2026-10-06, epoch redesign, 418 lines)

Read in full: `credentials.md` and ADR 0026. Read the changed parts of `ballot.md` and `shield.md`, and searched `verifier.md`, `verifier-runtime.md`, `services.md`, `context.md`, `deck.md`, `chat.md`, `issue-map.md`, `release.md` and `simulator.md` for the epoch model.

## Verdict

**Approve with fixes.** R1 to R4 are closed in this spec. One small blocker remains (T1). The R1 and R4 fixes rest on rules that `verifier.md` and `verifier-runtime.md` do not yet carry, so they are not real until those two specs land the epoch model. `ballot.md` and `shield.md` keep their verdicts: approve with fixes, no blockers.

## R1 to R4

| Blocker | Status | Evidence and what I checked |
| --- | --- | --- |
| R1 two valid cards | **Closed for evidence, device and document dedup. One route remains (T1).** There is no evidence-free renewal. The dedup row stores `lastEpoch` and the request hash and lives 30 days past that epoch. I walked every row state against every session time: no row, dead row, live row outside handover, live row in handover, row already at the next epoch. One dedup key yields at most one card per epoch in each case. A first session in handover returns two cards, of different epochs, which no deck accepts together | "Issuance", "Which epochs a session issues" |
| R2 `closes` extension | **Closed.** A ballot's cards must be of the epoch of `period(closes)` of the deck lineage's version 1, and must have started. An extension cannot move that epoch. `ballot.md` B2, `deck.md` and `release.md` R2 say the same, and the extension vector exists | "Validity"; `ballot.md` B2 |
| R3 join scope | **Closed.** Scope `hum/join/1 ‖ context lineage CID`, bound message the hash of the handles, as `chat.md` §2.5 has it. The identifier table lists the `join-record` nullifier beside the chat identity. The spec states that every card is new each epoch, so a member can register one new chat identity per issuer epoch; `chat.md` open question 16 states the same bound | "The uses", "Renewal" |
| R4 cohort tuple | **Closed in this spec.** Message 1 is the epoch. `kid` and `len` are fixed per epoch. During handover the next card has not started, so presentations still show one value. For one hour at an epoch boundary two values coexist, which is stated. The fields that still vary per person are `branches`, which issuer a person's card comes from when a source admits several, and the number of cards; all three are properties of the policy and are listed. Proof length does not vary, because the disclosed set is fixed by the policy | "Validity", identifier table |

**Lost-response recovery.** The signer's nym share is an HKDF of a host secret and the request hash, and an identical request gets the identical response. I see no linkage or blindness problem. The host always knew its own share. The request hash covers a hiding commitment, and no presentation reveals that commitment. A person cannot grind the share, because a different request against a spent row is refused. Even if a re-signed signature differed in bytes, the nym secret would be the same, so no second nullifier arises. An attacker who knows a victim's evidence cannot fetch the victim's card, because the response is returned only for the identical sealed request.

## Remaining blocker

**T1 (blocker, small) — "Which epochs a session issues" against `verifier.md` dedup method `credential`: a card-based dedup key changes every epoch of the presented card.**
The `credential` dedup key is the `hum/issuance/1` nullifier of the presented card. Every card now has a new nym secret each epoch, so that key changes whenever the presented issuer's epoch turns. Epoch grids differ between issuers with different `V`. Verifier B has epochs of 13 periods and dedups only by a card from verifier A, whose epochs are 6 periods. Inside one B epoch the person presents their A card of epoch 3, then their A card of epoch 4. B sees two different keys and no row for the second, and issues a second card of the same B epoch. Both are valid for the same deck. The five named profiles all carry an `evidence` or `device` key as well, so they are safe; a `custom` verifier with only a `credential` item is not.

Fix, one rule in `verifier.md` and one sentence here: a `credential` dedup item is never the only dedup item; or the asking verifier's `V` must divide the `V` of every verifier in the item's `accepts`, so no accepted card's epoch boundary falls inside the asker's epoch. Add the failing vector.

## Should fix

**TS1 — "On the phone", deletion at epoch end, against the ballot rule for later rounds.** Cards and nym secrets are deleted "at the end of their epoch". The ballot rule lets a card act in rounds 1 to 3 and in an extended deck after its epoch ended, and `shield.md` pins that card to the deck. A deck that closes in the last days of an epoch then loses every phone in its later rounds, because the phones deleted the card. Fix: delete a card when its epoch has ended and no shield entry that pins it is short of `released`.

**TS2 — Key rotation and layout do not fit `verifier.md` as written.**
- `verifier.md` allows exactly one `active` key, and `verify-only` means no new issuance. A late joiner to epoch `E` after a rotation must still get a card under epoch `E`'s key, which is no longer `active`. A first session in handover returns cards of two epochs that may need two keys, while the request and response carry one `kid` and the phone checks that `kid` is `active`. Fix: give each issuer key a `fromEpoch`, define the signing key of epoch `E` as the listed key with the largest `fromEpoch ≤ E`, carry `kid` per card in the response, and have the phone check that rule instead of `active`.
- Removing a key in an emergency kills every card of the epoch, and every dedup row then says `lastEpoch = E_now` and refuses a new session until handover. Fix: the row stores the `kid`; a row whose `kid` is no longer listed counts as no row.

**TS3 — `validity` is not frozen in `verifier.md`, and the epoch grid depends on it.** A change of `V` renumbers every epoch. Existing cards and dedup rows then carry numbers from the old grid. If the new number is lower than a row's `lastEpoch + 1`, the session rules have no case and the person is locked out for years. Fix: freeze `validity` within a verifier lineage, or disclose the epoch's first period instead of its index and state the transition rule.

**TS4 — Several dedup rows.** A uniqueness verifier has two dedup items. The session rules speak of "a row". Say which governs when a person's document row and a new device's absent row disagree: take the largest `lastEpoch` over all matched rows, then write it to every row.

**TS5 — The stated cost understates the wait and omits a use.** "Up to 56 days after the deck opens" holds only for a deck opened during handover. A long deck whose original `closes` falls in the next epoch counts nobody until that epoch starts, which can be most of an epoch. Two ways an organizer can shape the electorate should be written down, since both are visible in the log and neither singles out a person: placing the original `closes` just after an issuer's boundary favours members who renewed early, and closing on an epoch's last day and then extending freezes the electorate to that epoch's holders.

**TS6 — Renewal burden for one-time-code verifiers.** State that a renewal session presents the same code or roster entry, which maps to the same dedup row, so no new code is needed each epoch.

## The three earlier should-fixes

- **Padding outside the CBOR:** done. A uint32 length prefix, the canonical ballot, then zero bytes to `BALLOT_BYTES`; key 6 is gone; `ballot-frame-edges` covers the boundaries. `services.md` carries the frame.
- **8 KiB presentation cap in a ballot:** done in `ballot.md` B1 and P1 here. At M = 128 the frame holds 33,024 bytes of `cov` plus 8,192 with room.
- **Backup written at join:** done. The local write happens at once on a join, `shield.md` S12 forbids a first ballot in a context before it, and the platform's upload delay is stated as a residual.

## Sibling specs and the epoch model

| Spec | State |
| --- | --- |
| `chat.md` | Caught up: §2.5 names the issuer epoch; open question 16 bounds one new chat identity per issuer epoch |
| `deck.md` | Caught up: the ballot window on version 1's `closes`, the straddling-deck cost, `covStatements ≤ 128` |
| `release.md` | Caught up: R2 notes the version-1 anchor |
| `issue-map.md` | Caught up: public fields identical across an issuer's valid cards |
| `context.md` | No epoch change was needed |
| `simulator.md` | Notes one epoch and one card per phone in the fake; `vp_` is still described as a per-context pseudonym |
| `services.md` | **Partly.** Landed: issue body with `commits`, `hum/nym-share/1`, the ballot frame, the 8 KiB cap. Not landed: `POST /v1/verifier/reissue` and its `credential` auth class are still listed; V-3 still exists; `hum/reissue/1` and `hum/reissue-request/1` are still in the registry; the revocation endpoint still returns `period` and the text says "`period` equal to `validity`"; "one nullifier per (context, deck)"; "under the context's entry policy" |
| `verifier.md` | **Not caught up.** Dedup is still "seen within `validity` plus 30 days", which reopens R1. Revocation text still describes renewal in a card's last two periods with renewal nullifiers. "Lifetime" still describes a per-card issuance period. Security rows still describe a 28-day issuance cohort and a per-period renewal nullifier. Nothing on `lastEpoch`, the request hash, key-to-epoch alignment, layout at handover start, or the deterministic nym share |
| `verifier-runtime.md` | **Not caught up.** Step 5 and rule 11 still set an issuance period of `floor(session day / 28)`. The who-sees-what table still has a per-period renewal nullifier. Nothing on the epoch-issuing rule |

## For the owner

- ADR 0026's cost: evidence at every epoch, and decks that straddle an issuer's boundary.
- The two-phone residual risk (ADR 0023), the "I did not vote" control (ADR 0025) and phase-1 breakdowns are unchanged.
