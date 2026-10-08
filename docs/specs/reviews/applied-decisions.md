# Review of the applied cross-spec decisions — Draft 0.1

Oct 6, 2026 · adversarial review of ADRs 0100, 0101, 0102 (item 1), 0105 (item 1) and 0106 as applied · `seam:` every finding below touches a seam; this review changes no spec

**Update, later on 2026-10-06.** AB1 and AS1 to AS15 were reported applied (`cross-spec.md` §12.6). The "Re-review" section at the end checks them and carries the final verdict. The sections before it are kept as written and describe the specs before those fixes.

## Verdict

**Approve with fixes.** One blocker, fifteen should-fix items, nine notes.

- ADR 0100 (rule C16) closes B1 as claimed, with three gaps that need a rule each.
- ADR 0101 closes B2. The arithmetic of the two-value epoch check is right. Four places still let two implementers disagree.
- ADR 0102 item 1 closes the literal B3 attack. A variant still works, because `release.md` lets a release version be logged after the deck's `expires` and the shield caps its anchor at `expires`. That is the blocker.
- ADR 0105 item 1 is complete in the specs and the threat model, except three lines in `conformance.md`.
- The `manifest.md` edits agree with `services.md`, `release.md`, `deck.md` and ADR 0082, except two sentences that were not updated.

## What I read

`CLAUDE.md`; `docs/specs/reviews/cross-spec.md` sections 1, 11 and 12; ADRs 0082, 0100, 0101, 0102, 0105, 0106; in full: `context.md`, `credentials.md`, `shield.md`, `trust-list.md`, `deck.md`, `ballot.md`, `issue-map.md`, `agent-sponsor.md`, `manifest.md`, `docs/threat-model.md`; the changed sections of `chat.md` (§2.5), `services.md` ("The bundle", "Domain strings and scopes", "Log and ledger"), `release.md` ("Rounds", "Who signs", R1 to R15, the example); searches over `verifier.md`, `storage.md`, `take.md`, `simulator.md`, `conformance.md`.

Not read: `docs/design.md`, `verifier-runtime.md`, `chat.md` outside §2.5, `storage.md` outside the search hits, `vectors/`, and `reference/` beyond one search. I ran no code and no gate.

Severities follow `cross-spec.md`. Findings name the spec and section, not line numbers.

## Blocker

### AB1 — A release version may be logged after the deck's `expires`, and the shield stops counting 365 days after `expires`

**Specs:** `shield.md` ("Window", "Composition", S8); `release.md` (R13, "Rounds"); `deck.md` (D13). Invariant 3.

**What the specs say.** `shield.md` caps `settledAt` at the deck's `expires`: "a final version first seen after `expires` counts as seen at `expires`". An unsettled entry also anchors at `expires`. "Composition" then claims that the releases a person took part in that are published in any 365-day span sum to at most `SHIELD_RHO`.

That claim needs every release version to be published at or before `expires`. No rule says so. `release.md` R13 bounds only version 1's `issued`, to `closes` + 30 days. Later versions have no deadline. The ledger skips step 11. `deck.md` D13 allows `expires` = `closes` + (R+1) × `roundWindow`, and `roundWindow` may be one hour.

**With conforming, timely parties.** The `deck.md` example has `expires` = `closes` + 12 days. R13 lets version 1 be logged at `closes` + 30 days. Every entry then leaves the window 365 days after `expires`, which is 347 days after its release appeared. A person votes in seventeen such decks, then in seventeen more that close and release within 18 days of the first batch dropping out. Thirty-four releases, ρ 8.6, are published inside one 365-day span.

**With a Leader that delays.** Nothing dates versions 2 to 4. A Leader publishes version 1 on time and the map-tier versions 364 days after `expires`. The map tier carries about 85% of the plan's ρ in the default split. The phone's entries drop one day later and it reserves a full shield again. This is B3 again, within weeks, through an unmodified phone. It needs both aggregators to sign late, and at launch one operator may run both.

**Fix.**

1. `release.md` R13: every version's `issued` is at most the pinned deck lineage's latest `expires`. The Helper already checks `issued` against its clock. The ledger must also refuse a release version when its own clock is past that `expires`, because `issued` alone can be back-dated by a Leader and Helper run by one party.
2. Phones refuse to display a release version whose `issued` is after `expires`.
3. Decide what `deck.md` D13's minimum means next to R13's 30 days. Either raise the D13 minimum to `closes` + 30 days + R × `roundWindow`, or tell organizers that a short `expires` shortens the publication allowance.
4. Vectors: a release version with `issued` after `expires` (rejected, R13); `shield-window` case "final version logged before `expires`, seen after" stays; add a simulator case to `sim-shield-long-decks` with a late Leader.

With rule 1 the cap at `expires` is sound, the restore estimate stays an upper bound, and the "Composition" sentence becomes true.

## Should fix

### ADR 0102 — shield anchor

**AS1 — `deck.md` D13, D12; `shield.md` "Restore".** `expires` has no upper bound, and D12 lets it rise in any later version without `closes` moving. Two consequences:

- A member who votes in a deck that never gets a final version keeps that entry until `expires` + 365 days. A context names its own aggregators, so an organizer can arrange that. Seventeen such decks zero the person's shield in every context for as long as the organizer chose.
- Restore is worse. It adds an `estimated` entry for every deck of every backed-up context, voted or not. Eighteen abandoned decks with `expires` in 2090 leave a restored phone unable to vote anywhere until 2091. `shield.md` still says "up to a year after a restore", which is now false. The backup also keeps a left context "until 365 days after the latest `expires`", so leaving does not help.

Fix: D13 adds `expires` ≤ `closes` + 30 days + (R+1) × `roundWindow`. With D2 that bounds a lock at about 1 year + 150 days + 365 days. D12 keeps the same bound on later versions. `ballot.md` B12 has phones refuse a deck outside it. Add vectors `deck-invalid-D13-expires-far` and a version 2 that raises `expires` past the bound. Correct the "up to a year" sentence in `shield.md` to the real bound.

**AS2 — `shield.md` "The ledger", `settledAt`.** `settledAt` is the phone's clock when it verified the final version. A clock set back at that moment records an early `settledAt`, and the entry then drops early. "A clock set back never frees budget" is true only for a clock set back afterwards. Fix: `settledAt` = max(phone clock, the final version's `issued`), then capped at `expires`. Add the case to `shield-window`.

**AS3 — `shield.md` S8.** S8 names `settledAt` and `expires` and omits `chargedAt` from the maximum that "Window" and "The ledger" define. Make S8 repeat the three-way rule so the vector and the rule match.

### ADR 0100 — rule C16

**AS4 — `context.md` C16; `verifier.md`; `credentials.md` P3.** C16 counts verifier authorities. A card proof's `issuer` is an authority, and P3 resolves it to "a logged `verifier` whose lineage is not retired". No spec says an authority has one `verifier` lineage. Two unretired lineages under one authority would have different keys, `validity` and layouts, so their holders would differ in `kid`, `len` and `epoch` inside one "authority". Fix: `verifier.md` validation rules: the log refuses version 1 of a `verifier` when the same authority has an unretired `verifier` lineage. State it in `trust-list.md` "Refs" as well.

**AS5 — `deck.md` "Parts" (breakdown), D9; `verifier.md` "Exposure" item 5.** A breakdown source is "a `tl/<i>` or `issuers[i]` of `ctx`" and need not be a policy leaf, so C16 does not cover it. Both specs still say a trust-list source "pools every verifier the list accepts". A breakdown ballot would carry an extra card whose issuer differs between voters, and only consenting holders would carry it at all. Part 7 is not registrable in phase 1, so this is dormant. Fix: D9 requires the breakdown source to resolve to exactly one verifier authority by the C16 test, and the two "pools every verifier" sentences go.

**AS6 — `docs/threat-model.md`, "A malicious verifier", Stopped by, Denial.** "A person can use any issuer the context's trust list accepts" is false under C16. There is exactly one verifier per leaf. Say that denial by the one verifier has no protocol remedy in draft 0.1, and that the organizer's remedy is a new context version naming another verifier.

**AS7 — `verifier.md`, profile notes, Uniqueness.** "A context that accepts two uniqueness verifiers accepts that one person may hold a card from each" describes a context C16 rejects. Remove it or mark it as a later draft.

**AS8 — `credentials.md` "The uses" (issuance evidence) and P6; `verifier.md` evidence `accepts`.** `verifier.md` reads `accepts` as alternatives ("which cards the phone may present"). `credentials.md` says "one leaf per `accepts` entry", and P6 now forbids `any`, so every leaf must hold. One implementer demands every listed card and another demands one. Say which. If it is one of several, the asking host learns which issuer the person used. That is acceptable only because the host also sees the evidence, and the spec should say so.

### ADR 0101 — logged presentations

**AS9 — ADR 0101 "Consequences"; `credentials.md` "Validity"; `docs/threat-model.md` "Log and witnesses".** The envelope `issued` is author-chosen. The only bound is one log's clock at submission. Witnesses check consistency and never times, and `services.md` says a cosignature timestamp is informational. A context accepts a proof from any one of up to 8 listed logs. So one listed log that skips the check admits:

- a proof from an expired card with a back-dated `issued`, for as long as the `kid` stays in `issuerKeys`, which is the epoch plus 30 days by `verifier.md`;
- unlimited unsigned slots, by back-dating `issued` into old windows.

The ADR says the exposure is "the same as the existing one-hour grace". It is wider. Fix now: correct the ADR and add a row to the threat model saying the log is trusted for this clock check and that no witness audits it. Option for the owner: require of a later verifier that `issued` is at most 3,600 seconds after the earliest cosignature timestamp on the checkpoint that proves the object. That bounds forward-dating without a clock. A lower bound needs an earlier checkpoint in the bundle.

**AS10 — `credentials.md` "Message layout" and P3; `verifier.md` "Attributes".** `len` must be "the layout length of the card's epoch", fixed by "the verifier version in force at the start of that epoch's handover". That maps a wall-clock time to a log position. A later verifier has no clock, and "in force" tells it to read the layout at the object's log position. If a verifier appends an attribute during epoch E, an object written later in E carries the old `len`, and the version at its log position gives the new one. Implementers will disagree, and a deck that pins the object fails at whoever reads it strictly. Fix: give each attribute a `fromEpoch`, set once, as issuer keys already have. Then `len`(E) = 2 + the number of attributes with `fromEpoch` ≤ E, from any later version. Add a vector: attribute appended mid-epoch, object logged after it, valid.

**AS11 — `credentials.md` "in force"; `issue-map.md` "Several logs".** "In force" is defined "in the same log" as the object. A context may name several logs. Three cases have no rule:

- The object is in logs A and B and the key-removing verifier version sits before it in A and after it in B. Phones disagree.
- The verifier lineage is not in the object's log at all. The issuer is not a ref of an authored object, so step 9 at the log does not require it.
- A log that was unreachable for more than an hour can never accept the object, because `issued` is stale by then. A deck that pins the object then fails step 9 at that log.

Fix: (a) the log refuses an authored object or sponsor manifest when the issuer's verifier lineage is not in its own history; (b) an object is valid when the check passes in any listed log the verifier holds a proof for, and a phone that syncs several logs takes the earliest by the rule `issue-map.md` already uses for nullifiers, or the owner picks another rule; (c) a log accepts a stale `issued` when the bundle carries an inclusion proof from another log the context lists, and then applies the later-verifier rule. One vector each. ADR 0071 gives one log at launch, so none of this bites on day one.

**AS12 — `services.md` "What the log runs"; `issue-map.md` "Validation rules" (log bullet); `credentials.md` "Validity".** The first two say the disclosed epoch "must be the log's current epoch". `credentials.md` gives logs the first-hour grace, and the later-verifier formula (`issued` − 7200) depends on it. A log built from `services.md` rejects what a phone built from `credentials.md` expects to find. Fix: both sentences say "current, or the previous period's during the first hour". State whether "within 3,600 seconds" is inclusive. Add edge vectors: at the log, old epoch at boundary + 30 minutes (accepted) and + 61 minutes (rejected), `issued` two hours ahead of the log's clock (rejected); for a later verifier, old epoch at `issued` = boundary + 7199 (accepted) and + 7200 (rejected), new epoch at `issued` = boundary − 3600 (accepted) and − 3601 (rejected).

**AS13 — `verifier.md`, closing paragraph of "Validation rules"; `trust-list.md` steps 3 and 4.** Both say "the verifier version in force at the presentation's log position" for every presentation. A ballot, a join ticket and a token request have no log position, and `credentials.md` now defines two cases. Step 3 of `trust-list.md` also says a `"*"` filter is expanded "at presentation time", which for a logged proof contradicts step 4. Point both at the `credentials.md` definition.

### `manifest.md` edits

**AS14 — `manifest.md` "Verification", last paragraph.** It still says "Logs run steps 1–6 and 8 before appending, and the release ledger also runs step 10 on releases". `services.md` has the log run the step-9 ref rule and step 10 for every type, C16 and the P5 clock check included. ADR 0106 lists this edit as item 7 and its status says items 2 to 7 are applied. Apply it.

**AS15 — `manifest.md` "The envelope" (`issued` row) and "Security considerations" ("Clocks are wrong or manipulated").** `issued` is still "informational, never trusted for ordering". It now decides validity in `release.md` R10, R13 and R14, in the logged-presentation rule, in the unsigned slot window, and in `agent-sponsor.md` AS-6 and `issue-map.md` IM-13. Say where it is load-bearing and who bounds it in each case. This is the other half of ADR 0106 item 7.

## Notes

- **AN1 — `manifest.md` step 6, release.** A `kid` is a free byte string per keyset (ADR 0082 item 3), so both aggregator keysets can use the same `kid` for different keys. Say that a signature counts toward a keyset when it verifies under that keyset's key with that `kid`, and may be tried against both. Add an R9 vector where both keysets use the same `kid`.
- **AN2 — `manifest.md` "Authorities and keys", Compromise; ADR 0082 item 6.** The spec says "from a given log position onward" and then "logged after that position". The reference invalidates "at or after". Pick inclusive and say it once.
- **AN3 — `services.md` "Leaves".** ADR 0082 item 9 writes a genesis keyset's own CID in the leaf's authority slot. Neither spec says so. Add one sentence.
- **AN4 — `services.md` "The bundle", key 1 and B-4.** "Absent for participant-authored types" and "according to the manifest's type" are wrong for an issue-map object in the authority form, a moderation version, and a take signed by its own authority. The registry row in `manifest.md` is right. Make B-4 say "according to the author form". The sentence "If the manifest spec later defines one, that definition wins" is stale now that `manifest.md` points here.
- **AN5 — `agent-sponsor.md` AS-8.** "Each new version carries a proof made for that version" cannot be checked. The scope and the bound message (`agentKey`) do not depend on the version, so the same proof bytes verify in every version of the epoch. Reword to what the log enforces: the proof's epoch is current at each version's submission. The one-hour `issued` bound also limits how long a multi-signer sponsor has to collect signatures.
- **AN6 — `issue-map.md` IM-6, form 3.** "Unexpired at this log position" needs a time, and the log does not bound `issued` for agent objects. Use `issued` < the sponsor version's `expires` and extend the log's 3,600-second check to form 3.
- **AN7 — `services.md` "What the log runs" and `issue-map.md` vectors.** The log answers rule `P5` for a stale `issued`; `issue-map.md` files `im-bad-issued-skew` under IM-6. Name one rule in the expected output.
- **AN8 — stale text.** `credentials.md` "Assumptions", `issue-map.md` item ("same issuer, same branch"); `trust-list.md` "Vectors" ("the ward example"); the residual sentences in `issue-map.md`, `chat.md` §2.5 and the threat model say "first hour", but a logged object's stated `issued` may be up to two hours after the boundary.
- **AN9 — emergency key removal mid-epoch.** After a removal, re-issued holders present a new `kid` and a new nym secret. Ballots of one open deck then show two `kid` values split by time, and a re-issued voter has a second nullifier in that deck. This belongs to ADR 0104, which is still open. C16 does not make it worse.

## Answers to the six questions

### 1. ADR 0100

**Are the public fields identical for every presentation in one context?** Yes for ballots of one deck and for authorship proofs, given AS4. I traced `issuer`, `kid`, `len`, `epoch`, `branches`, the number and order of cards, the `disclosed` keys and the `context` field. What still varies:

| Varies | Where | Reveals | Covered |
| --- | --- | --- | --- |
| Two epoch values near a boundary | Join, token, authorship, sponsor | The holder had not switched cards | Documented residual |
| Two context versions | Join tickets only ("current or previous") | Which version the joiner held | Documented. Authors cannot choose a version (IM-3), a deck pins one, tokens use the latest |
| A trust list whose accepted set changes | Never within a context version; the list version is pinned by CID | Nothing | By construction |
| `kid` after an emergency removal | Ballots of an open deck | Before or after the removal | AN9 |
| Two verifier lineages under one authority | Any use | A cohort | AS4, not covered |
| Breakdown card | Ballots, once part 7 is on | Issuer and consent | AS5, dormant |
| Sponsor proofs | Agents only | Nothing about a person | One verifier, named in `refs.verifier` |

**Is C16 checkable from manifests alone?** Yes. `refs["tl/<i>"]` pins a trust-list version by CID. The test counts entries of that version whose `attributes` hold the name or are empty, and `trust-list.md` rule 4 makes entry authorities unique. No log position, verifier manifest or clock is needed. The count ignores class, retirement and whether the verifier declares the attribute, which is stricter than resolution and deterministic. P6 repeats "resolves to exactly one verifier authority" without saying it means this same static test; say so. Add two vectors: zero accepting entries (rejected), and a `[0, i]` leaf and a `[1, j]` leaf naming the same authority (valid).

**Do the specs agree?** `credentials.md`, `ballot.md`, `issue-map.md`, `chat.md` §2.5, `trust-list.md` and the threat model now make the same claim. False or stale statements left: AS5, AS6, AS7, AN8.

**Is `any` or a multi-issuer source still shown as usable?** Only in AS5 and AS7. `context.md` keeps the encoding, C5's `any` clauses and the `context-policy-eval-*` vectors, each marked as rejected in a context manifest. `cred-present-entry-any` is withdrawn.

### 2. ADR 0101

**Is the two-value rule right?** Yes. A log at time T accepts epoch(period(T)) or epoch(period(T − 3600)), and `issued` within 3,600 seconds of T. Every epoch it can accept is epoch(period(x)) for some x in [`issued` − 7200, `issued` + 3600]. That span is shorter than a period, so it holds at most one boundary, and the two endpoint values cover it exactly.

**Can an author back-date or forward-date?** Not past an honest log: back-dating fails the 3,600-second check, and a not-yet-valid card fails `epoch = E_now`. Past a dishonest log, yes; see AS9.

**Do IM-6, AS-8, step 9 and D7 agree?** Yes for an object written before an epoch turn, and for a key removed before or after the object's log position in one log. They disagree or are undefined in AS10, AS11 and AS12.

### 3. ADR 0102

**Does the B3 attack fail?** The attack as written fails. Seventeen entries reserved on day 0 for decks released on day 366 stay in the sum until day 731. The variant in AB1 succeeds.

**Is the restore estimate an upper bound?** Yes, once AB1 is fixed. The estimated anchor is `expires`; a real anchor is `settledAt` capped at `expires`, or `expires`, and a real `chargedAt` is earlier.

**What should bound `expires`?** `closes` plus the publication allowance plus the rounds; see AS1.

### 4. ADR 0105 rename

Control search first: `hum/(manifest|keyring|delivery)/1` matches on 24 lines in 8 files, so the search runs. Second search, any `(manifest|keyring|delivery)/1`, matches on 28 lines in 9 files. The difference is the leftovers:

| File | Where | Kind |
| --- | --- | --- |
| `conformance.md` | Coverage row "COSE_Sign, detached CID, `manifest/1`" | Leftover, not a quotation |
| `conformance.md` | Item 11 of the notes for other owners, "unlike `manifest/1`" | Leftover, not a quotation |
| `conformance.md` | Pending-ADR line for ADR 0105 | Describes the rename as pending; stale status |
| `services.md` | "Domain strings and scopes", intro | Deliberate mention of the old names |
| `manifest.md` | "The envelope", Domain separation | Deliberate mention of the old name |

`cross-spec.md` §12.3 mentions one `conformance.md` row; there are three lines. `docs/threat-model.md` has no leftover. `reference/src` already signs under `hum/manifest/1` and exports under `hum/keyring/1`; I found no `delivery` label there and did not look further.

### 5. `manifest.md` edits

- **Type registry.** Twelve names; `service` with the nine kinds of `services.md`; `blob-store` retired. Rows for `deck`, `release`, `verifier`, `take`, `agent-sponsor` and the authored types match their specs.
- **Two-keyset release rule.** Matches `release.md` R2 and R9 and "Who signs". See AN1.
- **Keyset version 1.** Matches ADR 0082 items 4 and 5. See AN3.
- **Deck example.** Checked against `deck.md` D1 to D14: required fields present, parts sum to 127/500, `expires` = `closes` + 4 × 3 days, no `aggregators` ref. It passes.
- **Bundle pointer.** Consistent with `services.md`. See AN4.
- **Contradictions left.** AS14, AS15, AN2.

### 6. Invariants and lost expressiveness

**Invariants.**

- Invariant 3: AB1. The yearly bound can be exceeded with an unmodified phone.
- Invariant 6: AS9. Every later verifier now relies on one named log having checked a clock, which no witness can audit.
- Invariants 1 and 2: stronger than before, subject to AS4 and AS5.

**Expressiveness the owner should know is gone in draft 0.1.**

- "Approved list or residents", "invite or approved", and any other two ways into one context.
- A trust list with two verifiers for one attribute cannot back a leaf. The Federation list, and any list covering several districts, is unusable as a policy source for that attribute. An entry with empty `attributes` counts against every attribute.
- No fallback issuer. Each leaf depends on one verifier for issuance, denial and key emergencies.
- No overlap when a context moves from one verifier to its successor. Members switch at a context version, and those without the new card wait.
- A list publisher that adds a second verifier for an attribute makes every context that re-pins the list invalid.
- "Wards 1 to 3" needs the verifier to coarsen at issuance.
- Two uniqueness verifiers cannot be accepted as alternatives.

## Vectors W0-08 still needs for these changes

Beyond the list in `cross-spec.md` §12.5: the R13 `expires` case and the late-Leader simulator case (AB1); D13 upper bound (AS1); `settledAt` with a set-back clock (AS2); C16 zero-entry and same-authority cases; second `verifier` lineage under one authority (AS4); breakdown source with two verifiers (AS5); `len` after a mid-epoch attribute append (AS10); the three multi-log cases (AS11); the six grace and skew edges (AS12); same `kid` in both aggregator keysets (AN1).

## Verdict

Approve with fixes. ADR 0102 item 1 is not closed until AB1 lands in `release.md`. AS1, AS4, AS10 and AS12 should land before W0-08 regenerates vectors, because each changes what a vector expects.

## Re-review

Later on 2026-10-06 · targeted re-check of the fixes recorded in `cross-spec.md` §12.6 · no spec edited, no code run

**Final verdict: approve with fixes. One blocker remains, RB1.** It is the last open path of AB1 and closes with one sentence in `release.md` R13. Six should-fix items follow.

Read for this pass: `cross-spec.md` §12.6 and §12.7; `release.md` R13; `deck.md` "Body fields" (`expires`), "Frozen fields", D2, D12, D13; `context.md` `PUBLISH_WINDOW`; `shield.md` "Window", "The ledger", "Composition", "Restore", S8, S9; `verifier.md` "Attributes" and rules 26 to 31; `credentials.md` "in force"; `issue-map.md` "Windows and clocks", "Several logs" and the log bullet; `services.md` "What the log runs". I did not re-check AS5 to AS9 or AS12 to AS15 beyond the lines these sections share.

### 1. AB1

**The two attacks as I wrote them now fail.**

- **Conforming, timely parties.** R13 holds every version's `issued` to at most `E`, the deck's `expires`, and a non-final version must leave room for its remaining rounds. With the `deck.md` example (`expires` = `closes` + 12 days) version 1 can no longer appear at `closes` + 30 days. Every publication is at or before `expires`. The anchor is `settledAt`, which is at least the final version's `issued`, or `expires`. Both are at or after the last publication. The entry therefore counts for 365 days after it.
- **Late Leader.** The Helper's clock bounds `issued`, the ledger refuses by its own clock after `E`, and phones refuse to display a version issued after `E`. A stalled release dies at `E`.

`shield.md` "Window", "The ledger", "Composition" and S8 agree with each other and with R13 and D13. AS2 and AS3 are closed. The restore estimate is an upper bound, and the "Restore" cost paragraph states the real bound.

**RB1 (blocker) — `release.md` R13; `deck.md` D12 and "Frozen fields". A deck version logged after the deck has expired moves `E` and re-opens publication.** R13 defines `E` as "the `expires` of the pinned deck lineage's latest version in this log". Every deck rule is clock-free by design, so nothing stops a deck version from being logged after the previous version's `closes` or `expires`. D2 and D13 only require the new `closes` to be within a year of `opens` and the new `expires` within 150 days of that. The path:

1. A deck opens on day 0, closes on day 10 and expires on day 22. The Leader logs release version 1 (tallies) on day 10 and then stalls. The release is not final.
2. A voter's entry is unsettled, so its anchor is day 22. It leaves the window on day 387. The phone reserves a full shield of new decks, which release by day 420.
3. On day 420 the organizer logs deck version 2 with `closes` = day 365 and `expires` = day 515. Both satisfy D2, D12 and D13.
4. `E` is now day 515. The Leader and Helper log release versions 2 to 4 on day 425. The ledger's clock check passes.

The map tier of the old decks and all of the new decks are published within weeks of each other. The phone revives the old entries when it sees deck version 2, which is too late. This needs the organizer and both aggregators to act together, and every step obeys the written rules. It is the late-Leader attack with one extra signer.

Fix: in R13, `E` is the `expires` of the deck version in `refs["deck"]`, which R8 freezes from release version 1. A later deck version then cannot move it. A legitimate extension is made while the deck is open, before any release exists, and release version 1 pins it under R2. Add one vector: release version 2 issued after the pinned deck version's `expires` and before a later deck version's (rejected, R13). Optionally the ledger also refuses a deck version above 1 when its clock is past the previous version's `closes`, which makes "logged before `closes`" in R2 mean one thing.

**Can `closes` extensions be chained to push `expires` out indefinitely?** No. D12 lets `expires` rise only with `closes`, D2 holds `closes` within one year of `opens`, and D13 holds `expires` within `PUBLISH_WINDOW` + (R+1) × `roundWindow` of `closes`. The ceiling is `opens` + 365 days + 30 days + 120 days, about 515 days, however many versions are chained. D13 says "checked on every version"; D2 should say the same. Chaining matters for the shield in two ways:

- RB1 above.
- **RS1 (should fix) — `shield.md` "Window", third bullet.** The unsettled anchor is the `expires` of "the latest deck version the phone has verified". A phone that voted under version 1 and has not looked since drops the entry 365 days after version 1's `expires`, while a legitimate extension lets publication run up to a year longer. Add a rule and an S8 case: before an unsettled entry leaves the window, the phone looks up the deck lineage's latest version in the log, and keeps the entry if it cannot.

### 2. `verifier.md` rules 30 and 31

**Rule 31 is sound.** One lineage per authority, retired or not, makes `issuer` name one lineage at every log position, which is what C16 and P3 need. It is stricter than my AS4 and I see no privacy cost. Two lock-outs follow from it:

- **RS2 (should fix) — `context.md` "Entry policy", the sentence after the table; `verifier.md` profile notes.** `context.md` still says a context runs its invite and approved-list verifiers "under its own authority". Under rule 31 a context authority can hold one verifier lineage, ever. A context cannot run both profiles there. Worse, `validity`, `profile` and `class` are frozen, so a wrong version 1, or a full `retiredKids`, cannot be replaced without a new authority, and for a context the authority is the context. Fix: say that an organizer-run verifier uses its own keyset authority, named in `issuers`, never the context's.
- A retiring verifier must move to a new authority, so every context and trust list that names it must republish, with no overlap (C16). That is already in §12.7 as "overlap when moving to a new verifier". No lineage can retire yet, because the envelope has no retired marker.

The tie-break for phones ("the one with the lower log index") should name the log: the log of record.

**Rule 30 is sound against an honest log, and it is one more clock that only a log checks.** It keeps an attribute out of an epoch whose cards may already exist. I checked the short-validity cases (`V` = 1 or 2, where handover covers the whole epoch) and a log clock slightly ahead or behind at a boundary; the rule gives a safe answer in each. The layout formula agrees at every log position, because an attribute's `fromEpoch` is always above the epochs that existed before it was listed.

- **RS3 (should fix) — `verifier.md` rules 29 and 30.** There is no upper bound. `fromEpoch` is frozen and must be non-decreasing in array order. A mistyped `fromEpoch` of 500 can never be corrected, and every attribute appended later must also be at least 500. The only way out is a new lineage, which rule 31 turns into a new authority. Fix: rule 30 also requires a new attribute's `fromEpoch` ≤ `E_now` + 2, and version 1 gets the same ceiling by the log's clock.
- **RS4 (should fix) — `docs/threat-model.md`, the assumptions row added for AS9; `manifest.md`, the new load-bearing-clock table.** A log that skips rule 30 lets an attribute join the current epoch. Cards already issued then carry the old `len`, every verifier computes the new one, and those holders are rejected until handover, since dedup blocks a re-issue. Later verifiers do not re-check. Add rule 30 to the list of checks that rest on a log's clock, and say which log makes it for a verifier manifest, which pins no context.

### 3. One log of record

**Invariant 6 holds.** The log of record is `logs[0].log`, an authority named by key in a signed, logged context version. No hostname and no reference network is assumed. The order of `logs` now carries meaning; deterministic CBOR keeps it, and an object pins one context version, so the answer is fixed per object.

**Against the multi-log rules of `services.md`:** R10 and R14 per log, and step 9 "already in this log", still work, because another listed log accepts an authored object on proof of inclusion in the log of record. Three texts were not brought along:

- **RS5 (should fix).**
  - `context.md` "Log entries" still says a manifest "must be proven in at least one listed log". Authored objects and sponsor manifests now need the first one.
  - `issue-map.md` "Posting" step 3 still says the phone "submits the bundle to each log the context names". The order is now the log of record first, then the others with its proof.
  - `issue-map.md` "Several logs" keeps "a nullifier seen under a different CID in any of them is reused (the earliest log position wins)". Positions in two logs cannot be compared, and an object outside the log of record is invalid anyway. IM-7 and IM-15 should count in the log of record only.
- **RS6 (should fix) — `credentials.md` "in force", sponsor manifests; `agent-sponsor.md` AS-8.** For a sponsor manifest the log of record is "the first entry of `logs` of the context in which the manifest is being used". A sponsor manifest pins no context and is logged before any context uses it. Context X's first log must itself have made the clock check within an hour of `issued`. A context whose first log is a different log can never use that version, and no proof from elsewhere helps, because for X no other log is the log of record. AS-8 also becomes valid in one context and invalid in another, which a step-10 rule should not be. `agent-sponsor.md` does not mention the log of record at all. With one reference log at launch nothing breaks. Fix for draft 0.1: say that a sponsor manifest's clock check is made by the log whose proof the bundle carries, and a context accepts it when that log is any entry of its `logs`. Sponsor proofs have no slot or uniqueness rule that needs a single log.

**Is the "log down for over an hour" path workable for unsigned slots?** Yes, with one addition. A rebuilt object has a new `issued`, so a new CID, a new bound message and a new edit key. That is consistent. The slot scope depends on the window and the slot, and neither was spent if nothing was logged. The gap is that a phone cannot tell an unreachable log from a lost response. If the first submission was in fact appended, the rebuilt object reuses its nullifier in the same window and the log refuses it under IM-7. Add to `credentials.md` "in force" and `issue-map.md`: before rebuilding, the phone asks the log of record for the old CID (`GET /v1/log/entry/{cid}`), and on an IM-7 refusal it treats the old object as logged and moves to the next slot. Add a vector for the lost-response case.

### Remaining items

| Id | Severity | Where | Fix in one line |
| --- | --- | --- | --- |
| RB1 | Blocker | `release.md` R13 | `E` is the `expires` of the deck version in `refs["deck"]` |
| RS1 | Should fix | `shield.md` "Window" | Look up the latest deck version before an unsettled entry drops |
| RS2 | Should fix | `context.md` "Entry policy"; `verifier.md` | Organizer-run verifiers use their own authority |
| RS3 | Should fix | `verifier.md` rules 29, 30 | Upper bound on a new attribute's `fromEpoch` |
| RS4 | Should fix | Threat model; `manifest.md` clock table | Rule 30 rests on a log's clock |
| RS5 | Should fix | `context.md`, `issue-map.md` | Three sentences that predate the log of record |
| RS6 | Should fix | `credentials.md`, `agent-sponsor.md` | A context-independent rule for sponsor manifests |

Notes AN1 to AN9 remain open as §12.6 records. AB1's two original attacks, AS1 to AS4, AS10 and AS11 are closed as checked here. With RB1 fixed I have no blocker left against ADRs 0100, 0101, 0102 item 1, 0105 item 1 or 0106.
