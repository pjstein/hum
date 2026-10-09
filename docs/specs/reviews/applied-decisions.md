# Review of the applied cross-spec decisions — Draft 0.1

Oct 6, 2026 · adversarial review of ADRs 0100, 0101, 0102 (item 1), 0105 (item 1) and 0106 as applied · `seam:` every finding below touches a seam; this review changes no spec

**Update, later on 2026-10-06.** AB1 and AS1 to AS15 were reported applied (`cross-spec.md` §12.6). The "Re-review" section at the end checks them and carries the final verdict. The sections before it are kept as written and describe the specs before those fixes.

**Update, 2026-10-08.** ADRs 0103, 0104 and 0107 were applied (`cross-spec.md` §12.9). The section "ADRs 0103, 0104, 0107" reviews them and carries its own verdict. "Re-review of TS1 to TS14" checks the fixes recorded in §12.10. The last two sections, "TS7, TS10 and rule O-6" and "Confirming check of RT1 to RT4", cover §12.11 to §12.13 and end with the final verdict for that round.

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

## ADRs 0103, 0104, 0107

2026-10-08 · adversarial review of the change set recorded in `cross-spec.md` §12.9 · `seam:` release tiers and floor checks, credential issuance, nullifiers, what leaves the phone, canonical encoding · no spec edited, no code run

**Verdict: approve with fixes. No blocker.** Fourteen should-fix items and one group of notes. TS1 is the one I would land first: it lets a network edge the specs already distrust obtain a card on another person's evidence.

**How I checked.** I had no shell in this session, so I did not run `git diff`. I worked from §12.9 and read each section it lists in the spec files: `release.md` ("Receipts", R1 to R15, vectors); `deck.md` ("Rating decks", D10 to D16); `context.md` ("Body fields" keys 20 and 21, "Log entries", "The noised daily count", C7); `services.md` ("Body keys", "Errors", "What services log", the registry, "Step 10 at the log", "Opening a deck" to "Publishing a release", AG-1 to AG-8, "Issuer and verifier host", "Resolver and mirrors", "OHTTP relay"); `chat.md` (§2.5, §5.17, §12.1 to §12.5, §12.9, §12.10); `issue-map.md` ("Membership proofs", "The `authorship` bundle field", IM-7); `verifier.md` ("Issuer key", "Host key", "Lifetime", rules 26 to 31, the security table); `simulator.md` ("Leak checks"); ADRs 0103, 0104, 0107 and 0110. Edits outside those sections are not covered. `take.md`, `storage.md`, `ballot.md`, `shield.md`, `credentials.md`, `manifest.md` and the threat model were checked by search at the lines §12.9 names.

### Should fix

**TS1 — `verifier.md` "Host key"; `services.md` "Sessions and evidence". A sealed evidence item can be replayed into another session.** Evidence is sealed with `info` = `hum/evidence/1` ‖ authority CID ‖ item name and an empty `aad`. That binds the item to the verifier and to the item name, as the text says. It does not bind it to the session. `verifier.md` says TLS is transport only and that an edge in front of the host sees ciphertext. Such an edge can copy a person's sealed items, open its own session, submit them, and send its own issuance request. The module sees valid evidence and the host signs the edge's commitment. The edge now holds a card, and the person whose evidence it was is refused as a duplicate. The issuance response already uses the 16-byte session ID as AAD; evidence should too. Fix: `aad` = the session ID, in both specs. Vector: an evidence item sealed for one session and submitted in another (rejected). An item that is a bearer secret by nature, such as a one-time code, still depends on the host; say so.

**TS2 — `credentials.md` "Issuance request and response", the HPKE table.** The row "Evidence and issuance request to a host" gives one `info`, `hum/issue/1` ‖ verifier authority CID, for both. `verifier.md` and `services.md` give evidence `hum/evidence/1` ‖ authority CID ‖ item name. The paragraph above the table was updated and the table was not. Split the row.

**TS3 — `release.md` R5 against R6, below the minimum.** R6 now says a below-minimum version records parts 0 and 4 only. R5 still says version 1 "contains part 0 (and 4–7 when planned)" and that a rating deck's version 1 "contains parts 0, 3 and 8". A below-minimum deck with part 5, 6 or 7 planned, and every below-minimum rating deck, cannot satisfy both. Fix: R5 applies when `unlocked` is not empty; below the minimum R6 lists `parts`. Say whether noise for parts 3, 5, 6 and 7 is drawn below the minimum; R6 implies it is not. Vectors: a below-minimum rating release, and a below-minimum release of a plan with part 5.

**TS4 — `ballot.md` "Receipts"; `release.md` "Receipts"; `docs/threat-model.md` "The operator", Remains.** Below the minimum there is no receipt tree, so a voter can no longer detect a dropped ballot. No text says this is a loss. `release.md` says "nothing was published, so there is nothing for a receipt to confirm". There is something: a Leader can now end any deck by reporting it below the minimum, and no voter holds checkable evidence against that. Signed receipts do not help, because a receipt carries a leaf and no nullifier, so a set of receipts does not prove a number of distinct voters. Phase 1 already trusts the Leader for the noise draw, so this is a stated-assumption gap and not a new break. Fix: one sentence in `ballot.md` "What a receipt proves" and one in the threat model.

**TS5 — `services.md` L-5 and the logging table.** L-5 bans exact ballot counts "for a deck that has no final release version". After the final version an aggregator may therefore log exact counts and keep them for the log retention. The rule's own reason, that an exact count beside `nHat` undoes the noise, holds after the final version too. Bucketing to the nearest 50 is rounding, not noise: at a bucket edge one ballot moves the logged value. Fix: no exact count at any time; aggregator logs carry only values that are already public (`nHat`, the padded leaf count, the noised daily series) or a bucket of those.

**TS6 — `deck.md` D11 against D15, rating decks.** D15 sets `minVoters` = max(`GATE_TALLIES`, the context's minimum) and raises `gates[0]` "so D11 holds". D11 also requires `minVoters` ≤ the effective gate of part 3. For a rating deck that gate is `GATE_CELL` per group, 300. A context whose minimum is above 300 then fails D11 on part 3, or passes if the reader takes the vote-deck gate of 800. Fix: D11 treats part 3 of a rating deck as a per-cell gate, outside the `minVoters` test, as it already treats part 7. Vector: a rating deck under a context minimum of 500 (valid).

**TS7 — `release.md` R10 and R14; `context.md` "Log entries" and C11.** The ledger of record is the first entry of `ctx.logs`, read from the context version the deck pins. A context version may reorder or replace `logs`. A new first log has no history, so R14's yearly sum for `rhoYear` and R10's count of rating releases per source both restart. `rhoYear` is a context floor that C10 lets only tighten. This is not new: before this change, dropping a log from `logs` had the same effect. It is now one field. Fix: C11 freezes `logs[0].log` from version 1, or R14 and R10 also count in every log that was first in an earlier context version. The person's shield is not affected either way.

**TS8 — `services.md` V-2.** "A different request answers `conflict`" has no scope. Within one session that is right. In a later session that maps to a spent dedup row, `credentials.md` and `verifier-runtime.md` answer with the masked dedup code, so the phone cannot tell a duplicate from another refusal. Read literally, V-2 answers `conflict` there and reveals the duplicate. Fix: "a different request in the same session answers `conflict`; in a later session the dedup rule and its masked code apply".

**TS9 — `chat.md` §2.5 step 4 and §5.17.** In sequence, one card cannot admit two identities: a ticket is refused when any of its nullifiers is recorded for a live identity, and I checked pooled cards under an `all` policy and a second ticket under the next context version. The remaining path is a race. Two greeters open two tickets from one card before either `join-record` arrives, and both commit an Add. The `join-record` is sent after the commit. Fix: a greeter that sees two live records sharing a nullifier removes the identity whose record is later in the organizers group's order, and a greeter re-checks the records when its Add is rebased onto a new epoch. Vector: two tickets, one card, two greeters.

**TS10 — `context.md` key 21 `relays`; `services.md` "Who runs it" and O-5; `docs/threat-model.md`.** Three gaps:

- No rule says which relay a phone picks, or whether a context relay may carry another context's requests. Two phones will behave differently.
- A relay that only context X names learns that each client address it sees belongs to a member of X. The relay row of the threat model does not list that, and membership is a protected asset there.
- `context.md` says a named relay "must pass O-5", and C7 does not check it. The part that needs no lookup can be a C7 rule: no entry of `relays` equals any authority the context names in `logs`, `aggregators`, `stores`, `resolvers` or `chat.delivery`.

Fix: state the selection rule (a context relay is used only for that context's requests, in rotation with the shipped relays), add the C7 check and a vector, and add the sentence to the threat model. Invariant 6 holds for both new fields: they name services by key, and absence falls back to constants in the audited build.

**TS11 — `services.md` "Who runs it, and how a phone finds one", the shipped bundles.** The shipped bundle of the reference log's `service` manifest carries the gateway key configuration of the day the build was made. O-2 accepts a new configuration only from a logged manifest, and the phone cannot read the log without a working configuration. After a key rotation a fresh install cannot make its first request. Fix: the reference gateway keeps decrypting under every key configuration shipped in a supported build; and at first contact the phone replaces each shipped bundle with the latest version of its lineage from the log. Vector or simulator case: a first request with a shipped configuration one rotation old.

**TS12 — `services.md` "Body keys" against its neighbours.** I found no key collision and no gap inside a row, and the issuance and token bodies agree with `credentials.md`, `storage.md` §6.2 and `chat.md` §12.3 to §12.5. What does not agree:

- `ballot.md` "Receipts" and its phase 2 section still give the receipt as `{leaf, signature}`. The table has `{0: leaf, 1: signature, 2: kid}`, and the list of what the phone keeps has no `kid`.
- The gallery responses and the two `/v1/log/proof/` responses have no row and no body shape anywhere. ADR 0107 item 3 said every body.
- "Step 10 at the log", `service` row, names `storage.md` BS-1 to BS-6 and not `chat.md` DL-1 to DL-5.

**TS13 — `simulator.md` "Leak checks".** Three points:

- "The checker fails if two phones of one context register different tuples" will fail on correct runs: a ballot carries the epoch of the deck's version-1 `closes` while an authorship proof carries the current epoch, two context versions may differ, and the first hour after an epoch turn allows two values. Compare per use and per context version, and exempt the grace hour.
- The registry holds nullifiers. A presentation carries the 48-byte pseudonym, and the nullifier is its hash. A pseudonym that reaches the wrong service is not found by a scan for the nullifier. Register both for every scope.
- The ledger row still says authored objects "carry an author nullifier". They no longer do; the log derives it.

**TS14 — `verifier.md` "Issuer key".** The text is honest that `KEY_TAIL` is a waiting time no rule enforces, and the arithmetic is right: one year of extension, 150 days to `expires`, 5 days of margin. What relies on it is every replacement and later round of a long deck, through P3. One consequence is not stated: `issuerKeys` holds at most 8 keys, a flaw fix requires a new `kid`, and a replaced key now stays listed for 520 days. A verifier can change keys about seven times in 17 months before the next change forces an emergency removal, which ends the later rounds of open decks. State the limit, or raise the cap.

### Notes

- **Stale sentences left by these edits.** `credentials.md` "One voting device" and "Open questions" still say the two-phone risk awaits the owner. `shield.md` "Open questions" says draft 0.1 has neither exception. `issue-map.md` "Rate limits" still asks `services.md` to name the counter retention, and its assumptions list still says "count IM-15 per log". `services.md` "Publishing a release" step 3 submits to "every log" with no order. `chat.md` §12.1 lists relay rules O-1 to O-4 and omits O-5. ADR 0101's and `credentials.md`'s "epoch plus the retirement tail" is now 520 days of exposure to a lax log, not 30; the wording is right and the size changed.
- **`deck.md` D16, second half.** "A release that pins its lineage" should say a valid release version.
- **`release.md`.** ADR 0103 item 4 has phones apply R14; the spec has phones run R1 to R13. Pick one.
- **`chat.md` §5.17.** When a context version moves `entry` to a different verifier, one person can hold one identity per card across the change. That follows from "one identity per card" and is the organizer's doing. The snapshot of 50,000 rows of up to eight nullifiers is about 15 MB in one message.
- **ADR 0110.** A second implementation in the Python reference keeps vectors away from the code under test. It is independent only if it is written from the drafts by a different workstream and shares no code or helper with the crate; the ADR should say so. Both sides read the same Hum layout text, so a shared misreading of the header or the presentation header passes. Keep `zkryptium` as a third check where its draft versions match.
- **Owner-only edits still pending.** `CLAUDE.md` invariant 3 needs the daily-count clause, and `sim/src/leak.rs` needs the allow-table change. §12.9 records both.

### Answers to the six questions

**1. ADR 0103 item 1.**

- **Does anything below the minimum reveal an exact or unbudgeted count?** No. A below-minimum version publishes `final`, an empty `unlocked`, `absorbed`, and ρ and σ for parts 0 and 4. The fact of being below the minimum is a function of the noised `nHat`, paid for by part 0. `absorbed` is a function of the noised daily total, paid for by part 4. The absence of receipts, the `404` and the missing `nHat` add nothing to that one fact. The daily series stays with organizers and is noised. The exception to this answer is the aggregator's own logs; see TS5.
- **Is the phone's charge still an upper bound?** Yes. The phone charges `plan.rho`, D8 still requires part 8 in the plan, and not drawing part 8's noise leaves ρ unspent.
- **Does a voter lose the ability to detect a dropped ballot, and is that stated?** Yes, and no. See TS4.

**2. ADR 0103 items 2 to 4.** D16's clock-free half agrees with R2: the release pins the highest deck version below it, and a deck version above a release is invalid. The rating-deck minimum has the gap in TS6. R10 and R14 against the ledger of record agree across `release.md`, `services.md` and `context.md`, with the gap in TS7.

**3. ADR 0104.**

- **`KEY_TAIL`.** Honest about not being enforced. See TS14.
- **Emergency key removal mid-deck.** `verifier.md` "Lifetime" and `ballot.md` "Security considerations" say the same thing, including the second count a modified client gets.
- **V-2.** See TS8.
- **Can one card admit two identities?** Not in sequence. By a race, yes; see TS9. Deleting a record when its identity leaves lets the same card join again under a new identity, which the text states and which predates this change.
- **Does the array or `day` link a join to anything else?** No. The nullifiers are under the join scope, sorted so position says nothing, and never leave the organizers group. `day` is the day of a join the group already sees in the tree. The maximum `validity` is 366 days, which gives epochs of at most 364 days, so the 396-day drop cannot remove a record whose card is still valid.
- **`authorship` without key 4.** A verifier can still recompute every nullifier. Each card proof carries its pseudonym, and the nullifier is the hash of `hum/nullifier/1` and that pseudonym. IM-7, the example and the log's counter row agree.

**4. ADR 0107.**

- **Keys 20 and 21.** See TS10.
- **Shipped bundles.** See TS11.
- **Body keys.** See TS12.
- **Evidence `info`.** `verifier.md` and `services.md` agree. `credentials.md`'s table does not (TS2), and the missing session binding is TS1.
- **DL-1 to DL-5.** They are checkable from the manifest and the previous version, and each has a vector. They are missing from the log's step-10 table (TS12).
- **`AUTHOR_WINDOW`.** Control search: `AUTHOR_WINDOW` matches on 10 lines in `services.md`, `issue-map.md` and `context.md`. The same search for `unsignedWindow` and `UNSIGNED_WINDOW` across `docs/specs/*.md`, the threat model and `docs/design.md` matches nothing. The rename is complete.
- **L-5.** See TS5.
- **The simulator allow table.** Delivery and device key are "no", and the four new kinds are placed as ADR 0107 says. See TS13.

**5. The two recorded decisions.** The two-phone risk is stated the same way in the threat model ("A compromised phone" and the assumptions table) and in `shield.md` ("Restore" and "Security considerations"), with the stale lines in the notes. ADR 0110: see the notes.

**6. Contradictions, the registry, stale text.** New contradictions: TS2, TS3, TS6, TS8 and TS12. Registry: I listed every `hum/…` string in the fourteen other spec files and compared them with the `services.md` table; none is missing, and `hum/evidence/1` is there. `hum/reissue/1` appears in `credentials.md` only as a withdrawn name. Stale text: the notes.

### Vectors these findings add

An evidence item replayed into another session (TS1); below-minimum rating release and below-minimum release with part 5 (TS3); an aggregator log line with an exact count after the final version (TS5); a rating deck under a context minimum of 500 (TS6); a context version that changes its first log, with R14 across the change (TS7); a different issuance request in a later session against a spent row (TS8); two tickets, one card, two greeters (TS9); a relay equal to a named service authority (TS10); a first request with a rotated gateway key (TS11); a receipt with `kid` in `ballot.md`'s vectors (TS12); public card fields for a ballot and an authorship proof of one phone (TS13).

### Verdict

Approve with fixes. No blocker. TS1, TS2, TS3, TS6 and TS12 change bytes or expected results, so they should land before W0-08 regenerates vectors. TS7 and TS10 need an owner choice between two fixes.

## Re-review of TS1 to TS14

2026-10-08 · targeted confirming pass on the fixes recorded in `cross-spec.md` §12.10 · no spec edited, no code run

**Final verdict: approve with fixes. No blocker.** Eleven of the fourteen are closed as written. TS1 and TS5 are each closed for the case I described and open for a neighbouring case (RT1, RT2). TS7 and TS10 stay with the owner, as recorded. Two small items follow (RT3, RT4).

Read for this pass: §12.10; `verifier.md` "Host key", "Issuer key"; `services.md` "Body keys", L-5 and the logging table, "Sessions and evidence", "Issuance", V-2, "Who runs it"; `credentials.md` HPKE table; `release.md` R5, R6; `deck.md` D11, D15; `context.md` C7; `chat.md` §2.5 step 4; `ballot.md` "Receipts"; `take.md` "Gallery ranking"; `simulator.md` "Leak checks"; the threat model by search. I did not find the threat-model sentence on what a context-named relay learns by search, so that one line is not confirmed.

### Still open

**RT1 (should fix, land first) — `verifier.md` "Host key"; `services.md` "Sessions and evidence", "Issuance". The session ID binds nothing the edge cannot choose, so the edge can still get a card on a person's evidence.** Replay into another session now fails: the AEAD does not open under another session ID. That closes TS1 as I wrote it. The claim `verifier.md` now makes is wider, and it does not hold, for two reasons:

- The session ID is 16 bytes the host returns in a plain response. The edge terminates TLS, so it sees the ID and can replace it. It can open its own session and hand that ID to the phone. The phone then seals its evidence for the edge's session.
- The edge does not need a second session. The session ID is the only credential for the `issue` call. The edge lets the phone's evidence through, drops the phone's issuance request, and sends its own sealed request in the same session. The host signs the edge's commitment and seals the response to the edge's HPKE context.

Either way the edge holds a card and the person is refused as a duplicate. Nothing ties the evidence to the issuance request that will be signed. Fix: the phone builds the issuance request first, and evidence `aad` = session ID ‖ SHA-256(issuance request plaintext). The host opens the issuance request, recomputes the hash, and refuses the session if any evidence item was sealed under another. The `credential` evidence kind already binds to that same hash as its bound message, so this is the existing pattern. The edge then cannot swap the request without the evidence failing to open. It can still deny service. Vectors: an issuance request that differs from the one the evidence was sealed for (rejected); a session ID replaced in transit (the phone's items open only with the matching request). This is not a blocker by this review's definition, since no `CLAUDE.md` invariant breaks, but the sentence "cannot be replayed … into another session" should not stand as the whole defence until it lands.

**RT2 (should fix) — `services.md` logging table, Aggregator and Gateway rows; L-1, L-5. Request logs still count accepted ballots.** L-5 now bans any count of accepted ballots, before and after the final version. Two rows of the same table let the count back in:

- The Aggregator row allows "timing per request without a ballot identifier" beside the deck CID and round. One line per request is a count.
- The Gateway row allows "decrypted request's path and result code … or counts per path", kept 30 days. A ballot path holds the deck CID and the round. The number of `200` answers on that path is the number of accepted round-0 sends: voters plus replacements. For a below-minimum deck that is a near-exact turnout the release withheld.

Fix: for ballot-intake paths the gateway and the aggregator log no per-request line and no per-path count. They may keep one counter per service per day, or the path with the deck CID removed. Extend the L-5 vector to a gateway log.

**On the rejected-request counts that were kept.** They cannot reveal turnout: a rejection adds no voter. They are not all voter-free, though. `closed` on a different round-0 body after `closes`, `conflict` with detail `duplicate` in rounds 1 to 3, and `conflict` with detail `nullifiers` each come from a pseudonym that already voted. An exact per-deck count of those says how many voters tried again, which is small, exact and unbudgeted. `malformed`, `too_large`, `rejected` and `forbidden` say nothing about voters. Fix inside RT2: count nullifier-dependent codes per service, not per deck and round. No single person is identified by any of these counts.

**RT3 (should fix, small) — `release.md` R6, rating decks.** TS6 is closed in `deck.md`: under a context minimum of 500 a rating deck has `minVoters` 500 and `gates[0]` 500, and D11 no longer tests part 3. R6 still unlocks "parts 1–3 iff planned and the part's own `n` ≥ gate(1)". For a rating deck that reads as 800, while `deck.md` gates part 3 per group at `GATE_CELL` in post-processing. Say in R6 that a rating deck's part 3 is unlocked with part 0 and its cells are filtered like part 7's. The new rating vector depends on it.

**RT4 (note) — `chat.md` §2.5 step 4.** The tie-break is sound: the delivery-service sequence number is the same for every member of the organizers group, so every greeter removes the same identity, and the re-check on rebase removes most races before they land. One gap remains: a greeter that commits the Add and fails before sending the `join-record` leaves no record, so the card can join again. Have any greeter that sees an Add with no record within a set time write the record or remove the leaf.

### Confirmed closed

| Item | What I checked | Result |
| --- | --- | --- |
| TS2 | `credentials.md` HPKE table | Two rows; evidence row gives `hum/evidence/1` ‖ authority CID ‖ item name with the session ID as `aad` |
| TS3 | R5 against R6 | R5's part lists apply only when `unlocked` is not empty. Below the minimum only parts 0 and 4 are noised, for vote, IBIS and rating decks. Not drawing noise for parts 3, 5, 6, 7 and 8 publishes nothing and leaves ρ unspent |
| TS4 | `ballot.md` "Receipts"; threat model "The operator" | Both state the loss |
| TS6 | D11, D15 at a minimum of 500 | Valid under `deck.md`; see RT3 for `release.md` |
| TS8 | V-2 | `conflict` in the same session only; the masked code in a later one |
| TS9 | §2.5 step 4 | See RT4 |
| TS11 | "Who runs it" | The gateway keeps shipped configurations; the phone refreshes at first contact |
| TS12 | `ballot.md`; "Body keys"; the log's step-10 table | The receipt carries `kid` in both places and in the kept set. No collision in the six new rows. The proof rows match the endpoint parameters. DL-1 to DL-5 are in the table |
| TS13 | "Leak checks" | Pseudonym and nullifier both registered; the tuple check is per use and per context version with the grace allowed; the ledger row is corrected |
| TS14 | "Issuer key" | The limit is stated |
| C7 | The lookup-free O-5 check | Present, with a vector. It also covers `issuers`, which is stricter than O-5 needs and harmless |

**On the six provisional "Body keys" rows.** Three loose ends against `take.md`'s sort key `(rated, hasGroupScore, score, forkCount, logIndex)`: the row calls the fourth element `forks` and the fifth `index`; `score` × 10⁶ needs the same rounding rule `take.md` uses for six decimals, with ties stated; and the row does not say what `score` holds for an unrated take. One sentence each.

**Stale sentences.** The seven phrases I listed in the earlier notes no longer match in `credentials.md`, `shield.md`, `issue-map.md`, `chat.md` or `services.md`. `services.md` "Publishing a release" step 3 now names the ledger of record first. I found no new stale sentence in the sections read.

### Open after this pass

| Id | Severity | Where | Fix in one line |
| --- | --- | --- | --- |
| RT1 | Should fix, first | `verifier.md`, `services.md` | Bind evidence to the hash of the issuance request, not to the session ID alone |
| RT2 | Should fix | `services.md` logging table | No per-request line or per-path count for ballot intake, at the aggregator or the gateway |
| RT3 | Should fix | `release.md` R6 | A rating deck's part 3 unlock rule |
| RT4 | Note | `chat.md` §2.5 | An Add with no `join-record` |
| TS7 | Owner choice | `context.md` C11 or `release.md` R10, R14 | Freeze the first log, or count across earlier first logs |
| TS10 | Owner choice | `services.md`, `context.md` | Which relay a phone picks for a context |
| — | Wording | `services.md` "Body keys" | The three gallery loose ends |

RT1 and RT3 change bytes or expected results and should land before W0-08 regenerates vectors.

## TS7, TS10 and rule O-6

2026-10-08 · check of the owner choices recorded in `cross-spec.md` §12.11 and the tightening in §12.13 · no spec edited, no code run

**Both are closed.** One residual is recorded as a note.

Read: `context.md` C11, key 7, key 21 and the C11 line of its vector list; `release.md` R14; `services.md` rule O-6 as it stands after §12.13.

**TS7.** `context.md` C11 freezes `logs[0].log` from version 1. The witnesses of that entry and the other entries may change. The ledger of record, and the log of record for authored objects, are therefore the same log for the whole life of a context lineage, so the counts of `release.md` R10 and R14 cannot restart. The cost is stated: a context whose first log must change starts a new lineage. The vector list in `context.md` has the cases: version 2 changes `logs[0].log` (rejected); version 2 swaps the first two entries (rejected); version 2 changes `logs[0].witnesses` and adds a second log (valid). I verified the line is there.

**TS10 and rule O-6.** The selection rule can be tested and never falls back to a direct connection: the relay set is built per request, the pick is uniform at random per new connection, a failure picks again from the rest, and a relay named by context A never carries a request of context B. Two kinds of request use the shipped relays only, whichever context they belong to:

- every request to an aggregator: ballots, receipt lookups, receipt pages, deck status and published rounds;
- every submission to a log, with its poll.

The first version of O-6 held back only ballots and receipt fetches. I raised two gaps and both are now closed in the text. An organizer-chosen relay could time deck status polls and round fetches, which mark an address as a probable voter. It could also time log submissions against the public log, and so tie an unsigned object to an address without any collusion. Log reads may still use a context relay, which is fine.

**Residual (note).** The phone puts an object's text blob to the store just before it submits the object to the log, and that put may still go through a context relay. The relay sees an address write to the store's gateway a few seconds before an unsigned object appears in the public log. The signal is weak: store puts are frequent, and the relay cannot tell a text blob from an attachment in the same size bucket. Either send the text-blob put for an unsigned object over a shipped relay, or delay the submission by a random time, or record it with the other timing residuals in the threat model.

## Confirming check of RT1 to RT4

2026-10-08 · check of the fixes recorded in `cross-spec.md` §12.12 · no spec edited, no code run

**RT1, RT2 and RT3 are closed. RT4's fix is right in its main rule and has two should-fix gaps in the rules around it (RU1, RU2). One small item remains under RT2 (RU3).**

Read: §12.12; `verifier.md` "Host key"; `services.md` "Sessions and evidence", "Issuance", V-1 to V-4, the Aggregator and Gateway rows and L-5; `release.md` R6; `chat.md` §2.5 step 4. I did not re-read `credentials.md` or `verifier-runtime.md` for RT1 and take §12.12's word that they follow.

### RT1 — closed

Evidence `aad` is now the session ID followed by SHA-256 of the issuance request plaintext. The host holds items sealed until the issue call, opens the request, and opens each item under its hash. I tried each path an edge has:

| The edge does | Result |
| --- | --- |
| Sends its own issuance request with the person's evidence, same session or its own | No item opens under the edge's request hash. `rejected`, rule V-4. No card |
| Hands the phone the ID of a session the edge opened | The phone's items are bound to the phone's own request. Only that request opens them, and the card it yields is the phone's |
| Reorders: its own request first, the person's evidence after | Same as the first row. The host runs nothing until it has the request and every item |
| Replays both the evidence and the person's request, in any session | The host signs the person's commitment. The response is sealed to the HPKE context of the person's request, and completing the card needs the person's own nym share. The edge gets nothing it can use. The dedup row stores that request's hash, so the person's own retry gets the identical response |
| Forges evidence for its own request | It cannot. The request plaintext holds fresh commitments and is sealed, so the edge cannot compute the hash of a request it did not make and cannot read the evidence to re-seal it |

Handover: one request with two commitments, one hash. Lost response: a new session, the same request plaintext, evidence sealed again under the new session ID and the same hash, identical response. Both work.

What remains is denial of service, which the text states. Three small points, none a finding: the host now stores sealed items for up to an hour before it can inspect them, so the per-session size cap must apply to ciphertext; `sessionCap` counted by the `device` item can only be applied at the issue call; and V-4 is listed before V-3.

### RT2 — closed, with one small item

The Aggregator row has no line per request, no timing per request and no count per deck, round or path for ballot intake. The Gateway row strips the deck CID and round from ballot paths and forbids a count of `200` answers per path. L-5 covers the gateway. Rejection codes that only an earlier voter can cause are counted per service per day; the others may be counted per deck. The table and L-5 agree.

**RU3 (should fix, small) — `services.md` Gateway row.** "The only counter is one per service per day." When an aggregator has one open deck on a given day, that counter is the number of accepted sends for that deck on that day, exact. That is common in a small network. Fix: the counter covers every request to the aggregator, whatever the path or result, so status polls and receipt fetches are mixed in; or it is dropped for ballot intake.

### RT3 — closed

`release.md` R6 unlocks a rating deck's part 3 with part 0 and filters its group cells at `GATE_CELL`, as part 7's are. It agrees with `deck.md` D11 and D15 and with R5.

### RT4 — main rule sound, two gaps

Sending the `join-record` before the Add is the right order. Every greeter sees records in one sequence, the greeter with the later record stops, and a greeter that fails between the two leaves a record and no member. Two tickets from one card cannot both be admitted by honest greeters.

**RU1 (should fix) — `chat.md` §2.5 step 4, the backstop "an Add of a new identity with no `join-record` … removes the leaf".** A malicious greeter gains nothing from it, since a greeter can already remove members. An honest greeter following the rule as written can remove legitimate members in four cases:

- **Open contexts.** §5.17 says a context whose entry policy is `[0]` produces no `join-record`. Every Add there has no record, so the backstop removes everyone.
- **Agents.** A shared agent is added with no card and no ticket, so it never has a record.
- **Ordering across two groups.** The record is in the organizers group and the Add is in the all-members group. A greeter that has processed the commit and not yet fetched the record sees an Add with no record.
- **A withholding delivery service.** A delivery service that delays the record to one greeter makes that greeter remove a legitimate member. Before this rule a delivery service could only drop messages.

Fix: the backstop applies only to an identity with a person credential, in a context whose entry policy yields a nullifier, and not to a new device of an existing identity. Before acting, the greeter fetches the organizers group past the time of the Add and waits a fixed grace, for example ten minutes. Vectors: an open context (no removal); an agent Add (no removal); a record that arrives after the commit within the grace (no removal).

**RU2 (should fix) — `chat.md` §2.5 step 4, the pre-commit check against "an earlier record … [that] names a different identity".** The same paragraph says a record whose identity is not a member is inert and blocks nothing. The check does not say the earlier record must be live. Read literally, an inert record blocks the card for 396 days in two ordinary cases: a person whose first ticket failed after its record and who retries under a new chat identity after reinstalling; and a person who left, whose record a greeter has not yet deleted. The check cannot simply require a live identity, because in the race neither identity is live yet. Fix: the earlier record blocks when its identity is a member, or when the record is younger than a fixed pending time, for example one hour. Vector: a retry under a new identity one day after a failed greeter (admitted).

### Open after this pass

| Id | Severity | Where | Fix in one line |
| --- | --- | --- | --- |
| RU1 | Should fix | `chat.md` §2.5 step 4 | Scope the no-record backstop and add a fetch and a grace |
| RU2 | Should fix | `chat.md` §2.5 step 4 | An earlier record blocks only when live or recent |
| RU3 | Should fix, small | `services.md` Gateway row | The daily counter must not equal one deck's intake |
| — | Note | `services.md` O-6 | The text-blob put before an unsigned submission |

Neither RU1 nor RU2 changes bytes. Both change expected results in the `chat/join` vectors.

### Final verdict for the ADR 0103, 0104 and 0107 round

**Approve with fixes. No blocker remains.** TS1 to TS14, RT1 to RT3, and the owner choices for TS7 and TS10 are closed. RU1, RU2 and RU3 are open as should-fix, and one timing residual is recorded as a note.
