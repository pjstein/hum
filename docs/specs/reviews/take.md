# Review: `docs/specs/take.md` (Draft 0.1, W0-04)

Reviewed 2026-10-06 against `CLAUDE.md`, `docs/design.md`, `docs/specs/manifest.md`, `docs/specs/context.md`, `docs/specs/deck.md`, `docs/specs/release.md`, `docs/specs/chat.md`, `docs/specs/storage.md`, `docs/specs/services.md`, `docs/specs/issue-map.md`, `docs/specs/agent-sponsor.md`, and decisions 0043, 0015, 0010 and 0013.

Not on disk: `credentials.md`, `ballot.md`, `shield.md` (W0-02). Findings that depend on them are marked.

## Verdict

**Approve with fixes.** A take is a query plus prose over pinned releases, so it costs no budget, and ratings are collected as a deck, so they inherit the cap, the floors, one release per deck and the shield charge. Both are right. Three blockers: an agent can publish a take under someone else's authority, a sealed take leaks its prose through the public manifest, and several measures are not defined well enough for two clients to draw the same number.

Answers to the questions the lead asked:

- Ratings as deck kind 1 are charged to the shield (the phone charges `plan.rho` at the first ballot, `deck.md`), count toward the context's yearly ρ (`release.md` R14 covers every release of the context lineage), and compose additively under zCDP with everything else. The two parts, tallies and groups, each have their own ρ and their own noise, so the per-part sensitivities in `deck.md` apply unchanged. OK.
- The justification for the group slot in phase 1 is wrong in one detail; see S3.

## Findings

### Invariants

**B1 (blocker) — "Authority and authorship", agent form, and TK-5.** An agent take has `authority` = the sponsor's keyset lineage but is signed by `agentKey`, not by that keyset. TK-5 checks the sponsor manifest's capability and the signature, and never checks that the sponsor manifest's envelope `authority` equals the take's `authority`. An agent of sponsor S can publish a take whose `authority` is any other lineage X, and the gallery shows it as X's. Fix: TK-5, agent case: "`refs.sponsor` resolves to an `agent-sponsor` manifest whose envelope `authority` equals this take's `authority`, is unexpired and unretired at the take's log position, and whose `capabilities` include `take`". Add vector `tk-bad-agent-authority-mismatch`.

**B2 (blocker) — "Body" keys 0, 1 and series key 6, for sealed takes.** `title` (120 scalars), `byline` (40) and every series `label` (40) are plaintext in the manifest body, which is logged in the clear. A members-only take over sealed results therefore publishes its headline ("The strike question splits Ward 2") and its series labels to anyone. `context.md` seals results so that non-members learn nothing but `nHat`. Fix: for every take, move `title`, `byline` and series labels into the text blob as a small CBOR header (or a separate `meta` blob pinned in `refs`), so they are sealed when the take is sealed and deletable when it is not. The gallery index reads them from the blob. This also answers invariant 4's "manifests carry no personal data": a byline is the closest thing to a name the protocol would otherwise log forever.

**S1 (should fix) — "Authority and authorship", person form.** Nothing stops a person from using their chat identity key as the keyset's `sign` key. That would put a members-only context's chat key (see `reviews/issue-map.md` S1) into a public keyset for every take they write. Say: a take authority's keys MUST be generated fresh for it and never equal a chat identity key, an edit key or a context keyset key.

**S2 (should fix) — "Ratings", eligibility, and `deck.md` D15.** "Every take version that pins the source release ... earliest-logged 60" reads as a rule, but neither D15 nor a TK rule checks it. An organizer can deal a rating deck of only the takes they like, and unrated takes sort below rated ones, so this is ranking power. Either make it checkable (add to D15: the cards are the first up to 60 eligible takes by log order at the deck's log position) or say plainly that card choice is the organizer's and that the gallery marks takes that were eligible but not dealt.

**S3 (should fix) — "A rating round is a deck", the phase-1 paragraph.** "It could already compute that from the same pseudonym's source-deck ballot" is false after release: `services.md` has the aggregator delete every ballot and nullifier within 24 hours. The rating ballot tells the phase-1 aggregator the pseudonym's group afresh. That is still inside the phase-1 model, where the aggregator sees pseudonymous votes by design, and the group is one one-hot coordinate inside the noised groups part, so the guarantee holds. Fix the sentence so it does not rest on retained ballots. Marked as depending on `ballot.md`.

**N1 (note) — `lang`.** Bound it as `verifier.md` does: text ≤ 16 with the BCP 47 pattern.

### Floors

Rating decks: ρ ≤ 1/20 and ≤ the context floor (D15, D10), cap ≤ 20 (D15), gates `GATE_TALLIES` and `GATE_CELL` per group (`deck.md` Parts), one release lineage per deck (R10), two per source per year (R10). Nothing here can loosen a floor. The parameters remain the owner's call (ADR 0043). OK.

### Sums

A rating is a card vote with a group slot; both parts are sums of bounded per-person vectors. Pooling across versions with the same `queryHash` is post-processing on noised sums. OK, but see S6 for the σ of a pooled cell.

### Federation

Releases, takes and sponsors are named by CID; the gallery is a cache phones can recompute (`services.md` G-1). OK.

### Consistency

**S4 (should fix) — "Query spec", series key 2 `statements`, and TK-4 "the pinned release's statement list".** A release carries no statement list (`release.md`, "A release carries no statement text"). The CIDs live in the pinned deck's `card/<i>` and `card/<i>/pro|con` refs. Say "in the `refs` of the deck the release pins". Also bound the array: no limit exists, and 12 series of unbounded CIDs can exceed the envelope. Suggest ≤ `MAX_CARDS` (256) per series.

**S5 (should fix) — "Query spec", series key 4 `attribute`.** Typed text, "as the release's `breakdown_cells` table spells it". That table's `value` column is int64 (the attribute's uint value, `verifier.md`). Make `attribute` a uint and rename it `value`.

**S6 (should fix) — "Ratings and versions" and "Gallery ranking": pooled cells.** Pooling noised counts across versions with the same `queryHash` sums independent noise. Say the pooled cell's σ is `√(Σ σᵢ²)` over the rating releases pooled, and that `f_low` uses it. Otherwise `take-rank-*` vectors are not reproducible. Also define `queryHash` bytes exactly: suggest `SHA-256("hum/take-query/1" ‖ deterministic CBOR of the array [query, chart])`, with the series `label` fields removed first if B2 moves them out of the body.

**S7 (should fix) — Measures against `release.md` tables.** Four measures cannot be computed as written:

- `movedToward`, `movedAway`, `unchanged`: "as `release.md` defines them". `release.md` defines no toward or away grouping; `movement` has `first` and `second` codes 0 agree, 1 disagree, 2 unsure. Define it here, for example toward = (disagree→agree, unsure→agree, disagree→unsure), away = the reverse three, unchanged = first = second.
- `count`: "one noised count of any row" names no column. Add a `column` field or one measure per column.
- `consensusScore`, `repnessScore` "with its published interval": `consensus` has `score`, `repness` has `metric` and `significant`; neither has an interval. Either drop "interval" or ask W0-01 to publish one.
- `mapCell`: the series has no `x`, `y` selector.

**S8 (should fix) — "Noise math", order of operations.** "Clamp `p` to [0, 1] and `N` to at least 1 for display, after computing σ_p from the unclamped values" leaves `N ≤ 0` producing a negative or infinite σ_p before the `N < 10σ` test. State the order: compute `N` from raw counts; if `N < 10σ` render the gap; else compute `p`, σ_p, then clamp for display. `release.md`'s round-1 rule clamps counts at 0 before summing; this spec does not. Pick one and say binary64, as `release.md` does, or the six-decimal vectors will disagree.

**S9 (should fix) — Enum encoding.** `author`, `compare`, `table`, `measure`, `chart.type`, `sortBy` are text. W0-01 uses uints. One decision for the cross-spec pass (see `reviews/issue-map.md` S9). Table names are the Parquet file names, so text is defensible there; say so if they stay.

**N2 (note) — TK-3 and "Forking".** "A fork of a sealed take is sealed" is not a rule. Add to TK-9: `forkOf` sealed ⇒ this take sealed and same context. Add vector `tk-bad-fork-unsealed`.

**N3 (note) — `refs.statement/<k>`.** No rule validates these. Add to TK-4: each resolves to a `position` manifest or statement blob pinned by one of the pinned releases' decks.

**N4 (note) — TK-1 and release versions.** A take may pin a non-final release version. That is fine for pinning, but rating eligibility compares against `refs.source`, which is the final version. Say takes SHOULD pin the final version, and that a take pinning an earlier version of the same lineage is eligible for the rating deck of that lineage's final release, or is not. Pick one.

**N5 (note) — `services.md` gallery paths.** The "Assumptions" section cites `/v1/gallery/takes`; `services.md` has it. OK.

### Implementability

**S10 (should fix) — "Gallery ranking", ties and the overall-only case.** "Sorts below any take with a group score at the same value" and "ties break by fork count, then log order" need a total order two implementations reproduce: define the sort key as a tuple, for example `(hasGroupScore, score, forkCount, −logIndex)` descending, with `score` compared in binary64 after rounding to six decimals.

**N6 (note) — Chart spec.** `axisMin`, `axisMax` share key 4. Give them separate keys.

### Testability

The vector list covers TK-1 to TK-9 with one failing case each and adds numeric sets. Gaps:

- B1: `tk-bad-agent-authority-mismatch`.
- B2: a sealed vector whose body carries no prose, and a failing `tk-bad-sealed-title-in-body`.
- S4: `tk-bad-statements-too-many`.
- S6: `take-rank-pooled` (two rating releases pooled, σ combined).
- S7: one numeric vector per measure, including `movedToward` on a fixed `movement` table and `mapCell` on a fixed `map`.
- S8: `take-noise-negative-n` (raw `N ≤ 0`).
- N2: `tk-bad-fork-unsealed`.
- `take-rank-*` vectors must ship the rating release tables as inputs and name the rounding used.

## Summary for the author

B1 is one clause in TK-5. B2 moves three text fields into the blob and touches the gallery index; do it now, before any take exists. S7 and S8 are what W0-08 needs to generate the numeric vectors. S2 and S3 need a sentence each. Settle S9 with the cross-spec pass.

## Re-review (2026-10-06, revised draft, 301 lines)

Re-read the revised spec in full and checked the measures against `release.md` (316 lines) as it is now.

**Status of the first-round findings.** B1 fixed: TK-5 requires the sponsor manifest's envelope `authority` to equal the take's, with expiry and retirement checked at the take's log position, and the vector exists. B2 fixed: the body carries no prose; `title`, `byline`, `labels` and `prose` live in the text blob (`application/hum-take+cbor`), sealed under the context keyring when the take is sealed, with TK-2 checking the label count against the series count. S7 fixed and consistent with `release.md`: the toward, away and unchanged buckets in the measure table are exactly the sets `release.md`'s Tables section now defines on the scale disagree < unsure < agree; `count` has a `column`, `mapCell` has a `cell`, and the score measures no longer claim an interval. The bucket σ of σ√3 is right, since each bucket sums three independently noised cells. S1 to S6, S8 to S10 and N1 to N6 are all addressed: fresh authority keys, curation made visible with a D15 clause proposed to W0-01, the phase-1 sentence corrected, `statements` bounded and tied to the deck's refs, `value` as a uint, pooled σ and `queryHash` bytes defined, the gap test first and binary64 throughout, uints for enums with table names kept as text, sealed forks in TK-9, `statement/<k>` validated, the sort key a tuple, separate axis keys.

**Rechecked.** The ratings path still charges the shield through `plan.rho`, counts under `release.md` R14 and composes additively. Nothing in the revision touches a floor or a sum.

**New findings on the new text.**

**N7 (note) — "Body", unknown keys.** The vector `tk-bad-sealed-title-in-body` rejects "an unknown body key carrying text", but no TK rule says the body may hold no unknown keys. `deck.md` D1 states it for decks. Add "no unknown keys" to TK-2 or TK-4 so the rejection has a rule to cite, and so a future draft cannot reintroduce prose in the body without a vector failing.

**N8 (note) — "The text blob", `labels`.** A series over a table the release did not unlock still needs a label entry, which the count check enforces. Say that the array is indexed by series position so an implementer does not skip gap series.

**Updated verdict: approve.** No blockers and no should-fix items remain. The two notes are one sentence each.
