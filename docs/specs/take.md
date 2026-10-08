# Hum Take Spec — Draft 0.1

Oct 6, 2026 · W0-04 draft, revised after review; not yet approved

## Scope

A take is a published reading of one or more releases: a query over release tables, a chart spec, and a text blob, pinned to the exact release versions it uses. It is the unit of the studio and the gallery. Because it is built only from releases, a take costs no one any privacy, and because the chart is computed from the query on every phone, a take can't show a number the release doesn't yield.

This spec defines the `take` manifest body, the text blob, the query and chart language, the noise math every client uses to draw error bars and to flag differences within the noise, forking, and how takes are rated and ranked in the gallery. Ratings are votes, so they are collected as a deck and released with differential privacy; this spec says how, and names the budget.

Out of scope: the release tables themselves (`release.md`), the deck and ballot mechanics the rating round reuses (`deck.md`, `ballot.md`, `shield.md`), the gallery index API (`services.md`), and real-data checks for contexts with 5,000+ voters (not in draft 0.1).

Conventions follow `context.md`: body keys are small uints, enumerations are uints with the names given in the tables, text is UTF-8 NFC with no control characters and a byte limit. Release table names stay text because they are the Parquet file names `release.md` fixes.

## Authority and authorship

A take's author is an authority: a keyset lineage (`manifest.md`, "Authorities and keys"). Anyone can create one on their phone, a 1-of-1 keyset with a separate rotate key is allowed, and the authority's CID is the author's stable identity across versions and forks. A take authority's keys are generated fresh for it and are never a chat identity key, an edit key or a context keyset key; reusing the chat identity key would publish, in a public keyset, a key that also proves membership of sealed contexts. A chosen byline is shown next to the authority; it lives in the text blob (below), not in the manifest.

Agents write takes too. A public or shared agent's take has the sponsor's authority as `authority`, `author` = 3, `refs.sponsor` naming the sponsor manifest version, and a signature by the `agentKey` under `hum/author/1` (as in `issue-map.md`) in place of the keyset threshold. The sponsor manifest's own `authority` must equal the take's, so an agent can publish only under its sponsor (TK-5). Clients label it.

| Form | Body `author` | Proof in the bundle |
| --- | --- | --- |
| Person or organization | 0 authority | The author's keyset `sign` threshold under `hum/manifest/1` |
| Agent | 3 agent | `hum/author/1` signature by the `agentKey` of `refs.sponsor` |

## Body

| Key | Name | Type | Required | Frozen | Meaning |
| --- | --- | --- | --- | --- | --- |
| 0 | author | uint | yes | yes | 0 authority · 3 agent (numbered as in `issue-map.md`) |
| 1 | query | map | yes | no | The query spec (below) |
| 2 | chart | map | yes | no | The chart spec (below) |
| 3 | sealed | bool | yes | yes | True when the pinned releases' tables are sealed; then the text blob is sealed too |
| 4 | epoch | uint | iff sealed | no | Keyring epoch that decrypts `refs.text` |
| 5 | lang | text ≤ 16 bytes | no | no | BCP 47 tag of the prose, pattern as in `issue-map.md` |
| 6 | assisted | bool | no | no | A personal agent helped draft the prose. Self-declared |
| 7 | retired | bool | no | — | Final version; the lineage ends |

No title, byline or label is in the body. Everything a person wrote lives in the text blob, so a sealed take leaks nothing through the public log and a public take's words are deletable.

### refs

| Name | Required | Points to |
| --- | --- | --- |
| `release/<n>` | at least one, `n` contiguous from 0, at most 8 | A release manifest version. The query names releases by `n`. Takes SHOULD pin the lineage's final version; a take pinning an earlier version of a lineage is eligible for that lineage's rating deck all the same |
| `text` | yes | The text blob (below), public or keyring-form sealed |
| `sponsor` | iff `author` = 3 | The agent-sponsor manifest version |
| `forkOf` | no | The take version this one was forked from |
| `statement/<k>` | no | A `position` manifest version or statement blob pinned by one of the pinned releases' decks, for clients that want to resolve text without opening the deck |

Releases are pinned by version. If a context publishes a correction as a new release version, existing takes keep showing the data they were built on, and the gallery marks them "built on an earlier version".

### The text blob

Deterministic CBOR, media type `application/hum-take+cbor`:

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | title | text ≤ 240 bytes | Shown as the headline |
| 1 | byline | text ≤ 80 bytes | A handle shown beside the authority's short CID. Not a verified name; clients never show it alone |
| 2 | labels | array of text ≤ 80 bytes | Indexed by series position: entry `i` labels `query.series[i]`, including a series whose tier the release did not unlock |
| 3 | prose | text ≤ 16,000 bytes | The take itself |

Public when the take is public, sealed under the context keyring (format 2) when the take is sealed. The gallery index reads title and byline from public blobs and lists sealed takes to members only. A deleted blob leaves a take listed as removed.

### Query spec

The query is declarative. It names cells of the pinned release tables and a measure over them. There is no arithmetic beyond the measures defined here, so every client computes the same numbers and every number is traceable to a cell.

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | series | array of series, 1..12 | |
| 1 | compare | uint | 0 groups · 1 releases · 2 contexts · 3 statements · 4 attributes: what the chart puts side by side |

A series:

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | release | uint | Index `n` of `release/<n>` |
| 1 | table | text | A table name from `release.md`: `tallies`, `group_tallies`, `group_sizes`, `breakdown`, `movement`, `moved`, `ratings`, `group_ratings`, `consensus`, `repness`, `map` |
| 2 | statements | array of CID, ≤ 256 | CIDs to select, matched against the table's `statement` column (`argument` for `moved`, `ratings`, `group_ratings`); each must be pinned by a `card/<i>` (or `/pro`, `/con`) ref of the deck the release pins. Empty means every row, in the table's order |
| 3 | group | uint | Opinion group index, for `group_tallies`, `group_sizes`, `group_ratings` and `repness`; absent means all groups |
| 4 | value | uint | For `breakdown`: the cell's `value` as the release's `breakdown_cells` table carries it |
| 5 | measure | uint | See the measure table |
| 6 | column | text | For measure 4 (`count`): the column name |
| 7 | cell | array `[x, y]` of uint | For measure 13 (`mapCell`): the histogram cell |

Measures and the cells they read:

| Measure | Name | Reads | Formula |
| --- | --- | --- | --- |
| 0, 1, 2 | `agreeShare`, `disagreeShare`, `unsureShare` | `agree`, `disagree`, `unsure` of a `tallies`, `group_tallies` or `breakdown` row | count ÷ (agree + disagree + unsure); `m` = 3 |
| 3 | `agreeMinusDisagree` | the same three counts | (agree − disagree) ÷ (agree + disagree + unsure) |
| 4 | `count` | the named `column` of a row | the raw noised count, with σ |
| 5 | `participants` | `nHat`, or a `group_sizes` row | the count itself |
| 6 | `movedToward` | the nine `movement` rows of a card | Σ n over (first, second) ∈ {(1,0), (2,0), (1,2)} ÷ Σ n over all nine; `m` = 3 with the three buckets below as the cells |
| 7 | `movedAway` | same | Σ n over {(0,1), (0,2), (2,1)} ÷ total |
| 8 | `unchanged` | same | Σ n over first = second ÷ total |
| 9, 10 | `movesMe`, `against` | `moves`, `neutral`, `against` of a `ratings` or `group_ratings` row | count ÷ (moves + neutral + against); `m` = 3 |
| 11 | `consensusScore` | `consensus.score` | the published value; no interval |
| 12 | `repnessScore` | `repness.metric`, with `significant` | the published value; drawn hollow when not significant |
| 13 | `mapCell` | the `map` histogram at `cell` | the noised cell count, with σ |

Codes for `first` and `second` are `release.md`'s: 0 agree, 1 disagree, 2 unsure. The buckets are `release.md`'s own direction rule ("Tables"): on the scale disagree < unsure < agree, a transition is toward when `second` is closer to agree than `first`, away when closer to disagree, unchanged on the diagonal; the cell lists above spell that out. For measures 6 to 8 the three buckets are sums of three independent noised counts each, so each bucket's σ is σ√3 before the share formula is applied with `m` = 3.

A series over a table the release did not unlock (its tier did not open) is valid but renders as "not released at this size". The take still verifies; the gap is shown, not hidden.

### Chart spec

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | type | uint | 0 bars · 1 dots · 2 lines · 3 grid · 4 table |
| 1 | interval | uint | Interval width shown, in percent: 80, 90 or 95. Default 90 |
| 2 | flagWithinNoise | bool | Gray out differences within the noise. Always true in the reference client; the field exists so a take can't claim it was off |
| 3 | sortBy | uint | 0 none · 1 value · 2 statement |
| 4 | axisMin | int | Optional fixed axis minimum in percent; an axis that doesn't start at zero is drawn with a break mark |
| 5 | axisMax | int | Optional fixed axis maximum in percent |

Clients render the chart from the query and the pinned tables. A take carries no rendered image and no numbers in its body. The prose may quote numbers; the chart next to it is the check.

## Noise math

Every release publishes, per part, the standard deviation σ of the noise added to each count (`release.md`: `parts[p].sigma`, `hum.sigma` in each table's metadata, `hum.noise_sd` on derived tables; all are round(σ_r × 10⁶) where σ_r is the rational bound the sampler drew with, see `release.md` "Noise"). A take reads that published value and never recomputes σ from ρ and the sensitivity: the published value is the one the noise was actually drawn with. Error bars and "within noise" flags come from it alone. They say how much the published numbers could differ from the exact sums of the votes cast. They say nothing about whether the voters represent anyone else; the studio keeps "people here think X" and "the district thinks X" apart, and this spec does not try to close that gap.

All arithmetic is IEEE binary64. Let a cell's raw noised counts be `c₁ … c_m`, each with independent noise of standard deviation σ, and `N = Σ cᵢ` over the raw, unclamped counts.

1. **Gap test.** If `N < 10σ`, the cell renders as "too few votes to read"; nothing else is computed. Negative or zero `N` fails here.
2. **Share.** `p = c₁ ÷ N` and

```
σ_p = (σ ÷ N) · √( (1 − p)² + (m − 1) · p² )
```

   This is the first-order (delta-method) variance of a ratio of correlated noised sums; `m` is 3 for tallies, movement and argument ratings, and 2 for a take's fairness share. For `agreeMinusDisagree`, `d = (c₁ − c₂) ÷ N` and `σ_d = (σ ÷ N) · √( (1 − d)² + (1 + d)² + d² )`.

3. **Display.** Clamp `p` to [0, 1] after σ_p is known. The drawn bar is `p ± z · σ_p` with `z` = 1.282 (80%), 1.645 (90%) or 1.960 (95%), clipped to [0, 1].
4. **Difference within noise.** Two shares `p₁, p₂` from different cells are compared with `σ_diff = √(σ_p₁² + σ_p₂²)`. When `|p₁ − p₂| < z · σ_diff` at the take's interval, the pair is flagged "within noise" and drawn gray. Cells from different groups, different breakdown cells or different releases carry independent noise, so this rule applies to them all. Two measures of the same cell are not compared.
5. **Pooled cells.** When counts from several releases are summed (ratings pooled across versions, below), the pooled σ is `√(Σ σᵢ²)` and the formula above is applied to the pooled counts.

The derived tables (`consensus`, `repness`) already include the research pipeline's `λ = max(1, σ)` pseudo-count and `n_eff`; takes read their published values and never recompute them.

Vectors fix σ, the counts and the expected σ_p, intervals and flags to six decimal places (`take-noise-*`).

## Forking

A fork is a new take lineage with `refs.forkOf` naming the version it started from. The fork copies the query and chart and may change anything. The gallery shows forks under their parent ("7 forks" on `S-Take`), ordered by their own rank. A fork of a sealed take is sealed and pins the same context (TK-9).

Nothing is owed to the parent beyond the pointer. If the parent is retired or its text deleted, the fork stands.

## Ratings

"Is this a fair reading?" is answered with the same gesture as voting, and it is a vote: it reveals how a person reads a political claim, by opinion group. So ratings leave the phone only as ballots to aggregators, in a deck, and come back only as one differentially private release. No gallery server ever sees a rating.

### A rating round is a deck

A context's authority deals a **rating deck**: a `deck` manifest with `kind` = 1 (`deck.md`, "Rating decks", rule D15) whose cards are take versions (card `kind` 2) and whose release plan has the `tallies` (part 0) and `groups` (part 3) parts plus the receipt-padding part 8 every deck carries. The groups are the source release's: each rater's phone already knows which centroid it was nearest in the source deck, so the group slot travels in the round-0 ballot and there are no post-close rounds. The release is one final version (`release.md`, rule R5).

| Rating deck | Rule |
| --- | --- |
| Source | `refs.source` names a final release of this context whose groups unlocked. Only people who voted in that deck can rate: their group lives only on their phone |
| Cards | Fixed by `deck.md` D15, not chosen: exactly the eligible takes (pin the source, not retired, public or sealed in this context, logged before the deck) in log order, truncated to the first 60, with no omission, addition or reordering. Left-out takes wait for the next round. The organizer picks nothing, so dealing a rating deck is not ranking power |
| Votes | Right (agree) = fair, left (disagree) = misleading, up (unsure) = can't say. Encoded exactly as a card vote in `ballot.md`, with the group slot |
| Contribution cap | `cap` (K) at most 20 takes per person per rating deck. The phone deals cards in its own random order and stops counting after K |
| Release plan | `parts`: tallies 0.4 and groups 0.6 of what is left after part 8's share (`deck.md`); `rho` at most 1/20 (0.05) |
| Rounds | At most two rating releases per source release per year; the ledger enforces it by `source` (`release.md`, rule R10) |
| Floors | `GATE_TALLIES` (100) noised raters to publish overall fairness; `GATE_CELL` (300) in a group's noised size to publish that group's share (`deck.md` gates part 3 per group for rating decks). Below that, the take shows overall fairness only, or "not enough ratings yet" |
| Shield | Each rating deck charges its planned ρ to the rater's shield like any deck. At ρ 0.05, a rating deck costs about a fifth of a full release |

In phase 1 the rating ballot tells the aggregator the pseudonym's source-release group. That is inside the phase-1 model, where the aggregator sees pseudonymous votes by design, and the group is one one-hot coordinate inside the noised groups part, so the published guarantee is unchanged. In phase 2 the group slot is a share like any other. `ballot.md` should state it the same way.

Why a deck and not a new mechanism: the deck, ballot, release and shield specs already give the pipeline every property a rating needs (membership proof, contribution cap, one release per deck, noise planned and charged before sending, receipts). Reusing it means ratings can't have a weaker guarantee than votes by accident. The decision is `docs/decisions/0043-w0-04-ratings-are-decks.md`; W0-01 accepted it in `docs/decisions/0015-w0-01-rating-decks.md`.

Why ρ 0.05 and K = 20: the groups part's sensitivity is √(K+1) ≈ 4.6, and with 0.6 of the ρ (0.03) σ per group cell is 4.6 ÷ √(2 · 0.03) ≈ 19. With 400 raters in a group and "fair" near 60%, the share sits at ±6 points (90%). With 1,000 raters, ±2. That is enough to tell "both groups call it fair" from "one group calls it misleading", which is all the ranking needs. Each rating round adds 0.05 to a context's yearly ρ. Four releases alone compose to about ε 8.5; with one rating round per release, about ε 9.4; with two per release, about ε 10.3. The owner may move these numbers; they are deck fields, not constants.

### What the rating release publishes

Exactly three tables, `tallies`, `group_tallies` and `group_sizes` as `release.md` defines them, with the take version CID in the `statement` column: noised counts of fair (`agree`), misleading (`disagree`) and can't say (`unsure`), overall and per source-release group, each part with its σ. A rating release carries no derived tables: `consensus` and `repness` are statements about positions and groups, and a "consensus take" means nothing the gallery ranking does not already say. `release.md` R7 and its one-version paragraph say the same: for a rating release these three tables and never `consensus` or `repness`. Nothing per person, nothing per phone.

### Ratings and versions

A rating names a take version. Define `queryHash = SHA-256("hum/take-query/1" ‖ deterministic CBOR of the array [query, chart])`. When an author publishes a new version:

- If `queryHash` is unchanged (a prose, title or label edit), ratings of the earlier versions carry forward: the gallery pools the counts of every rated version with the same `queryHash`, with the pooled σ of "Noise math" step 5.
- If `queryHash` changed, the pool resets. The take is "unrated since its last change" until the next rating round includes it.

## Gallery ranking

A take's score is how fair it looks to the group that finds it least fair.

For each (context, group) with a pooled `group_tallies` row and a `group_sizes` entry at or above `GATE_CELL`, compute `f` = fair ÷ (fair + misleading) with `m` = 2 and the pooled σ, through the noise-math steps (a cell that fails the gap test is skipped), and its lower 90% bound `f_low = f − 1.645 σ_f`. Then:

```
score = min over cells of f_low
```

- A take rated in only one context uses that context's groups. A take over several releases is rated in each context that deals a rating round for it, and the minimum runs across all of them.
- A take with an overall `tallies` row but no group cell past `GATE_CELL` gets `score` from the overall row and `hasGroupScore` = false.
- Agent-authored takes rank by the same rule and keep their label.

The sort key is the tuple `(rated, hasGroupScore, score rounded to six decimals, forkCount, logIndex)`, compared element by element, every element descending, where `logIndex` is the take's version 1 leaf index in the log of record. So unrated takes sort last, and among ties and among unrated takes the most recently logged comes first.

The reference client shows the per-group point estimates ("Fair to A 64% · B 58%") and uses `score` for order. A gallery index service (`services.md`) may precompute the order, but every phone can recompute it from the rating releases, and the conformance suite checks that it does (`take-rank-*`).

## Validation rules

Steps 1 to 5 and 7 to 9 of `manifest.md` run as written; step 6 is rule TK-5; these run as step 10. Logs run TK-1, TK-3 to TK-6, TK-8 and TK-9; phones run all of them, including the blob checks in TK-2.

| Rule | Check | Rejects |
| --- | --- | --- |
| TK-1 | `refs.release/<n>` present for `n` contiguous from 0, at least 1 and at most 8, each resolving to a `release` manifest | missing or gapped releases; a non-release ref |
| TK-2 | Body has no unknown keys; `refs.text` present; `sealed` ⇔ `epoch` present. Phones: the blob decodes as the text-blob map with its limits, `labels` has one entry per series, and a sealed blob has first byte `0x02` | unknown body key; over-length; label count mismatch; sealed without epoch |
| TK-3 | `sealed` is true iff any pinned release's context version has `perms.results` ≠ 0 (its tables are sealed, `context.md`); a sealed take pins releases of exactly one context | public take over sealed data; sealed take over public data |
| TK-4 | `query.series` has 1 to 12 entries; every `release` index exists; every `table` and `measure` is a known name and the measure is allowed for the table; `group`, `value`, `column` and `cell` are present exactly where the table or measure takes them; `statements` has at most 256 CIDs, each pinned by the deck of the series' release; every `refs.statement/<k>` is pinned by one of the pinned releases' decks | unknown table; bad index; statement not in deck |
| TK-5 | `author` = 0: the keyset threshold under `hum/manifest/1`. `author` = 3: `refs.sponsor` resolves to an `agent-sponsor` manifest whose envelope `authority` equals this take's `authority`, unexpired and unretired at the take's log position, with `capabilities` including `take`, and the bundle carries an `hum/author/1` signature by its `agentKey` | mismatch; agent under another authority; agent without capability |
| TK-6 | `sponsor` present iff `author` = 3 | label stripped |
| TK-7 | `chart.type` and `sortBy` known; `interval` ∈ {80, 90, 95}; `flagWithinNoise` present; `axisMin` < `axisMax` when both present | unknown chart; interval 50 |
| TK-8 | Version > 1: `author` and `sealed` unchanged; `forkOf`, if present, unchanged; no version follows one with `retired` = true | author swap; version after retire |
| TK-9 | `forkOf`, if present, resolves to a `take` version not in this take's own lineage; a sealed `forkOf` implies this take is sealed and pins the same context | self-fork; public fork of a sealed take |

Rendering checks, run by the conformance suite against the reference client's output rather than against manifests: `take-noise-*` (σ_p, intervals, flags), `take-rank-*` (scores and order from fixed rating tables), `take-render-gap` (a series over an unreleased tier renders as a gap).

## Example

```json
{
  "spec": 1,
  "type": "take",
  "authority": "c2mk7a…r4w",
  "version": 1,
  "issued": 1791097200,
  "refs": {
    "release/0": "cb7e4m…3fa0",
    "text": "c5tx9q…d1p"
  },
  "body": {
    "author": 0,
    "sealed": false,
    "query": {
      "compare": 0,
      "series": [
        { "release": 0, "table": "group_tallies", "group": 0, "measure": 0,
          "statements": ["c1end…ors", "c2str…ike", "c3onl…ine"] },
        { "release": 0, "table": "group_tallies", "group": 1, "measure": 0,
          "statements": ["c1end…ors", "c2str…ike", "c3onl…ine"] }
      ]
    },
    "chart": { "type": 0, "interval": 90, "flagWithinNoise": true, "sortBy": 0 }
  }
}
```

The text blob: `{0: "The electoral question splits the union", 1: "millbrook.weekly", 2: ["A", "B"], 3: "Group A wants…"}`. Rendered on `S-Take`: three statements, two bars each with 90% intervals, the third pair gray because 45% and 43% differ by less than the noise.

## Vectors

Under `vectors/take/`:

Valid: `tk-ok-one-release`, `tk-ok-two-contexts` (compare 2 over two public releases), `tk-ok-sealed` (body carries no prose; blob sealed), `tk-ok-agent`, `tk-ok-fork`, `tk-ok-prose-edit` (version 2, same `queryHash`), `tk-ok-retire`.

Invalid, one per rule: `tk-bad-no-release`, `tk-bad-release-gap`, `tk-bad-ref-not-release` (TK-1); `tk-bad-text-long`, `tk-bad-labels-count`, `tk-bad-sealed-no-epoch`, `tk-bad-sealed-title-in-body` (an unknown body key carrying text) (TK-2); `tk-bad-public-over-sealed`, `tk-bad-sealed-two-contexts` (TK-3); `tk-bad-table-unknown`, `tk-bad-release-index`, `tk-bad-statement-foreign`, `tk-bad-statements-too-many`, `tk-bad-group-on-tallies` (TK-4); `tk-bad-sig`, `tk-bad-agent-authority-mismatch`, `tk-bad-agent-capability` (TK-5); `tk-bad-sponsor-missing`, `tk-bad-sponsor-on-person` (TK-6); `tk-bad-interval` (TK-7); `tk-bad-author-swap`, `tk-bad-after-retire` (TK-8); `tk-bad-self-fork`, `tk-bad-fork-unsealed` (TK-9).

Numeric, each shipping its input tables and naming binary64 with six-decimal rounding: `take-noise-share` (m = 3), `take-noise-ratio` (m = 2), `take-noise-diff` (within and beyond noise at each z), `take-noise-too-few` (N < 10σ), `take-noise-negative-n`, `take-measure-moved` (toward, away, unchanged on a fixed `movement` table), `take-measure-mapcell`, one vector per remaining measure, `take-queryhash` (prose edit keeps it, chart edit changes it), `take-rank-min-group`, `take-rank-overall-only`, `take-rank-unrated-last`, `take-rank-pooled` (two rating releases pooled, σ combined).

## Security considerations

| Threat | Mitigation |
| --- | --- |
| A take shows numbers the release doesn't support | The body carries a query, not numbers; every client recomputes from pinned tables |
| A chart hides the noise | `interval` and `flagWithinNoise` are in the signed body; the reference client always draws them |
| A take is edited after it was rated | Ratings pool by `queryHash`; a changed chart resets the pool |
| An agent publishes under someone else's name | TK-5 requires the sponsor's authority to equal the take's |
| A sealed take's headline leaks through the log | Title, byline and labels live in the sealed blob; the body holds structure only |
| Ratings reveal a person's politics | Ratings are deck votes under the voting pseudonym with planned noise, cap and floors; no gallery server sees one |
| Rating decks drain the shield | ρ ≤ 0.05 and at most two per source release per year, charged like any deck |
| An organizer curates which takes get rated | Impossible: D15 fixes the cards as the first 60 eligible takes in log order, checked against the log |
| A gallery server ranks dishonestly | Phones recompute the order from rating releases; the conformance suite checks it |
| An agent's take passes as a person's | `author` is in the signed bytes and must match the proof |
| Prose misleads | The chart is next to it, and the rating round is the answer the protocol gives |

## Open questions

- **Rating deck parameters:** ρ 0.05, K = 20, two rounds per source release per year, 60 cards. For the owner together with the privacy targets. Filed in `docs/decisions/0043-w0-04-ratings-are-decks.md`.
- **Who may rate:** draft 0.1 says only voters of the source release, because only they have a group. Should non-voting members be allowed to rate in an "ungrouped" cell?
- **Cross-context takes:** a take over Global and Millbrook is rated in each context separately, and the minimum spans both. Is that the right reading of "every opinion group"?
- **Byline collisions:** two authorities can claim the same handle. Is authority short-CID beside the handle enough, or does the gallery need a name registry? A registry would be a server people trust; this draft avoids one.
- **Real-data checks** for 5,000+ voter contexts: a separate spec later; they spend budget and need declared queries.

## Assumptions about sibling specs

Checked against the drafts on disk on 2026-10-06.

- `deck.md` (W0-01, exists): aligned. Rating decks are `kind` 1 with `refs.source`, take cards (`kind` 2), parts 0 and 3, ρ ≤ 1/20, cap ≤ 20, rule D15.
- `release.md` (W0-01, exists): aligned. Table names and columns in "Query spec" are its; σ is `parts[p].sigma` and `hum.sigma`; `statement` carries the card's CID, which for a rating deck is the take version CID; a rating release is one final version (R5) and the two-per-year limit is R10; `movement` codes 0 agree, 1 disagree, 2 unsure.
- `ballot.md` and `shield.md` (W0-02, exist): a rating deck's round-0 ballot carries the group slot, and "What the aggregator learns" in `ballot.md` states the phase-1 group disclosure as this spec does; the shield charges the plan's ρ before sending.
- `context.md` (W0-01, exists): `perms.results` decides whether a take over the context's releases is sealed (TK-3).
- `services.md` (W0-07, exists): the gallery index at `/v1/gallery/takes` lists and ranks takes by watching the log and reading public text blobs; phones treat it as a cache.

## Seam

`seam: DP budget accounting and release tiers.` The rating deck's ρ, contribution cap and floors are the only budget this spec introduces. `seam: anything that decides what leaves the phone.` Ratings leave the phone only as ballots.
