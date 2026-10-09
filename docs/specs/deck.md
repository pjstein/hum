# Hum Deck Spec — Draft 0.1

Oct 6, 2026 · W0-01

## Scope

A `deck` manifest is a fixed set of cards that opens, collects votes, closes, and gets exactly one release. It pins the context version it runs under, the statement behind every card, and a release plan that fixes, before anyone votes, what the release will contain and what it will cost.

This spec defines the `deck` body, its step-10 rules, the release plan, and the per-phone card order. The envelope is in [`manifest.md`](manifest.md). Conventions and protocol constants are in [`context.md`](context.md). What happens after close is in [`release.md`](release.md). How a phone encodes its votes is in [`ballot.md`](ballot.md); how it charges its shield is in [`shield.md`](shield.md). Positions and arguments are [`issue-map.md`](issue-map.md)'s; takes and rating decks are [`take.md`](take.md)'s.

## Lifecycle

```
composed ──logged──► scheduled ──opens──► open ──closes──► closed ──rounds──► released
```

- **Scheduled:** logged, `opens` in the future. Everything but `closes` is already frozen; an organizer who needs a different deck retires this lineage and deals a new one.
- **Open:** phones vote. `closes` may move later, never earlier.
- **Closed:** no new ballots. If the plan has map and groups parts, phones take part in up to three short rounds (`release.md`).
- **Released:** the release lineage's final version is logged. Nothing more happens under this deck.

A phone votes under the deck version it holds a log proof for, and keeps that version's rules even if a later version is logged.

## Body fields

| Key | Name | Type | Required | Meaning | Frozen |
| --- | --- | --- | --- | --- | --- |
| 0 | `title` | text ≤ 120 bytes | yes | Shown on the deck card | from version 1 |
| 1 | `opens` | time | yes | Voting starts | from version 1 |
| 2 | `closes` | time | yes | Voting ends | may only increase |
| 3 | `topics` | array of text ≤ 32 bytes, 1..`MAX_TOPICS` | yes | Topic labels for the topic meters | from version 1 |
| 4 | `cards` | array of card, 1..`MAX_CARDS` | yes | One entry per card, in deck index order | from version 1 |
| 5 | `plan` | map | yes | The release plan (below) | from version 1 |
| 6 | `order` | uint | yes | 0 each phone deals in its own random order · 1 fixed, as listed | from version 1 |
| 7 | `kind` | uint | yes | 0 vote deck · 1 rating deck (below) | from version 1 |

`refs` names:

| Name | Points to | Required |
| --- | --- | --- |
| `context` | The `context` manifest version this deck runs under | yes |
| `card/<i>` | The statement behind card `i`: a `position` manifest version, or a statement blob | one per card, i = 0..cards−1 |
| `card/<i>/pro`, `card/<i>/con` | An `argument` manifest version shown on the back of card `i` | no; at most one of each per card; vote decks only |
| `source` | The final version of a `release` of this context whose groups the ratings use | rating decks only |

A deck does not pin aggregators; it inherits the pair from the context version it pins. The manifest spec's deck example and registry row now say the same.

The envelope's `expires` MUST be present (rule D13). It bounds every action under the deck, including the post-close rounds. It may increase only in a version that also moves `closes` later, it never decreases, and it is bounded above (rule D13): `expires` is the last moment anything about the deck can be published (`release.md` R13), and a person's shield entry for the deck stays in their yearly window until 365 days after it (`shield.md`).

### A card (key 4 entries)

| Key | Name | Type | Required | Meaning |
| --- | --- | --- | --- | --- |
| 0 | `kind` | uint | yes | 0 `position` manifest · 1 statement blob · 2 `take` manifest (rating decks only) |
| 1 | `topic` | uint | yes | Index into `topics` |
| 2 | `origin` | uint | yes | 0 this context · 1 Global |
| 3 | `epoch` | uint | if kind 1 and sealed | Keyring epoch that decrypts a sealed statement blob |

A statement blob is UTF-8 text ≤ 2 KiB: public in a public context and for every Global card, sealed under the context keyring in a sealed context. Positions carry their own text and epoch (`issue-map.md`).

The card's front shows the statement. The back shows `card/<i>/pro` and `card/<i>/con` if present: each must be an `argument` of the matching `kind` whose `parent` is the position behind card `i` (rule D7), so only `kind` = 0 cards carry arguments. Arguments are fixed with the deck so that movement and ratings count against known objects.

A deck may pin only positions that are dealable: `state` = `active` in the latest version logged before the deck's log position, and not withdrawn, merged or hidden (`issue-map.md`). Pinning a position freezes its text (`issue-map.md`, "dealt").

## Rating decks

A rating deck (`kind` = 1) collects "is this a fair reading?" on takes, with the opinion groups of an earlier release. It is a deck because every guarantee a rating needs already exists in the deck pipeline (`take.md`, ADR 0043). Differences from a vote deck:

| | Vote deck | Rating deck |
| --- | --- | --- |
| Cards | positions and statements | exactly the eligible `take` versions (`kind` = 2) in log order, the first 60 if more are eligible; eligible means it pins `refs["source"]`, is not retired, is public or sealed in this context, and was logged before this deck (`take.md`). The organizer picks nothing; takes left out wait for the next round |
| Swipe | agree · disagree · unsure | fair · misleading · can't say, encoded as agree · disagree · unsure |
| Who may vote | the context's vote policy | the same, and the phone takes part only if it voted in the source deck, because only then does it know its group. Nobody but the phone can check this; a modified client can rate under any group, which is a data-quality risk, not a privacy one |
| Plan parts | any | parts 0, 3 and 8 only; `minVoters` = max(`GATE_TALLIES`, `ctx.floors.minVoters`), with `gates[0]` raised to the same value when it is above `GATE_TALLIES`; part 3 gated at `GATE_CELL` per group |
| Groups | computed in rounds 1–3 | fixed: the source release's `centroids`; the phone's group is the one it computed for the source deck, so group tallies travel in the round-0 ballot and there are no later rounds |
| ρ | ≤ context floor | ≤ 1/20, and ≤ context floor |
| Cap | K | R, at most 20; the phone counts its first R cards in its own order |
| Arguments, topics | as above | no argument refs; `topics` is a single label |

A rating release is one version, final, with parts 0, 3 and 8 and `groupsK` equal to the source's (`release.md`). At most two rating decks per source release per year; the ledger counts them under R10 of `release.md` by `source`.

## The release plan (key 5)

The plan is a contract between the organizer, every phone and both aggregators. Phones refuse decks whose plan breaks a floor and charge their shield for the plan's total before voting. Aggregators add noise exactly as the plan says. The ledger refuses a release that differs from it.

| Key | Name | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- | --- |
| 0 | `rho` | rat | yes | — | Total ρ the release may spend, including rounds and the daily count |
| 1 | `delta` | rat | yes | — | δ for the ε conversion |
| 2 | `parts` | map part → rat | yes | — | ρ for each part; the values sum to `rho` |
| 3 | `cap` | uint 1..`MAX_CARDS` | yes | — | K: votes counted per person in the tallies, groups and breakdown parts |
| 4 | `covStatements` | uint ≤ 128 | no | min(60, cards) | M: statements the covariance round uses |
| 5 | `grid` | uint 8..64 | no | 24 | Map grid is `grid × grid` |
| 6 | `blur` | rat, 0 ≤ `blur` ≤ `grid` | no | 1/1 | Gaussian blur in cells applied to the noised map (post-processing) |
| 7 | `minVoters` | uint | yes | — | Smallest noised voter count that publishes anything |
| 8 | `gates` | map part → uint | no | protocol gates | Raised gates per part |
| 9 | `absorb` | bool | no | false | When a tier stays locked, its ρ goes to the tallies part instead of going unspent |
| 10 | `roundWindow` | uint seconds, 3600..2592000 | no | 259200 (3 days) | How long phones have to answer each post-close round |
| 11 | `capMovement` | uint ≥ 1 | if part 5 | — | K_m: cards on which a person's re-vote is counted |
| 12 | `capRatings` | uint ≥ 1 | if part 6 | — | K_r: arguments a person rates |
| 13 | `breakdown` | map | if part 7 | — | `{0: source, 1: name, 2: [values]}` as in a policy leaf: the attribute and its value set, values as uints (`verifier.md`) |
| 14 | `covScale` | uint, power of two, 2⁸..2²⁴ | no | 65536 | Fixed-point scale of covariance contributions |

### Parts

| Id | Part | What is summed | Per-person L2 sensitivity | Gate | Round |
| --- | --- | --- | --- | --- | --- |
| 0 | `tallies` | Agree, disagree, unsure per card, plus one participant coordinate | √(K+1) | `GATE_TALLIES` | 0 (vote) |
| 1 | `covariance` | Outer product of the unit vote vector over the M selected statements, from the full hand (K does not apply) | 1 | `GATE_MAP` | 1 |
| 2 | `map` | One cell of the `grid × grid` histogram, projected from the full hand | 1 | `GATE_MAP` | 2 |
| 3 | `groups` | Per-group agree, disagree, unsure per card, plus a participant coordinate per group | √(K+1) (√(K+K_r+1) with part 6) | `GATE_MAP` (rating decks: `GATE_CELL` per group) | 3 (rating decks: 0) |
| 4 | `count` | Ballots received per UTC day | 1 | none | 0 |
| 5 | `movement` | Per card: 3 × 3 transition counts (first vote → re-vote), and "this moved me" for at most one shown argument | √(2·K_m) | `GATE_COMMON` | 0 |
| 6 | `ratings` | Per rated argument: moves me · neutral · against | √K_r | `GATE_COMMON` | 0 |
| 7 | `breakdown` | Per attribute value: agree, disagree, unsure per card, plus a participant coordinate | √(K+1) | `GATE_CELL` per cell | 0 |
| 8 | `receipts` | Padding of each round's receipt tree: one coordinate per round, 1 for every round the person answered | √(R+1), R = post-close rounds (0 or 3) | none | every round |

Every part is a sum of bounded per-person vectors, which is what lets two-server aggregation replace central noise without changing the math. Noise per part is σ = Δ / √(2ρ_part) with the Δ above, rounded up to the rational σ_r = n/2²⁰ that `release.md`'s Noise section defines and drawn by its mechanism.

- **Tiers.** Parts 1, 2 and 3 are one tier: present together or not at all. Parts 0 and 8 are always present. Parts 4–7 are each optional.
- **Which vote counts.** Part 0 counts a person's final vote on each counted card: if the card flipped and they re-voted, the re-vote. Part 5 counts one transition per card the person re-voted on, first vote → re-vote, diagonal included when they re-voted the same way; a card they never flipped, or flipped before voting, contributes nothing to part 5. "This moved me" is at most one of pro or con per card, so a card contributes at most two ones and the bound is √(2·K_m). These are requirements on `ballot.md`.
- **Default split** for a four-part plan, from the DP study: tallies 0.15 · covariance 0.35 · map 0.15 · groups 0.35 of `rho`, then 1/200 each off tallies for parts 4 and 8. Recommended split with IBIS parts: tallies 0.13 · covariance 0.30 · map 0.13 · groups 0.30 · movement 0.08 · ratings 0.06. Adding ratings also raises part 3's sensitivity, so group tallies get noisier at the same share; organizers should see that trade.
- **Contribution cap.** K trades dropped votes for less noise. Set K at or above the card count so small decks drop nothing; a phone with more than K votes counts the first K cards it cast, in cast order, a set that never shrinks when a ballot is replaced (`ballot.md`; under random order this is a uniform random K, and it is the only rule under which a replacement never reveals a dropped card), and uses the same K votes in parts 0, 3 and 7. Parts 1 and 2 use the full hand, as the oracle does, because their bounds do not depend on K.
- **Receipts.** Every round's receipt tree is padded with dummy leaves so that its leaf count is a noised number, not the exact number of ballots (`release.md`, "Receipts"). Part 8 pays for that: one coordinate per round, sensitivity √(R+1). Default ρ 1/200.
- **Absorb.** If `absorb` is true, the aggregator decides the map tier before it draws any tallies noise, from the daily count's final running total taken at `closes` after the last bucket is noised (so `absorb` requires part 4, and both aggregators see the same total). If that total is below the map gate, the tier's ρ is added to the tallies part's ρ, the tier stays locked whatever `nHat` turns out to be, and tallies noise is drawn with the larger ρ. The decision cannot wait for `nHat`, because `nHat` comes out of the tallies noise. A tallies-only release of a 30-card deck at 300 voters is ±4 points at ε 4 this way.
- **Why movement costs more.** A re-vote reveals a person's first vote, second vote and which argument moved them, per card. That is a vector of up to two ones per card against the tallies' one, so at equal cap its sensitivity is √2 times larger and its noise, at equal ρ, √2 times larger. To keep the noise usable the cap K_m is small (10 is recommended) and the part needs its own share of ρ, which comes out of the other parts because `rho` is capped. Movement is user-level like everything else: it is in the same release and the same shield charge.
- **Ratings** are an ordinary three-way count per argument. By group they are reported in round 3 as part of the group vector, which is why part 3's sensitivity grows to √(K+K_r+1) when part 6 is present. Only arguments named in `refs` can be rated, and the phone picks a uniformly random K_r of them.
- **Breakdown** repeats the tallies per value of one attribute, named by a policy source and an attribute name. The source must resolve to exactly one verifier authority, by the same test as `context.md` rule C16 (D9), so every breakdown ballot of a deck carries a card from the same verifier. Only `breakdown`-exposure attributes qualify (`verifier.md`). Cells whose noised participant coordinate is below `GATE_CELL` are suppressed in post-processing. A person holding two credentials with different values discloses exactly one (`ballot.md` B9), or the √(K+1) bound fails. In draft 0.1 phase-1 aggregators do not register decks with part 7, pending the owner's decision on phase-1 breakdowns (see Open questions); the plan rules stay so the format is fixed.

### Floors the plan must meet

With `ctx` the pinned context version:

- `rho` ≤ `ctx.floors.rho`, `delta` ≤ `ctx.floors.delta`, `minVoters` ≥ `ctx.floors.minVoters`.
- `parts[4]`, if present, ≤ `ctx.count.rhoMax` (default 1/200).
- Every gate in `gates` ≥ the protocol gate for that part, and `minVoters` ≤ every gate of a gated part (parts 4 and 8 have none; part 7's gate is per cell and is applied in `release.md`).
- A phone also checks `rho` against its remaining shield (`shield.md`) and sits the deck out if it does not fit. That check is per person and is not a manifest rule.

## Card order on the phone

With `order` = 0 (the default and the recommendation) each phone shuffles the deck once with its own CSPRNG when it first shows it, keeps the permutation locally, and never transmits it. Ballots index cards by deck index, not by position shown, so the order has no effect on any sum.

Random order means no card is systematically first or last, and a phone's order cannot fingerprint it because nothing about the order leaves the phone. `order` = 1 is for decks that tell a story, such as a case presented in sequence; organizers accept the order effect.

Global cards (`origin` = 1) are shuffled with the rest. The results deck (`Swipe-Reveal`) shows cards in deck index order, not the phone's.

## Frozen fields

Everything but `closes` is frozen from version 1: title, times, topics, cards, plan, order, kind and every ref. A later version may only move `closes` later, with `expires` moving to match. The rule (D12) is checkable from bytes alone by every party, with no clock and no `issued` involved. One rule beside it does use a clock: the ledger and the aggregators refuse a later version once the previous version's `closes` has passed (D16), so an expired deck cannot be reopened. An organizer who needs a different scheduled deck retires the lineage (the manifest spec's retired marker) before `opens` and deals a new one; a retired deck accepts no ballots. Because every version of a lineage has the same cards and plan, the ballots of a deck whose `closes` was extended are all under one set of rules, and the release pins the highest version logged before `closes`.

The ballot validity window is anchored to version 1's `closes`, not to the version in force (`credentials.md`, ADR 0026): every resident card in a ballot's presentation must carry the issuer epoch that contains version 1's `closes` and must already have started. An extension therefore cannot admit a card's successor. A deck whose original close falls in issuer epoch E+1 collects ballots only from E+1 cards, which nobody holds as a started card until E+1 begins, so members wait from `opens` until that start, up to most of an epoch for a long deck; the deck card says "counting starts <date>". Epoch grids are public, so organizers can deal around them, and two levers follow, both visible in the log and neither able to single out a person: an original `closes` just after a boundary makes the electorate the members who renewed in handover, and an original `closes` on an epoch's last day, extended afterwards, freezes the electorate to that epoch's holders. Phones keep the card they voted with pinned to the deck until the release is final, so rounds 1–3 still have it after the epoch ends (`credentials.md`, "Validity").

## Validation rules (verification step 10 for `deck`)

| Rule | Check |
| --- | --- |
| D1 | Required fields present with the types and limits in the tables; no unknown keys; `order` ∈ {0,1}; `kind` ∈ {0,1} |
| D2 | `opens` + 3600 ≤ `closes`, and `closes` − `opens` ≤ 31536000 (one year). Checked on every version |
| D3 | `topics` has 1..`MAX_TOPICS` distinct labels; every card's `topic` < len(`topics`) |
| D4 | `cards` has 1..`MAX_CARDS` entries; `refs["card/<i>"]` exists for exactly i = 0..len−1; no two card refs are the same CID; every `card/<i>/pro` or `/con` ref has a card `i` with `kind` = 0 |
| D5 | `refs["context"]` resolves to a `context` manifest (not retired) |
| D6 | Every card with `origin` = 1 is allowed: `ctx.mixGlobal` is true, and the card's object belongs to the Global context lineage |
| D7 | Pinned positions and arguments are verified as of their own log positions (`manifest.md` step 9): their authorship proofs are checked with the logged-presentation rule of `credentials.md` and no clock, so a deck may pin an object written in an earlier issuer epoch. Every card with `origin` = 0 and `kind` = 0 resolves to a `position` whose `refs["context"]` is in the same lineage as this deck's context and whose latest version logged before this deck is `active`; every `card/<i>/pro` or `/con` resolves to an `argument` whose `kind` matches the ref name, whose `parent` is the lineage of `card/<i>`, and whose latest version logged before this deck is `active`; `kind` = 1 statement blobs with `origin` = 0 in a sealed context have `epoch` present, and with `origin` = 1 or in a public context have it absent; `kind` = 2 only in rating decks |
| D8 | `plan.parts` contains parts 0 and 8; for vote decks (`kind` = 0) parts 1, 2 and 3 are all present or all absent; rating decks (`kind` = 1) have exactly parts 0, 3 and 8 (D15); no unknown part ids; every ρ > 0; Σ `parts` = `rho` in exact rational arithmetic, compared after reduction |
| D9 | `absorb` true ⇒ part 4 present. Part 5 present ⇒ `capMovement` present and at least one card has a `pro` or `con` ref; part 6 ⇒ `capRatings` present and ≥ 1 argument ref; part 7 ⇒ `breakdown` present, well-formed, with 2..64 values and a source the context's vote policy can satisfy (a `tl/<i>` or `issuers[i]` of `ctx`), the source resolves to exactly one verifier authority by the test of `context.md` rule C16 (a `[1, i]` source always does; a `[0, i]` source does when exactly one entry of the pinned trust list accepts the attribute name), and the attribute has `exposure` = `breakdown` in that verifier's version in force at this deck's log position (`verifier.md`) |
| D10 | `rho` ≤ `ctx.floors.rho`; `delta` ≤ `ctx.floors.delta`; `minVoters` ≥ `ctx.floors.minVoters`; `parts[4]` ≤ `ctx.count.rhoMax` when present |
| D11 | `gates` names only parts 0, 1, 2, 3, 5, 6; every entry is ≥ the protocol gate for its part; `minVoters` ≤ every effective gate of those parts, except part 3 of a rating deck, whose gate is per group cell (`GATE_CELL`) and is applied in post-processing like part 7's, so it is outside this test; `covStatements` ≤ min(len(`cards`), 128), because a round-1 ballot is 4·M(M+1)/2 bytes inside a 48 KiB padded ballot (`ballot.md`); `grid` in 8..64; `blur` in 0..`grid`; `covScale` a power of two in 2⁸..2²⁴; `roundWindow` in range |
| D12 | Version > 1: fields 0, 1, 3, 4, 5, 6, 7 and all `refs` equal prev; `closes` ≥ prev.`closes`; `expires` ≥ prev.`expires`, and `expires` > prev.`expires` only if `closes` > prev.`closes` |
| D13 | `expires` is present, with `closes` + (R+1) × `roundWindow` ≤ `expires` ≤ `closes` + `PUBLISH_WINDOW` + (R+1) × `roundWindow`, where R = 3 if part 1 is present, else 0, and `PUBLISH_WINDOW` = 2,592,000 seconds (30 days, the allowance `release.md` R13 gives version 1). Checked on every version. At the minimum the aggregators have one `roundWindow` of slack in total between `closes` and the last round; an organizer who wants the full 30 days to publish version 1 sets `expires` at the maximum. Every release version must be issued by `expires` (`release.md` R13), so a deck that runs out of time is abandoned, never published late |
| D14 | `cap` in 1..`MAX_CARDS`; `capMovement` ≤ len(`cards`) and `capRatings` ≤ number of argument refs when present |
| D15 | Rating decks (`kind` = 1): `refs["source"]` resolves to a final `release` whose deck's context is this deck's context lineage and whose `unlocked` includes part 3; every card has `kind` = 2; the cards are exactly the eligible takes (`take.md`) in log order, truncated to the first 60, with no omission, addition or reordering, as checked against the log at this deck's log position; no `card/<i>/pro` or `/con` refs; `plan.parts` has exactly parts 0, 3 and 8; `plan.rho` ≤ 1/20; `cap` ≤ 20; `topics` has one entry ; `plan.minVoters` = max(`GATE_TALLIES`, `ctx.floors.minVoters`), and when that is above `GATE_TALLIES` the plan sets `gates[0]` to the same value so D11 holds. A context that raised its minimum can therefore still deal a rating deck (ADR 0103). Vote decks: no `source` ref and no `kind` = 2 cards |
| D16 | At the ledger and at each aggregator, by its own clock, for a version greater than 1: the clock is before the previous version's `closes`. A deck can be extended only while it is open. The rule needs a clock, so phones do not run it; they rely on `release.md` R13, which ties publication to the deck version the release pins. A second half needs no clock and everyone runs it: a deck version is invalid when a valid release version that pins its lineage has a lower index in the ledger of record, so a deck cannot change once its release exists (ADR 0103 item 2) |

D5–D7, D9–D10 and D15 need refs resolved (step 9). Aggregators run D1–D15 before accepting the first ballot and again on every new version. Phones run them before voting. The ledger runs them when logging the deck.

## Example (JSON view)

The deck behind the `Spring priorities` release on the `P-Ledger` board: 18 cards, cap 18, six parts: the four of the DP study plus the daily count and receipt padding.

```json
{
  "spec": 1,
  "type": "deck",
  "authority": "c4f7q2…k2a",
  "version": 1,
  "issued": 1778544000,
  "expires": 1781395200,
  "refs": {
    "context": "c6a0te…p3e",
    "card/0": "c1e9wz…x8r", "card/0/pro": "c2ar…", "card/0/con": "c3ar…",
    "card/1": "c7gl…",
    "card/17": "c5ps…"
  },
  "body": {
    "title": "Spring priorities",
    "opens": 1778630400,
    "closes": 1780358400,
    "topics": ["Housing", "Money", "Politics", "Union"],
    "cards": [
      { "kind": 0, "topic": 0, "origin": 0 },
      { "kind": 1, "topic": 2, "origin": 1 },
      { "kind": 0, "topic": 3, "origin": 0 }
    ],
    "plan": {
      "rho": "127/500",
      "delta": "1/1000000",
      "parts": { "0": "281/10000", "1": "889/10000", "2": "381/10000", "3": "889/10000", "4": "1/200", "8": "1/200" },
      "cap": 18,
      "covStatements": 18,
      "grid": 24,
      "blur": "1/1",
      "minVoters": 100,
      "absorb": true,
      "roundWindow": 259200
    },
    "order": 0,
    "kind": 0
  }
}
```

`cards` is shortened to three entries. The parts sum to 127/500: tallies 0.0281, covariance 0.0889, map 0.0381, groups 0.0889, count 0.005, receipts 0.005. With cap 18, tallies noise is σ = √19 / √(2 × 0.0281) ≈ 18.4 and group-tally noise σ = √19 / √(2 × 0.0889) ≈ 10.3, close to the figures on the `P-Ledger` board. `expires` is `closes` + 4 × 3 days.

## Vectors (for W0-08)

Directory `vectors/deck/`. Each case ships with the context vector it pins.

Valid:

- `deck-valid-full`: the example above, all 18 cards.
- `deck-valid-tallies-only`: parts 0, 4 and 8 only, `absorb` false, `expires` = `closes` + `roundWindow`.
- `deck-valid-ibis`: parts 0–6 and 8 with the recommended IBIS split, `capMovement` 10, `capRatings` 10.
- `deck-valid-breakdown`: part 7 on attribute `ward` with values `[1, 2, 3]`.
- `deck-valid-rating`: `kind` = 1, 12 take cards, `source` a final release, parts 0, 3 and 8 at ρ 1/50, 11/400 and 1/400, cap 20.
- `deck-valid-v2-extend`: version 2 with only `closes` and `expires` later.
- `deck-valid-fixed-order`: `order` = 1.

Invalid, one per sub-condition, named `deck-invalid-<rule>-<case>`:

- D1: missing `order`; `kind` 2; unknown key.
- D2: `closes` 10 minutes after `opens`; a 400-day window.
- D3: duplicate topic; topic index out of range.
- D4: `card/2` missing with three cards; duplicate card CID; `card/5/pro` with four cards; `card/1/pro` on a `kind` = 1 card; a `pro` ref on a take card (`kind` = 2).
- D5: context ref points at a deck.
- D6: Global card with `mixGlobal` false; Global card whose object is in this context.
- D7: position from another context; withdrawn position; `con` argument under `/pro`; argument whose parent is another card; sealed statement blob without `epoch`; Global statement blob with `epoch`; `kind` = 2 card in a vote deck.
- D8: part 8 missing; part 1 without 2 and 3; unknown part 9; zero ρ; parts sum below `rho`; rating deck with part 1; rating deck without part 3.
- D9: `absorb` without part 4; part 5 with no argument refs; part 6 without `capRatings`; breakdown with one value; breakdown on a gate-only attribute; breakdown source not in the context; breakdown source a trust list that accepts the attribute from two verifiers.
- D10: `rho` above the context floor; `delta` above; `minVoters` below; a rating deck with `minVoters` 100 under a context floor of 300 (D10, not D15); part 4 above `count.rhoMax`.
- D11: `gates[0]` = 50; `gates[4]`; `minVoters` 900 with map gate 800; `minVoters` 300 on a rating deck; `covStatements` > cards; `covStatements` 129; `grid` 7; `blur` > `grid`; `covScale` 1000; `roundWindow` 60.
- D12: version 2 changes a card; moves `closes` earlier; changes `opens`; changes the plan; adds a ref; lowers `expires`; raises `expires` with `closes` unchanged.
- D13: `expires` absent; `expires` too short for three rounds; version 2 extends `closes` so that `expires` is too short; `deck-invalid-D13-expires-far` (`expires` one second past `closes` + 30 days + (R+1) × `roundWindow`); `expires` exactly at the upper bound (valid).
- D14: `cap` 0; `cap` 300; `capMovement` larger than the deck; `capRatings` larger than the argument count.
- D16: at the ledger, version 2 submitted one second after version 1's `closes` (refused); one second before (accepted); a version 2 logged after release version 1 of the same deck (invalid for every verifier).
- D15: a rating deck with `minVoters` 300 and `gates[0]` 300 under a floor of 300 (valid); a rating deck under a context minimum of 500, with `minVoters` 500 and `gates[0]` 500 (valid: D11 does not test part 3); rating deck with part 1 (D8 fires first; listed under D8); `rho` 1/10; `cap` 25; 61 cards; `source` not final; `source` from another context; a card that is a position; an eligible take omitted; a retired take included; cards out of log order; vote deck with a `source` ref. A `pro` ref on a take card is a D4 case and `minVoters` 300 on a rating deck a D11 case; both are listed there.

Plus a plan-math vector set under `vectors/release-math/` (shared with `release.md`): σ per part for the valid plans including the rating plan, and Δ_cov for (M, `covScale`) in {(18, 2¹⁶), (60, 2¹⁶), (60, 2⁸), (256, 2²⁴)}. Encoding vectors for final-vote, transition and moved-me (B1 above) are listed in `ballot.md`.

## Security considerations

- Freezing from version 1 means nothing a person voted on can change after the fact and no two versions of one lineage can collect ballots under different cards; extending `closes` only adds voters.
- The plan's total is what the phone charges, so a release can never cost a person more than the deck said, whichever tiers unlock.
- A deck that names an argument on a card fixes which text was shown; movement and ratings cannot be re-attributed later.
- Card refs are CIDs, so the organizer cannot show two voters different text under one card.
- Nothing in the deck or its plan names a person, and the per-phone order never leaves the phone.

## Open questions

Filed in `docs/decisions/`:

- **IBIS caps and shares** ([`0013-w0-01-ibis-parts.md`](../decisions/0013-w0-01-ibis-parts.md)): K_m = K_r = 10 and the recommended split are proposals from the sensitivities, not from an experiment. The simulator should test them before wave 1 commits.
- **Retired marker:** freezing from version 1 means a scheduled deck can only be withdrawn, never edited, and withdrawal needs the retired marker the manifest spec describes but has not assigned a key to.
- **One round fewer** ([`0014-w0-01-release-rounds.md`](../decisions/0014-w0-01-release-rounds.md)): the covariance round exists because the oracle centers votes on the noised tallies before normalizing. If a normalize-then-center estimator matches the oracle in the simulator, round 1 can fold into the vote ballot.
- **Rating decks as `kind` 1** ([`0015-w0-01-rating-decks.md`](../decisions/0015-w0-01-rating-decks.md)): accepts `take.md`'s proposal with the parameters of ADR 0043; the owner sets the ρ and cap with the privacy targets.
- **Breakdown attributes in phase 1:** a breakdown contribution tells the phase-1 aggregator the pseudonym's attribute value. `verifier.md` already requires the person's per-context consent; whether that is enough, or whether breakdowns wait for phase 2, is for W0-02 and the owner.

Now written and aligned: `ballot.md` encodes the per-part vectors in this spec's Parts table with the rules under "Which vote counts" (its B4–B6), one K selection shared by parts 0, 3 and 7, exactly one breakdown value (B9), the group slot for rating decks, and round-0 ballots replaceable until `closes` with the last one counting; `shield.md` charges `plan.rho` once at the first round-0 ballot.

Already aligned: `issue-map.md` defines `position` and `argument` with a `context` ref and the `active` state D7 checks. `take.md` defines the `take` type rating decks pin. The Global context is a context lineage clients know; which CID that is belongs in `docs/DECISIONS.md` once the reference network exists.
