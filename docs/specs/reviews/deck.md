# Review: `docs/specs/deck.md` (Draft 0.1, W0-01)

Reviewed 2026-10-06 against `CLAUDE.md`, `docs/design.md`, `docs/specs/manifest.md`, `docs/specs/context.md`, `docs/specs/release.md`, `docs/specs/verifier.md`, `docs/specs/trust-list.md`, `docs/specs/services.md`, `docs/specs/issue-map.md`, `docs/specs/take.md`, `docs/research/dp-polis/polis_dp.py`, and decisions 0010 to 0015 and 0043.

Dependencies not yet written: `ballot.md`, `shield.md`, `credentials.md`. Findings that depend on them say so.

## Verdict

**Approve with fixes.** The release plan is the right contract: every part is a bounded per-person vector with a correct L2 bound, the parts sum to one ρ that the floors cap, and the plan is frozen before anyone votes. Two blockers: the `issued`-based freeze rule (D12) lets a logged deck lineage carry two versions with different cards during voting, and the tallies part never says which of a person's two votes it counts when the card flips. Both are local edits.

## Findings

### Invariants

Nothing in the body or refs names a person. Card refs are CIDs, the per-phone order never leaves the phone, and the plan carries only parameters. OK.

**N1 (note) — "Parts", part 7, and "Breakdown".** A phase-1 aggregator learns a pseudonym's attribute value from a breakdown contribution. The spec files it as open. One more thing to say: a person who holds two credentials with different values for the breakdown attribute (two wards from two verifiers pooled by one trust list) must disclose one, or the per-person bound of √(K+1) is wrong. Request it from `ballot.md`.

**N2 (note) — "Rating decks", who may vote.** "The phone takes part only if it voted in the source deck" cannot be checked by anyone but the phone: `services.md` AG-5 deletes nullifier sets after release, so the Leader cannot tell. A modified client can rate under any group. That is a data-quality problem, not a privacy one, but the spec should say it is unenforced.

### Floors

**S1 (should fix) — "Floors the plan must meet" and rule D11.** "`minVoters` ≤ every effective gate" has no definition for part 4, whose gate is "none", or for part 7, whose gate is per cell. Say that parts without a gate are excluded and that part 7's gate is compared per cell in `release.md`, not here.

**N3 (note) — rule D14.** `cap` has no upper bound. A plan with `cap` = 10⁹ is valid; it only inflates σ, so privacy holds, but bound it at `MAX_CARDS` so `release.md`'s σ arithmetic stays in range. Same for `capMovement` and `capRatings` (already bounded by the deck).

### Sums

Each part's bound checks out against the oracle:

| Part | Vector | L2 bound | Note |
| --- | --- | --- | --- |
| 0 | ≤ K one-hots plus a 1 | √(K+1) | Matches `polis_dp.py` |
| 1 | upper triangle of u uᵀ, scaled and rounded | `covScale` + ⌈√(M(M+1)/2)/2⌉ | Correct: ‖u uᵀ‖_F = 1, rounding adds ≤ ½ per entry |
| 2 | one-hot over grid² | 1 | |
| 3 | part 0's vector in one group slot (plus K_r one-hots with part 6) | √(K+1), √(K+K_r+1) | Design doc said √K; the participant coordinate is the right addition |
| 4 | one-hot over day buckets | 1 | |
| 5 | per card ≤ 3 ones, ≤ K_m cards | √(3·K_m) | Conservative if "moved me" is exclusive per card (then √(2·K_m)) |
| 6 | K_r one-hots | √K_r | |
| 7 | part 0's vector in one value slot | √(K+1) | See N1 |

**B1 (blocker) — "Parts", parts 0 and 5, and ADR 0013: which vote the tallies count.** The design doc says a person votes, the card flips, and they may re-vote. Part 5 records first → second. Part 0 never says whether it counts the first vote, the second, or both. Three implementations are possible and they produce different sums. Also unsaid: whether a person who re-voted the same way lands on the transition matrix's diagonal, and what a person who never flipped contributes to part 5 (nothing, per the ADR, but the spec should say it). Fix: part 0 counts the person's final vote on each counted card; part 5 counts one transition per card the person re-voted on (diagonal included) and nothing for cards they did not flip; "this moved me" is at most one of pro or con per card (then the bound is √(2·K_m), or keep √(3·K_m) and say it is deliberate slack). Give `ballot.md` these as requirements.

**S2 (should fix) — "Parts", part 1, and "Contribution cap".** "The phone applies the same K in every part that uses it" and part 1's row ("the unit vote vector over the M selected statements") leave it open whether the covariance and map vectors use the K-capped hand or the full hand. The oracle uses the full hand ("bounding only matters for count releases") and `release.md`'s round-1 text says "where it voted on j". Pick one and say it in the Parts table; the full hand is correct for parts 1 and 2 because their bounds do not depend on K.

### Federation

Aggregators come from the pinned context version by authority CID. The Global context is a lineage CID clients ship with; where it is published is still open (noted in the spec). OK.

### Consistency

**S3 (should fix) — rule D7, statement blobs on Global cards.** "A statement blob is … public … for every Global card, sealed under the context keyring in a sealed context", but D7 says "`kind` = 1 statement blobs in a sealed context have `epoch` present". A Global card with `kind` = 1 in a sealed context satisfies both and fails D7. Fix: D7 conditions on `origin` = 0 for the sealed case and requires `epoch` absent when `origin` = 1.

**S4 (should fix) — rule D4 and `card/<i>/pro`, `card/<i>/con`.** D4 checks only that an argument ref has a card. Nothing checks that the argument's `parent` lineage is the position behind card `i`, that its `kind` matches the ref name (`pro` under `/pro`), or that it is `active`. An organizer could put any argument on any card. Add to D7: each `card/<i>/pro` or `/con` resolves to an `argument` whose `kind` matches, whose `parent` is the lineage of `card/<i>`, and whose latest version logged before this deck is `active`. Only for `kind` = 0 cards; say what a `kind` = 1 card may carry.

**S5 (should fix) — rule D9, "the current version of every verifier that source accepts".** "Current" at which log position? Phones, aggregators and the ledger evaluate at different times. Fix: the verifier version in force at this deck's log position, as `trust-list.md` step 4 and `release.md` R12 do.

**S6 (should fix) — `breakdown.values` and `context.md` predicate values.** `breakdown` is `{0: source, 1: name, 2: [values]}` "as in a policy leaf". `verifier.md` makes every value a uint; `context.md`'s example uses text. Fix here as in `context.md` review B3: values are uints. The vector `deck-valid-breakdown` ("attribute `ward` with three values") should carry `[1, 2, 3]`.

**S7 (should fix) — `services.md` cites "D1 to D14" and "C1 to C14".** This spec has D15. Flag to W0-07 (noted here because the drift started on this side).

**N4 (note) — `manifest.md` registry row for `deck`.** It says a deck pins "Context version, statement list" and its example has an `aggregators` ref. This spec pins per-card refs and no aggregators. ADR 0010 already asks for the edit. Also `manifest.md` "Frozen fields" says "only its closing time can move, and only later", which agrees with this spec's intent but not with D12's pre-open escape (see B2).

**N5 (note) — `blur`.** A `rat` with no bound. Bound it (0 ≤ `blur` ≤ `grid`) so the aggregator's kernel is finite.

### Implementability

**B2 (blocker) — "Frozen fields" and rule D12.** D12 decides "in use" from the new version's `issued` against the previous `opens`. The spec admits a dishonest `issued` passes D12, and relies on aggregators and phones that already voted to refuse the version. Two things it does not cover:

- A phone that has not voted yet fetches the latest version through the log, verifies it (D12 passes), and votes under the new CID. `services.md` derives the task ID from the deck CID and lets an aggregator "register the deck on its own" when it sees it in the log, so two tasks can collect ballots for one deck lineage, and R10 then lets only one of them release. Late voters are silently dropped or the two aggregators disagree.
- The ledger has appended a version the protocol says is invalid, so honest clients disagree about which version is the deck.

Fix: freeze fields 0, 1, 3, 4, 5, 6 and all refs from version 1, and let only `closes` (and `expires` with it) grow. An organizer who needs to change a scheduled deck retires the lineage before `opens` and deals a new one. This removes `issued` from the rule entirely and D12 becomes checkable by every party from bytes alone. It needs `manifest.md` to assign the retired marker (already an open question in three specs). If pre-open edits must stay, the alternative is to require both aggregators to co-sign a pre-open version (they know no ballot was accepted), which is heavier.

**S8 (should fix) — rule D13 and `expires`.** `expires` is an envelope field, not in D12's frozen list, and D13 is re-checked on every version. Say explicitly that `expires` may increase when `closes` does, and may never decrease.

**S9 (should fix) — "Rating decks", the ρ and cap rows.** "ρ ≤ 1/20, and ≤ context floor"; "cap R, at most 20". D15 encodes both. Also say that a rating deck's `plan.minVoters` is `GATE_TALLIES` and that part 3 is gated by `GATE_CELL` per group, as the table says, so `release.md` R6 has one rule to point at.

**S10 (should fix) — "Card order on the phone".** "Shuffles the deck once with its own CSPRNG when it first shows it" is fine, but the results deck "uses the release's order", which is undefined: `tallies` rows sort by card index. Say "deck index order".

**N6 (note) — rule D8, "Σ parts = rho exactly (as rationals)".** Implementable, but say that the sum is computed in exact rational arithmetic and compared after reduction, so a sum that reduces to `rho` with a different `den` passes.

**N7 (note) — "Absorb".** The decision reads the daily count's final running total, a noised value with σ ≈ 10·√days. Fine as post-processing. Say that it is taken at `closes`, after the last bucket is noised (see `context.md` review S9), so both aggregators compute the same decision.

### Testability

The list covers D1 to D15 with one failing vector each. Gaps:

- D7 has at least four sub-conditions (foreign context, not `active`, epoch present or absent wrongly, `kind` = 2 in a vote deck); D9 has five; D11 has five; D15 has nine. One vector per sub-condition.
- No vector for B2's case: version 2 with `issued` before `opens` but logged after a ballot, since that is the hole.
- No vector for a `closes` extension that leaves `expires` too short (D13 on version 2).
- The plan-math set (`vectors/release-math/`) should include Δ_cov for several (M, `covScale`) pairs and the σ for a rating-deck plan, since those are the ones most likely to differ between implementations.
- A vector for the IBIS encodings in B1 (final vote, transition, moved-me) once `ballot.md` exists.

## Summary for the author

B2 is the one that changes the design: freeze everything but `closes` from version 1 and drop the `issued` test. B1 is one paragraph in the Parts section plus a line to `ballot.md`. S3 to S6 are rule edits that `reference/` needs before vectors. Everything under Sums holds; the bounds are right.

## Re-review (2026-10-06, after the author's fixes)

Read the whole spec again, plus ADRs 0013 and 0014 and the new `release.md`.

**Resolved.** B1 ("Which vote counts": final vote for part 0; one transition per re-voted card, diagonal included, nothing for unflipped cards; moved-me at most one per card), B2 (everything but `closes` and `expires` frozen from version 1; D12 is byte-checkable; retire-and-redeal for scheduled decks), S1 (gated parts defined, D11 names them), S2 (parts 1 and 2 use the full hand), S3 (D7 conditions on `origin`), S4 (argument `kind`, `parent` and `active` in D7; D4 limits arguments to `kind` 0 cards), S5 (verifier version at the deck's log position), S6 (uint breakdown values), S8 (`expires` grows with `closes`, D12 checks it), S9 (rating-deck `minVoters` and gate in D15), S10 (deck index order), N1 (one disclosed value, requirement on `ballot.md`), N2 (unenforced, stated), N3 (`cap` ≤ `MAX_CARDS`), N5 (`blur` bounded), N6, N7. Vectors are enumerated per sub-condition.

**Bounds after the change, rechecked.**

| Part | Vector | Bound | Verdict |
| --- | --- | --- | --- |
| 0 | ≤ K one-hots of the final vote, plus 1 | √(K+1) | Correct; the oracle has no re-votes, so counting the final vote is the oracle's own case |
| 5 | per re-voted card: one transition cell and at most one moved-me bit; ≤ K_m cards | √(2·K_m) | Correct, now tight |
| 3 | part 0's vector in one slot, plus K_r one-hots with part 6 | √(K+K_r+1) | Unchanged, correct |
| 8 | one coordinate per round, 1 if answered | √(R+1) | Correct: at most R+1 ones; a rating deck has R = 0 so Δ = 1 |
| 1, 2, 4, 6, 7 | unchanged | | Unchanged |

Part 8 is in `plan.parts`, D8 requires it, D8 requires Σ parts = `rho`, and the phone charges `plan.rho`, so the receipt padding is inside the shield charge and inside the context floor. The example's parts sum to 127/500 and its tallies σ (18.4) matches the release example.

**S11 (should fix) — "Rating decks" and `release.md` line 28 and R5 still say a rating release has "parts 0 and 3".** D15 now requires parts 0, 3 and 8. Change both places in `release.md` and the sentence under the rating-deck table here to "parts 0, 3 and 8".

**N8 (note) — Example caption says "four parts plus the daily count".** It is now six parts.

**N9 (note) — the `retired` marker is now load-bearing.** A scheduled deck can only be withdrawn by retiring the lineage, and `manifest.md` has no key for it. The spec lists this as open, which is right; it should be the first item W0-10 carries to the manifest spec, because until then an organizer cannot cancel a scheduled deck at all.

**Updated verdict: approve.** No blockers remain. S11 and N8 are editorial.
