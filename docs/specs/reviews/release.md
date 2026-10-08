# Review: `docs/specs/release.md` (Draft 0.1, W0-01)

Reviewed 2026-10-06 against `CLAUDE.md`, `docs/design.md`, `docs/specs/manifest.md`, `docs/specs/context.md`, `docs/specs/deck.md`, `docs/specs/services.md`, `docs/specs/storage.md`, `docs/specs/chat.md`, `docs/specs/take.md`, `docs/specs/trust-list.md`, `docs/specs/verifier.md`, `docs/research/dp-polis/polis_dp.py`, and decisions 0010 to 0015.

Dependencies not yet written: `ballot.md` (receipts, vector encodings), `shield.md`. Findings that depend on them say so.

## Verdict

**Approve with fixes.** The accounting is sound: one lineage per deck, one plan, each part noised once with σ² = Δ²/(2ρ_part) and frozen across versions, the yearly cap charged at version 1 for the whole plan, and dropouts handled with per-part totals. The assurance list is manifest-derived, not a sum, so it costs nothing. Five blockers, none of which changes the shape: the per-round receipt blobs publish exact participant counts beside the noised ones; the sampler must take the exact rational σ², not the rounded `sigma`; the keybox has no byte format or media type; rule R6 contradicts itself for the daily count below the voter floor; and `unlocked` has no canonical order.

## Findings

### Invariants

**B1 (blocker) — "Body fields" key 9 `receipts`, "Security considerations", and `services.md` "Receipts".** The round-n receipt blob holds "every receipt leaf of the round in tree order" and is a public blob. Its leaf count is the exact number of ballots in that round. `nHat` and every `parts[p].n` are noised precisely so that participation is protected (the design doc: "never who voted or whether they did"), and the exact count beside them undoes that: an organizer who knows that every other member voted learns whether you did, at ε = ∞. The sentence "a phone that dropped out of a round has no receipt for it and nothing is leaked by its absence" is false as written, because the per-round counts give exact dropouts too. Fix, in order of preference: pad each round's tree with dummy leaves to `N + Y` where `Y ≥ 0` is a truncated discrete noise drawn by the Leader, with its budget declared (a small δ from truncation, or a tiny ρ as a ninth part); or pad to the next multiple of a fixed bucket and record the bucket-edge leak in `docs/threat-model.md`. Dummy leaves must be indistinguishable from real ones in the blob. This belongs to `ballot.md` and `services.md` as much as here; raise it with W0-02 and W0-07 now because it changes the receipt tree. Seam: ballot construction.

**S1 (should fix) — "Members-only results" and `nHat`.** `nHat` public in a sealed release is an accepted leak and is stated. `parts[*].n`, `groupsK`, `unlocked` and the receipt counts are public too. List them all in one sentence so the accepted leak is complete.

**N1 (note) — "Rounds", who may act, and `services.md` AG-5.** "The Leader checks this against its ballot store" for rounds 1 to 3, but AG-5 deletes ballots and nullifiers "after the release is logged". Version 1 is a logged release. Ask W0-07 to say "after the final version is logged".

### Floors

**S2 (should fix) — rule R14 and R10, "in the last 365 days".** Log entries carry no time. Phones and the ledger need one rule: use `issued` of each release's version 1 (the only time in the bytes), and say that `issued` is therefore load-bearing for this one check even though `manifest.md` calls it informational. Add to R13 a bound so `issued` cannot be back-dated far: version 1's `issued` within, say, 30 days after `deck.closes`.

**N2 (note) — ADR 0014, "Why versions rather than interim blobs".** The ADR says an abandoned round "would be spent but invisible". R14 charges `plan.rho` in full at version 1, so the yearly floor never depends on later versions. The versions earn their keep through frozen-field enforcement and proof-before-action, which the spec also says. Trim the ADR's first reason so nobody later weakens R14 believing the versions cover it.

### Sums

Every published table is a noised sum of bounded per-person vectors or post-processing of those sums, except the receipt counts (B1). The oracle's inverse-variance blend of tallies with summed group tallies is correctly dropped. `nHat` and `parts[p].n` are themselves sums. Per-part σ values in the example check out against the formulas (tallies 16.94, count 10, covariance 2.3716 after dividing by `covScale`, map 3.6227, groups 10.3376).

**B2 (blocker) — "Noise" and ADR 0010 item 3: what the sampler takes.** `sigma` is a binary64 computation rounded to micro-units for display. σ² = Δ²/(2ρ) is an exact rational (`delta_sq × den / (2 × num)`), and the Canonne–Kamath–Steinke sampler takes a rational σ². The spec never says which one the aggregator feeds the sampler. An implementation that converts the rounded `sigma` back to a float and samples from it is the floating-point attack surface `CLAUDE.md` warns about, and the Helper cannot tell. Fix: "The sampler is called with the exact rational σ² = Δ² · den / (2 · num). `sigma` is derived from the same rational for display and is never an input to sampling." Add to the Helper's attestation list that `sigma` equals the rounding of that rational. Seam: DP noise sampling.

**N3 (note) — "Parts" part 3 with part 6.** Group tallies pay for the ratings' extra sensitivity (√(K+K_r+1)) out of part 3's ρ, so adding ratings makes group tallies noisier even at the recommended split. Say so where the split is recommended, so organizers see the trade.

### Federation

Both aggregators by authority CID; stores by authority; the keybox and tables by CID. OK.

### Consistency

**B3 (blocker) — rule R6 and "After round 0", part 4 below the voter floor.** R6 says `unlocked` is "exactly the parts whose gate `nHat` meets", "`nHat` is present iff `unlocked` is non-empty", and "`nHat` absent ⇒ … `parts` holds only part 0 (and 4)". Part 4 has no gate, so by the first clause it is always unlocked, which forces `nHat` present, which contradicts the vector `release-valid-below-minimum` (`unlocked` empty, `nHat` absent). Also unsaid: whether the `count` table, already served live to organizers, is published when the release is below the floor. Fix: part 4 is unlocked iff part 0 is; below the floor nothing is published and `parts` records part 0 and part 4 with their ρ and σ only.

**B4 (blocker) — "Body fields" key 8 `unlocked`, "array of part ids".** The example has `[0, 4, 1, 2, 3]`. Two implementations will produce different bytes. Fix: sorted ascending. Same for `assurance` (already "in CID order"; say bytewise over the 33-byte CID) and for the keys of `receipts` (CBOR map keys sort themselves).

**S3 (should fix) — rule R2 and `refs["deck"]`, "the deck manifest version the ballots were cast under".** When `closes` was extended, ballots were cast under two versions. Say: the highest deck version logged before `closes`, and R2 checks that every earlier version in the lineage differs from it only in `closes` and `expires`. If `deck.md` review B2 lands (frozen from version 1), this becomes trivial.

**S4 (should fix) — "Tables", `breakdown_cells.value` is `utf8`.** `verifier.md` makes every attribute value a uint and `deck.md`'s `breakdown.values` should follow (see those reviews). Make `value` `int32`. `take.md`'s `series.attribute` ("the cell `value` as `breakdown_cells` spells it") then becomes a uint too; flag to W0-04.

**S5 (should fix) — "Tables" and `refs`, which part owns each table.** `t/<table>` is present "when the table's part is unlocked", and every file carries `hum.part`. The mapping from table to part is only implied: `consensus` at stage 1 comes from part 0, at stage 4 from part 3; `repness` from part 3; `axes` from part 1; `centroids` from part 2; `breakdown_cells` from part 7. Add a column to the Tables table. R7 and R15 cannot be tested without it.

**S6 (should fix) — "Tables", `movement`, and `take.md` "Measures".** `take.md` reads "toward, away and unchanged as `release.md` defines them". This spec never defines them. Add: with the card's position as the reference, toward = second vote closer to agree than the first, away = closer to disagree, unchanged = equal; or define toward relative to the argument's side. Pick one.

**S7 (should fix) — "Example", `assurance`.** The example lists `c5ab7k…u9e`, which in `context.md`'s example is `issuers[0]` (the approved-list verifier, assurance 1 by profile) at level 2. R12 lists verifiers in the accepted set of the *vote* policy, and that context's vote policy names only `tl/0`. The example contradicts R12 on two counts. Fix the example.

**S8 (should fix) — rule R13 and `roundDeadline` = `issued` + `roundWindow`.** `issued` is informational per `manifest.md`, yet here it fixes the round. A Leader can set `issued` in the past and close a round before any phone sees the version. No privacy loss (dropouts are safe), but it is a denial of participation that the Helper could refuse if asked. Add to the Helper's attestation: version `issued` is within 1 hour of the Helper's clock.

**N4 (note) — `services.md` "Opening a deck" and the deck's `expires`.** Consistent with D13. No action.

**N5 (note) — "Who signs" vs `manifest.md` step 6 and the bundle's `signatures` array.** R9 extends step 6 to two keysets. Say how a verifier assigns each COSE_Sign1 to a keyset: match `kid` within each of the two keysets, count distinct signatures per keyset, and require each threshold. Key IDs can collide across keysets, so also require that no public key appears in both aggregators' keysets (rule R2 can check it), or one signature could count toward both thresholds. ADR 0010 item 5 already asks `manifest.md` to say this; add the matching rule here so `reference/` can implement it before `manifest.md` changes.

**N6 (note) — Domain strings.** `hum/results-keybox/1` is unique across every spec on disk and namespaced. `hum/results-key/1` (context) likewise. OK.

### Implementability

**B5 (blocker) — "Members-only results", the keybox.** The keybox is "a blob containing the sealed references … encrypted with HPKE". Not defined: the byte layout (HPKE `enc` ‖ ciphertext? CBOR wrapping?), the HPKE `aad` (empty? the release CID cannot be used since the keybox CID is in the release), the media type, and how it is put to a store. `storage.md` §6.3 accepts only `application/vnd.hum.sealed` with a format byte, or a listed public media type; HPKE output is neither, so the reference store rejects it with `415 format`. Also: a new version adds tables, so there is a new keybox per version. Say whether it holds every table so far or only the new ones, and whether earlier versions' `keybox` refs are frozen (R8 does not list `keybox`). Fix: define `keybox = 0x01 ‖ enc (32 bytes) ‖ HPKE-Seal(ct)` with `aad` = the deck CID bytes and `info` as stated; media type `application/vnd.hum.keybox`; ask W0-06 to list it in the reference store's public formats (or define a sealed format 3); one keybox per version holding every table so far; `keybox` not frozen. Seam: sealed blob format.

**S9 (should fix) — "What a phone computes", rounding.** "Rounded to the nearest integer" in round 1: say ties-to-even (or away from zero) and that the computation is binary64 throughout, including `covScale × entry`. The round-1 vector is the one place a phone's bytes must match the reference exactly.

**S10 (should fix) — "After round 2", "one effective σ (σ after blur, as the oracle computes it)".** The oracle's `sc_eff` depends on scipy's kernel truncation (`truncate = 4.0`) and on a 13 × 13 padded impulse. Give the formula (σ_eff = σ · ‖kernel‖₂ with the kernel radius stated) or say "as `reference/` computes it" and ship the value in `hum.threshold_sigma` so phones never recompute it. The second is simpler.

**S11 (should fix) — "Tables" vectors as "hex Parquet bytes".** Parquet is not byte-deterministic across writers, so two conformant aggregators produce different CIDs for the same rows. That is fine for the protocol (the Helper hashes the Leader's bytes), but the vectors cannot compare bytes. Say that table vectors are compared row-wise and by metadata after decoding, or fix a writer profile (no compression, one row group, plain encoding, no statistics, fixed metadata order) and require it. The first is cheaper and sufficient.

**S12 (should fix) — "Security considerations", "Derived tables can be recomputed from the sums by anyone".** Centroids come from k-means with restarts that the spec says need not be reproducible. Soften to: `axes`, `repness` and `consensus` are recomputable exactly; `centroids` approximately.

**N7 (note) — "Rounds", "roots are per round".** `services.md`'s `GET .../receipts` is already per round. The open question in this spec is stale.

**N8 (note) — "What the aggregators compute between rounds", after round 1: `n` for the part = round(trace(S)).** The trace is the sum of diagonal entries, each noised with σ_cov, so its noise is σ_cov · √M. Say so, since `n < GATE_MAP` is decided on it and at M = 60 that is 7.7 σ_cov.

### Testability

The list has one failing vector per rule R1 to R15 and good deterministic coverage of the phone-side math with noise as an input. Gaps:

- R5 has at least seven conditions, R6 four, R7 three, R8 five, R11 four, R13 three. One failing vector per condition.
- B3: a vector for `count` present with `nHat` absent, once the rule is fixed.
- B4: a vector with `unlocked` unsorted that fails canonical form.
- B5: a keybox vector (fixed X25519 key pair, fixed table references, expected bytes), and a failing one with the wrong `info`.
- S9: the round-1 vector should include a hand whose scaled entry lands exactly on .5.
- A vector for the rating-deck release's R10 limit (third rating release in a year).
- No vector exercises R12 across a trust-list expansion (two verifiers for one attribute, one with `minVersion`); add one, since the accepted-set algorithm is `trust-list.md`'s and this is where it is consumed.

## Summary for the author

B1 is the one that touches the design and needs W0-02: receipt trees must not reveal exact counts. B2 is one sentence that keeps floating point out of the sampler. B3, B4 and B5 are rule and format edits that `reference/` needs before it can generate vectors. The rest is alignment with `take.md`, `verifier.md` and the example.

## Re-review (2026-10-06, after the author's fixes)

Read the whole spec again, plus ADRs 0010, 0011, 0013 and 0014, `storage.md` §9.1 and the new `deck.md`.

**Resolved.** B1 (padded receipt trees, part 8), B2 (sampler takes the exact rational σ²; Helper attests the rounding), B3 (R6 rewritten: parts 4 and 8 follow part 0; below the floor `parts` records 0, 4 and 8 with ρ and σ), B4 (`unlocked` ascending, `assurance` bytewise), B5 (keybox bytes, `aad`, media type listed in the store defaults, one per version, not frozen under R8), S1 (public fields of a sealed release listed), S2 (R10, R13, R14 use `issued` with a 30-day bound), S3 (R2 pins the highest pre-close version), S4 (`breakdown_cells.value` int64), S5 (Part column in the Tables table), S6 (toward · away · unchanged defined), S7 (example `assurance` fixed), S8 (Helper clock check), S9 (ties to even, binary64), S10 (`hum.threshold_sigma` shipped), S11 (row-wise table comparison), S12 (centroids approximate), N1 (nullifier set kept until the final version; AG-5 flagged), N2 (ADR 0014 rationale trimmed), N3, N5 (kid matching and no shared key, R2), N7, N8. Vectors are enumerated per sub-condition and the new math vectors are listed.

**Receipt padding, checked.** Per round r the published leaf count is `N_r + 6·⌈σ_8⌉ + Z_r` with `Z_r` a discrete Gaussian of the receipts part.

- *Sensitivity.* A person contributes 1 to each round they answered and 0 otherwise, so the vector over R+1 rounds has L2 norm at most √(R+1). `R` is fixed by the plan (3 if part 1 is present, else 0), and a release that ends early only zeroes coordinates, so the bound holds whatever happens. √(R+1) is right. For a rating deck R = 0 and Δ = 1.
- *Mechanism.* Gaussian noise with σ² = (R+1)/(2ρ_8) on each coordinate gives ρ_8-zCDP for the whole vector, and additive composition puts it inside `plan.rho`. The offset `6·⌈σ_8⌉` is a public constant and changes nothing. The clamp at zero truncates the Gaussian at −6σ, which is not pure post-processing; the spec correctly charges it to δ (below 10⁻⁹ per round, so at most 4·10⁻⁹ per release against a `DELTA_MAX` of 10⁻⁶). See S13 for the one sentence this still needs.
- *Tree shape and order.* An RFC 9162 tree's shape depends only on its leaf count, which is the noised count. Leaves are sorted bytewise and dummies are hashes of fresh random input of the same fixed length, so neither position nor appearance separates them, provided `ballot.md` makes real leaves uniformly distributed hash outputs (stated as a requirement). The Helper never sees the real count.
- *Shield.* Part 8 is in `plan.parts`, D8 requires it and requires Σ parts = `rho`, and the phone charges `plan.rho`, so it is inside the shield charge. Below the floor the round-0 root is still published (R13), and `parts` records part 8's spend. Consistent.
- *Other views of N.* `nHat`, the `count` series and the padded leaf count are three noised views of the same quantity, each with its own ρ. Composition covers them.

This closes B1. What remains is implementability (S13, S14).

**S13 (should fix) — "Receipts", `⌈σ_8⌉`.** σ_8 is the square root of a rational. An implementation that takes a binary64 square root can land on 19.999… where another gets 20 and the ceilings differ by one, which changes the published count by one and breaks the vector. Define it in integers: with σ_8² = p/q in lowest terms, `⌈σ_8⌉` is the least integer `m` with `m²·q ≥ p`. Same for any other place a ceiling of σ is taken.

**S14 (should fix) — "Noise" and "Receipts", the δ bookkeeping.** Say where the truncation δ goes: either "ε at δ is computed with the plan's `delta`; the clamp adds at most (R+1)·10⁻⁹, which is ignored because the offset is 6σ", or fold it into the reported δ. One sentence, so two implementers report the same ε.

**S15 (should fix) — "One release, several versions" and rule R5 still say a rating release carries "parts 0 and 3".** `deck.md` D15 now requires parts 0, 3 and 8. R5 says "contains", so a literal reading passes, but the sentence on line 28 and the rating vector should say "0, 3 and 8".

**N9 (note) — keybox `aad`.** `aad` is the deck CID, so a keybox from version 1 verifies under version 2's refs if a Leader pins the old one. Members then cannot open the new tables; nothing leaks. Adding the stage to `aad` would let the Helper catch it. Optional.

**N10 (note) — "Members-only results" cites `storage.md` §9.1 and the media type `application/vnd.hum.keybox+hpke`.** Both exist in `storage.md` on disk. Aligned.

**N11 (note) — `services.md` "Receipts" still says "every receipt leaf of the round in tree order".** The spec lists this under open questions as raised with W0-07. It has to change to "the padded, bytewise-sorted leaf list" before W0-08 writes the receipt vector.

**Updated verdict: approve with fixes.** No blockers remain. S13 and S14 are determinism and bookkeeping sentences; S15 is editorial.
