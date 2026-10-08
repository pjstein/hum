# Hum Release Spec — Draft 0.1

Oct 6, 2026 · W0-01

## Scope

A `release` is the only thing that ever leaves aggregation: the noised sums of one deck, the parameters they were noised with, the tiers the voter count unlocked, and the receipts that let a voter check their ballot was counted. Every release is a sum of bounded per-person contributions, so the same spec serves central noise in phase 1 and two-server aggregation in phase 2.

This spec defines the `release` body, the post-close rounds, the noise mechanism, the Parquet tables, who signs and what each signer attests, the step-10 rules the ledger enforces, and how members-only results coexist with a public ledger. The envelope is in [`manifest.md`](manifest.md); conventions and constants in [`context.md`](context.md); the plan it fulfils in [`deck.md`](deck.md). The ballot encoding and receipts are [`ballot.md`](ballot.md)'s. The aggregator API that moves ballots and publications is [`services.md`](services.md)'s. The math is the oracle in `docs/research/dp-polis/polis_dp.py`.

## One release, several versions

A release is one manifest lineage per deck. Each post-close round that needs something published before phones can act adds a version. The ρ budget is declared once, in the deck's plan; every version adds parts to it and never re-noises an earlier one.

| Version | Stage | Published | Phones then do |
| --- | --- | --- | --- |
| 1 | 1 `tallies` | Tallies, daily count, movement, ratings, breakdown (as unlocked), `nHat`, round-0 receipt root | Round 1: center and normalize their votes on the published tallies, send the outer product |
| 2 | 2 `axes` | Covariance, the derived axes (two eigenvectors, means, box), round-1 receipt root | Round 2: project themselves, send one map cell |
| 3 | 3 `centroids` | Map histogram, derived centroids, round-2 receipt root | Round 3: pick their nearest centroid, send group tallies |
| 4 | 4 `final` | Group tallies, group sizes, representative statements, common ground, round-3 receipt root | Nothing. The results deck posts back to chat |

A release may become `final` early: at stage 1 when the plan has no map tier or `nHat` does not unlock it, at stage 2 or 3 when a round's noised participant total falls below the map gate. A final version ends the lineage; the ledger refuses a fifth version or a version after `final`.

"One release per deck" means one release lineage per deck lineage. Versions of that lineage are stages of the same release and are covered by the same plan.

Why versions and not unlogged interim blobs: every version spends budget, and budget spent must be logged so the ledger can enforce the yearly floor (`context.md`, `rhoYear`) and phones can reconcile their shields with the ledger. A round that is published and then abandoned still appears. `services.md`'s `GET .../rounds/{n}/published` therefore returns the release version's bundle (CID, signatures, log proof) rather than a separately signed blob; see Open questions.

A rating deck (`deck.md`, `kind` = 1) produces a one-version release: stage 1, final, with parts 0, 3 and 8, since its groups come from the source release and travel in the round-0 ballot. Its tables are exactly `tallies`, `group_tallies` and `group_sizes` (`take.md`, "What the rating release publishes"); it carries no `consensus`, `repness` or `count` table, because fairness ratings are read per group, not ranked.

## Body fields

| Key | Name | Type | Required | Meaning | Frozen |
| --- | --- | --- | --- | --- | --- |
| 0 | `mechanism` | uint | yes | 0 central discrete Gaussian, ρ-zCDP (phase 1) · 1 reserved for DAP/Prio3 (phase 2) | yes |
| 1 | `helper` | auth | yes | The second aggregator authority; `authority` is the Leader | yes |
| 2 | `stage` | uint 1..4 | yes | Equal to `version` | — |
| 3 | `final` | bool | yes | No later version will be published | once true |
| 4 | `rho` | rat | yes | ρ spent so far: the sum of `parts[*].rho` | may only grow |
| 5 | `delta` | rat | yes | Equal to the plan's `delta` | yes |
| 6 | `parts` | map part → part record | yes | Every part noised so far (table below) | earlier entries |
| 7 | `nHat` | int | if `unlocked` is non-empty | Noised participant count: the tallies part's participant coordinate, raw (may be negative) | yes |
| 8 | `unlocked` | array of part ids, ascending | yes | Parts whose tables are published so far | earlier entries |
| 9 | `receipts` | map round → bytes32 | yes | Merkle root over the padded receipt tree of each completed round (see Receipts) | earlier entries |
| 10 | `assurance` | array of `[auth, uint]`, sorted bytewise by the 33-byte CID | yes | Each verifier authority the context's vote policy accepts, with its declared assurance level | yes |
| 11 | `sealed` | bool | yes | Tables are sealed to the context's `resultsKey` | yes |
| 12 | `resultsEpoch` | uint | if sealed | The context's `resultsEpoch` the keybox was sealed to | yes |
| 13 | `roundDeadline` | time | if not final | `issued` + the plan's `roundWindow`; after it the aggregators close the next round | — |
| 14 | `groupsK` | uint 2..5 | from stage 3 | Number of groups | yes |
| 15 | `absorbed` | bool | yes | The map tier's ρ was folded into tallies under the plan's `absorb` | yes |

A part record (values of key 6):

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | `rho` | rat | ρ this part spent |
| 1 | `sigma` | uint | σ_r in real units × 10⁶, rounded to nearest (ties to even); σ_r is the rational the sampler was called with (see Noise) |
| 2 | `n` | int | The part's own noised participant total (see Dropouts); absent for parts 4, 5, 6, 7 and 8 |

`refs` names:

| Name | Points to | Present when |
| --- | --- | --- |
| `deck` | The highest version of the deck lineage logged before this release lineage's version 1; earlier versions differ from it only in `closes` and `expires` (`deck.md`, D12) | always |
| `t/<table>` | A Parquet blob (public) or a sealed blob (when `sealed`) | the table's part is unlocked at this stage |
| `keybox` | The HPKE keybox for every sealed table so far (below); a new one per version, not frozen | `sealed` |
| `receipts/<n>` | Round `n`'s receipt root blob: `k` and the CIDs of the 2^k leaf pages (`services.md`, "Receipts"), so the padded tree is reproducible from the ledger | one per completed round |

Table names: `tallies`, `count`, `movement`, `moved`, `ratings`, `breakdown`, `breakdown_cells`, `covariance`, `axes`, `map`, `centroids`, `group_tallies`, `group_sizes`, `group_ratings`, `repness`, `consensus`.

A release carries no statement text. Tables key rows by the card's deck index and by the pinned object's CID; text resolves through the deck's `card/<i>` refs, and a deleted text shows as removed (`issue-map.md`).

## Rounds

Round 0 is voting (between the deck's `opens` and `closes`). A phone may replace its round-0 ballot until `closes`; the last accepted ballot counts and only its leaf is in the tree (`ballot.md`), while the daily count still counts first ballots. Rounds 1–3 happen only when the plan has the map tier and the counts unlock it. In each round a phone contributes one bounded vector; what it contributes is in `deck.md`'s Parts table, and its encoding is `ballot.md`'s.

- **Who may act.** Only a pseudonym that cast a round-0 ballot may contribute to a later round, once per round. In phase 1 the Leader checks this against its nullifier set, which it keeps until 24 hours after the final version is logged (`services.md` AG-5); in phase 2 the DAP tasks for rounds 1–3 take the round-0 receipt as the report's authorization (`ballot.md`).
- **Deadlines.** A round opens when its version is logged and closes at that version's `roundDeadline`. The aggregators enforce the deadline by their own clocks; phones treat `roundDeadline` as advice and verification step 11 (`expires`) as the hard stop. Nothing about a deck is published after its `expires`: R13 bounds every version's `issued` by it and the ledger refuses later submissions by its own clock. A deck whose aggregators run out of time is abandoned with the versions already logged.
- **Independence.** A phone that misses round 1 may still take part in rounds 2 and 3: each round needs only the published tables and the phone's own hand. Nothing a phone contributes in a later round depends on what it contributed in an earlier one, so a dropout removes one person from one sum and nothing else.
- **Budget.** All rounds are in one plan and one shield charge. Each part is noised exactly once, in the version that first publishes it, with the σ the plan implies. Later versions copy earlier parts unchanged (frozen), so no number is ever released twice with fresh noise.

### What a phone computes

All of this is deterministic given the published tables. Phones compute in IEEE-754 binary64 with the formulas below, in this order. Boundary cases (a projection exactly on a cell edge) are rare and a one-cell difference between implementations changes no guarantee; the conformance vectors fix the expected cell for their inputs.

**Round 1 (axes), from `tallies`:** let `na, nd, nu` be the noised counts clamped at 0, `ns = max(na + nd + nu, 1)`, `mu = clip((na − nd) / ns, −1, 1)`. `sel` is the `M` cards with the largest `ns`, ties to the lower card index, in ascending card index. The phone's vector over `sel` is `z_j = x_j − mu_j` where it voted on `j` (`x` ∈ {+1 agree, −1 disagree, 0 unsure}) and 0 where it did not. If `‖z‖ = 0` the phone contributes nothing. Else `u = z / ‖z‖` and the contribution is the upper triangle of `u uᵀ` (i ≤ j, row-major), each entry multiplied by `covScale` in binary64 and rounded to the nearest integer, ties to even. Its integer L2 norm is at most `Δ_cov = covScale + ⌈√(M(M+1)/2) / 2⌉`; the phone clamps to that and the Leader (phase 1) rejects larger vectors.

**Round 2 (map), from `axes`:** with `pc1, pc2, mu` per `sel` card and `half_x, half_y, grid` from the table, `nv` = number of `sel` cards the phone voted on (skip if 0), `P = (z · pcs) × √(M / nv)`, `cx = clip(⌊(P_x + half_x) × grid / (2 half_x)⌋, 0, grid − 1)`, same for `cy`. The contribution is a one-hot over `grid²` at `cx × grid + cy`.

**Round 3 (groups), from `centroids`:** the same `P`, unclipped. `g` = the centroid with the smallest Euclidean distance, ties to the lower group index. The contribution is the phone's capped tally vector and participant coordinate placed in group `g`'s slot, plus, when the plan has part 6, its ratings in group `g`'s slot.

### What the aggregators compute between rounds

Sums are noised (next section) and then post-processed. Post-processing is free: it adds no ρ. It is published rather than left to phones so that every phone uses identical axes and centroids.

- **After round 0:** `nHat` is the noised participant coordinate. Publish `tallies` (raw noised counts), `count`, and, where `nHat` meets their gates, `movement`, `moved`, `ratings`, `breakdown` (cells with noised participant coordinate ≥ `GATE_CELL` only; the rest listed as suppressed in `breakdown_cells`). When the plan has part 0 only or `nHat` is below `GATE_MAP`, `consensus` is computed from `tallies` alone (one group) if `nHat` ≥ `GATE_COMMON`, and the version is final. A rating deck's release skips every derived table: it publishes `tallies`, `group_tallies` and `group_sizes` and is final at stage 1.
- **After round 1:** `S` = noised covariance in real units (integer sums / `covScale`), symmetrized. `n` for the part = round(trace(S)); its noise is σ_cov·√M, which at M = 60 is 7.7 σ_cov, so the gate decision is coarse. If `n` < `GATE_MAP`, final. Else eigendecompose `S`; `pc1, pc2` are the eigenvectors of the two largest eigenvalues `λ1, λ2`, with the sign convention that the entry of largest magnitude is positive. Box half-widths follow the oracle: `vbar = mean_j clip((na_j + nd_j)/ns_j − mu_j², 0.05, 1)` over `sel`; `half_a = 3.5 × √(max(λ_a, 10⁻⁹) / max(nHat, 1)) × √(M × vbar)`. Publish `covariance` and `axes`.
- **After round 2:** `H` = noised histogram, `n` = round(sum). If `n` < `GATE_MAP`, final. Else blur `H` with a Gaussian of the plan's `blur` cells (constant zero padding), clamp at 0, zero every cell below one effective σ (σ_eff = σ_r · ‖kernel‖₂ for the truncated kernel the reference implementation uses; the aggregator ships the value in `hum.threshold_sigma` so nobody recomputes it), and if fewer than 6 cells survive use the unthresholded clamped `H`. Run weighted k-means for k = 2..5 on cell centers weighted by the cells (10 restarts, seed 0, as the oracle), pick k by weighted silhouette, and publish `map` and `centroids`. Centroids are the only thing phones need, so k-means does not have to be reproducible across implementations; two aggregators agreeing on the Leader's centroids is enough (see Who signs).
- **After round 3:** publish `group_tallies`, `group_sizes` (each group's noised participant coordinate), `group_ratings` when present, then `repness` and `consensus` computed with the oracle's `repness` and `consensus` using `noise_sd` = the groups part's σ. Final.

### Dropouts

Each round's sum is over the phones that answered that round. `parts[p].n` records every part's own noised total: `nHat` for tallies, trace for covariance, the histogram sum for the map, the sum of group sizes for groups. Downstream numbers use each part's own total and never assume two parts cover the same people: group shares are group sizes over their sum, not over `nHat`; the oracle's inverse-variance blend of tallies with summed group tallies is not done in draft 0.1 because the two populations differ. A later round's total being below an earlier one is normal and is not an error.

## Noise

Every sum is a vector of integers (counts, or fixed-point covariance entries). Noise is the discrete Gaussian of Canonne, Kamath and Steinke (2020) on each coordinate, with variance σ² = Δ² / (2ρ_part) in integer units, where Δ is the part's L2 sensitivity from `deck.md` (for covariance, `Δ_cov` above). The vetted samplers take a rational σ, and σ = √(Δ²·den/(2·num)) is usually irrational, so every implementation uses the same rational upper bound (accepted by the owner, 2026-10-07; ADR 0010 item 3):

```
σ² = p/q in lowest terms, with p = Δ²·den and q = 2·num
n   = the least integer with n²·q ≥ p·2⁴⁰        (integer arithmetic; no square root)
σ_r = n / 2²⁰
```

**The sampler is called with the exact rational σ_r.** Because σ_r ≥ σ, the draw is at least as private as planned: Δ²/(2σ_r²) ≤ ρ_part, and the part's `rho` stays the plan's value. The overshoot is below 2⁻²⁰ in absolute terms, under 10⁻⁶ relative at σ = 10. `sigma` in the body is round(σ_r × 10⁶), ties to even, and is for display; an implementation that samples from a binary64 value, or from σ rather than σ_r, is non-conformant. That gives at least ρ_part-zCDP for the part and, by additive composition, `rho`-zCDP for the whole release; ε at δ follows ε = ρ + 2√(ρ ln(1/δ)). No floating-point sampler is used anywhere; the sampler must be the vetted discrete one the aggregation workstream records in `docs/DECISIONS.md`.

For covariance, σ² and σ_r are in integer units and the published `sigma` is round(σ_r / `covScale` × 10⁶). The published `sigma`, and the same value as `hum.sigma` in table metadata and `hum.noise_sd` in derived tables, is what the studio's error bars, `take.md`'s noise math and the noise-aware rankings read; they never recompute σ from ρ.

When the plan says `absorb` and the map tier is locked by the daily count (see `deck.md`), the tallies part is noised with ρ_tallies + ρ_cov + ρ_map + ρ_groups and `absorbed` is true; the three tier parts never appear in `parts`.

Noise cannot be a test vector. The reference implementation tests the deterministic path (sums, σ, gates, post-processing) with noise supplied as an input, and a statistical harness checks the sampler's mean, variance and tails.

## Receipts

Each round's accepted ballots form an RFC 9162 Merkle tree whose leaves `ballot.md` defines; the root is `receipts[round]` and the leaf list is a public blob (`services.md`, `GET .../receipts`). The leaf count must not be the exact number of ballots, because `nHat` and every `parts[*].n` are noised to hide participation and an exact count beside them would undo that.

- **Padding.** Before publishing round `r`'s tree, the Leader appends `Y_r` dummy leaves, where `Y_r = 6·⌈σ_8⌉ + Z_r`, `Z_r` is a discrete Gaussian draw with the receipts part's σ_r, and `Y_r` is clamped at 0. `⌈σ_8⌉` keeps its integer rule, which is exact: with σ_8² = p/q in lowest terms, it is the least integer `m` with `m²·q ≥ p` (always equal to ⌈σ_r,8⌉, since every integer is a multiple of 2⁻²⁰ and σ_r never crosses an integer σ does not; the rule over σ² is the normative one). The clamp truncates the Gaussian at −6σ, which adds at most 10⁻⁹ per round, (R+1)·10⁻⁹ ≤ 4·10⁻⁹ per release, to δ; the reported ε is computed from the plan's `delta` alone and this term is ignored, because it is below 10⁻² of `DELTA_MAX`. Every implementation reports the same ε. The published leaf count is therefore a noised count, and part 8's ρ pays for all rounds at once: a person adds 1 to each round they answered, so Δ = √(R+1).
- **What a receipt proves.** A round-0 receipt proves the ballot was accepted, not that it is in the tree, because a later ballot under the same primary nullifier replaces it. Dispute rule: a complainant shows ballot and receipt; the Leader rebuts only with a later valid ballot under the same primary nullifier. Rounds 1–3 have no replacement, so a valid receipt whose leaf is missing is evidence on its own. A ballot's cards must carry the issuer epoch containing version 1's `closes` (`credentials.md`, ADR 0026), so an extension never changes which cards may vote, and a replacement from a card that has since rotated fails while the accepted ballot stands. A round-0 dispute must be raised before the Leader deletes ballots, 24 hours after the final version is logged (`services.md`); after that an unanswered dispute proves nothing either way.
- **Dummy leaves** must be indistinguishable from real ones in the blob: `ballot.md`'s leaf format must be a fixed-length hash output, and dummies are hashes of fresh random input. The Helper cannot tell them apart and does not try.
- **Order.** Leaves are sorted bytewise before the tree is built, so position reveals nothing about arrival time.
- **Pages.** The padded leaf list is served in 2^k pages by leaf prefix, with `k` the smallest integer such that the padded count divided by 2^k is at most 4096; a root blob lists `k` and the page CIDs and is pinned as `refs["receipts/<n>"]` (`services.md`). A phone fetches the one page its leaf's prefix selects.
- **The exact count** of a round's ballots is never published or served. The aggregator's own logs round counts as `services.md` requires.
- **Uploading.** The aggregators put tables, keyboxes and receipt blobs with the authority signature (`hum/service-request/1` and the `Hum-Context` header, `storage.md` §6.3), not with a member token; they have no membership proof.

## Tables

Tables are Parquet files, one per name, with the columns below and these key-value metadata entries on every file: `hum.spec` = `release/1`, `hum.deck` = the deck CID (text form), `hum.part` = part id, `hum.rho` = `num/den`, `hum.sigma` = σ in real units as a decimal string, and for derived tables `hum.noise_sd` = the σ they were computed with. Noised sums are stored raw, as signed integers, so negative values appear; clamping is the reader's post-processing. Sorted by the listed key columns ascending.

| Table | Part | Columns | Rows | Derived |
| --- | --- | --- | --- | --- |
| `tallies` | 0 | `card` int32, `statement` binary(33), `agree` int64, `disagree` int64, `unsure` int64 | one per card | no; metadata `hum.n_hat` |
| `count` | 4 | `day` int32 (bucket index from `opens`), `ballots` int64 | one per bucket | no |
| `movement` | 5 | `card`, `statement`, `first` int8 (0 agree · 1 disagree · 2 unsure), `second` int8, `n` int64 | 9 per card | no |
| `moved` | 5 | `card`, `argument` binary(33), `side` int8 (0 pro · 1 con), `n` int64 | one per shown argument | no |
| `ratings` | 6 | `card`, `argument` binary(33), `moves` int64, `neutral` int64, `against` int64 | one per argument ref | no |
| `breakdown_cells` | 7 | `value` int64 (the attribute's uint value as `verifier.md` encodes it), `n` int64, `published` bool | one per attribute value | no; metadata `hum.attribute` |
| `breakdown` | 7 | `value`, `card`, `statement`, `agree`, `disagree`, `unsure` | cards × published values | no |
| `covariance` | 1 | `i` int32, `j` int32 (card indices, i ≤ j), `s` double (noised sum / `covScale`) | M(M+1)/2 | no; metadata `hum.cov_scale`, `hum.n` |
| `axes` | 1 | `card` int32 (the `sel` order), `mu` double, `pc1` double, `pc2` double | M | yes; metadata `hum.lambda1`, `hum.lambda2`, `hum.half_x`, `hum.half_y`, `hum.grid`, `hum.m` |
| `map` | 2 | `x` int32, `y` int32, `n` int64 | grid² | no |
| `centroids` | 2 | `group` int32, `x` double, `y` double | k | yes; metadata `hum.k`, `hum.blur`, `hum.threshold_sigma` |
| `group_tallies` | 3 | `group`, `card`, `statement`, `agree`, `disagree`, `unsure` | k × cards | no |
| `group_sizes` | 3 | `group`, `n` int64 | k | no |
| `group_ratings` | 3 | `group`, `card`, `argument`, `moves`, `neutral`, `against` | k × argument refs | no |
| `repness` | 3 | `group`, `rank` int32 (0 = top), `card`, `statement`, `direction` int8 (0 agree · 1 disagree), `metric` double, `significant` bool | up to 15 per group | yes |
| `consensus` | 3 at stage 4, else 0 | `rank` int32, `card`, `statement`, `score` double | up to 15 | yes |

Movement direction, for `take.md`'s toward · away · unchanged measures, is relative to the card's position on the scale disagree < unsure < agree: a transition is *toward* when `second` is closer to agree than `first`, *away* when closer to disagree, *unchanged* on the diagonal. All three are sums of `movement` cells.

`statement` and `argument` are the CIDs the deck pins for that card (33 bytes: algorithm byte plus digest), so takes and map annotations can join on CID without opening the deck. Group indices are stable within a release and, for a rating deck, equal the source release's.

Derived tables are post-processing: `axes`, `repness` and `consensus` can be recomputed exactly from the sum tables with the oracle's functions; `centroids` only approximately, since k-means restarts are not reproducible. The studio treats them as a convenience, not as evidence. Parquet is not byte-deterministic across writers, so conformance compares tables row-wise and by metadata after decoding, never by bytes; the CID binds whatever bytes the Leader wrote.

Each file is a public blob with media type `application/vnd.apache.parquet`, or a sealed blob holding that file when `sealed`.

## Who signs

A release version is signed by both aggregator authorities, each at its own keyset's `sign` threshold; the envelope's `authority` is the Leader and `helper` names the other. Verification step 6 for releases requires both (rule R9): a verifier matches each signature's `kid` within each keyset, counts distinct keys per keyset, and requires each threshold. No public key may appear in both keysets (R2), or one signature could count toward both. One aggregator alone cannot publish, and the ledger will not log a version that lacks either.

**Phase 1 (one party adds the noise).** The Leader holds the ballots, computes the sums, draws the noise, does the post-processing and writes the tables. The Helper does not see ballots or raw sums. Its signature attests exactly this:

1. It verified the deck and its context through all eleven steps, including every rule in `context.md` and `deck.md`, and the plan against the floors.
2. The body matches the plan: `delta`, each part's `rho`, each `sigma` equal to round(σ_r × 10⁶) for the σ_r the Noise section derives from the plan, the gates, `unlocked` against `nHat` and the parts' `n`, the stage sequence, `absorbed`, and the frozen fields against the previous version; and the version's `issued` is within one hour of the Helper's own clock, so a Leader cannot back-date a version to shorten a round.
3. It has not signed, and will not sign, another version with this stage for this deck, nor a release for this deck under another lineage.
4. Every `t/*` and `keybox` reference the Leader sent resolves to bytes with that CID, and public tables carry metadata matching the body.
5. The Leader gave it `nHat`, the receipt roots and the tables, and it signs them as given.

The Helper does not attest that the sums are correct or that the noise was drawn fairly. The ledger board says so ("not checkable yet"). When the Leader and Helper are run by one operator, as at launch, the Helper's signature is a second, separately keyed check of the parameters and of one-release-per-deck, nothing more.

**Phase 2 (two-server).** Each aggregator holds shares and adds its own noise; both attest the sums they computed. Mechanism 1 and that protocol are specified with `ballot.md`'s DAP mapping and are out of scope for draft 0.1.

## Members-only results

The context setting `perms.results` can limit results to members or organizers, but the ledger is public and every release must be logged. The resolution: the manifest is logged in the clear, and the tables are sealed.

- The release body is public: `nHat`, every `parts[*].n` and σ, `unlocked`, `groupsK`, the receipt roots and the padded leaf counts. `nHat` stays public because the ledger needs it to enforce the floors. A sealed release therefore reveals noised participation per round and the number of groups, and nothing about any statement.
- Each `t/*` ref points to a sealed blob in the storage spec's format. The aggregators seal each table with a fresh key.
- `refs["keybox"]` points to the keybox: bytes `0x01 ‖ enc ‖ ct`, where `enc` is the 32-byte HPKE encapsulated key and `ct` the HPKE ciphertext (RFC 9180; DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode) to the context's `resultsKey`, with `info` = the ASCII string `hum/results-keybox/1` followed by the deck CID bytes and `aad` = the deck CID bytes. The plaintext is a CBOR array of direct-form sealed references (`storage.md` §3) for every sealed table published so far, in `t/` name order. Each version has its own keybox holding every table so far, so a member needs only the latest. The keybox is a public blob with media type `application/vnd.hum.keybox+hpke` (`storage.md` §9.1), not a sealed blob in storage's sense, and has no format byte.
- Members hold the private key because `resultsKey` is derived from the keyring epoch `resultsEpoch` (`context.md`, "The results key"), so newcomers who receive that epoch can open old releases. The aggregators never hold a keyring. Organizers-only results are deferred in draft 0.1.
- No key appears in the manifest, the log or a store request: the manifest carries the keybox's CID only, and the keybox is ciphertext.

The results deck, the studio and the gallery open sealed releases only on members' phones; the public gallery lists a sealed release by its manifest alone.

## Validation rules (verification step 10 for `release`)

With `deck` the pinned deck version, `plan` its plan and `ctx` the context version the deck pins.

| Rule | Check |
| --- | --- |
| R1 | Required fields present with the types and limits in the tables; no unknown keys; `stage` = `version` |
| R2 | `refs["deck"]` resolves to a `deck` and is the highest version of its lineage whose log position is below the release lineage's version 1 (a clock-free check from log positions; the ballot window itself is anchored to version 1's `closes`). That it is also the version in force at `closes` follows from clocks held elsewhere: `deck.md` D16 makes the ledger and the aggregators refuse any deck version after the previous `closes`, and R13 makes the ledger refuse a release version 1 issued before `closes`. `ctx.aggregators` = [`authority`, `helper`]; no public key appears in both aggregators' keysets in force. Checked on every version, so a changed `helper` fails here |
| R3 | `mechanism` = 0 |
| R4 | `delta` = `plan.delta`; every part in `parts` is in `plan.parts` and has `rho` = the plan's, except tallies when `absorbed`, whose `rho` = plan tallies + covariance + map + groups; `absorbed` ⇒ `plan.absorb`; `sigma` = round(σ_r × 10⁶) with σ_r from the Noise section (n/2²⁰, n the least integer with n²·q ≥ p·2⁴⁰, σ² = p/q = Δ²·den/(2·num)), Δ² from `deck.md`'s Parts table and `cap`, `capMovement`, `capRatings`, `covStatements`, `covScale` from the plan, covariance divided by `covScale`; `rho` = Σ `parts[*].rho` ≤ `plan.rho` |
| R5 | Stage sequence: version 1 contains part 0 (and 4–7 when planned); `final` is true at stage 1 iff the plan has no part 1, or `absorbed`, or `nHat` < gate(1), or `unlocked` is empty; version v > 1 has prev not final and prev.stage = v − 1; stage 2 adds part 1, stage 3 part 2, stage 4 part 3; `final` is true at stage 2 or 3 iff that stage's part has `n` < gate(1); `final` is true at stage 4. Rating decks: version 1 contains parts 0, 3 and 8, is final, and `groupsK` equals the source release's |
| R6 | `unlocked` is sorted ascending and is exactly: part 0 iff `nHat` ≥ `plan.minVoters`; parts 4 and 8 iff part 0 is unlocked; parts 5, 6, 7 iff planned and `nHat` ≥ their gate (`GATE_CELL` for 7, cells filtered in post-processing); parts 1–3 iff planned and the part's own `n` ≥ gate(1). `nHat` is present iff part 0 is unlocked. Below the floor: `final`, no `t/*` refs, and `parts` records parts 0, 4 and 8 with `rho` and `sigma` only, since their noise was drawn |
| R7 | For every unlocked part, its tables are in `refs` (per the Tables section, including `consensus` when `nHat` ≥ `GATE_COMMON` and `repness` at stage 4), and no table of a part that is not unlocked is present; `groupsK` present iff stage ≥ 3 and not final at 2, or the deck is a rating deck. Rating decks: the tables are exactly `tallies`, `group_tallies` and `group_sizes` when unlocked; `consensus` and `repness` are never present |
| R8 | Version > 1: fields 0, 1, 5, 7, 10, 11, 12, 15 and `refs["deck"]` equal prev; every entry of prev's `parts`, `unlocked`, `receipts` and `t/*` refs is present and unchanged; `rho` ≥ prev.`rho`; `final` was false in prev. `keybox` may change |
| R9 | Signatures meet the `sign` threshold of both `authority`'s and `helper`'s keysets (extends step 6) |
| R10 | No release of another lineage pinning a deck of the same deck lineage was logged earlier; for a rating deck, fewer than two rating releases with the same `source` have a version 1 `issued` within 365 days before this one's (the ledger checks its own log; a phone checks what it has seen) |
| R11 | `sealed` iff `ctx.perms.results` ≠ 0; `keybox` present iff `sealed`; `resultsEpoch` = `ctx.resultsEpoch` when sealed; when not sealed, every `t/*` is a public blob |
| R12 | `assurance` lists each verifier authority in the accepted set `trust-list.md` derives for `ctx`'s vote policy (trust lists expanded at the versions `ctx` pins, plus `ctx.issuers` named in the policy), once, in CID order, with the assurance level of that verifier's manifest version in force at the deck's log position. Issuer status is not re-checked at close: ballots cast under the deck's context version stand (`verifier.md`, "Emergency distrust mid-deck") |
| R13 | `receipts` and `refs["receipts/<n>"]` have entries for rounds 0..stage−1 exactly; `roundDeadline` present iff not final and = `issued` + `plan.roundWindow`; version 1's `issued` is in [`deck.closes`, `deck.closes` + `PUBLISH_WINDOW`] (30 days). **Every version's `issued` is at most `E`, the `expires` of the deck version in `refs["deck"]`**, which R8 freezes from release version 1, so no later deck version can move `E` (a legitimate extension is logged while the deck is open, before any release exists, and R2 makes release version 1 pin it; `deck.md` D16 also stops a deck version from being logged after `closes`), and a version that is not final has `issued` + (number of rounds still to run) × `plan.roundWindow` ≤ `E`, so a round is never opened that cannot close before `E` (for version `v` of a plan with `R` post-close rounds, `R − v + 1` rounds remain). The ledger also refuses any release version when its own clock is past `E`, because a Leader and Helper run by one party could back-date `issued`. A phone refuses to display, and to act on, a release version whose `issued` is after `E`. `issued` is load-bearing here and in R10 and R14; the Helper's clock check and the ledger's clock bound it. This is what makes the deck's `expires` the last moment anything about the deck can be published, which `shield.md` relies on |
| R14 | Yearly floor: if `ctx.floors.rhoYear` is set, `plan.rho` plus the `plan.rho` of every release of this context lineage whose version 1 has `issued` within 365 days before this one's ≤ `rhoYear` (checked on version 1, charging the whole plan at once) |
| R15 | Public tables: each `t/*` blob is valid Parquet with the columns, row count and metadata of its table, `hum.deck` = the deck CID and `hum.sigma` consistent with `sigma` |

The ledger runs R1–R14 before appending (R10 and R14 against its own history); it resolves no blobs, so R15 is the Helper's before it signs and the phone's for every table it opens. Phones run R1–R13 before displaying a release. Aggregators run all fifteen on each other's proposal before signing. The studio and gallery run nothing: they only post-process logged releases.

## Example (JSON view)

Version 4 (final) of the `Spring priorities` release shown on the `P-Ledger` and `B-Release` boards. Sigma values are the exact round(σ_r × 10⁶) for this plan (cap 18, M 18, `covScale` 2¹⁶, Δ_cov 65543).

```json
{
  "spec": 1,
  "type": "release",
  "authority": "c7k3na…m1d",
  "lineage": "c0rl…",
  "version": 4,
  "prev": "c3rl…",
  "issued": 1780963200,
  "refs": {
    "deck": "c9dk…",
    "t/tallies": "c1ta…", "t/count": "c1co…",
    "t/covariance": "c2cv…", "t/axes": "c2ax…",
    "t/map": "c3mp…", "t/centroids": "c3ce…",
    "t/group_tallies": "c4gr…", "t/group_sizes": "c4gs…",
    "t/repness": "c4rp…", "t/consensus": "c4cs…",
    "keybox": "c4kb…"
  },
  "body": {
    "mechanism": 0,
    "helper": "c9hp2x…q0s",
    "stage": 4,
    "final": true,
    "rho": "127/500",
    "delta": "1/1000000",
    "parts": {
      "0": { "rho": "281/10000", "sigma": 18386906, "n": 1243 },
      "1": { "rho": "889/10000", "sigma": 2371813,  "n": 1198 },
      "2": { "rho": "381/10000", "sigma": 3622619,  "n": 1171 },
      "3": { "rho": "889/10000", "sigma": 10337391, "n": 1150 },
      "4": { "rho": "1/200",     "sigma": 10000000 },
      "8": { "rho": "1/200",     "sigma": 20000000 }
    },
    "nHat": 1243,
    "unlocked": [0, 1, 2, 3, 4, 8],
    "receipts": { "0": "b7e4…", "1": "19c2…", "2": "0d5a…", "3": "3fa0…" },
    "assurance": [["c4yx8d…t3k", 3], ["c5r2hq…9ta", 2]],
    "sealed": true,
    "resultsEpoch": 3,
    "groupsK": 2,
    "absorbed": false
  }
}
```

The ε shown on the board is `rho_to_eps(127/500, 10⁻⁶)` = 4.0. Each round lost a few dozen phones: 1,243 voted, 1,198 answered round 1, 1,171 round 2, 1,150 round 3, all noised. `assurance` lists the two verifiers the context's trust list accepts for its vote policy (`area` at level 2, `unique` at level 3), in CID order.

## Vectors (for W0-08)

Directory `vectors/release/`, each case bundled with its deck and context vectors, its tables (as hex Parquet bytes) and the noise values used as inputs.

Valid:

- `release-valid-stage1-final-tallies-only`: a tallies-only plan; version 1 final with `tallies`, `count`, `consensus`.
- `release-valid-below-minimum`: `nHat` 80 under `minVoters` 100; version 1 final, `unlocked` empty, no tables, `nHat` absent, `parts` holding 0, 4 and 8 with ρ and σ.
- `release-valid-absorbed`: `absorb` plan, count total 420; version 1 final, `absorbed` true, tallies σ from the summed ρ.
- `release-valid-four-stages`: versions 1–4 of the example, with the phones' round contributions as inputs and the published tables as outputs (axes from a fixed covariance, centroids from a fixed histogram).
- `release-valid-dropout-final-at-3`: like the above but round 2's `n` falls to 790; version 3 final with `map` and no `centroids`.
- `release-valid-public`: the four-stage case with `results` = 0: public tables, no keybox.
- `release-valid-ibis`: an IBIS plan with `movement`, `moved`, `ratings`, `group_ratings`.
- `release-valid-rating`: a rating deck's one-version release with parts 0, 3 and 8, tables `tallies`, `group_tallies`, `group_sizes`, and `groupsK` from the source.

Invalid, one per sub-condition, named `release-invalid-<rule>-<case>`:

- R1: `stage` ≠ `version`; `unlocked` unsorted; `assurance` unsorted.
- R2: `helper` not the context's; deck ref not the highest deck version logged below release version 1; a key in both keysets; version 2 changes `helper` (`release-invalid-R2-helper-changed`; R2 fires before R8).
- R3: `mechanism` 1.
- R4: tallies `sigma` off by one in the 6th decimal (σ instead of σ_r); a part not in the plan; `absorbed` without `plan.absorb`; `rho` above `plan.rho`; version 2 changes a prior part's `sigma` (R4 fires before R8).
- R5: version 1 not final though `nHat` 500 < 800 and no absorb; version 2 after a final version 1; stage 3 missing part 2; stage 4 not final; final at stage 2 with `n` 900; rating release not final; rating `groupsK` ≠ source's.
- R6: part 0 in `unlocked` with `nHat` 90; part 4 unlocked below the floor; part 5 unlocked at `nHat` 250; part 1 unlocked with `n` 700; `nHat` absent with part 0 unlocked.
- R7: `t/group_tallies` present at stage 2; `t/consensus` missing at `nHat` 400; `groupsK` at stage 2; `t/consensus` on a rating release; version 2 drops a prior `t/*` (R7 fires before R8).
- R8: version 2 changes `nHat`; changes `receipts[0]`; drops a prior `parts` entry. Other frozen fields are caught earlier: `helper` by R2, `delta` and a prior `sigma` by R4, `assurance` by R12, `sealed` and `resultsEpoch` by R11, a dropped `t/*` by R7, a lowered `rho` by R4. (A changed prior `sigma` is an R4 case and a dropped prior `t/*` an R7 case; both are listed there.)
- R9: Leader signatures only; Helper below its threshold.
- R10: second lineage for the same deck; third rating release for one source in a year.
- R11: sealed context with public tables; public context with a keybox; wrong `resultsEpoch`; sealed without keybox.
- R12: assurance missing an issuer; wrong level; including the entry-only issuer.
- R13: `roundDeadline` on a final version; `roundDeadline` ≠ `issued` + window; version 1 `issued` 40 days after `closes`; receipts missing a round; a version 3 with `issued` one second after the deck's `expires`; a version 2 with `issued` after the pinned deck version's `expires` and before the `expires` of a later deck version (rejected: `E` is the pinned version's); a non-final version 1 with `issued` + 3 × `roundWindow` past `expires`; at the ledger, a version with a valid `issued` submitted when the ledger's clock is past `expires` (refused); a final version with `issued` equal to `expires` (valid).
- R14: fifth release of the year over `rhoYear`.
- R15: tallies table with 17 rows for an 18-card deck; wrong `hum.deck`; `hum.sigma` inconsistent.

Phone-side computation vectors under `vectors/release-math/`: `sel` and `mu` from a tallies table; the round-1 integer vector and its norm for three hands, one with a scaled entry exactly on .5; the round-2 cell for hands near and far from a cell edge; the round-3 group for a hand equidistant from two centroids (lower index wins); σ_r (as n/2²⁰) and `sigma` for every part of the valid plans, including one whose σ² is a perfect square and one whose σ is within 2⁻²⁰ below an integer (both ceilings equal); the eigenvector sign convention; `repness` and `consensus` outputs from fixed group tables; a receipt tree padded with a fixed `Y_r`; a keybox from a fixed X25519 key pair and fixed references, and a failing one with the wrong `info`; R12's accepted set across a trust list with two verifiers for one attribute, one with `minVersion`.

## Security considerations

- Every published number is a noised sum of per-person vectors with a declared bound, so the privacy guarantee does not depend on how many people take part in a round or on who drops out.
- Parts are noised once and frozen across versions. A ledger that enforces R8 makes re-noising impossible without a visible fork.
- `nHat` is public in sealed releases. A context that must hide even its size should not use the ledger in draft 0.1.
- The Helper's phase-1 signature is a parameter check, not a correctness proof. Verifiable noise is open research and is listed on the design doc's risk list.
- Receipt roots let a voter check inclusion without identifying themselves (`ballot.md`). Trees are padded with dummy leaves to a noised size, so neither a round's count nor a dropout count is exact.
- `axes`, `repness` and `consensus` can be recomputed exactly from the sums by anyone, so a Leader that publishes misleading rankings can be caught by the studio; `centroids` only approximately.

## Open questions

Filed in `docs/decisions/`:

- **Release rounds as versions** ([`0014-w0-01-release-rounds.md`](../decisions/0014-w0-01-release-rounds.md)): three post-close rounds and one lineage with up to four versions, versus the design doc's two rounds. `services.md` is aligned: `GET .../rounds/{n}/published` returns version n+1's bundle, and DAP task IDs are per round and part (SHA-256 of `hum/dap-task/1` ‖ deck lineage CID ‖ round ‖ part, as `ballot.md` defines). The covariance round exists because the oracle centers votes on the noised tallies; folding it into the vote ballot needs a simulator test.
- **Members-only results** ([`0011-w0-01-members-only-results.md`](../decisions/0011-w0-01-members-only-results.md)): the HPKE keybox and the public `nHat`. `services.md` step 1 of "Publishing a release" says sealed table keys reach members over MLS; the keybox replaces that, since aggregators are not MLS members. `storage.md` may want to define the keybox as a sealed-blob variant.
- **Two signers, one `authority` field** ([`0010-w0-01-body-conventions.md`](../decisions/0010-w0-01-body-conventions.md)): the envelope has one authority; this spec puts the Helper in the body and extends step 6. The manifest spec should say so too.
- **Split noise before phase 2:** the Helper could add half the noise variance in phase 1 at no cost to the math, giving a weaker guarantee (2ρ) when only one aggregator is honest. Deferred until the Helper is a separate organization; see ADR 0014.
- **Assurance counts:** draft 0.1 lists issuers without per-issuer voter counts, because a count is a breakdown and needs budget. Whether releases should spend on it is for the owner.
- **Receipt padding** (seam: ballot construction): the padded tree, dummy leaves and part 8 require `ballot.md`'s leaf to be a fixed-length hash output. `services.md` serves only padded trees, per round, in pages. Raised with W0-02.

Assumptions about sibling specs:

Now written and aligned: `ballot.md` (leaf = SHA-256(`hum/receipt-leaf/1` ‖ round ‖ nonce ‖ payload hash), fixed length, no nullifier; the vector encodings and bounds here; rules B4–B6 for which vote counts; round-0 receipt authorizes rounds 1–3 through a DAP extension) and `shield.md` (charges `plan.rho` once at the first round-0 ballot).

Already aligned: `storage.md` defines the sealed blob and the direct-form sealed reference the keybox carries, and aggregators put blobs with the authority signature rather than a member token; `services.md` defines the aggregator API and the Leader–Helper exchange, including per-round receipt pages and AG-5 deleting ballots after the final version is logged; `take.md` reads `tallies`, `group_tallies` and `breakdown` by statement CID and group index as the Tables section provides.
