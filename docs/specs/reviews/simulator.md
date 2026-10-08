# Review: `docs/specs/simulator.md` (W0-09), draft 0.1

Reviewed 2026-10-06 against `prompts/wave-0/09-simulator.md`, `CLAUDE.md`, `docs/design.md`, `docs/specs/services.md`, `release.md`, `deck.md`, `context.md`, `storage.md`, `issue-map.md`, `docs/research/dp-polis/`, ADRs 0090 and 0091, and the code in `sim/src/`. `ballot.md` and `shield.md` do not exist yet. I did not run the simulator; findings about runtime behavior come from reading the code. Where a claim depends on a run, I say so.

## Verdict (first pass)

**Approve with fixes.** The architecture is right: one trait per service, every call on a tape, phones as data, the research pipeline as the oracle, gates per source and tier, an empty tape fails. The spec is honest about most of what is faked. Two things must change before wave 1 plugs in, because the leak checker as specified would bless an invariant-2 join and would not notice a bypassed port. Several other findings are about the fake aggregator disagreeing with `release.md` in ways that would make it a wrong oracle for W1-03.

## Blockers

### B1. The leak checker's allow-list sanctions a cross-identity join at the verifier

Section "Leak checks", rule `identity-not-allowed-here`; `sim/src/leak.rs:145-148`; section "How wave 1 plugs in", row W1-02.

The rule says the aggregator and the verifier may see pseudonyms. The sim's `Verifier::admit(context, proof, nullifier)` models a service that sees the per-context voting pseudonym at join time. No such service exists in the design. `docs/design.md`'s who-sees-what table gives the credential issuer "that you got a resident card" and nothing else, and `services.md`'s issuer and verifier host sees evidence, which identifies the person. The real nullifier is seen only inside a ballot at the aggregator (`services.md`, "Ballot intake") and, under separate domain strings, at the log for authored objects.

The W1-02 row tells identity to replace `FakeVerifier` with the real verifier host behind the `Verifier` port. If they do, the leak checker will allow the verifier host to record `vp_` tokens beside the evidence it already holds, which is exactly the resident-card-to-pseudonym join invariant 2 forbids, and the run will pass.

Fix: remove `verifier` from the pseudonym allow-list. Split the port: `Issuer` (sees a blinded request, never a pseudonym) and an `Admission` step that is phone-side proof generation plus the aggregator's own membership check on the ballot, as `services.md` describes. Make the fake aggregator check the presentation and nullifier itself (see S2). Derive the allow-list from the design table and `services.md`'s logging table, and print that derivation in the spec as a table with one row per service and one column per identity class.

### B2. A bypassed port passes the leak check as long as some other service wrote to the tape

Section "Leak checks" ("An empty tape fails"); `sim/src/leak.rs:64-66`; plug-in rule 2.

The vacuity guard is one global `records > 0`. When W1-05 replaces `FakeDelivery` and forgets the recording wrapper, the aggregator, store and ledger records still make the tape non-empty, the delivery tape is empty, and the run passes. This is the single most likely way the leak checker goes silent in wave 1, and the spec's own rule 2 ("everything a real service sees must still reach the tape") has no check behind it.

Fix: the world counts calls per port (a counter in the trait object wrapper the world owns, not in the fake) and the leak report fails when any port with a non-zero call count has zero tape records. Report records per service in the JSON. Add a unit test that drives one fake without the tape and asserts failure.

## Should fix

### S1. The leak checker can only find the sim's own field names and prefixes; there is no registry for real tokens

Section "Identities and the fake credential flow"; "Leak checks"; plug-in rule 3; `sim/src/leak.rs:69-90, 119-131`.

Rule 1 fires on JSON keys literally named `votes`, `hand`, `hands`, `shield`, or the substring `spent_rho`. Those are the sim's `Ballot` and `Shield` field names. A real component that serializes a vote vector under any other name, as CBOR, or as bytes, passes. Identity detection is a fixed `prefix + 16 hex` scan; real nullifiers are 32 random bytes and real credentials are BBS proofs, so nothing in wave 1 will match. The spec says real tokens "must be registered", but `leak::check` takes only `&[Phone]` and reads three fixed fields; there is no API to register anything. The store fake also records bytes through `from_utf8_lossy`, which mangles binary secrets before the scan.

Fix: specify a registry: `Secrets::register(kind, bytes)` per phone, with kinds {resident card, pseudonym, chat key, sealed key, hand canary, device key, author key, author nullifier}. Record tape payloads as raw bytes plus a JSON view. Scan each record for every registered value in raw, hex and base64url forms. Keep the key-name rule as a second, weaker net. Make the hand canary `storage.md` §10 asks for an actual registered secret seeded into each hand.

### S2. "Agents never vote" and "no double counting" are checked by string prefix, not membership

Section "Protocol checks", rows "Agents never vote" and "No double counting"; `sim/src/fakes/aggregator.rs:142-144`; `sim/src/scenario.rs:539-552, 757-781`.

The fake aggregator accepts any ballot whose pseudonym starts with `vp_`. The full-ratchet agent ballot is refused only because it uses the string `agent:facilitator`. The malicious-agent hook shows the gap: a forged `vp_deadbeefdeadbeef` is accepted and counted, and the spec reports that as "wave 1 identity's membership check". The spec table nonetheless says "a ballot without a member's pseudonym is refused".

Fix: the fake aggregator holds the admitted set per context (today it lives in `FakeVerifier`) and refuses a ballot whose nullifier was not admitted. Then the forged ballot is refused today, the table is true, and W1-02 inherits a check instead of a hole. Rewrite the two table rows to say what is actually checked.

### S3. The fake decides the release tier from the raw ballot count, not the noised one

Section "Assumptions made in wave 0", third bullet; `sim/src/fakes/aggregator.rs:187-213`.

In `Tiering::Gated` the parts list is chosen by `m.n()`, the exact number of ballots. `release.md` ("What the aggregators compute between rounds", R6) gates every tier on `nHat` or on a part's own noised total, and `deck.md` gates the map under `absorb` on the daily count's noised total. Which parts appear is a published fact, so deciding it from the raw count is a non-private output. The fake is also "the oracle every real release is judged against", so W1-03 would be compared against a release whose tiering rule differs from the spec.

Fix: decide tiers from `n_hat` after drawing the tallies noise, exactly as R6 says, and state that rule in the spec. Keep `Tiering::Research` as it is and label it "not a conforming release".

### S4. The fake's public tallies blend in the group tallies; `release.md` says not to

Section "The research baseline and metrics"; `sim/src/pipeline/dp.rs:214-234`.

`dp_pipeline` publishes tallies as the inverse-variance combination of the tallies part with the summed group tallies. `release.md`, "Dropouts", says this blend is not done in draft 0.1 because rounds cover different people. The blended tallies have lower error than raw tallies, so every tally gate the fixture was calibrated on is stricter than a conforming release can meet, and the metric-by-metric comparison the W1-03 row promises would fail for the wrong reason.

Fix: add a `blend` switch to the pipeline, off for the oracle a release is judged against, on only when reproducing the research CSV. Recalibrate the synthetic tally gates with the blend off and record both numbers in the threshold table.

### S5. A below-minimum close produces nothing and logs nothing

Section "Protocol checks", row "One release per deck"; `sim/src/fakes/aggregator.rs:223-230`; `sim/src/world.rs:521-538`.

When `n_hat` is below `minVoters` the fake returns an error, no release exists, nothing reaches the ledger, and the "exactly one ledger entry per released deck" oracle skips the deck because `release` is `None`. `release.md` R6 and `services.md` AG-4 say version 1 is still published and logged, final, with `unlocked` empty, so the spend is on the ledger for R14 and shields reconcile. Today the phones were charged and the ledger shows nothing.

Fix: return a release with empty `parts` and `unlocked` and `n_hat` absent, log it, and make the one-entry oracle cover every closed deck, not only released ones. Add this case to the fast suite (a 120-voter deck at ε 4 will land below 100 some seeds; pick one that does).

### S6. Position manifests carry a chat name, and the manifest oracle quietly exempts it

Section "Protocol checks", row "Every manifest verifies" ("no identity token or sealed key in a body"); `sim/src/world.rs:297, 503-508`.

`promote` writes `"author": cn_…` into the position body. `verify_manifests` scans bodies for `rc_`, `vp_` and `sk_` but not `cn_`, so the spec's sentence and the code disagree. Separately, the leak rule says the ledger sees no identity at all, but `services.md` has the log check authorship proofs and keep a per-log nullifier set for `hum/author-once/1` and `hum/author-slot/1`. The moment W1-01 or W1-07 routes a position through the `Ledger` port with authorship, either the rule fires on legitimate traffic or someone widens it ad hoc.

Fix: add two identity classes, author key and author nullifier, with the log as their only allowed service, and a rule that an author nullifier and a voting pseudonym never share a record. Say in the manifest-oracle row which classes a body may carry (none for `rc_`, `vp_`, `sk_`; an author key only in the authorship side-structure, never in the body). Change the code or the sentence so they agree.

### S7. Thresholds: no reference at ε 1, and the synthetic tally gate ignores ε

Section "Thresholds"; "The two suites"; `sim/src/thresholds.rs:166-170, 204-221`.

`e2.csv` has no ε 1 rows (checked: zero matches for `,1,` in the eps column). For a Polis replay at ε 1, `reference_for` returns nothing, `gates_for` returns an empty list, and the scenario passes with no gate applied and status `Pass`, not `Pending`. The synthetic tally thresholds (25, 16, 12 pp) are applied at every ε including 1 and 2, though the table says "calibrated ε ≤ 4". ADR 0091 says `sim full` on the fixture passes at every ε; that is plausible only if the fixture is far easier than Polis at ε 1, and the measured values are not recorded. Also, the Polis ARI gate becomes `max(0, mean − 0.45)` = 0 at ε 2, and ARI can be negative (the CSV has −0.018), so a mean just under zero fails a gate that was meant to be vacuous.

Fix: drop ε 1 from the Polis sweep or mark it "no reference, no gate" with status `Pending`; scale the synthetic tally gate with σ or give the table one row per ε; skip a gate whose threshold clamps to zero instead of applying it; record the measured full-suite values per ε in the ADR when they are next run.

### S8. The nightly never sees Polis data, so the research comparison is never automated

Section "The two suites"; "Conformance"; `.github/workflows/ci.yml:49-59`.

The nightly job runs `just sim-full` with no `HUM_POLIS_DATA` and no checkout step, so it runs the fixture only. The prompt's "done when" asks for metrics within the research range; the spec's evidence is one manual `vtaiwan.uberx` run with three seeds. That run is not reproduced anywhere.

Fix: have the nightly clone `compdemocracy/openData` at depth 1 into a cached directory and set `HUM_POLIS_DATA`, and say in the spec that the fixture is the merge gate and the nightly Polis replay is the evidence. This is W1-13's wiring, but the spec should state the requirement.

### S9. The leak checker's self-test covers four of six rules

Section "Leak checks" ("The checker's own tests inject one leak of each kind and assert each is caught"); `sim/src/leak.rs:212-233`.

`shield-left-phone` and `unknown-identity-token` have no unit test. The latter is exercised only by the malicious-agent scenario.

Fix: add the two cases, and make the sentence a conformance rule: every leak rule has one failing fixture in `leak.rs` tests.

### S10. Nothing stops a workspace crate from depending on `hum-sim` or `rand_distr`

Section "Scope" ("neither may be copied into `core/` or `services/`"); ADR 0090 ("a grep … is a review finding"); `sim/Cargo.toml`; `sim/src/lib.rs`.

`hum-sim` is a library crate that exports `pipeline`, including a floating-point Gaussian sampler, under a workspace name W1-03 will be tempted to reuse as its oracle. Today no crate outside `sim/` references `hum-sim`, `rand_distr`, `fake_hash` or `Normal::new` (checked by grep across the repo excluding `sim/`), but the only guard is a reviewer remembering to look.

Fix: add a check to `just check` (a script in `tools/`) that fails if any `Cargo.toml` outside `sim/` names `hum-sim` or `rand_distr`, or any file outside `sim/` contains `fake_hash`. Say in the spec that W1-03 compares against the oracle by running the simulator, not by linking it. Also fix the stale ADR number in `sim/Cargo.toml:17` (`0002` should be `0090`).

### S11. Federation is not modelled and the plug-in table does not ask for it

Section "Sim-side object shapes"; "How wave 1 plugs in"; `sim/src/world.rs:157-163, 412-414`.

The context body has no `aggregators`, `logs` or `stores`; services are labels (`aggregator-leader`, `authority/sponsor`). Invariant 6 (clients accept only what a manifest names by key) is therefore untestable, and no row in the plug-in table asks anyone to make it testable.

Fix: add to the W1-01 row that the context manifest names each service by authority CID and the world routes only to named services; add an adversarial hook "unnamed service": a release signed by an aggregator the context does not name must be refused by phones and the ledger.

## Notes

- **N1. Determinism claim.** "Byte for byte apart from timings" (Architecture). `protocol_checks` iterates a `HashMap` of decks and the leak checker a `HashMap` of seen kinds, so violation order can vary between runs. Use `BTreeMap` or sort violations before writing the report.
- **N2. Churn does not model leaving or round dropouts.** The "leavers" simply do not vote; there is no removal event, no re-keying, no second round of one deck. The spec says post-close rounds are not modelled, but the scenario table still says "leave" and the `Kind::Churn` doc comment says "dropouts between rounds". Say "do not vote" and "a second deck" until W1-03 and W1-05 land.
- **N3. Over-collecting verifier hook is a world-side flag.** `World::join` returns before calling the verifier, so the verifier is never exercised. Fine as `Pending`, but the table cell "Every phone refuses to present" reads as a check of something. Say "the world refuses; nothing is tested yet".
- **N4. Unlisted fakes.** The status table omits that parts 4 to 7 (count, movement, ratings, breakdown), rating decks, `absorb`, `covScale` integer vectors, and the cap applied on the phone are not modelled. Add them to the "What is not modelled" row so W1-03 sees the full list.
- **N5. Floors shape.** `Floors` puts `yearly_shield_rho` in the context body; `context.md` says the yearly shield is not a context field, and omits `rhoYear` and `minWitnesses`. The table says "same values". Say "same values for the four fields both have; the sim adds the shield for convenience".
- **N6. Rule IDs drift.** The spec cites `services.md` rules by number (V-2 to V-4, RS-1, RS-2, G-1, O-3, O-4). `services.md` changed between my two reads (AG-8 appeared). Cite by ID and add a `tools/` check that every ID the simulator spec names exists in the services spec.
- **N7. Two time budgets.** "Under 60 s" (suites) and "under about 15 minutes with caching" (W1-13 row) are both called the fast budget. Say which is the binary and which is the CI job.
- **N8. Metric table.** It says `tally_within5pp` gates the tallies tier; only `tally_median_pp` does. Also `k_match` and `pca_affinity` are reported but never gated; say so.
- **N9. Tokens derived from CIDs.** The fake store token is `pp_` + hash(CID), so the same blob always carries the same token. Fine for a fake, but the leak checker has no rule for T-1 (single use) or for a token that is a function of content. Add a note for W1-06.
- **N10. Prompt deviation is documented.** The prompt's "done when" asks for a Polis replay in `sim-fast`; the spec runs the fixture and defers Polis to nightly (ADR 0091). That is the right call for an offline merge gate, and the ADR says why. It is listed here so the owner sees it.
- **N11. The research reference table matches the CSV where I checked.** The 40 rows at 800 voters and ε 4 average ARI 0.606, tally error 12.29 pp, with per-run ARI from 0.12 to 0.90, which is what `thresholds.rs` and the spec say. The vtaiwan-only numbers in the spec also match.

## Checklist coverage

1. **Invariants.** B1 (verifier allowed to see pseudonyms), S2 (prefix-only membership), S6 (chat name in a manifest body, author identities missing from the model). No sealed key reaches a manifest, a log line or a store request in the wave 0 flows I traced; the `sk_` rule would catch the sim's own tokens but not real keys (S1).
2. **Floors.** Enforced at phone, aggregator and ledger in the fake flows; `Floors::allows` only tightens. S3 (tier from raw count) and S5 (unlogged below-minimum spend) are the floor-adjacent gaps.
3. **Sums.** Every `Release` field is a sum or post-processing of sums. S4: the tallies blend is post-processing the spec forbids.
4. **Federation.** S11.
5. **Consistency.** S6, S7, N5, N6, N7, N8.
6. **Implementability.** The spec is a harness spec, so the usual two-implementer question becomes: can two workstreams plug in without producing different leak results? B2 and S1 are where they would.
7. **Testability.** No W0-08 vectors are expected for a harness. S9 for the leak checker's own tests; S5 for a missing fast-suite case.

## What is good and should stay

The tape as the single record of what services saw; one trait per service with the fake and the trait extended together; phones computing their own groups from published axes so the oracle never uses the aggregator's labels; the empty-tape rule; gates per source and tier with the slack explained from the CSV's own spread; the research pipeline ported with unit tests pinning accounting, σ and the noiseless agreement; the honest assumptions list; the fixture's exposure skew and the story of how it was found.

---

## Re-review (2026-10-06, after the author's fixes)

Checked against the current `docs/specs/simulator.md` and `sim/src/{leak,ports,world,phone,scenario,thresholds}.rs`, `sim/src/fakes/{aggregator,identity,ledger}.rs`, `sim/src/pipeline/dp.rs`, `sim/tests/isolation.rs`, `sim/Cargo.toml`. I read the code, not the author's summary. I still did not run the simulator, so the measured values in the spec's threshold table (12.5 pp, 11.4 pp, ARI 0.73 and the vtaiwan rerun) are unverified.

### Verdict: approve

Both blockers are fixed in code and in the spec. Of the should-fix items, S1 to S7, S9 and S10 are fixed; S8 and S11 are filed as open questions with an owner, which is acceptable for a wave 0 harness. No remaining blocker.

### Blockers

- **B1 fixed.** `ports.rs` has no `Verifier` trait and `fakes/identity.rs` has no `FakeVerifier`. A `Ballot` carries `presentation` and `pseudonym`; `FakeAggregator::submit` calls `PresentationVerifier::verify(context, presentation, nullifier)` before counting (`fakes/aggregator.rs:160-167`). `leak::ALLOWED` is exactly aggregator → pseudonym; ledger → chat key, author nullifier; delivery → device key; issuer and store → nothing, and `NEVER_TOGETHER` forbids author nullifier or chat key beside a pseudonym. That matches `design.md`'s who-sees-what table and the spec's new allow table, and the spec now says the earlier verifier was wrong. The world test `a_forged_or_cardless_ballot_is_refused` covers a forged nullifier and a real nullifier with another phone's presentation.
- **B2 fixed.** `World::called(port)` runs before every port call I could find (enroll, join, add_agent, put_public, send, deal, vote, submit_raw, close). `leak::check` takes the counts and emits `port-not-taped` for any called port with zero records; `passed()` treats it as a violation. Unit test `a_called_port_with_no_records_fails` asserts both the failure and the pass once the count is dropped. The report carries records and calls per service.

### Should-fix items

- **S1 fixed.** `Secrets::register(phone, kind, bytes)` with seven kinds; values under 8 bytes refused; each value indexed in raw, lowercase-hex and base64url forms; `Record.raw` holds bytes and `Tape::see_bytes` records binary payloads. `an_empty_registry_fails` and the hex/base64url test exist. The hand canary is a real per-phone secret inside `Hand` and is registered at enroll.
- **S2 fixed.** See B1. The malicious-agent hook now requires both the forged and the replayed ballot to be refused and the ballot count to stay zero.
- **S3 fixed.** `dp_pipeline` compares `map_gate` and `common_gate` against `n_hat_raw` (`dp.rs:108-118`) and returns a tallies-only analysis when locked; the aggregator sets the gates only under `Tiering::Gated`. `Research` is labelled non-conforming in both code and spec.
- **S4 fixed.** `DpParams::blend` defaults to false; the inverse-variance combination runs only when it is true. The synthetic gates were re-set (32/20/14 pp) and the spec says they were calibrated with the blend off.
- **S5 fixed.** Below the minimum the aggregator returns a release with `n_hat: None`, empty `parts`, `rho` equal to the tallies share; the ledger accepts it only when no tables are present; `protocol_checks` requires one ledger entry per closed deck; a `below-minimum-40` scenario is in both suites and reports pending when noise lifts the count over 100.
- **S6 fixed.** The chat key is the position's `authority`, not a body field; `verify_manifests` rejects `rc_`, `vp_`, `cn_`, `sk_`, `hc_`, `an_` in any body and a chat-key authority on any type but `position`. Author nullifiers are a registered class allowed only at the ledger.
- **S7 fixed.** ε 1 is out of both suites; `gates_for` returns `None` for a pair with no reference and the scenario goes pending; a Polis floor gate that would clamp to zero is skipped; the synthetic tally gate scales with √(ρ₄/ρ_ε) and the ranking gates apply only from ε 4 up.
- **S8 filed** as an open question for W1-13. The nightly still runs without Polis data.
- **S9 fixed.** One failing fixture per rule, nine tests, including the two that were missing.
- **S10 fixed.** `sim/tests/isolation.rs` walks the workspace outside `sim/`, asserts it found manifests (so the check cannot pass on zero subjects), and fails on `hum-sim` or `rand_distr` in any `Cargo.toml` or `fake_hash` or `hum_sim::` in source. The ADR number in `sim/Cargo.toml:17` now reads 0090.
- **S11 filed** as an open question for W1-01 and W2-01, with the "unnamed service" hook written into the W1-01 row.

### New notes from the re-review (none blocking)

- **R1. Base64url scan misses two of three alignments.** `Secrets` indexes `base64url(value)` as a substring. When a secret sits inside a larger byte string that is base64-encoded as a whole, its encoding depends on its byte offset mod 3, so only one of the three possible encodings is searched. Fix: also register the encodings of `[0] ‖ value` and `[0, 0] ‖ value` with the first 2 or 3 characters dropped, and uppercase hex. Small change in `leak.rs:122`; the spec sentence "in raw, lowercase-hex and base64url forms" can stay once that is done.
- **R2. The fake scheme's shared state is an off-tape channel.** `SchemeState.issued` holds every card (not "the set of signatures", as the spec's "Identities" paragraph says), and `SchemeVerifier` recomputes nullifiers from cards, so in memory the fake aggregator can map a nullifier back to a card. Nothing writes that to the tape, and the spec says the scheme gives information flow only. Two small fixes: say "the set of cards it issued, standing in for the issuer public key" in the spec, and add to the W1-02 row that the real `PresentationVerifier` must be constructible from public key material alone, with no shared state with the issuer.
- **R3. Research-mode replays at 100 voters score an unpublished analysis.** With σ for the participant count near 28 at ε 4, about half the seeds at size 100 land below `minVoters`, the release publishes nothing, and `run_replay` still compares `last_analysis` with the baseline. That is consistent with "not a conforming release" but worth one sentence in the Polis replay row so nobody reads a size-100 tally gate as evidence about a published release.
- **R4. `unknown-identity-token` is prefix-based by design.** It can only flag sim-shaped forgeries; a real forged 32-byte nullifier would be caught by the aggregator's presentation check, not by this rule. The spec's rule table should say "simulator tokens only" so W1-02 does not count on it.
