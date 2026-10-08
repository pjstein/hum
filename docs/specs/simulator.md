# Hum Simulator Spec — Draft 0.1

Oct 6, 2026 · W0-09

## Scope

The simulator is the project's main test. It is a headless world of simulated phones that runs the whole ratchet (chat → issue map → deck → release → chat) through the real core crates and services, in-process, and judges every run three ways: against the non-private research baseline, against the protocol rules the specs give it, and against a search of everything every service saw for anything it must never see.

This spec defines the architecture, the scenarios, the oracles, the leak checks, the two modes and their reports, the thresholds, the data, and how each wave 1 workstream replaces a fake with its real component. Wave 0 ships the skeleton in `sim/` as described here. Wave 1 workstreams plug in; wave 2 (`W2-01`) removes the last fakes and owns the full-ratchet scenarios after that.

What the simulator is not: it is not a conformance suite (that is `reference/` and `vectors/`, W0-08), and nothing in `sim/` is product code. Its fakes use floating-point noise and a non-cryptographic hash, both labelled, and neither may be copied into `core/` or `services/`.

## Status of this draft

| Piece | Wave 0 state |
| --- | --- |
| Scenario loading, fast and full suites, report writer | Done |
| Simulated phones (three identities, per-deck nullifiers, hand, shield state machine, floors, restore from backup) | Done, as data structures |
| Ports for aggregator, ledger, issuer, delivery, blob store | Done; one trait each, see below. There is no verifier service port: presentations are verified by the aggregator with the issuer's public key material |
| Fakes behind every port | Done, including a fake aggregator that is a port of the research pipeline and a fake credential scheme that refuses any presentation not backed by an issued card |
| Polis loader and the seeded synthetic fixture | Done |
| Research metrics and the churn floor | Done; validated against the research CSVs on real data (see Thresholds) |
| Protocol oracles (manifests verify, floors, one release per deck, below-minimum releases logged, shield, ledger chain) | Done structurally, on the sim's own manifest shapes |
| Leak checker over the tape, with a secrets registry and per-port vacuity | Done |
| Adversarial hooks | Switches wired, each with a minimal detection check; wave 2 fills the attacks |
| Post-close rounds (release stages 1–4), round dropouts, receipts, the daily count (part 4), movement (5), ratings (6), breakdown (7), rating decks, `absorb`, `covScale` integer vectors, the cap applied on the phone | Not modelled; the fake aggregator computes the four research parts in one close with the cap applied centrally. See "How wave 1 plugs in", aggregation |
| Real manifests, CIDs, signatures, log proofs; services named by key in the context (invariant 6) | Not modelled; structural checks only. See Open questions |

## Architecture

One Rust binary, `hum-sim` (`sim/`), in the workspace with the core crates and services. `just sim-fast` and `just sim-full` run it.

```
                 ┌──────────── World ────────────┐
   scenario ───► │ phones[]   contexts  decks     │ ──► report (JSON + text)
                 │     │                          │
                 │     ▼ ports (traits), calls counted per port
                 │ Aggregator Ledger Issuer       │
                 │ Delivery BlobStore             │
                 │     │                          │
                 │     ▼ every call is recorded   │
                 │   Tape + Secrets ──► leak checker
                 └────────────────────────────────┘
```

- **World** (`sim/src/world.rs`) holds the phones, the contexts, the decks, every manifest it produced, the plaintext side of chat (what members see), the secrets registry, and the services. It drives the flows: enroll, join, add an agent, post, promote, deal, vote, close. It is the only caller of a port and counts every call per port. After a run it executes the protocol oracles and the leak checker.
- **Phones** (`sim/src/phone.rs`) are data structures. Each holds a secret, a resident card, a chat name, one voting pseudonym per deck (`ballot.md`: scope `hum/ballot/1` ‖ the deck lineage CID), one hand per deck (the first K cards cast in the phone's own deal order, plus a canary secret), a shield, its floors, and a device generation. Checking a deck reserves the plan's ρ on the shield; building the ballot marks the entry pending; a receipt marks it charged; a reservation drops only if nothing was ever sent (`shield.md` S3–S10). After a release the phone places itself on the published axes and picks its group locally. Draft 0.1 has one voting device and no transfer of a hand or a shield: a device change is a restore from backup that loses every hand and rebuilds the shield as an upper bound, with an estimated entry for every deck of every context the phone joined.
- **Ports** (`sim/src/ports.rs`) are the traits services are called through, plus the sim-side object shapes that cross them. Every production service is behind exactly one trait. The world never reaches around a port. There is no verifier port: a presentation is generated on the phone and checked by whoever receives it, with the issuer's public key material (`PresentationVerifier`, implemented by the credential scheme, not by a service).
- **Fakes** (`sim/src/fakes/`) implement the ports in wave 0. Each enforces what an honest service of its kind enforces, and each writes everything it sees to the tape before acting on it.
- **The tape** (`Tape` in `ports.rs`) is an ordered list of `(service, operation, JSON view, raw bytes)`. It is the simulator's record of what every service saw, and the input to the leak checker.
- **The pipeline port** (`sim/src/pipeline/`) is a Rust port of `docs/research/dp-polis/polis_dp.py`: accounting, the non-private baseline, the DP pipeline, noise-aware rankings and the comparison metrics. The fake aggregator calls it. It is also the oracle every real release is judged against.
- **Data** (`sim/src/data/`): the vote matrix, the Polis loader and the synthetic fixture.
- **Scenarios, thresholds, report, CLI** (`scenario.rs`, `thresholds.rs`, `report.rs`, `cli.rs`).

Everything is seeded. The same scenario with the same seed produces the same report, byte for byte apart from timings.

### Sim-side object shapes

The simulator's `Manifest`, `ReleasePlan`, `Ballot` and `Release` are simplified shapes modelled on the specs' JSON views. They let the oracles check structure now. They are replaced by the real types when `hum-manifest`, `hum-ballot` and `hum-release` land (wave 1). Known simplifications:

| Sim shape | Spec | Difference |
| --- | --- | --- |
| `Manifest { type, authority, version, prev, refs, body }` with a `fakecid_` id | `manifest.md` | No CBOR, no signatures, no log proofs, no `lineage`, `issued` or `expires`. The CID is FNV-1a over canonical JSON and proves nothing |
| `ReleasePlan { rho, delta, parts: [names], cap, statements }` under body key `plan` | `deck.md`, "The release plan" | Parts are names, not ids with per-part ρ; no `minVoters`, `absorb`, `gates`, `covStatements`, `grid`, `blur`, `roundWindow`. The fake aggregator uses the research default split and the context's `minVoters` |
| `Ballot { deck, pseudonym, presentation, votes: full-length vector }` | `ballot.md` (W0-02) | The credential is the ballot (presentation plus per-deck nullifier), as `services.md` says; the phone keeps its first K cards cast and the aggregator refuses a ballot with more than K votes. One nullifier per presentation; no receipt leaf; no 48 KiB padding |
| `Release { deck, rho, delta, n_hat: Option, parts (= unlocked), tallies, sigmas, axes, group_tallies, rep, cons, signers }` | `release.md` | One version, not four stages; `n_hat` is raw and absent when nothing unlocked (R6); `rho` is what was spent; no `receipts`, `assurance`, `sealed`, Parquet tables, or `groupsK` as such |
| `Floors { max_rho, max_delta, min_voters, releases_per_deck, yearly_shield_rho }` | `context.md`, "Protocol constants" | Same values for the four fields both have; the sim adds the yearly shield here for convenience, though `context.md` keeps it off the context; `rhoYear` and `minWitnesses` not modelled |

### Identities and the fake credential flow

Identities are tokens with prefixes for readability: `rc_` resident card, `vp_` per-deck pseudonym (nullifier, scope `hum/ballot/1` ‖ the deck lineage CID), `cn_` chat name, `dk_` device key, `hc_` hand canary, `sk_` sealed-blob key, `blind_` blinded issuance request, `zk_` presentation, `ct_` ciphertext, `pp_` store token. The leak checker does not rely on the prefixes: every secret is registered with it by value (see Leak checks).

The fake credential scheme (`sim/src/fakes/identity.rs`): the issuer signs a blinded request and records only that request on the tape; the phone derives its card from the signature and its secret; for a context it derives a nullifier from the card and a presentation bound to that nullifier. Verification uses the issuer's key material, which in the fake is the set of signatures it issued, so a presentation with no issued card behind it (a forged nullifier, an agent) or a nullifier paired with someone else's presentation is refused. The scheme gives the information flow and the check structure, not unforgeability or unlinkability; `hum-cred` replaces it.

## Scenarios

A scenario is a source of votes plus a kind. Sources are the synthetic fixture (by generator seed) or one Polis conversation directory. Kinds:

| Kind | What it does | Parameters |
| --- | --- | --- |
| **Polis replay** | Sizes a conversation to `n` participants (Polis: uniform subsample, only when `n` ≤ 0.85 × the conversation, as the research did), runs the non-private baseline, then for each seed enrolls `n` phones, creates a context at protocol floors, joins them all, deals a deck with one card per statement and the research plan (all four parts, cap 60), has every phone vote its row, closes, logs, and compares the release with the baseline. Phones compute their own groups from the published axes; the comparison uses those, never the aggregator's internal labels. A (size, ε) pair with no gate is not run and is reported pending | `size` ∈ {100, 300, 800, 1,600, 5,000}, `eps` ∈ {2, 4, 8, 16}, `seeds` |
| **Full ratchet** | A context with a shared agent (a visible membership event): members chat, one attaches a sealed file, three messages are promoted to positions (text in public blobs, manifests pin them, the author's chat key signs), a 20-card deck is dealt under the design's size gates, everyone votes, the agent tries to vote with a forged presentation and is refused, the deck closes, the release is logged and the agent posts the digest | `size` |
| **Churn** | One deck: 70% vote, 10% of those restore from a backup onto a new device after voting (hand lost, shield rebuilt as an upper bound, the counted ballot stands) and re-vote, which derives the same per-deck nullifier and replaces rather than adds; 10% do not vote; 10% join late and vote; the rest vote. A second deck: 20% drop out between releases. Checks ballot counts, that a restore never double counts, that a restored phone carries exactly one shield entry per deck, and that two decks put exactly 2 × 0.254 on a shield. Leaving a context (removal, re-keying) and post-close round dropouts are not modelled until W1-05 and W1-03 land | `size` |
| **Below minimum** | A 40-member context deals a deck at ε 4 and closes. The noised count lands below 100, the release is still published and logged, final, with nothing unlocked and no tables, and the tallies part's ρ is on the ledger (`release.md` R6, services AG-4). When noise lifts the count above the minimum for a seed the scenario reports pending rather than passing vacuously | `size` |
| **Adversarial** | One hook per run with its wave 0 minimal check (table below) | `hook` |

Above the protocol floor (ε > 4, ρ > 0.254) a replay cannot go through phones, because honest phones refuse the deck. Those runs go through the pipeline alone and the report marks them `through_world: false`. They exist to compare with the research at ε 8 and 16.

### Adversarial hooks

| Hook | Switch | Wave 0 check | Wave 2 fills |
| --- | --- | --- | --- |
| Lying log | `FakeLedger::lying` rewrites an entry after appending | `Ledger::verify` reports the rewrite | Equivocation between two readers; phones' checkpoint exchange in channels catches it (`manifest.md`, Transparency logs) |
| Modified client | `Phone::modified` skips the phone's floor check | The aggregator still refuses a plan above the floor | A client that forges ballots, replays, or votes under a loosened plan; AG-1 to AG-8 |
| Over-collecting verifier | `FakeIssuer::over_collects` | The world refuses to apply on every phone's behalf; nothing is tested yet | A verifier module that asks beyond its manifest (`verifier-runtime.md`); V-1 to V-3 |
| Malicious agent | A ballot with a forged nullifier and presentation, then a member's nullifier with the agent's presentation | Both refused by the aggregator's presentation check; the forged token is flagged by the leak checker as no phone's | Floods, prompt injection into promotions, an agent that tries every path to a ballot (`agent-sponsor.md`) |

### The two suites

| Suite | Scenarios | Budget |
| --- | --- | --- |
| `sim fast` (`just sim-fast`, every commit) | Synthetic replay at 300 and 800, ε 4, 2 seeds each; full ratchet at 300; churn at 300; below minimum at 40; the four adversarial hooks | The binary runs in under 60 s: measured 3.9 s on 2026-10-06 (debug profile, Apple Silicon). The CI job around it (checkout, cache, build) is W1-13's 15-minute budget |
| `sim full` (`just sim-full`, nightly) | Two synthetic fixtures × sizes {100, 300, 800, 1,600, 5,000} × ε {2, 4, 8, 16} × 5 seeds; full ratchet, churn and below minimum; with `--polis DIR` or `$HUM_POLIS_DATA`, the four research conversations at the same sizes and ε (pairs a conversation cannot supply, or that have no research reference, are reported pending); the adversarial hooks | No budget. A pass with Polis data was measured at about 5 s per scenario on 2026-10-06, so roughly 15 minutes for the whole suite |

`sim replay --size N --eps E --seeds K [--polis DIR --conversation NAME]` runs one replay. `sim fixture --out DIR` writes the synthetic fixture in the Polis layout.

## Oracles

### The research baseline and metrics

The non-private baseline and the metrics are those of `polis_dp.py`, ported one to one (`sim/src/pipeline/`). For each release the simulator reports:

| Metric | Meaning | Tier it gates |
| --- | --- | --- |
| `tally_median_pp` | Median agree-share error against exact counts, in percentage points, over statements with ≥ 10 votes | gated: tallies (100) |
| `tally_within5pp`, `tally_err_{10,50,200,1000}` | Share within 5 pp, and the median error by vote-count bin | reported only |
| `consensus_relaxed` | Share of the release's top-5 common-ground statements in the baseline's top 15 | gated: common ground (300) |
| `consensus_overlap` | The same against the baseline's top 5 | reported only |
| `ari` | Agreement of phone-side groups with the baseline's (adjusted Rand index) | gated: map and groups (800) |
| `repness_relaxed` | Per matched group, share of the top-5 representative statements in the baseline's top 15 | gated: map and groups (800) |
| `repness_overlap`, `k_match`, `pca_affinity` | The strict version, same number of groups, affinity of the two principal subspaces | reported only |

The oracle publishes the tallies part alone. The research code blended the summed group tallies into the public tallies by inverse variance; `release.md` ("Dropouts") forbids that in draft 0.1, so the pipeline has a `blend` switch that is off for every release the simulator judges and on only when reproducing the research CSVs. The tier a release reaches is decided from the noised count, never the raw ballot count (`release.md` R6); `Tiering::Research` computes every part at every size and is not a conforming release.

Alongside each replay the report prints the no-DP churn floor (the baseline rerun with a random 10% of participants missing) and the research rows for that size and ε, so a reader sees the three numbers side by side.

The port was checked two ways on 2026-10-06. Unit tests pin the accounting (ε 4 ↔ ρ 0.254, four releases compose to ε 8.5), the blur's noise factor against SciPy, the eigensolvers against each other, and that the noiseless pipeline agrees with the baseline on the fixture. A replay of `vtaiwan.uberx` at 800 voters and ε 4 with 3 seeds, blend off, through phones and the fake services, gave ARI 0.36 (0.16–0.57), tally error 6.3 pp, representative overlap 0.57, common-ground overlap 0.93 and PCA affinity 0.78; the research's 10 runs on the same conversation and size, blend on, gave ARI 0.53 (0.21–0.90), 4.4 pp, 0.77, 0.78 and 0.78. Every number is inside the research's per-run range, the tally error is higher because the blend is off, and the ARI mean is on its low side with 3 seeds.

### Protocol checks

After every scenario the world runs these and lists each failure as a violation:

| Check | Source rule | Wave 0 implementation |
| --- | --- | --- |
| Every manifest verifies | `manifest.md` steps 1–11 | Structural: known type, version/prev consistent, every ref resolves, deck plan within the pinned context's floors, release pins a deck. A body may carry no identity class, no hand canary and no sealed key; a chat key appears only as a position's `authority` (its signer), never in a body and never on any other type |
| Every release respects the floors | `context.md` C3, `deck.md` D10, `release.md` R4, R6 | ρ spent ≤ the plan and ≤ `RHO_MAX`, δ ≤ `DELTA_MAX`; tables only when `n_hat` ≥ `minVoters`; `n_hat` absent exactly when nothing unlocked; declared cap |
| One release per deck, every deck released | `release.md` R6, R10; services AG-4 | Aggregator refuses a second close; ledger refuses a second entry; exactly one ledger entry per closed deck, including decks that closed below the minimum |
| The ledger chains | `manifest.md` Transparency logs; services LG-1, LG-3 | Fake hash chain verifies end to end |
| No shield overspends | `shield.md` (W0-02) | Each voter charged exactly the plan's ρ once per deck; no phone above `SHIELD_YEAR` |
| No double counting | services AG-2; `ballot.md` replacement | One counted ballot per nullifier per deck: a different body under a known nullifier before close replaces the earlier one, an identical resubmission is idempotent, and a restored device derives the same nullifier |
| No shield refund after a send | `shield.md` S5–S7 | Every voter's entry for a closed deck is charged or estimated at the plan's ρ, never pending or missing; a reservation can drop only while nothing was sent |
| Only members vote; agents never vote | services ballot intake check 4; `CLAUDE.md` invariant 7 | The aggregator verifies every ballot's presentation against the nullifier with the issuer's key material and refuses a forged nullifier, a nullifier paired with another phone's presentation, and any ballot from an agent (which has no card); adding the agent was a membership event; the digest is labelled |

The services spec names the rules the simulator tests: LG-1 to LG-8, AG-1 to AG-8, V-1 to V-3, RS-1, RS-2, G-1, O-3 to O-5, and the logging table. Wave 0 covers AG-2, AG-3, AG-4, the presentation check of ballot intake check 4 and a structural LG-3; the rest wait for the real components (see the plug-in table). Rule IDs drift as the services spec changes; W1-13 should add a check that every ID named here exists there.

### Leak checks

The leak checker (`sim/src/leak.rs`) reads the tape, a secrets registry and the world's per-port call counts.

**The registry.** Every secret is registered by value with `Secrets::register(phone, kind, bytes)`; values under 8 bytes are refused. Kinds: resident card, pseudonym (nullifier), chat key (also the author key of authored objects), sealed key, hand canary, device key, author nullifier. The world registers the sim's own tokens; a wave 1 component registers the real ones (a BBS credential, a 32-byte nullifier, an AES key) at the moment it creates them. Each record's raw bytes are scanned for every registered value in raw, lowercase-hex and base64url forms, so a secret is found however a component serialises it. A second, weaker net looks for the simulator's own field names (`votes`, `hand`, `hands`, `shield`). The hand canary is a per-phone secret seeded into every hand, as `storage.md` §11 asks, and is allowed nowhere.

**The allow table** is derived from `docs/design.md`, "Privacy model and trust", and `services.md`, "What services log". Anything not listed is forbidden. It is the constant `ALLOWED` in `leak.rs`, and the W1-02 plug-in cannot widen it without changing this table:

| Service | Resident card | Pseudonym | Chat key | Sealed key | Hand canary | Device key | Author nullifier | Why |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| aggregator | no | **yes** | no | no | no | no | no | Phase 1 sees pseudonymous ballots |
| ledger (log) | no | no | **yes** | no | no | no | **yes** | Authored objects are signed by the chat key and carry an author nullifier |
| delivery | no | no | no | no | no | **yes** | no | MLS members are visible to the group as device leaves |
| issuer | no | no | no | no | no | no | no | Sees a blinded request and evidence, never a card or a nullifier |
| store | no | no | no | no | no | no | no | Sees ciphertext, a CID and a token |

Two classes may never share a record even where each is allowed on its own: an author nullifier with a pseudonym, and a chat key with a pseudonym.

**Rules:**

| Rule | What it finds | Invariant |
| --- | --- | --- |
| `port-not-taped` | A port the world called that has no tape records: a real component wired without its recording wrapper | the method itself |
| `no-secrets-registered` | An empty registry: nothing could have been found | the method itself |
| `votes-outside-ballot` | A `votes`, `hand` or `hands` key in any record other than a ballot submitted to the aggregator | 1 |
| `shield-left-phone` | A shield in any record | 1 |
| `identities-joined` | Two different identity classes of one phone in one record | 2 |
| `classes-never-together` | A pair from the never-together list in one record, whoever they belong to | 2 |
| `identity-not-allowed-here` | A registered value at a service the table does not allow | 2, 4 |
| `unknown-identity-token` | An identity-shaped token that no phone registered (a forgery) | 2 |

A check passes only when records were scanned, every called port has records, the registry is non-empty, and nothing was found. The report lists calls and records per port. The checker's own tests inject one failing fixture per rule, including a sealed key in hex and a canary in base64url inside raw store bytes; every rule added later needs its fixture in the same test module. This is a conformance rule for `sim/`.

The rules are the services spec's logging table reduced to what wave 0 can see. When the real services land, their log output is appended to the tape under `op = "log"` and the same rules apply; `storage.md`'s canary and put-tag trace and `chat.md`'s ballot-structure scan are the same mechanism with more values registered. The fake store's token is a function of the blob's CID, so the same blob always carries the same token; `storage.md`'s single-use rule (T-1) has no check yet and is W1-06's to add.

## Modes and reports

Every run writes `target/sim/<mode>.json` and prints a text summary. The JSON holds, per scenario: name, kind, source, size, statements, ε, seeds, whether it went through the world, metrics per seed and their mean, the churn floor, the research reference rows, gate outcomes, protocol violations, the leak summary (records and calls per port, secrets registered, violations), notes and wall time. Violations are sorted, so two runs with the same seeds produce the same JSON apart from timings. The run's status is `pass` when no scenario failed; `pending` scenarios (adversarial hooks, skipped sizes) do not fail a run. The exit code is 0 on pass, 2 on fail, 1 on error, so CI needs no parsing.

## Thresholds

Gates apply to the mean over a scenario's seeds, only for tiers the design unlocks at that size (tallies from 100, common ground from 300, map and groups from 800), and are per source. A (size, ε) pair with no gate is not run: the scenario is reported pending, never as a pass. ε 1 has no research reference (the size sweep has no ε 1 rows) and is left out of both suites.

**Polis data:** the research mean for the nearest size at or below `n` (E2 in `docs/research/dp-polis/results/e2.csv`), with slack for seed spread: tally error ≤ 1.5 × mean + 2 pp; common-ground overlap ≥ mean − 0.25; ARI ≥ mean − 0.45; representative overlap ≥ mean − 0.35. A gate whose threshold would clamp to zero is skipped rather than applied, because ARI can be negative. The ARI slack is wide because the research's own per-run ARI at 800 voters and ε 4 ranged from 0.12 to 0.90 around a mean of 0.61. The research tallies were blended; the simulator's are not, which the tally slack absorbs (measured 6.3 pp against a gate of 20.4 on `vtaiwan.uberx` at 800).

**Synthetic fixture (calibrated 2026-10-06, blend off):**

| Size | tally error ≤ (ε 4) | common ground ≥ (ε ≥ 4) | ARI ≥ (ε ≥ 4) | representative ≥ (ε ≥ 4) | Measured in `sim fast`, ε 4 |
| --- | --- | --- | --- | --- | --- |
| 100–299 | 32 pp | — | — | — | — |
| 300–799 | 20 pp | 0.15 | — | — | 11.8 pp, 0.20 |
| 800+ | 14 pp | 0.30 | 0.45 | 0.40 | 9.6 pp, 0.40, 0.52, 0.47 |

The tally gate scales with the noise from its ε 4 value (σ ∝ 1/√ρ: × 1.7 at ε 2, × 0.53 at ε 8, × 0.33 at ε 16). The ranking and group gates apply from ε 4 up, where a larger ε only makes them easier; at ε 2 the fixture, like the research, has no reliable groups and only the tally gate applies. With the blend on and the cap applied by the aggregator, the earlier calibration measured 8.1 pp at 300 and 7.7 pp at 800; the blend is what the research CSVs contain and is off for every release the simulator judges, and the cap is now applied on the phone (first K cards in deal order), which moved the fixture's numbers once more. The common-ground gate below 800 is 0.15 because the research means there are 0.14–0.20.

For comparison the research means at ε 4 are 22.5–17.1 pp and 0.14–0.20 at 200–400 voters, and 12.3 pp, 0.45, 0.61, 0.67 at 800. The fixture is a little easier than real conversations on tallies and about the same on groups and rankings. Its gates are deterministic given the seeds; a change that alters the order in which the pipeline draws random numbers will move the measured values and may need the gates re-read, which is a deliberate tripwire. ADR 0091 says how to recalibrate. The measured values at ε 2, 8 and 16 are to be recorded in the ADR when the nightly next runs.

The research reference table embedded in `thresholds.rs` is the E2 mean per (ε, size) computed from the CSV on 2026-10-06; regenerate it if the research results change.

## Data

**Polis open data** (CC BY 4.0, <https://github.com/compdemocracy/openData>) is not vendored. Fetch it with `git clone --depth 1 https://github.com/compdemocracy/openData DIR` (about 370 MB) and pass `--polis DIR` or set `HUM_POLIS_DATA`. The loader (`sim/src/data/polis.rs`) is a port of the research `load`: it keeps comments with `moderated ≥ 0`, takes the last vote per (comment, voter) by timestamp, drops participants with fewer than 7 votes and statements nobody voted on, and reads Polis' own group per participant from `participants-votes.csv` when present. The four conversations the research's size sweep used are `march-on.operation-marchin-orders`, `austria-climate.9xnndurbfm.2022-07-07`, `american-assembly.bowling-green` and `vtaiwan.uberx`. Credit the data wherever its numbers are shown.

**The synthetic fixture** (`sim/src/data/synthetic.rs`) is generated in memory from a seed, so `just sim-fast` runs offline and the repo carries no data. It has three latent groups of sizes 0.5 / 0.3 / 0.2; 25% consensus statements, 45% divisive (one group agrees with probability 0.85, the others 0.15), 30% noise; a long-tailed vote count per participant (median 45); and a skewed exposure curve (statement `j` is shown with weight `(1 + j)^-1.2`), because in Polis the 60 most-voted statements of a large conversation each carry votes from 40–60% of participants and the covariance part depends on that. Without the skew the covariance had too little signal at any ε, which is how the parameter was found. Statement count grows with size as in the open data (30 + n/5, capped at 400). `sim fixture --out DIR` writes it in the Polis layout so the research Python can read it too.

## How wave 1 plugs in

Each workstream replaces one fake behind one port, registers what the leak checker must know, and gains a set of checks that start running on every commit. The world and the scenarios do not change.

| Workstream | Replaces | Behind | Must register | The simulator then checks |
| --- | --- | --- | --- | --- |
| **W1-01 manifests and logs** | `Manifest`, `Cid`, `fake_hash`; `FakeLedger` | `Ledger`; the sim-side `Manifest` type | Real CIDs; log proofs on every bundle the world hands a phone; author nullifiers of authored objects with `Secrets::register` | Every manifest through `hum-manifest` verification steps 1–11; LG-1 to LG-8; the lying-log hook becomes equivocation between two readers and the phones' consistency check must catch it; the context manifest names each service by authority CID and the world routes only to named services (invariant 6), with a new hook: a release signed by an aggregator the context does not name is refused by phones and the ledger |
| **W1-02 identity** | `FakeIssuer`, the fake credential scheme (`fakes/identity.rs`) and its `PresentationVerifier`, the card/nullifier/presentation derivations in `Phone`, the shield state machine | `Issuer`; `PresentationVerifier` (used by the aggregator, never a service) | Each phone's real card, per-deck nullifiers and shield entries with `Secrets::register`, so the leak checker finds them in any encoding. The allow table does not change: no service but the aggregator may see a nullifier | Unlinkability (the issuer's tape never contains a card or a nullifier, and the aggregator's never a card); V-1 to V-3; the over-collecting-verifier hook runs a real module in the sandbox; the malicious-agent forgery stays refused at the aggregator |
| **W1-03 aggregation** | `FakeAggregator` and the use of `pipeline::dp` inside it | `Aggregator` | Nothing new; the `Aggregator` trait grows round calls | The real `hum-release` with real `hum-ballot` ballots, post-close rounds as release versions 1–4 (`release.md`), round dropouts, receipts, the daily count, the discrete sampler; AG-1 to AG-8; the port in `sim/src/pipeline/` (blend off, tiers from `n_hat`) becomes the oracle the real release is compared with, metric by metric, at every size and ε, by running the simulator and never by linking `hum-sim` (a test in `sim/tests/isolation.rs` fails the build if any crate outside `sim/` depends on `hum-sim` or `rand_distr` or uses `fake_hash`); the two open simulator questions in `deck.md` (IBIS caps and shares; folding the covariance round) |
| **W1-04 publication and open data** | Nothing in `sim/` | `Ledger` (shared with W1-01), the public blob path of `BlobStore` | Which blobs are releases and manifests | The leak check finds nothing but releases and manifests in public storage; a simulator release downloads, verifies with the CLI and exports with its context (G-1, RS-1, RS-2) |
| **W1-05 chat** | `FakeDelivery`, the `seal` function in `World`, the plaintext side of `messages` | `Delivery` | MLS group ids per channel; device keys as MLS leaves | Hundreds of members across channels with joins, removals and device changes; the delivery tape holds only ciphertext, timing and channel tokens; franking reports verify; a removed member reads nothing sent after removal |
| **W1-06 storage** | `FakeBlobStore`, `blob_cid`, the sealed-blob and token fakes | `BlobStore` | Sealed keys, file names and member identifiers as tokens; the hand canary | A file goes chat → folder → map evidence → public copy without a second upload; the store tape has no keys, file names or member identifiers; re-keying on removal; the put-tag trace and the canary of `storage.md` |
| **W1-07 deliberation** | The `promote` flow and `position` manifests in `World` | The sim-side `Manifest` type (issue-map bodies) | Nothing new | Messages become positions with pro and con arguments, are dealt, voted, flipped and re-voted, and come back annotated; members-only text never appears unsealed outside members' phones |
| **W1-08 core and FFI, W1-09 iOS, W1-10 Android** | `Phone` | The phone API `hum-ffi` exposes | Nothing new | The simulator's phone scenarios run through the real core behind the same API the apps use; the fake stays as the apps' early build target |
| **W1-11 studio and gallery** | Nothing in `sim/` | Post-processing of logged releases | Nothing new | Takes built on a simulator release, rated, ranked and reproducible; error bars match the published σ |
| **W1-12 agents** | The `add_agent` and `agent_post` flows | `Delivery` (as a member), the sponsor manifest | The agent's sponsor key as a token | A facilitator proposes positions; a flood hits rate limits; a personal agent sends nothing off the device; no code path lets an agent submit a ballot |
| **W1-13 platform** | Nothing; owns the harness wiring | — | — | `just sim-fast` in CI under about 15 minutes with caching, `just sim-full` nightly, the report archived; the leak checker and the logging-policy lint fed by the services' real log output |

Rules for plugging in:

1. Replace the fake behind the port; do not call the real component from the world directly. If the port is missing something, extend the trait and the fake together in the same change.
2. Everything a real service sees must still reach the tape. The simplest way is a recording wrapper around the real client that calls `Tape::see` before each call, plus the service's own log lines appended with `op = "log"`.
3. Register every new secret with `Secrets::register` at the moment it is created; a value the checker does not know about is a hole, not a pass. Never widen `ALLOWED` in code; change the table in this spec first.
4. Keep `just sim-fast` under 60 s. A component that cannot run its scenario in that budget runs a smaller one in fast and the full one nightly.
5. When a real component disagrees with the fake, the spec decides. File the question in `docs/decisions/` and keep the fake's behavior until it is answered.

## Assumptions made in wave 0

Written against the specs as they stood on 2026-10-06; each is a place a wave 1 workstream may need to adjust the sim shapes.

- `ballot.md` and `shield.md` (W0-02) landed after this draft and the model now follows them: pseudonyms are per deck; the shield runs reserved → pending → charged with no refund after any send and estimated entries after a restore; the counted hand is the first K cards cast in the phone's deal order, never a random subset drawn later; a different ballot body under a known nullifier before close replaces the earlier one. Not yet modelled: issuer epochs (cards are re-issued each issuer epoch, which is `V` 28-day periods, with a new nym secret, so every nullifier changes at an epoch boundary and a ballot's card must be the one of the epoch of the deck's version-1 `closes`); shield entries pinning the full card set, with S11 "never send with other cards" tested across an epoch boundary; S12 (no first round-0 ballot in a context until a local backup lists it); the 48 KiB ballot padding; more than one nullifier per presentation; rounds (so "rounds add no entry" is vacuous); the 365-day window; and `chargedAt`. The fake has one epoch and one card per phone. The scenarios those specs name, `sim-shield-sit-out`, `sim-shield-restore` (with left, closed-unreleased, abandoned and extended-close decks), `sim-shield-never-leaves`, `sim-shield-dropping-leader`, `sim-shield-two-decks`, `sim-ballot-before-proof`, `sim-ballot-off-relay`, `sim-ballot-epoch-boundary` (S11) and `sim-shield-backup-before-vote` (S12), are W1-02's and W1-03's to add behind the same ports; shield entries become a registered secret kind allowed nowhere, and the relay and log-proof checks need the real manifests. The fake's restore and churn scenario cover the core of `sim-shield-restore` today.
- `release.md` defines four stages with three post-close rounds. The fake computes the parts in one close, as the research code does, because it has the whole matrix. The phone-side half of rounds 2 and 3 is modelled: each phone recomputes its projection and group from the published axes and centroids, and the oracle uses those labels. Round dropouts are not modelled.
- `deck.md`'s plan has per-part ρ, `minVoters`, `absorb` and gates. The fake uses the research split (0.15 / 0.35 / 0.15 / 0.35) and the context's `minVoters`. With `Tiering::Gated` (full ratchet, below minimum) the tallies part is noised first and its noised count decides the rest: below `minVoters` nothing unlocks and only the tallies part's ρ is spent; below `GATE_COMMON` tallies only; below `GATE_MAP` tallies and a common-ground ranking computed from the tallies as a single group; otherwise all four parts. The unspent ρ of a locked tier stays unspent (`absorb` is not modelled). Replays use `Tiering::Research`, computing every part at every size, because the research metrics are defined that way; that is not a conforming release.
- `release.md` requires a discrete Gaussian sampler. The fake uses `rand_distr::Normal` on floating point, exactly as the research code does. This is acceptable for an oracle and a fake and is forbidden in `hum-release`.
- `services.md` requires the aggregator to delete ballots after release (AG-5). The fake drops its ballot store on close; the retention clock is not modelled.
- There is no verifier service. Joining a context is phone-side (pseudonym derivation) plus the channel's MLS membership event; membership is proven on each ballot and checked by the aggregator against the issuer's key material. `services.md` says the same; the earlier draft of this spec had a verifier that saw nullifiers, which was wrong.
- `storage.md`'s sealed format and tokens, `chat.md`'s MLS: the fakes carry opaque `ct_`, `sk_` and `pp_` tokens with the right visibility and nothing else.

## Open questions

Filed in `docs/decisions/`:

- **Simulator dependencies and fakes** ([`0090-w0-09-simulator-dependencies.md`](../decisions/0090-w0-09-simulator-dependencies.md)): `rand`, `rand_chacha`, `rand_distr`, `serde`, `serde_json`, `csv`, `anyhow` in `sim/` only; floating-point noise and FNV-1a allowed in fakes and the oracle, never in a seam.
- **Fixture and thresholds** ([`0091-w0-09-fixture-and-thresholds.md`](../decisions/0091-w0-09-fixture-and-thresholds.md)): the synthetic fixture stands in for Polis data in `sim-fast`; Polis data is fetched, not vendored; gates per source as above; how they are recalibrated.

Not yet filed, for the owner or the named workstream:

- **Research-mode replays versus gated releases.** The research metrics need map and groups at every size; the design gates them at 800. The simulator runs replays in research mode so the numbers are comparable with the study. Should `sim-full` also report the gated release's metrics at 300, as a user would see them, so the two can be compared? (W1-03.)
- **Rounds as versions.** The fake collapses `release.md`'s four versions into one. Modelling round dropouts needs a phone that may skip a round; that is a world change W1-03 and W2-01 should agree on before W1-03 starts.
- **Seed spread.** At 800 voters and ε 4 the ARI of one release varies by a factor of five with the noise seed, in the research and here. Gates on a mean over two seeds are therefore loose. Nightly runs use five seeds; fast runs could use the median instead of the mean. (W1-13.)
- **Debug versus release profile.** `just sim-fast` runs the debug profile and finishes in 3 s; the 5,000-voter replay takes about 6 s per seed in debug. If the real crates make fast runs slow, the fix is a profile override in the root `Cargo.toml` for `hum-sim` (owner, since the file is shared), not a smaller scenario.
- **Which real conversations.** The research's size sweep used four conversations and no 5,000-voter run on real data (the largest conversation has 5,310 participants and the 0.85 rule skips it). `sim-full` inherits that; whether to add the full-size E1 replays (every conversation at its real size) is a nightly-budget question. (W1-13.)
- **The nightly never sees Polis data yet.** `.github/workflows/ci.yml` runs `just sim-full` without `HUM_POLIS_DATA`, so the research comparison is a manual run today. The nightly should clone `compdemocracy/openData` at depth 1 into a cached directory and set `HUM_POLIS_DATA`; the fixture is the merge gate and the Polis replay is the evidence. (W1-13.)
- **Services named by key.** The sim's context body has no `aggregators`, `logs` or `stores`; services are labels, so invariant 6 is untestable in wave 0. The W1-01 row now asks for the context to name services by authority CID and for an "unnamed service" hook; the world change should land with the real manifest types. (W1-01, W2-01.)
- **A `tools/` check for simulator isolation.** `sim/tests/isolation.rs` enforces it under `cargo test`; a shell script in `tools/` wired into `just check` would catch it before compiling and is W1-13's to add.

## Conformance

`just sim-fast` is a merge gate (`CLAUDE.md`, "How work flows"). It fails on any gate, protocol violation or leak, and on an empty tape. `just sim-full` runs nightly and archives `target/sim/full.json`. A change that is hard to put under the simulator is a design smell and the summary of that change must say so.
