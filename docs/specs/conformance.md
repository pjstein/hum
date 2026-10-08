# Hum Conformance — Draft 0.1

Oct 7, 2026 · W0-08 · fifth version, after the fifth reference run (sampler option B in `release.md` Noise; owner acceptances of 2026-10-07)

## Scope

This document says how an implementation runs the test vectors in `vectors/`, what "conformant" means for each kind of implementation, how spec rules map onto vector cases, which rules have no vector yet and why, and what the interop milestone is. The vectors come from the Python reference in `reference/` and from nowhere else. `just vectors` regenerates them and `just conformance` fails when the committed files differ from a fresh run.

Status of this version: every spec on disk has a reference module and a vector directory. The reference verifies every manifest type through the eleven steps with each type's step 4 schema, step 6 replacement (authorship, two-signer releases, agent takes) and step 10 rules. What is still missing needs a library the repo has not adopted (BBS with pseudonyms, HPKE, Argon2id, Parquet, a WebAssembly component runtime, an MLS stack, Privacy Pass, Prio3) or an owner decision; every such item is in the gaps table with its reason.

## Vector files

One directory per spec, one JSON file per topic, a list of `cases`. Every case has:

| Field | Meaning |
| --- | --- |
| `id` | `<spec>/<file>/<suffix>-<nnn>`; the suffix is the spec's own vector name where it gives one (`deck-invalid-D4-duplicate-card-cid`, `im-bad-slot-reused`) |
| `description` | What the case shows, for people |
| `section` | The spec section or rule the case tests |
| `inputs` | Everything an implementation needs to reproduce the case |
| `expected` | Outputs an implementation must reproduce (accepting case) |
| `rejection` | What an implementation must refuse: `step` (manifest verification step, or `null`), `rule` (the spec's rule id, when a type rule), and for non-manifest checks a `check` naming the operation; API decisions add `status`, `code`, `detail` and, where the spec fixes it, the exact error `body` |

Exactly one of `expected` and `rejection` is present. Normative in a rejection: `step`, `rule`, `check`, `status`, `code`, `detail`, `body`. Advisory: `reason`. Where a spec names rejection reasons (`storage.md` §1.5, the `detail` strings of `services.md` and `storage.md` §6.7) the vector carries that name and an implementation must report the same one.

A file may carry `notes`: what the file covers, what in it is pending and why, and any reading of the spec the reference had to choose. Notes are part of the record and are quoted in the gaps table below.

Bytes are lowercase hex strings. CBOR data items appear in a JSON form that keeps the CBOR types:

| CBOR | JSON form |
| --- | --- |
| unsigned or negative integer | JSON number |
| text string | JSON string |
| byte string | `{"hex": "…"}` |
| array | JSON array |
| map | `{"map": [[key, value], …]}` in encoded order |
| tag | `{"tag": n, "value": …}` |
| `false`, `true`, `null` | JSON `false`, `true`, `null` |

Floats appear where a spec computes in binary64 (`release.md` "What a phone computes", `take.md` "Noise math", `issue-map.md` annotations, `shield.md` display). They are printed with the shortest round-trip representation. An implementation matches a float when `|a − b| ≤ 1e-9 × max(1, |b|)`; `take.md` and `issue-map.md` say six decimals and their files say so. Integers, lists of integers, rationals (`rat`), σ in micro-units, cells, group indices, rankings and every byte string must match exactly.

Large inputs (plaintexts over 4 KiB, ciphertexts over 8 KiB, a million-leaf receipt page set) are given by a rule and a SHA-256 instead of their bytes; the rule is stated in the case.

### Worlds

Manifest cases resolve references against a shared test world: `manifest/world.json` (the base log, its keysets, witnesses and the first 36 entries), extended by `deck/world.json`, `issue-map/world.json`, `agent-sponsor/world.json`, `verifier/world.json`, `trust-list/world.json`, `services/service-manifests.json` and `take/world.json`. Every world file lists its bundles with envelope, signatures or authorship, CID, log proof and a readable view, and the blobs its refs name. Entries a spec would never log (an invalid version, a fork) were appended by a "misbehaving log" so that phones reach the step the case tests; each world file says which. `take/world.json` re-finalizes the base log, so its checkpoint and proofs differ from the other worlds'; its notes say to resolve base bundles by CID and use the checkpoint it gives.

## Running the vectors

A conformance runner reads every file under `vectors/`, and for each case builds the inputs, runs the operation the file and `section` name, and compares. The runner is written per implementation (Rust core, Go ledger, the Swift and Kotlin bindings); its skeleton:

1. Encoding and hashing: `manifest/cbor`, `manifest/cid`, `log/merkle`, `log/leaves`, `services/leaves`, `storage/cid`.
2. Signatures and notes: `manifest/signature`, `log/checkpoint`, `services/checkpoint`, `services/signed-requests`, `services/aggregator` (receipt signatures), `storage/delete-order`.
3. Worlds: load every world file into the resolver by CID with its proof; load blobs by CID.
4. Manifest verification: for each case in `manifest/verification`, `deck/manifests`, `deck/rating`, `release/manifests`, `release/rating`, `issue-map/objects`, `agent-sponsor/manifests`, `verifier/manifests`, `trust-list/manifests`, `services/service-manifests`, `services/step9-at-log`, `take/manifests`: a fresh verification cache, the phone's state from `context` (`now`, `log_authority`, `log_public`, `witness_keys`, `min_witnesses`, `held_checkpoint`, `for_action`, `global_context`, and `checkpoint_override` when present), verify, compare the outcome. A rejection must name the same step and, at steps 4, 6 and 10, the same rule.
5. Wire formats and decisions: `log/bundle`, `services/bundle`, `services/errors`, `services/witness-protocol`, `services/relay`, `storage/*`, `chat/*`, `ballot/*`, `credentials/*`, `shield/*`.
6. Numbers: `release/*` (math files), `deck/plan-math`, `take/numeric`, `issue-map/derived`, `trust-list/resolution`, `verifier/summary`, `verifier-runtime/*`.

The reference's own runner is its test suite: `uv run --project reference pytest -q reference`.

## What conformant means

**Client (phone core).** Passes every vector a phone runs: all eleven verification steps for every type, proofs and checkpoints, sealing and opening, references, keyring keys, folders, plan and floor checks, shield arithmetic, the round computations, ballot framing and the counted hand, presentation structure, chat content types. Beyond the vectors (simulator checks): a client never writes a vote, a hand, a shield entry or a receipt anywhere but a ballot to an aggregator; never sends a sealed reference, key, keyring secret or delete secret outside an MLS message, a sealed blob or a delete request; refuses to act on a manifest without an inclusion proof against a witnessed checkpoint; reserves its shield before the first card and never refunds after a send; sends every request through the relay.

**Aggregator.** Passes the `manifest/`, `deck/`, `release/`, `context` (in `deck/world`) and `log/` vectors it runs before accepting a share; the `ballot/` intake vectors (B1, B4–B8, B10) and replacement state machine; `release/` σ, gates, receipts and rankings; `services/aggregator`. Adds noise with a vetted discrete sampler whose draws pass `release/sampler`'s checks at z = 4 over at least 20,000 draws per σ it uses, called with the exact rational σ_r = n/2²⁰ of `release.md` Noise, never with σ or a binary64 value.

**Log and ledger.** Passes manifest steps 1 to 6 and 8 for every type, step 9 as `services/step9-at-log` (LG-8), and step 10 for every type as the table in `services.md` assigns it; `log/` and `services/leaves`, `services/checkpoint`, `services/witness-protocol`. LG-1 to LG-8 are simulator checks.

**Blob store.** Passes `storage/cid`, `storage/store-api` (the visibility table, put order, re-put, tombstones), `storage/delete-order`, `services/service-manifests` for its own manifest. It must not be able to pass `storage/sealed`'s opening cases.

**Witness.** Passes `log/checkpoint` and `services/witness-protocol`.

**Verifier host.** Passes `verifier/manifests`, `verifier/summary`, `verifier-runtime/*`, `credentials/issuance` (the host's epoch decisions) and the presentation rules it runs for `credential` evidence.

A conformant implementation of any kind rejects every rejecting case at the named step, rule or check. Accepting a case the vectors reject is a failure even when the implementation is "stricter" elsewhere.

## Coverage

Rule to vector files and ids. "Gap" entries are expanded in the next section.

### manifest.md

| Rule | Vectors |
| --- | --- |
| Deterministic CBOR, bytewise key order, no floats, shortest ints | `manifest/cbor` (29+17) |
| CID and text form | `manifest/cid` (5+5) |
| Envelope fields and presence rules; 1,024 refs | `manifest/verification` step-04-* (16 rejecting) |
| 64 KiB envelope | `manifest/verification` step-01 |
| Reference depth 16 | `manifest/verification` step-09 (depth 17), accept (depth 16) |
| COSE_Sign, detached CID, `hum/manifest/1` as `external_aad` (ADR 0105) | `manifest/signature` (3+4) |
| Keyset body (version 1 without `authority`), roles, thresholds, pre-rotation, revocation by position, rotation signing | `manifest/keyset`, `manifest/verification` step-04-012..016, step-05, step-06, step-10, accept-004/006/007/012 |
| Chain rules and forks | `manifest/verification` step-08 (4) |
| Inclusion, witnesses, accepted log, consistency with the held checkpoint | `manifest/verification` step-07 (13), `log/inclusion`, `log/consistency`, `log/checkpoint` |
| References resolve and verify; blob refs | `manifest/verification` step-09, `services/step9-at-log` |
| Expiry gates actions | `manifest/verification` step-11, accept-013/014 |
| Type registry: `service` registered, `blob-store` retired; two-keyset release rule at step 6 | `services/service-manifests`, `release/manifests` R9 |
| Retiring and successor markers | Gap (no envelope key assigned) |

Every one of the eleven steps has at least one rejecting case: 1 (1), 2 (5), 3 (1), 4 (16), 5 (3), 6 (7), 7 (13), 8 (4), 9 (3), 10 (2 keyset rules; type rules below), 11 (2).

### services.md

| Rule | Vectors |
| --- | --- |
| `service` body, S-1 to S-8, one valid per kind | `services/service-manifests` (11+29) |
| Blob-store kind, BS-1 to BS-6 (`storage.md` §7) | `services/service-manifests` |
| Bundle map, B-1, B-4, bad path | `services/bundle` (3+4), `log/bundle` (2+1) |
| Leaf encoding, LG-6, entry bundles, bad leaf hash | `services/leaves` (5+1), `log/leaves` (10+0) |
| Step 9 at the log, LG-8 | `services/step9-at-log` (2+1) |
| Checkpoints, origin, key ids, W-1, W-2, tampered timestamp, unlisted witness | `services/checkpoint` (1+5), `log/checkpoint` (7+4) |
| Witness protocol 200/409/409/422, W-3 | `services/witness-protocol` (5+0) |
| A-1 payload, A-2 COSE_Sign, A-3 freshness and replay | `services/signed-requests` (3+4) |
| Task ids per (round, part) over the deck lineage CID, receipt signatures, receipt pages for 100, 4096, 4097, 1,000,000 leaves | `services/aggregator` (10+2) |
| The log's clock check on logged presentations (`rejected`, rule P5, ADR 0101) | `services/log-submission` (4+4) |
| Error bodies per code, bare 401 and 404, E-1 | `services/errors` (17+1) |
| O-3 padding buckets, O-5 relay authority, bootstrap witnesses | `services/relay` (12+3) |
| Tokens T-1 to T-4 | Gap (Privacy Pass) |
| LG-1 to LG-8, AG-1 to AG-8, V-1 to V-4, RS-*, G-*, O-4, logging table | Simulator |

### storage.md

| Rule | Vectors |
| --- | --- |
| Padding §1.2 | `storage/padding` (9+2) |
| Sealing §1.3–1.5, formats 1 and 2, every rejection reason | `storage/sealed` (7+11) |
| Ranges §1.4, `range-c-from-size`, content-length mismatch, appended chunk | `storage/ranges` (5+2) |
| CIDs and digest §2 | `storage/cid` (5+0) |
| References §3.1, every `ref-*` rejection; ExternalPart reverse rule §3.2 | `storage/reference` (4+10), `storage/reference-more` (1+12) |
| Keyring §4: blob keys, two blobs, keyring-share and its rejections, exporter arithmetic | `storage/keyring` (7+0), `storage/keyring-share` (0+2) |
| Folders §5: replay with every §5.4 rule named, rights, index | `storage/folders` (3+0) |
| Store API §6: visibility table, put order, re-put, tombstone in another context, promotion | `storage/store-api` (23+7) |
| Store manifest §7 | `services/service-manifests` |
| Delete secret §8.1, delete orders §8.2 | `storage/delete` (1+2), `storage/delete-order` (1+4) |
| Keybox §9.1 | Gap (HPKE) |
| Tokens, §11 | Gap (Privacy Pass); simulator |

### context.md

| Rule | Vectors |
| --- | --- |
| Protocol constants, C3, C4, C10 | `release/floors` (4+9) |
| C1 to C16 on whole manifests, every sub-condition the spec lists (C16: four rejecting, one accepting, ADR 0100) | `context/manifests` (5+63) |
| Policy evaluation | `context/policy-eval` (11+0), `trust-list/resolution` |
| Daily count buckets | `context/count` (4+0) |
| Results key derivation and the mismatch a member refuses | `context/results-key` (3+1) |

### deck.md

| Rule | Vectors |
| --- | --- |
| D1 to D14, every sub-condition the spec lists, incl. D12's monotone `expires` and D13's upper bound | `deck/manifests` (8+63) |
| D16 (the ledger's clock check at admission) | `deck/manifests` `deck-invalid-D16-*`, `{"check": "log-admission"}` |
| D15 rating decks, deck-valid-rating | `deck/rating` (1+14) |
| σ² per part, σ_r = n/2²⁰ and `sigma` = round(σ_r × 10⁶) (covariance over `covScale`), Δ_cov for four (M, covScale) pairs | `deck/plan-math` (9+0), `release/sigmas` |
| Plan floors D8, D10, D11, D14 as plan-only checks | `release/plans` (4+20) |

### release.md

| Rule | Vectors |
| --- | --- |
| R1 to R14, every sub-condition the spec lists; valid scenarios incl. four stages, dropout, public, ibis, absorbed, below minimum | `release/manifests` (25+52) |
| R13 against the pinned deck's `expires` (phone side) and against the aggregators' clock (log-admission side) | `release/manifests` `release-invalid-R13-*` |
| Rating releases: exactly `tallies`, `group_tallies`, `group_sizes`; R5 groupsK; R7 no consensus; R10 by source | `release/rating` (1+4), `release/manifests` `release-invalid-R7-rating-consensus` |
| Receipt padding, integer ⌈σ_8⌉ over σ², pages | `release/receipts` (10+0) |
| R9 two signers | `release/manifests` R9 cases |
| ε↔ρ, σ, gates, caps, phone round computations, rankings, sampler harness | `release/accounting`, `sigmas`, `gates`, `cap`, `phone`, `ranking`, `sampler` |
| σ_r rule (`release.md` Noise, option B): the example plan's six parts, σ² a perfect square (n at the bound), the square of a dyadic, one unit of 2⁻⁴⁰ below a square (n rounds up), σ within 2⁻²⁰ below an integer with both ⌈σ_8⌉ forms; R4 `sigma` from σ instead of σ_r | `release/sigmas` `example`, `boundary-*`; `release/manifests` `release-invalid-R4-sigma-not-rounded-up` |
| R15 Parquet tables | Gap |
| Keybox, eigenvector sign convention, blur and k-means | Gap |

### issue-map.md

| Rule | Vectors |
| --- | --- |
| IM-1 to IM-15, every listed im-ok and im-bad case that needs no proof primitive, incl. the logged-presentation cases of ADR 0101 (`im-ok-verified-next-epoch`, `im-ok-kid-removed-after`, `im-bad-proof-epoch-mismatch`, `im-bad-issued-skew`, `im-bad-kid-removed-before`) | `issue-map/objects` (83+42) |
| Authorship map per form, editSig, rejections | `issue-map/authorship` (4+3) |
| Edit-key derivation, annotations, duplicate detection | `issue-map/derived` (12+0) |
| Log of record: the first `logs` entry, an object present only in the second log, a bundle without a record-log proof | `issue-map/objects` `im-ok-two-logs`, `im-ok-two-logs-second-log-accepts`, `im-bad-two-logs-no-record-proof` |
| Membership proof verification, `im-bad-proof-unbound`, `im-bad-slot-reused-other-log` | Gap |

### take.md

| Rule | Vectors |
| --- | --- |
| TK-1 to TK-9 | `take/manifests` (7+24) |
| Noise math, measures 0–13, queryHash, gallery ranking | `take/numeric` (28+0) |

### agent-sponsor.md

| Rule | Vectors |
| --- | --- |
| AS-1 to AS-9, incl. `as-ok-proof-after-epoch` and `as-bad-proof-epoch-mismatch` | `agent-sponsor/manifests` (13+25) |
| AS-2b against the synthetic report | `agent-sponsor/attestation` (1+2) |
| as-x-* cross-spec | `issue-map/objects` (IM-6), `take/manifests` (TK-5) |

### verifier.md, trust-list.md, verifier-runtime.md

| Rule | Vectors |
| --- | --- |
| verifier rules 1–28 incl. 7a–7c, 20a–20e; one valid per profile; the district lineage | `verifier/manifests` (13+74) |
| Disclosure summaries | `verifier/summary` (12+0) |
| trust-list rules 1–9, 11–13; core v1–v3, community, agent lists | `trust-list/manifests` (5+22) |
| Resolution rows, `minVersion`, agent rows and `vote` | `trust-list/resolution` (11+0) |
| Datasets and rule 15; build recipes and rule 16; masking rule 12 | `verifier-runtime/datasets` (5+5), `build` (6+1), `masking` (6+0) |
| verifier-runtime rules 1–11, 13, 14; decisions; module instantiation | Gap (wasm runtime) |
| Issuer key `fromEpoch`, key-of-epoch selection, rules 3, 15, 16, 21, 26 as revised | `verifier/manifests` |

### chat.md

| Rule | Vectors |
| --- | --- |
| Content types §5.2–5.16, generic drop rules, ExternalPart count, deck-dealt lineage, release-digest match | `chat/content` (18+11) |
| Message ids §5.1, padding §4.3, authenticated data §4.2, safety code §2.2 | `chat/derivations` (9+4) |
| Everything that needs a live MLS group | Gap (list below) |

### credentials.md, ballot.md, shield.md

| Rule | Vectors |
| --- | --- |
| Periods, epochs, handover, ballot window, grace | `credentials/epochs` (18+0) |
| Message layout, header, scopes and bound messages for every use, nullifier, `ph` | `credentials/layout` (16+0) |
| P1, P2, P3 (in force at the log position for logged presentations), P5 (three validity rows), P6 (one cell per context: `branches` always `[]`, no `any`, one verifier per leaf), P7, P8; one presentation per use; `cred-present-entry-one-cell`; `cred-present-entry-any` withdrawn | `credentials/presentations` (22+42) |
| Issuance plaintexts, host epoch decisions, nym share, phone checks | `credentials/issuance` (8+9) |
| Backup and chat-only export plaintexts, refused keys | `credentials/backup` (2+2) |
| P4 BBS proofs, pseudonyms, blind issuance, sealed issuance bytes, backup wrap | Gap (BBS, HPKE, Argon2id) |
| Ballot map, body, bound message, frame, round-0 payload and part vectors, rounds 1–3, round1-max | `ballot/round0` (10+0), `ballot/rounds` (5+0) |
| Receipt leaf, padded tree and page check | `ballot/receipts` (2+0) |
| B1, B3 set logic, B4–B8, B10 | `ballot/invalid` (0+34) |
| Client-side counted hand, movement selection, ratings selection, send schedule | `ballot/client` (6+0) |
| B2, B3 with real cards, B9, B11, DAP report | Gap (presentations, Prio3) |
| S1, S2, S8 (window anchored at `settledAt` or `expires`, ADR 0102), S9 (restore by `expires`), compose, fit, window, long decks, states, restore, display, and the refused events | `shield/shield` (46+14) |
| S3–S7, S10–S12 | Simulator |

## Gaps

Each needs a library, an owner decision or a sibling artifact. Nothing here is a reading the reference could have made on its own.

| Gap | Reason | Unblocked by |
| --- | --- | --- |
| BBS signatures, blind issuance, pseudonyms, P4 proof verification, the completed card in `cred-issue-*`, "same nym secret under two scopes" | No Python implementation of draft-irtf-cfrg-bbs-signatures -12 with the blind-signatures -03 and per-verifier-linkability -03 extensions exists (`docs/research/seam-libraries.md`: PyPI `bbs` is pre-IETF and dead; `pybbs` is not on PyPI); the only library at the cited drafts is the Rust crate `zkryptium`, unaudited | ADR 0110 (accepted 2026-10-07): Hum implements the three drafts in-house in a core crate over a vetted BLS12-381 library, with `zkryptium` as the comparison. Primitive vectors come from the drafts' own JSON fixtures. Still to decide under 0110: the BLS12-381 library, and how composite vectors (cards, presentations, nullifiers in Hum's layout) get a check independent of the crate: a second implementation in this reference over a pairing library, `zkryptium` driven as the cross-check, or both |
| HPKE: issuance request and response sealing (incl. RFC 9180 §9.8 export), the release keybox, the backup wrap, join tickets | `cryptography` 50.0.2 has HPKE but no export interface, no AAD argument and no way to fix the ephemeral key, and Hum needs all three | `pyhpke` or a wrapper, a seam dependency needing approval |
| Argon2id for the recovery phrase | No gap in the primitive: `cryptography` 50.0.2 has Argon2id (RFC 9106). The backup wrap still waits on HPKE above | HPKE (above) |
| Parquet tables, R15, `hum.*` metadata, table row checks | No Parquet writer | `pyarrow` (dev) and a decision that table bytes are compared row-wise |
| Eigenvector sign convention, box half-widths, blur and threshold, k-means centroids | Needs a numeric library at generation time; vector bytes would depend on a BLAS build | Decide whether these are vectors with a stated tolerance or simulator comparisons against the oracle |
| verifier-runtime rules 1–11, 13, 14; decision, replay and instantiation vectors; the profile binaries | Needs a WebAssembly component runtime and the built modules | `wasmtime` with component support, plus the W1 profile builds |
| Chat vectors needing MLS state (list below) | Needs an MLS implementation driven from the reference | Owner chooses the MLS stack |
| Privacy Pass issuance and redemption (T-1 to T-4, store and delivery tokens) | Needs an RFC 9578 implementation | A library decision; the RFC's own vectors for types 0x0001 and 0x0002 |
| DAP reports, `ballot-dap-report`, B11 | Needs Prio3 | Phase 2 is out of draft 0.1 scope |
| B2, B3 with real cards, B9 gate disclosure | Need real presentations | BBS (above) |
| Membership-proof verification in IM-6 and AS-8, `im-bad-proof-unbound`, `im-bad-slot-reused-other-log` | Need credentials primitives; the reference checks structure, scope bytes and bound messages and emits them per case. `im-bad-slot-reused-other-log` also needs the same nullifier seen under two logs' scopes, which only a real pseudonym gives | BBS (above) |
| `as-bad-proof-scope` | A wrong scope is only visible inside the BBS proof's `ph` (P4) | BBS (above) |
| Verifier attribute key 7 `fromEpoch` (attributes appended mid-lineage) | The verifier builders have no parameter for it yet; the credentials layout cases cover it (`cred-present-logged-old-len-after-append`), the issue-map world does not | Next run: a builder parameter |
| Log-of-record vectors beyond `issue-map/objects` (a lineage absent from the log of record for decks, releases and verifiers) | Only the issue-map world has a second log | A two-log base world |
| Retiring and successor markers | `manifest.md` assigns no envelope key | Manifest spec owner |
| Tokens, breakdown part 7 at intake, daily count readers | Owner decisions in the specs | — |

### Chat vectors that need a live MLS implementation

From `chat.md` §16, these sets cannot be generated without an MLS stack and remain pending; the owner must choose the implementation (OpenMLS is the recorded candidate): `chat/credential`, `chat/exporter`, `chat/frank`, `chat/stamp` (needs a `PrivateMessage` to stamp), `chat/tokens`, `chat/join`, `chat/roles` (the commit acceptance matrix; the `roles` message bytes and signature are in `chat/content`), `chat/ignore`, `chat/promote` (as a message sequence), `chat/directory` (replay), `chat/agent-limits`, `chat/history`, `chat/ds-api`, `chat/no-votes` (needs `ballot.md` structures in message bodies). Generated now: `chat/content` (every content type's bytes and drop rules) and `chat/derivations` (message ids, padding, authenticated data, safety code).

### Applied owner decisions, and what they changed

Accepted by the owner on 2026-10-07: ADRs 0100, 0101, 0102 item 1, 0105 item 1, 0106, the reference library list recorded in `docs/DECISIONS.md` (ADR 0081), BBS in-house (ADR 0110) and sampler option B (ADR 0010 item 3). Applied on 2026-10-06 (`docs/specs/reviews/cross-spec.md` §12) and 2026-10-07; the reference and vectors follow them:

- **ADR 0100** (one cell per context, `context.md` C16): `context/manifests` carries the four C16 rejections and the accepting case; every context in every world now has no `any` node and one verifier per leaf; `credentials/presentations` has `cred-present-entry-one-cell`, `branches` is always `[]`, and `cred-present-entry-any` is withdrawn.
- **ADR 0101** (logged presentations checked against `issued` and the log position): `credentials/presentations` P3 and P5 logged cases, `issue-map/objects` and `agent-sponsor/manifests` new cases, `services/log-submission` for the log's clock check.
- **ADR 0102 item 1** (shield window anchor): `shield/shield` window, long-deck and restore cases use `settledAt` capped at `expires`, or `expires`. Items 2 and 3 (the receipt clamp's δ) stay open; the accounting vectors still report ε at the plan's δ.
- **ADR 0105 item 1** (names): `hum/manifest/1` is the `external_aad` of every manifest signature, `hum/keyring/1` and `hum/delivery/1` the exporter labels; every signed bundle and the keyring exporter vector changed bytes. Items 2 to 5 stay open (see disagreement 11).
- **ADR 0106**: keyset version 1 without `authority`, the two-keyset release rule at step 6, the retired `blob-store` type name, the bundle pointer to `services.md`, the deck example.
- **ADR 0010 item 3, sampler option B** (`release.md` Noise, normative 2026-10-07): σ² = p/q = Δ²·den/(2·num) in lowest terms, n the least integer with n²·q ≥ p·2⁴⁰ in integer arithmetic, σ_r = n/2²⁰; the sampler takes the rational σ_r, the part's `rho` stays the plan's, `sigma` = round(σ_r × 10⁶) ties to even (covariance round(σ_r/`covScale` × 10⁶)), ⌈σ_8⌉ keeps the integer rule over σ². Every `sigma` in `deck/plan-math`, `release/sigmas`, `release/manifests`, `release/rating` and the deck, take, issue-map and rating worlds changed; covariance `sigma` is now in real units (before: integer units); the R4 case is `release-invalid-R4-sigma-not-rounded-up`. The reference reproduces W0-01's example values (tallies 18386906, covariance 2371813, map 3622619, groups 10337391, count 10000000, receipts 20000000) in `release/sigmas` `example`.
- **ADR 0110** (BBS in-house): changes the BBS gap's "unblocked by" column above; no vector changed.

Still open and unchanged in the vectors: envelope keys for the retired marker and successor pointers; ADR 0102 items 2 and 3; ADR 0105 items 2 to 5.

## Disagreements and drift found while building

Noted, not resolved; the owning workstream decides. Items from the first run that the specs have since fixed (COSE_Sign vs COSE_Sign1 in the bundle; ε 4.0007 at `RHO_MAX`) are removed.

1. **Task ids.** Resolved: `services.md` now hashes `hum/dap-task/1 ‖ deck lineage CID ‖ uint8(round) ‖ uint8(part)` like `ballot.md` (ADR 0024); `services.task_id` and `services/aggregator` follow it.
2. **Take sort key.** Resolved: `take.md` now writes `logIndex` (the version-1 leaf index in the log of record), every element compared descending; the reference matches.
3. **Sponsor row disclosures.** Resolved: `credentials.md` defines the possession leaf `[4, authority]`; the sponsor row is `[4, A]` and each issuance-evidence `accepts` alternative is `[4, accepts[k].authority]` plus that entry's attributes. W0-02 confirmed the possession leaf has no `minVersion` test (no trust-list row supplies one); its only key condition is that `kid` is the key of the card's epoch or a still-listed key of an earlier epoch's card. The reference implements kind 4 that way: `cred-valid-P6-possession-no-minversion`, `cred-invalid-P6-possession-issuer`.
4. **Consensus on a rating release.** Resolved: `release.md` R7 and `take.md` both say a rating release carries exactly `tallies`, `group_tallies` and `group_sizes`; the reference rejects `t/consensus` on a rating release (`release-invalid-R7-rating-consensus`).
5. **Unreachable sub-cases.** Resolved by relabeling in the specs: "changes a prior sigma" is R4, "drops a prior t/*" is R7, R8 has "changes receipts[0]"; verifier 20c is now "every dedup item the profile's row requires is present" (`uniqueness` without its `device` item); `im-bad-moderation-form-mismatch` is dropped, `im-bad-sponsor-missing` is IM-6, `im-bad-sponsor-on-member` is IM-9, `im-bad-frozen-editkey` replaces `im-bad-frozen-kind`; a pro ref on a take card is D4, `minVoters` 300 on a rating deck is D11, a rating deck with part 1 is D8. R8's "version 2 changes helper" cannot reach R8 because R2 compares `helper` with the context's aggregators on every version; `release.md` now lists it under R2 as `release-invalid-R2-helper-changed`, matching the reference, and R8's list keeps only reachable cases.
6. **Verifier issuer keys.** Resolved in run 2: the verifier module and `verifier/manifests` follow `fromEpoch`.
7. **MIMI encodings.** Resolved: `chat.md` now pins MIMI content -09 and settles both readings in §5.1 (big-endian uint16 URI lengths in the message id; the flat draft-09 nestedPart layout for the ExternalPart); `chat/derivations` and `storage/reference-more` follow them.
8. **Keyset version 1 and `authority`.** Resolved: `manifest.md` now says version 1 of a keyset has no `authority` and is signed by its own `rotate` threshold (ADR 0106).
9. **`manifest.md` deck example.** Resolved: the example was replaced.
10. **D8 and rating decks.** Resolved: D8 now says vote decks have the tier all present or absent and rating decks exactly parts 0, 3 and 8.
11. **Delete-order and roles signatures.** Open as ADR 0105 item 2: the reference signs them with the domain string prefixed to the detached payload and empty external AAD until the two specs say otherwise. For W0-05, W0-06.
12. **`context.md` key 19 (`nullifier`).** Resolved: the example now carries it.
13. **Which card's nullifier is the authorship nullifier.** Resolved: `issue-map.md` now says `authorship.nullifier` is the primary one, from the card the context's designated `nullifier` leaf names, and IM-7 checks every nullifier the presentation yields against the log of record's seen set; the reference does both (`im-bad-secondary-nullifier-reused`, `im-ok-two-cards`).
14. **`since` below `minVersion`.** Resolved: `credentials.md` moved the case to P6 as `cred-invalid-P6-minversion`.
15. **D13 upper bound.** Resolved: the reference enforces `closes + (R+1)·roundWindow ≤ expires ≤ closes + PUBLISH_WINDOW + (R+1)·roundWindow` (`deck-invalid-D13-expires-far`, `deck-valid-expires-max`), D12's "`expires` rises only with `closes`", and D16 and R13's clock halves as log-admission callables (`{"check": "log-admission"}` cases), since `deck.md` D16 and `release.md` R13 give those checks to the ledger and the aggregators by their own clocks and phones do not run them.
16. **R2's "highest version logged before `closes`".** Resolved: `release.md` R2 is now clock-free, "the highest version of the deck lineage whose log position is below the release lineage's version 1", checked on every version, with D16 and R13 named as the clocks that make it the version in force at `closes`. The reference already read it that way.
17. **Rule 31's "ignores the other".** `verifier.md` says a phone uses the lower-index lineage and ignores the other; the reference rejects the higher-index version 1 at step 10, which is the same outcome for every reader of one log.
18. **`release.md` Receipts, "⌈σ_8⌉ … equal to ⌈σ_r,8⌉ except when σ_8 is within 2⁻²⁰ below an integer, where the two differ by one".** The two never differ: σ_r is the least multiple of 2⁻²⁰ at or above σ, and every integer is such a multiple, so any integer m ≥ σ has σ_r ≤ m, giving ⌈σ_r⌉ = ⌈σ⌉. `release/sigmas` `boundary-below-integer` shows both equal to 20 at σ² = 400 − 2⁻³⁰. Resolved: W0-01 verified the equality and `release.md`'s Receipts parenthetical and release-math vector note now say the two are always equal; the σ² rule stays normative and the reference implements it.

## Interop milestone

A second, independent implementation verifies a deck and a release produced by the first. Concretely:

1. The Rust core builds `manifest/world.json` and `deck/world.json` from its own code with the same seeds, byte for byte.
2. The Go ledger accepts every bundle the vectors mark accepting, rejects every rejecting one at the same step and rule, and emits leaves and checkpoints the reference verifies.
3. The reference verifies a deck and a release produced by the Rust aggregator in the simulator's fast run, including the σ values in the release's part records.
4. A Swift or Kotlin binding runs the manifest, deck and release verification cases through the uniffi surface with the same outcomes.

## Open questions

- Which library closes the BBS gap, and whether the drafts' own vectors are adopted meanwhile.
- Whether numeric post-processing (eigenvectors, k-means) gets vectors with a tolerance or stays a simulator comparison.
- How the conformance runner is packaged for the apps.
- World build time: the deck and take worlds verify every appended manifest against a growing resolver and take about a minute each; a cheaper index in `Resolved` would help the Rust port as well.
