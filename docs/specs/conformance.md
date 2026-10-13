# Hum Conformance — Draft 0.1

Oct 13, 2026 · seven-lane integration follow-up · executed coverage and remaining gaps below

## Scope

This document says how an implementation runs the test vectors in `vectors/`, what "conformant" means for each kind of implementation, how spec rules map onto vector cases, which rules have no vector yet and why, and what the interop milestone is. The vectors come from the Python reference in `reference/` and from nowhere else. `just vectors` regenerates them and `just conformance` fails when the committed files differ from a fresh run.

Status of this version: every spec on disk has a reference module and a vector directory. The reference verifies every manifest type through the eleven steps with each type's step 4 schema, step 6 replacement (authorship, two-signer releases, agent takes) and step 10 rules. Remaining coverage needs implementation using the approved libraries, sibling artifacts or an owner decision; phase 2 Prio3 remains deferred. Library approval is recorded in `docs/DECISIONS.md`; it does not mean those integrations or vectors exist. Every gap is listed below. The frozen seven-lane integration passed `just check`: 483 Python tests and a clean recursive comparison of 960 accepting / 931 rejecting generated cases. The totals include the explicitly experimental artifacts described below; `just sim-fast` reported 5 passing, 0 failing and 4 pending scenarios. Proposed WIT, B1 backup and E1 BBS formats remain opt-in and are not accepted normative formats.

Android feasibility now includes actual emulator execution: Kotlin generated from the Android UniFFI library made 20 calls and passed 120 assertions through approved blst 0.3.17. This establishes the tested bridge on that Android runtime, not production BBS/profile interoperability; see `docs/research/android-blst-feasibility.md`.

## Vector files

One directory per spec, one JSON file per topic, a list of `cases`. The separate `experimental/` namespace contains opt-in proposals (`proposed-host`, `proposed-backup`, `proposed-bbs`). These are explicitly excluded from normative client/server conformance obligations until the owner adopts the corresponding choices. Their tests and generation must still pass; existing normative BBS/P4 obligations are unchanged. Every case has:

| Field | Meaning |
| --- | --- |
| `id` | `<spec>/<file>/<suffix>-<nnn>`; the suffix is the spec's own vector name where it gives one (`deck-invalid-D4-duplicate-card-cid`, `im-bad-slot-reused`) |
| `description` | What the case shows, for people |
| `section` | The spec section or rule the case tests |
| `inputs` | Everything an implementation needs to reproduce the case |
| `expected` | Outputs an implementation must reproduce (accepting case) |
| `rejection` | What an implementation must refuse: `step` (manifest verification step, or `null`), `rule` (the spec's rule id, when a type rule), and for non-manifest checks a `check` naming the operation; API decisions add `status`, `code`, `detail` and, where the spec fixes it, the exact error `body` |

Exactly one of `expected` and `rejection` is present. Normative in a rejection: `step`, `rule`, `check`, `status`, `code`, `detail`, `body`. Advisory: `reason`. V-4 requires `rejected` and rule `V-4`, but no fixed detail string or body containing one. For O-6, relay-set enumeration, request-kind labels, example picks and random-stream draws are harness fixtures, not interoperability outputs: check set membership, uniqueness, uniform selection, retry eligibility and the no-direct-fallback outcome. A deterministic example alone does not prove a production CSPRNG uniform. Where a spec names rejection reasons (`storage.md` §1.5, the `detail` strings of `services.md` and `storage.md` §6.7) the vector carries that name and an implementation must report the same one.

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
| Task ids per (round, part) over the deck lineage CID, receipt body `{0 leaf, 1 signature, 2 kid}`, receipt pages for 100, 4096, 4097, 1,000,000 leaves with the GET response body, root blob `{0 k, 1 pages}` (never carries the root) and the GET response `{0 root, 1 k, 2 pages}`, which a phone rejects when `k` or `pages` differ from the pinned blob (`receipts-response-matches-blob`, `-k-mismatch`, `-pages-mismatch`, `-root-mismatch`), `404` below the minimum (AG-4, ADR 0103) | `services/aggregator` (13+5) |
| The log's clock check on logged presentations (`rejected`, rule P5, ADR 0101) | `services/log-submission` (4+4) |
| Error bodies per code, bare 401 and 404, E-1; host rejection `rule` `vr-<code>`; `too_large` (413) for a presentation over 8 KiB | `services/errors` (20+1) |
| "Body keys": every row's integer-keyed body, encode and decode; an unknown field rejected. The gallery listing element is `{0 cid, 1 logIndex, 2 rated, 3 hasGroupScore, 4 score, 5 forkCount}` with `score` = take.md's score rounded half to even to six decimals × 10⁶ and absent for an unrated take (`service-body-gallery-takes-unrated-and-tie`: 1/128 → 7812). The six rows for `/v1/log/proof/inclusion`, `/v1/log/proof/consistency` and the four gallery responses are **provisional** (cross-spec §12.10: first defined there) and marked so in the file notes, each description and `inputs.provisional` | `services/bodies` (24+1) |
| V-2 and V-4: one issuance request per session, identical retry, `conflict` only within the session, a different request in a later session against a spent row gets the masked dedup code (TS8); the host holds evidence sealed and opens it beside the issue call, ending the session on a mismatch (`host-v4-*`); response bytes are placeholders (BBS, HPKE) | `services/host` (4+5) |
| L-5 and L-6 (TS5, RT2, RU3): L-6's per-service field table with domains for every row (log, witness, aggregator, host, delivery, store, resolver, gallery, relay, gateway), one allowed and one forbidden line per row; L-5's intake rules (no accepted-ballot count at any time, no per-request line, no per-deck, per-round or per-path intake count, `conflict` `duplicate` at no grain, nullifier-dependent codes only in the daily total; gateway no intake counter or ballot-path count). `rule` is L-5 where that rule names the failure, L-6 otherwise; every L-5 failure is also an L-6 failure. The bucketed receipt field is `padded_leaves` | `services/logging` (19+35) |
| O-3 padding buckets, O-5 relay authority, bootstrap witnesses; a first request with a gateway configuration one rotation old accepted and an unsupported one refused (TS11, structural: key-config id comparison); O-6 relay selection (§12.11, tightened in §12.13): a context relay carries only the context's delivery service, its stores and token issuers, and log or resolver reads; everything else (ballots, receipts, every aggregator request, every log submission, an authored object's text and evidence blob puts and their token issuance) uses the shipped relays only; each connection picks uniformly from the allowed set and re-picks from the rest on failure, never direct. The draws come from a fixed SHA-256 stream under `hum/relay-pick/1`, a reference device, not a protocol rule (`o6-*`, `o6-all-failed` rejected) | `services/relay` (23+5) |
| Tokens: actual type-1/type-2 issuance adapter, fixed challenge and issuer/context/key binding, T-1 durable atomic nonce redemption, T-4 caller-supplied connection separation | `services/token-policy` (2+6), plus 18 Python tests and ten RFC issuance known answers. Membership-proof verification, transport identity and key-lifetime policy remain external boundaries |
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
| Keybox §9.1 | Real HPKE keybox seals in `release/receipts` and `release/manifests`; `credentials/hpke` transport cases. Table payload validation remains separate |
| RFC 9578 type-1/type-2 framing and type-2 RSA verification | `storage/privacy-pass-rfc9578` (10+10). The isolated Rust bridge executes all ten RFC issuance/finalization fixtures; Python calls actual type-1/type-2 issuance and verifies redemption. Delivery seed HKDF-Expand and RFC 9497 key derivation, policy binding and atomic redemption execute in `services/token-policy`; P4 proof verification remains separate |

### context.md

| Rule | Vectors |
| --- | --- |
| Protocol constants, C3, C4, C10 | `release/floors` (4+9) |
| C1 to C16 on whole manifests, every sub-condition the spec lists (C16: four rejecting, one accepting, ADR 0100); keys 20 `resolvers` and 21 `relays` with C7 (`context-valid-discovery`, duplicate relay, five relays, empty resolvers, relay equal to the Leader authority, relay equal to the delivery authority; TS10's lookup-free check); C11 `logs[0].log` frozen from version 1 (TS7 option a): `context-invalid-C11-changes-log0`, `context-invalid-C11-swaps-logs`, `context-valid-v2-logs-witnesses-and-second-log` | `context/manifests` (7+71) |
| Policy evaluation | `context/policy-eval` (11+0), `trust-list/resolution` |
| Daily count buckets | `context/count` (4+0) |
| Results key derivation and the mismatch a member refuses | `context/results-key` (3+1) |

### deck.md

| Rule | Vectors |
| --- | --- |
| D1 to D14, every sub-condition the spec lists, incl. D12's monotone `expires` and D13's upper bound | `deck/manifests` (8+64) |
| D16 (the ledger's clock check at admission) | `deck/manifests` `deck-invalid-D16-*`, `{"check": "log-admission"}` |
| D15 rating decks, deck-valid-rating; `minVoters` = max(GATE_TALLIES, context minimum) with `gates[0]` raised (ADR 0103 item 3): `deck-valid-rating-min-300`, `deck-valid-rating-min-500`, `deck-invalid-D11-gates0-not-raised`, `deck-invalid-D10-minvoters-under-floor`; D11 exempts part 3 (TS6) | `deck/rating` (3+16) |
| D16 clock-free half: a deck version logged after a release of its lineage (`deck-invalid-D16-after-release`, step 10) | `deck/manifests` |
| σ² per part, σ_r = n/2²⁰ and `sigma` = round(σ_r × 10⁶) (covariance over `covScale`), Δ_cov for four (M, covScale) pairs | `deck/plan-math` (9+0), `release/sigmas` |
| Plan floors D8, D10, D11, D14 as plan-only checks | `release/plans` (4+20) |

### release.md

| Rule | Vectors |
| --- | --- |
| R1 to R14, every sub-condition the spec lists; valid scenarios incl. four stages, dropout, public, ibis, absorbed, below minimum | `release/manifests` (27+54) |
| Below the minimum (ADR 0103 item 1, TS3): `parts` holds 0 and 4 only, `receipts` empty, no `receipts/0`, R5 lists apply only when `unlocked` is non-empty: `release-valid-below-minimum` (rebuilt), `release-valid-below-minimum-ibis`, `release-valid-below-minimum-rating`, `release-invalid-R13-below-minimum-receipt-root` | `release/manifests`, `release/rating` |
| Ledger of record = first `logs` entry: for `release` and `deck` manifests the step 7 inclusion proof must be against it whichever log served the bundle (`release-invalid-step7-not-in-ledger-of-record`, step 7, one result for either phone); R10 and R14 count only that ledger's history (ADR 0103 item 4); `release-valid-D16-after-release-v1` | `release/manifests` |
| R13 against the pinned deck's `expires` (phone side) and against the aggregators' clock (log-admission side) | `release/manifests` `release-invalid-R13-*` |
| Rating releases: exactly `tallies`, `group_tallies`, `group_sizes`; part 3 unlocks with part 0 (R6, RT3; `release-valid-rating-nhat-400`, cells filtered at `GATE_CELL` in table post-processing, not modelled); `groupsK` present iff a rating deck with part 0 unlocked (`release-invalid-R7-groupsk-below-minimum`; the below-minimum rating release carries none); R5 groupsK; R7 no consensus; R10 by source | `release/rating` (3+7), `release/manifests` `release-invalid-R7-rating-consensus` |
| Receipt padding, integer ⌈σ_8⌉ over σ², pages | `release/receipts` (10+0) |
| R9 two signers | `release/manifests` R9 cases |
| ε↔ρ, σ, gates, caps, phone round computations, rankings, sampler harness | `release/accounting`, `sigmas`, `gates`, `cap`, `phone`, `ranking`, `sampler` |
| σ_r rule (`release.md` Noise, option B): the example plan's six parts, σ² a perfect square (n at the bound), the square of a dyadic, one unit of 2⁻⁴⁰ below a square (n rounds up), σ within 2⁻²⁰ below an integer with both ⌈σ_8⌉ forms; R4 `sigma` from σ instead of σ_r | `release/sigmas` `example`, `boundary-*`; `release/manifests` `release-invalid-R4-sigma-not-rounded-up` |
| R15 opened Parquet tables, verified manifest-derived contracts, all sixteen logical schemas, public and sealed four-stage release worlds, metadata/row domains/CID binding and rating group-cell floor | `release/parquet` (1+11), `release/opened-tables` (10+2), plus signed public/sealed integration tests. Derived numerical columns remain conveniences, not oracle computation proofs |
| Keybox seal/open and direct-reference array | `release/receipts`, `release/manifests`, `credentials/hpke` |
| Eigenvector sign convention, blur and k-means | Gap |

### issue-map.md

| Rule | Vectors |
| --- | --- |
| IM-1 to IM-15, every listed im-ok and im-bad case that needs no proof primitive, incl. the logged-presentation cases of ADR 0101 (`im-ok-verified-next-epoch`, `im-ok-kid-removed-after`, `im-bad-proof-epoch-mismatch`, `im-bad-issued-skew`, `im-bad-kid-removed-before`) | `issue-map/objects` (83+42) |
| Authorship map per form without key 4 (ADR 0104 item 4), editSig, rejections incl. `im-authorship-key-4` (IM-6 at step 6); every nullifier derived from the proof; `AUTHOR_WINDOW` | `issue-map/authorship` (4+4) |
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
| Actual component decision/rejection, code CID, module size, memory/stack/fuel/deadline limits, disabled threads/relaxed SIMD, NaN canonicalization; host decision checks | `verifier-runtime/component-sandbox` (4+9), plus unit tests. The exact proposed WIT adapter links all eight imports only with explicit opt-in: `experimental/proposed-host` (10+2). Replay day, claims-only projection, dataset proofs and image-container guards are tested; five profile binaries remain pending |
| Issuer key `fromEpoch`, key-of-epoch selection, rules 3, 15, 16, 21, 26 as revised | `verifier/manifests` |
| `KEY_TAIL` = 44,928,000 s: the three-version lineage with ordinary retirement after the tail, an emergency removal, and the capacity of about seven key changes (TS14). All accepting: `verifier.md` states the tail in prose, not as a rule, so the vectors fix the earliest retirement time, not a rejection | `verifier/keys` (3+0) |
| Evidence sealing: `info` = `hum/evidence/1` ‖ verifier authority CID ‖ item name, `aad` = session ID ‖ SHA-256(issuance request plaintext), 48 bytes (ADR 0107 item 5, TS1, RT1); handover with two commitments in one request (valid, one hash); lost-response retry in a new session (valid, re-sealed under the new session ID and the same hash); a different request in the same session, a session ID replaced in transit, another item name, another verifier (all `rejected`, rule V-4, 422). Real HPKE seals and opening checks, including tampered AAD and info | `verifier/evidence` (3+4) |

### chat.md

| Rule | Vectors |
| --- | --- |
| Content types §5.2–5.17, generic drop rules, ExternalPart count, deck-dealt lineage, release-digest match | `chat/content` (19+11) |
| Message ids §5.1, padding §4.3, authenticated data §4.2, safety code §2.2 | `chat/derivations` (9+4) |
| `join-record` §5.17 (key 1 `nullifiers` sorted bstr(32) ×1..8, key 5 `day`; snapshot rows `[nullifiers, identity, day]`), the greeter sequence record → wait → pre-commit check → Add (RT4), the ticket decision, two greeters admitting one card (the later record's greeter stops, TS9/RT4), a greeter that fails between record and commit, a record at least `JOIN_PENDING` = 3,600 s old resent (3,599 usable; 3,600 and 3,601 require a fresh record), the pre-commit rule (RU2: live member stop, 30 minutes pending stop, two hours and not a member commit), the no-record backstop (RU1: removed only after the organizers group is fetched `JOIN_GRACE` = 600 s past the Add; kept before that, when unfetched, in an `entry` [0] context, for an agent leaf, for a second device, and when the record arrives; historical Adds and previously observed records pruned later never trigger removal), re-check on rebase; a record whose `day` is more than 396 days before the current UTC day blocks nothing and is omitted from snapshots whether or not deleted (`join-record-expired-inert`, `join-record-expired-snapshot-omits`; deletion itself stays MAY, `join-records-prune` advisory) (ADR 0104 item 4). The ordering is a `sequence` list; the MLS messages themselves stay pending | `chat/join-records` (32+6) |
| DL-1 to DL-5 for the `delivery` service kind (§12.1, ADR 0107 item 7): `service-delivery-valid` and one failing case per rule; DL-4 is `limits.tokensPerIssuance` ≤ 64 and `limits.commitsPerHour` ≤ 3,600 (`service-delivery-invalid-DL-4-tokens`, `-DL-4-commits`); stray keys are S-1 and S-3 at step 4 (`service-delivery-invalid-S-1-key-17`, `-S-3-origin`) | `chat/delivery` (2+13) |
| Live MLS primitives and transactional receive policy | `tools/mls-reference`: 38 live checks (26 raw-stack + 12 transactional), including captured synthetic state replay. This is partial integration, not fourteen complete Hum suites (list below) |

### credentials.md, ballot.md, shield.md

| Rule | Vectors |
| --- | --- |
| Periods, epochs, handover, ballot window, grace | `credentials/epochs` (18+0) |
| Message layout, header, scopes and bound messages for every use, nullifier, `ph` | `credentials/layout` (16+0) |
| P1, P2, P3 (in force at the log position for logged presentations), P5 (three validity rows), P6 (one cell per context: `branches` always `[]`, no `any`, one verifier per leaf), P7, P8; one presentation per use; `cred-present-entry-one-cell`; `cred-present-entry-any` withdrawn | `credentials/presentations` (22+42) |
| Issuance plaintexts, host epoch decisions, nym share, phone checks | `credentials/issuance` (8+9) |
| Backup and chat-only export plaintexts, refused keys | `credentials/backup` (2+2); opt-in B1 envelope proposal: `experimental/proposed-backup` (2+9). Proposed framing is not normative interoperability |
| Base BBS signatures and selective-disclosure proofs | `credentials/bbs-base` (4+12); pinned base -12 known answers and seven N=1 pseudonym verification fixtures. Separate E1 proposal: `experimental/proposed-bbs` (3+18), generated commitments/signatures and seven full proofs checked byte-exact against complete upstream private inputs and separately against published -03 outputs. E1 is unadopted; normative Hum P4 is unchanged |
| HPKE issuance request/response exporter, evidence, release keybox, join-ticket framing, backup Argon2id/X25519/key wrap | `credentials/hpke` (6+13); both RFC 9180 suites checked in unit tests. Proof contents remain opaque; the B1 backup envelope is a separate opt-in proposal, not an accepted wire format |
| Ballot map, body, bound message, frame, round-0 payload and part vectors, rounds 1–3, round1-max | `ballot/round0` (10+0), `ballot/rounds` (5+0) |
| Receipt leaf, padded tree and page check; `ballot-receipt-kid` (the receipt names the signing key; another listed kid rejected) | `ballot/receipts` (3+1) |
| B1 (incl. `too_large` for a presentation over 8 KiB), B3 set logic, B4–B8, B10 | `ballot/invalid` (0+34) |
| Client-side counted hand, movement selection, ratings selection, send schedule | `ballot/client` (6+0) |
| B2, B3 with real cards, B9, B11, DAP report | Gap (presentations, Prio3) |
| S1, S2, S8 (window anchored at `settledAt` or `expires`, ADR 0102), S9 (restore by `expires`), compose, fit, window, long decks, states, restore, display, and the refused events | `shield/shield` (46+14) |
| S3–S7, S10–S12 | Simulator |

## Gaps

Remaining gaps require additional integration, sibling artifacts or explicit owner/spec decisions. Library availability alone does not close them.

| Gap | Reason | Unblocked by |
| --- | --- | --- |
| Normative blind issuance, Hum P4 and composite presentation integration | Base -12 and N=1 verification execute over py_ecc 8.0.0. Opt-in E1 resolves pinned-draft ambiguities for tested commitments/signatures/proof generation using complete upstream private fixtures, but has not been adopted | Owner acceptance, outside review and Hum P4 integration; see `docs/research/bbs-pinned-draft-findings.md`. Experimental outputs do not replace existing proof requirements/placeholders |
| Full protocol composition around HPKE | pyhpke 0.6.5 seals, response export, keybox and ticket frames now execute; credential proof contents remain opaque | Full BBS cards and protocol state adapters, rather than another HPKE library |
| Normative recovery-phrase backup envelope | Opt-in B1 proposal implements phrase/framing and tamper checks over real Argon2id/X25519/HPKE; it is not an accepted protocol format | Owner acceptance of the versioned proposal and independent interoperability fixtures |
| Consensus stage transitions | New R15 contracts expose a pre-existing R6/R7/R8 conflict: locked part 3 at stage 4, and early consensus frozen under part-0 metadata | Owner clarification in ADR 0115, followed by coordinated rules and transition vectors; current worlds cover unlocked part 3 without early consensus |
| Derived release numerical computation | Public and sealed four-stage release worlds now open actual Parquet against verified plan/body contracts; all sixteen schemas and rating group-cell filtering execute | Complete oracle comparisons for derived numerical columns; table validation does not attest correct aggregation/noise |
| Eigenvector sign convention, box half-widths, blur and threshold, k-means centroids | Needs a numeric library at generation time; vector bytes would depend on a BLAS build | Decide whether these are vectors with a stated tolerance or simulator comparisons against the oracle |
| Normative verifier ABI and five profile binaries | Wasmtime 49.0.0 now links all eight imports through exact proposed `hum:verifier/host@0.1.0` WIT; opt-in replay, projection, image-container validation and process deadlines execute. Normal mode still refuses imports; adapter permits one memory | Owner acceptance of proposed WIT spelling and W1 profile builds; no claim of five-profile conformance |
| Complete Hum chat suites (list below) | Real mls-rs 0.56.0 UniFFI groups execute 26 raw-stack and 12 transactional checks. Reviewed clone/process/publish wrapper preserves current/past-epoch state and storage on failure; captured public synthetic state replays exactly. Raw upstream failure consumption remains reproduced | Complete Hum admission/roles/history/service policy composition and independently reproducible fixtures; captured replay is not deterministic stack generation |
| End-to-end Privacy Pass admission | Actual approved-library type-1/type-2 Python adapter, channel derivation, fixed challenge/key/context binding, persistent atomic redemption, held-secret MAC and fifteen-minute fetch cookies execute. T-4 uses caller-supplied connection identity | P4 membership proofs, verified directory/context and actual relay connection boundary; unresolved key rotation/expiry policy is not invented and 48-hour enforcement is not claimed |
| DAP reports, `ballot-dap-report`, B11 | Needs Prio3 | Phase 2 is out of draft 0.1 scope |
| B2, B3 with real cards, B9 gate disclosure | Need real presentations | BBS (above) |
| Membership-proof verification in IM-6 and AS-8, `im-bad-proof-unbound`, `im-bad-slot-reused-other-log`, the V-2 response bytes in `services/host`, proof-bearing join-ticket composition | Need credentials primitives; the reference checks structure, scope bytes and bound messages and emits them per case. `im-bad-slot-reused-other-log` also needs the same nullifier seen under two logs' scopes, which only a real pseudonym gives | BBS (above) |
| `as-bad-proof-scope` | A wrong scope is only visible inside the BBS proof's `ph` (P4) | BBS (above) |
| Verifier attribute key 7 `fromEpoch` (attributes appended mid-lineage) | The verifier builders have no parameter for it yet; the credentials layout cases cover it (`cred-present-logged-old-len-after-append`), the issue-map world does not | Next run: a builder parameter |
| Log-of-record vectors for verifiers (a verifier lineage absent from the ledger of record) | The deck world's second log mirrors the ledger of record and holds the deferred releases only | Extend the deck world's second log |
| Full proof-bearing evidence and join tickets | Sealing now executes; proof and credential contents still use opaque fixtures | BBS composite proof adapters above |
| Retiring and successor markers | `manifest.md` assigns no envelope key | Manifest spec owner |
| Token context/key rotation lifetime, breakdown part 7 at intake, daily count readers | Remaining owner decisions in the specs; primitive issuance and durable nonce redemption are implemented | — |

### Chat vectors that need a live MLS implementation

The owner approved OpenMLS 0.9.0 for core and `mls-rs` 0.56.0 through UniFFI for reference generation. `tools/mls-reference` now runs actual group traffic, exporter agreement, authenticated data, private control handling, franking/stamp primitives, transactional rejection and storage/replay checks: 26 raw-stack checks plus 12 transactional checks. A captured public synthetic state fixture supplies exact replay; it does not make randomized stack setup deterministic. The raw upstream receive-generation consumption failure is retained as a reproduction, while the reviewed wrapper clones state, validates the candidate and publishes only success.

These fourteen complete Hum suites remain incomplete despite that primitive/policy coverage: `chat/credential`, `chat/exporter`, `chat/frank`, `chat/stamp`, `chat/tokens`, `chat/join`, `chat/roles`, `chat/ignore`, `chat/promote`, `chat/directory`, `chat/agent-limits`, `chat/history`, `chat/ds-api`, and `chat/no-votes`. Complete admission, roles and service state machines are not established by happy-path MLS traffic. Generated protocol bytes remain in `chat/content` and `chat/derivations`; token composition is separately covered by `services/token-policy`.

### Applied owner decisions, and what they changed

Accepted by the owner on 2026-10-07: ADRs 0100, 0101, 0102 item 1, 0105 item 1, 0106, the reference library list recorded in `docs/DECISIONS.md` (ADR 0081), BBS in-house (ADR 0110) and sampler option B (ADR 0010 item 3). Applied on 2026-10-06 (`docs/specs/reviews/cross-spec.md` §12) and 2026-10-07; the reference and vectors follow them:

- **ADR 0100** (one cell per context, `context.md` C16): `context/manifests` carries the four C16 rejections and the accepting case; every context in every world now has no `any` node and one verifier per leaf; `credentials/presentations` has `cred-present-entry-one-cell`, `branches` is always `[]`, and `cred-present-entry-any` is withdrawn.
- **ADR 0101** (logged presentations checked against `issued` and the log position): `credentials/presentations` P3 and P5 logged cases, `issue-map/objects` and `agent-sponsor/manifests` new cases, `services/log-submission` for the log's clock check.
- **ADR 0102 item 1** (shield window anchor): `shield/shield` window, long-deck and restore cases use `settledAt` capped at `expires`, or `expires`. Items 2 and 3 (the receipt clamp's δ) stay open; the accounting vectors still report ε at the plan's δ.
- **ADR 0105 item 1** (names): `hum/manifest/1` is the `external_aad` of every manifest signature, `hum/keyring/1` and `hum/delivery/1` the exporter labels; every signed bundle and the keyring exporter vector changed bytes. Items 2 to 5 stay open (see disagreement 11).
- **ADR 0106**: keyset version 1 without `authority`, the two-keyset release rule at step 6, the retired `blob-store` type name, the bundle pointer to `services.md`, the deck example.
- **ADR 0010 item 3, sampler option B** (`release.md` Noise, normative 2026-10-07): σ² = p/q = Δ²·den/(2·num) in lowest terms, n the least integer with n²·q ≥ p·2⁴⁰ in integer arithmetic, σ_r = n/2²⁰; the sampler takes the rational σ_r, the part's `rho` stays the plan's, `sigma` = round(σ_r × 10⁶) ties to even (covariance round(σ_r/`covScale` × 10⁶)), ⌈σ_8⌉ keeps the integer rule over σ². Every `sigma` in `deck/plan-math`, `release/sigmas`, `release/manifests`, `release/rating` and the deck, take, issue-map and rating worlds changed; covariance `sigma` is now in real units (before: integer units); the R4 case is `release-invalid-R4-sigma-not-rounded-up`. The reference reproduces W0-01's example values (tallies 18386906, covariance 2371813, map 3622619, groups 10337391, count 10000000, receipts 20000000) in `release/sigmas` `example`.
- **ADR 0110** (BBS in-house): changes the BBS gap's "unblocked by" column above; no vector changed.
- **ADRs 0103, 0104, 0107 and the review fixes TS1 to TS14** (cross-spec §12.9 and §12.10, applied 2026-10-08): below-minimum releases, D16's clock-free half, rating-deck `minVoters`, ledger of record for R10/R14, `KEY_TAIL`, `join-record` nullifiers and `day`, authorship key 4 removed, context keys 20 and 21, integer body keys in `services.md` with receipt `kid`, evidence `info` and `aad`, `vr-<code>`, `too_large`, DL-1 to DL-5, `AUTHOR_WINDOW`, L-5 without counts. Byte changes: every `authorship` map in `issue-map/` (key 4 gone), the context world's unknown-key case (now key 22), `ballot/invalid` B1 9 KiB (`too_large`), the aggregator receipt and receipts-response bodies. The six new `services.md` "Body keys" rows are provisional, see the services row above.
- **§12.11 to §12.14** (TS7 and TS10 option a, RT1 to RT4, RU1 to RU3, applied 2026-10-08): C11 freezes `logs[0].log`; O-6 relay selection; evidence `aad` is 48 bytes (session ID ‖ request hash) with rule V-4; gallery element names and score rounding; a rating release unlocks part 3 with part 0; the greeter sends its `join-record` before the Add with `JOIN_PENDING` and `JOIN_GRACE`; L-5 without intake counters. Byte changes: every `verifier/evidence` and `services/host` aad; `service-body-gallery-takes`; the rating release's `unlocked`.

Still open and unchanged in the vectors: envelope keys for the retired marker and successor pointers; ADR 0102 items 2 and 3; ADR 0105 items 2 to 5.

## Disagreements and drift found while building

Resolution status is stated per item; owner decisions remain open. W0-11 closes the requested tail (20, 26–29 and 31–33), with behavior changes reviewed in `reviews/wave-0-closeout.md`. Items from the first run that the specs have since fixed (COSE_Sign vs COSE_Sign1 in the bundle; ε 4.0007 at `RHO_MAX`) are removed.

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
19. **`deck.md` D15 vector list.** Resolved: the case is listed under D10 and D15's list keeps only reachable cases; `deck-invalid-D10-minvoters-under-floor` stands.
20. **`release.md` `groupsK` below the minimum.** Resolved: R5 compares a rating release’s `groupsK` to its source only when part 0 is unlocked; R7 requires it absent below the minimum. The reference follows both rules; `release-invalid-R7-groupsk-below-minimum` covers the forbidden field.
21. **`release.md` across two logs.** Resolved: for `release` and `deck` manifests the step 7 inclusion proof must be against the ledger of record whichever log served the bundle (`release.md` R10, `context.md` "Log entries", `services.md` "Submitting a manifest"), so there is one result, step 7. The reference registers a per-type ledger-of-record hook at step 7 and the vector is `release-invalid-step7-not-in-ledger-of-record`.
22. **`chat.md` §12.1 DL-4.** Resolved: DL-4 is now the delivery-specific rule `limits.tokensPerIssuance` ≤ 64 and `limits.commitsPerHour` ≤ 3,600, with the stray keys refused at step 4 by `services.md`; the two old cases are relabeled S-1 and S-3 and two DL-4 cases added.
23. **`issue-map.md` "Sibling specs".** Resolved by W0-04: the sentence now says the authorship field carries no nullifier and the verifier derives every nullifier from the proof; the slot-scope table says "at most once in the log of record". No vector change.
24. **`services.md` receipts bodies.** Resolved: two distinct bodies are intended and said so; the pinned blob never carries the root, and a phone rejects a GET response whose `k` or `pages` differ from the pinned blob (`services/aggregator` `receipts-response-*`). The spec names no rule id for that rejection; the vectors use `check: "receipts-response"`.
25. **`verifier.md` `KEY_TAIL`.** Resolved, prose by design: the spec now says at the definition that it is a commitment, not a checkable rule (the log cannot tell early retirement from emergency removal); `verifier/keys` is informative, accepting only.
26. **`services.md` L-6 field domains.** Resolved: the table and its domain list now define delivery fields, integer/date days (host day stays the integer `time.day`), error/status codes, minute timestamps, host outcomes 0–999, complete host session lines and exactly `{cid, count}` for resolver counts after 24 hours. The reference rejects malformed hexadecimal encodings, invalid calendar dates, wrong enum types, incomplete host lines and incomplete resolver count lines. Structural field permission never overrides the owning spec’s privacy, retention or noised-value requirements.
27. **`chat.md` §5.17 old records.** Resolved: records older than 396 days do not block tickets or trigger duplicate-nullifier removal, and snapshots omit them. A record naming an identity still establishes existence for the no-record backstop. That backstop only checks Adds observed after current membership state and the organizers snapshot were acquired; it never rechecks historical Adds from a pruned snapshot. Once a record was observed for an Add, expiry or deletion does not revoke the result. The reference covers expired records, historical Adds and pruning after observation.
28. **`release.md` R6, rating part 3 and `n`.** Resolved: vote parts 1–3 use their own `n` for unlocks; rating part 3 unlocks iff part 0 does. A recorded rating part 3 requires `n` but does not use it for unlock. R1 enforces required `n` on recorded parts 0–3 when `nHat` is present, rejects boolean `n`, and has a missing-rating-`n` vector.
29. **Rating release at `nHat` 400.** Resolved: `release.md` names `release-valid-rating-nhat-400` and states that it checks the manifest unlock and part record only. That manifest vector does not claim table-content coverage; separate opened-table integration now tests rating group-cell filtering at 299/300.
30. **`services.md` logging rows.** Superseded by L-6 (item 26): per-deck counts for `malformed`, `too_large`, `rejected`, `forbidden` only, `closed` and `conflict` at no grain, intake paths identified by `/ballots`. Resolved with 26.
31. **`services.md` V-4 evidence failures.** Resolved: every failure to open evidence (wrong request, session, item name or verifier) ends the session with `rejected`, rule `V-4`, and no issuance. No detail string is normative. Generated mismatch vectors no longer require the reference diagnostic in an error body; the library follow-up now exercises actual HPKE opening in `verifier/evidence`.
32. **`services.md` O-6 selection fixtures.** Resolved: the normative relay set contains distinct authorities, selection is uniform, retries exclude failures, and total failure waits without direct fallback. Set order, kind labels and deterministic random-stream picks belong to the reference harness, not the protocol. The spec and vector notes say which outputs are advisory.
33. **`chat.md` §2.5 timing.** Resolved: sequence number orders records; delivery-service receive time measures pending age. A retry can reuse its record only at age less than 3,600 seconds; exactly 3,600 requires a fresh sequenced record and another pre-commit check. This closes the reference’s former inclusive-endpoint race. The no-record backstop’s fetch bound is inclusive at 600 seconds (599 keeps the leaf). Boundary and snapshot cases are generated.

## Interop milestone

A second, independent implementation verifies a deck and a release produced by the first. Concretely:

1. The Rust core builds `manifest/world.json` and `deck/world.json` from its own code with the same seeds, byte for byte.
2. The Go ledger accepts every bundle the vectors mark accepting, rejects every rejecting one at the same step and rule, and emits leaves and checkpoints the reference verifies.
3. The reference verifies a deck and a release produced by the Rust aggregator in the simulator's fast run, including the σ values in the release's part records.
4. A Swift or Kotlin binding runs the manifest, deck and release verification cases through the uniffi surface with the same outcomes.

## Open questions

- BBS library choice is settled: independent Python construction over approved `py_ecc`, checked against the pinned drafts’ fixtures. Base signatures and proofs execute; the additional blind/pseudonym composition remains a separately versioned proposal pending resolution of pinned-draft ambiguities.
- Whether numeric post-processing (eigenvectors, k-means) gets vectors with a tolerance or stays a simulator comparison.
- How the conformance runner is packaged for the apps.
- World build time: the deck and take worlds verify every appended manifest against a growing resolver and take about a minute each; a cheaper index in `Resolved` would help the Rust port as well.
