# Review: `docs/specs/verifier-runtime.md` (Draft 0.1, W0-03)

Reviewed 2026-10-06 against `CLAUDE.md`, `docs/design.md`, `docs/specs/manifest.md`, `docs/specs/verifier.md`, `docs/specs/trust-list.md`, `docs/specs/services.md` and decisions 0031, 0035.

Dependencies not yet written at first review: `credentials.md` (the issuance protocol around `decide`, the issuance-time presentation scope). Findings that depend on it are marked.

## Verdict

**First review: approve with fixes.** **Re-review (see the end of this file): approve with two should-fixes.** All blockers are fixed.

## Findings (first review)

### Invariants

**S1 (should fix) — "Exports", rejection code 1 (`duplicate`).** Returning "duplicate" to the phone is an oracle. For the district profile the evidence is a name and address matched against a voter file. Anyone can submit a neighbor's details and learn from code 1 that the neighbor already holds a card, which says they use Hum. Fix: the host returns code 0 (`no match`) to the phone for both no-match and duplicate unless every required evidence item has `kind` `document`, `selfie`, `credential` or `device` (evidence that binds the submitter). Log the true code internally. One vector: district manifest, duplicate decision, expected phone-visible code 0.

**S2 (should fix) — "What the host does with a decision", step 5 and rule 11, `valid-for`.** A per-decision validity becomes a per-person credential expiry. If `credentials.md` discloses expiry as a value, it is a fingerprint across contexts. Require `valid-for` to be quantized to whole days and tell `credentials.md` that expiry is proven as a range ("not yet expired") and never disclosed. Marked as depending on `credentials.md`. Also step 5 says nothing about what happens on violation while rule 11 says "clamped"; make step 5 say clamp.

**S3 (should fix) — "Imports", `evidence.credential`, and "What the module can never reach".** The never-reach list says "any presentation ... none of these exist in the module's inputs", but a `credential` evidence item is a presentation the host verifies. Reword: the module sees disclosed claims of a credential evidence item, never the proof, nullifier or any context-scoped presentation. Then state the issuance-time scope requirement (same as B2 in `reviews/verifier.md`): the nullifier scope is `hum/issuance/1 ‖ verifier authority CID`, distinct from every context scope, so the host cannot join the card to a context. Marked as depending on `credentials.md`.

**S4 (should fix) — "Transparency", host logging rules, vs `services.md` logging table.** This spec says the session log line has exactly five fields and rule 13 tests that. `services.md` line 186 says the issuer host logs "Session ID, profile, result code, the evidence it declared it keeps". Two conformance suites would disagree. Align: adopt this spec's list, add the session ID only if `services.md` needs it for abuse handling, and have `services.md` point here. Also "the module's resource use" is a fingerprint of input size (an image's byte count); round it to buckets.

**N1 (note) — "Transparency", host operator sees "per-day session counts".** Fine, but say the host never writes evidence or dedup rows to any blob store or context store. Invariant 4 forbids personal data in a store request; today nothing in this spec says the host's own evidence storage is not a `put`.

**N2 (note) — "Imports", `evidence.device`.** Verifying a platform attestation requires the host to call Apple or Google. Google then learns that this app instance used a verifier. State it in Security considerations as a known leak of "someone with this device got a card from verifier X", and that the host sends the attestation nowhere else.

**N3 (note) — "Datasets", private commitments.** Leaves are unsalted. Add a per-dataset random salt (held by the host, shared with auditors) mixed into every leaf, so a small roster of emails cannot be confirmed by guessing. See N1 in `reviews/verifier.md`.

### Floors

No field touches a release floor. `valid-for` can only shorten. OK.

### Sums

Not applicable.

### Federation

Hosts are named by `hostKeys`; the platform host and a self-run host are "the same code" and the manifest does not say which. Good.

**S5 (should fix) — "Where code runs" and `hostKeys`.** As in S4 of `reviews/verifier.md`: say what the HPKE host key encrypts. Recommend: the evidence body and the blind request are HPKE-sealed to a listed `hostKeys` entry, and TLS is transport only. Otherwise the manifest-named key binds nothing and a TLS terminator in front of the host reads evidence.

### Consistency

**B1 (blocker) — "Reproducible builds", `parameters`, vs `verifier.md` rule 5.** "The five reference profiles are the same module code with different `parameters`" baked into the build means each configured verifier has different bytes and a different CID. `verifier.md` rule 5 requires `code` ref equal to the `profile` ref, and trust-list `attested` CIDs name one binary. Fix: one fixed binary per profile, built once by the reference operator; configuration comes from `manifest.body` (value sets, bands) and from declared datasets (code lists, rosters, voter files). Keep `parameters` in the recipe only for the reference build and say it is empty for the five profiles.

**B2 (blocker) — "Imports" `dataset.lookup` and "Datasets", public datasets.** `dataset.lookup` returns a record with a Merkle inclusion proof, but a public dataset's commitment is "the blob's CID digest", not a Merkle root, so no proof exists. Fix: public datasets use the same record format as private ones. The blob is the canonical CBOR array of `[key, fields]` records sorted by key; the commitment is the Merkle root over them; `refs["dataset.<name>"]` pins the blob. Then `dataset.lookup` behaves identically for both kinds and the module code does not branch on `kind`.

**B3 (blocker) — "Exports", `decision.dedup-key`, vs `verifier.md` uniqueness profile.** The profile says `device` "adds a second key"; the decision record has one optional key and step 4 checks one. Make it `dedup-keys: list<list<u8>>` (bounded, say ≤ 4), check every key with `dedup.seen`, fail the session if any is seen, and record all of them in step 6. Change `verifier.md` `dedup` to match (see B3 there).

**S6 (should fix) — "The sandbox", CPU limit.** "2 seconds of fuel-metered execution" mixes two units. Fuel is an instruction count and differs per engine. Specify a fuel budget as a number (for example 2 × 10¹⁰ units in Wasmtime's accounting) and keep wall clock as the portable limit. The conformance vector for rule 6 must be an unbounded loop so it fails under any budget.

**S7 (should fix) — "Imports", `time.day`.** A module that calls `time.day` is not a pure function of its declared inputs unless the day is fixed per session. Say: `time.day` returns the UTC day the session was opened, and that day is the day-granular timestamp in the session log, so an auditor replays with the same value.

**S8 (should fix) — "Imports", `util.normalize`.** The open question already says normalizer drift breaks dual-run audits. Recommend removing the import and shipping normalizers inside the reference module, so they are pinned by the code hash like everything else. If kept, add a `normalizers` version string to the build recipe and to the world name.

**S9 (should fix) — "Datasets", record and proof format.** Two implementers will build different trees. Pin down: records sorted by `key` bytewise, duplicate keys invalid; the leaf hash is `SHA-256(0x00 ‖ canonical CBOR of [key, fields])`; interior nodes `SHA-256(0x01 ‖ left ‖ right)` with RFC 9162 split for non-power-of-two sizes; `proof` is the audit path from leaf to root and `index` is the leaf position; the module recomputes the leaf from the key it looked up, not from a key the host returns, so a host cannot substitute a different record with a valid proof.

**S10 (should fix) — "Reproducible builds" vs `verifier.md` "Disclosure summary".** This spec says the summary shows whether a pinned trust list attests the code; the summary has no such field. Add it there or drop the sentence here.

**N4 (note) — "Reproducible builds", `image`.** A bare `sha256:…` digest names no registry. Add `imageRef` (text, informational) beside the digest, or write `image` as `registry/name@sha256:…`.

**N5 (note) — "Reproducible builds", `rejections` and `lang`.** Rejection sentences are shown to the person in whatever language the recipe used. Say they are in the manifest's `lang`, or give the recipe its own `lang`.

**N6 (note) — "Reproducible builds", `parameters: map`.** Key type unspecified for a canonical CBOR blob. Say text keys sorted bytewise, or drop the field with B1.

**N7 (note) — rule 1 vs `manifest.md` step 9.** Rule 1 is enforced by the host at instantiation; the phone enforces the weaker "the `code` ref resolves". Say that the phone also checks the fetched blob hashes to the CID (it must, per the resolver rules) and that it does not instantiate.

### Implementability

**N8 (note) — "The host interface", type names.** `record record { … }` shadows the WIT keyword. Rename to `dataset-record`.

**N9 (note) — "What the host does with a decision", step 4 and `dedup.method: device`.** Step 4 requires a key whenever `method` is not `none`, but for `method: device` the host, not the module, holds the device claim. Say whether the module must echo the device key hash as its dedup key or the host adds it itself. Resolves with B3.

**N10 (note) — vectors and module bytes.** Decision vectors need the Python reference to run WebAssembly components (wasmtime-py with component support) and need up to 16 MiB module binaries. `vectors/` is JSON with hex. Tell W0-08 whether modules ship as separate binary files referenced by CID, and record the runtime dependency in `docs/DECISIONS.md`.

### Testability

The vector list is good. Gaps:

- Rules 12, 13 and 14 have no vector. Add: a session with `kept` 0 evidence and the expected empty host store; a log line with an extra field expected to fail rule 13; a recipe whose `toolchain` differs from the manifest expected to fail rule 14.
- Rules 4 and 5 (undeclared names trap) are listed under instantiation but need a running module; name them under "Host checks" with a module that calls `evidence.get("undeclared")`.
- Add the S1 vector (duplicate shown to the phone as code 0).
- Add a `time.day` replay vector: same inputs, two different host days, decisions differ only if the module uses the day (age band), and the logged day reproduces the decision.
- Add a public-dataset lookup vector once B2 lands.

## Re-review (2026-10-06, revised spec, 244 lines)

**Verdict: approve with two should-fixes.** Both are small and local.

Blocker status:

- **B1 fixed.** "One binary per profile": no build-time parameters, configuration from `manifest.body` and datasets, the recipe has no `parameters` field, and the text names `verifier.md` rule 20e as the rule this makes satisfiable.
- **B2 fixed.** "Datasets" gives one record format and one tree for both kinds; `dataset.lookup` is "same behavior for `public` and `private`"; the public blob is `[salt, record, …]`; rule 15 recomputes the root. The leaf, node, split, path order, index and key-substitution rules from S9 are all stated.
- **B3 fixed.** `decision.dedup-keys` is a list; step 4 assembles module keys plus host-supplied `credential` and `device` keys, checks the count (`host-invalid-dedup`) and fails on any seen key; step 6 records all of them. Matches `verifier.md`'s dedup array.

Should-fix status: S1 (duplicate masking, rule 12, two vectors), S2 (whole days, clamp in step 5 and rule 11, ZK expiry in the assumptions), S3 (never-reach list reworded, issuance scope stated), S4 (log line fixed, `services.md` line 193 and V-4 now defer here, resource use bucketed), S5 (HPKE-sealed payloads), S6 (fuel as a number, wall clock portable, unbounded-loop vector), S7 (`time.day` is the session's opening day and is logged), S8 (`util.normalize` removed), S10 (attestation sentence removed from the phone row) are all in the text. N1 through N10 are addressed, including `dataset-record`, `image` as `registry/name@sha256:…`, recipe `lang`, and the vector-modules note for W0-08.

Remaining findings:

**S11 (should fix) — "Imports", `dedup.seen`.** The host now checks every dedup key itself in step 4, so the import is redundant, and a module that calls it makes `decide` depend on host state. That breaks the determinism claim in "The sandbox" and makes a dual-run audit of a duplicate rejection unreproducible. Remove `dedup.seen` from the host world. If a reason to keep it appears, say that modules calling it are not replayable and that the reference profile binaries never call it.

**S12 (should fix) — "Reproducible builds", recipe encoding.** The paragraph says "canonical CBOR with text keys sorted bytewise" and the table assigns integer keys 0–7. Two implementers will produce different recipe bytes and different `build` CIDs. Pick one. Integer keys match every other body in the protocol.

Notes, no action required for approval:

- The duplicate-masking vector "a uniqueness manifest with a duplicate, expected phone-visible code 1" only holds for the `device` plus `document` plus `selfie` variant. The `device` plus `phone` variant has a required `phone` item, which does not bind the submitter, so rule 12 masks it to 0. Name the variant in the vector.
- Verifying an RFC 9162 audit path needs the tree size. Say the module uses `records` from the manifest as the size.
- The salt reaching the module is stated to be harmless because the module has no write path. That holds as long as `dedup-keys` and `valid-for` stay host-internal and expiry is never disclosed; the spec says both, so it is consistent, but the reasoning deserves one sentence in Security considerations.
- `credentials.md` still does not exist. The issuance scope, the kid-in-presentation assumption and the ZK expiry assumption remain unverified against it.
