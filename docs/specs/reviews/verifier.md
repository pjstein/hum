# Review: `docs/specs/verifier.md` (Draft 0.1, W0-03)

Reviewed 2026-10-06 against `CLAUDE.md`, `docs/design.md`, `docs/specs/manifest.md`, `docs/specs/context.md`, `docs/specs/deck.md`, `docs/specs/services.md`, `docs/specs/trust-list.md`, `docs/specs/verifier-runtime.md` and decisions 0031–0035.

Dependencies not yet written at first review: `credentials.md`, `release.md`, `ballot.md`, `agent-sponsor.md`. Findings that depend on them are marked. I did not guess their content.

## Verdict

**First review: approve with fixes.** **Re-review (see the end of this file): approve with one should-fix.** All blockers are fixed in the revised spec.

## Findings (first review)

### Invariants

**B1 (blocker) — "Profiles", rule 5, and "Refs" `profile`.** Rule 5 says a profile verifier's `code` ref MUST equal its `profile` ref. `verifier-runtime.md` ("Reproducible builds") says the five reference profiles are "the same module code with different `parameters`" baked in at build time, and the invite example bakes in "the code list's hash". Baked parameters change the bytes, so every organizer's invite verifier has a different `code` CID and rule 5 can never pass, and trust-list `attested` CIDs never match. Fix: one fixed binary per profile; all configuration goes in the manifest body (the module already gets `manifest.body`) or in a declared dataset. Say so in both specs. Secret inputs like one-time codes and rosters become `private` datasets with a commitment, never build parameters.

**B2 (blocker) — "Evidence item", the `credential` kind, and "Dedup" `method: credential`.** Both are underspecified in ways that two implementers would resolve differently, and one resolution breaks invariant 2:

- Which cards are accepted is "named in `purpose` and in `datasets`". `purpose` is free text shown verbatim; a phone cannot parse it to choose which card to present, and a host cannot verify against it. Add a structured field to the evidence item, for example key 7 `accepts: array of {authority: CID, attributes: array of text}`, and validate it (non-empty when `kind` is `credential`).
- The presentation made at issuance needs a nullifier scope that is unique to this verifier and never equal to any context scope, or the issuing host and a context could join the same card. State the requirement here, since this spec introduces the mechanism, and name the scope for `credentials.md` to adopt, for example `hum/issuance/1 ‖ verifier authority CID`. Marked as depending on `credentials.md`.
- Define the dedup key for `method: credential`: it should be that scoped nullifier and nothing else.

**B3 (blocker) — "Profiles", uniqueness row, and "Dedup".** The uniqueness profile says "`device` adds a second key", but `dedup` has one `method` and one `field`, and the runtime's `decision.dedup-key` is a single optional byte string. `method: device` is listed but has no `field` semantics (rule 13 only covers `evidence` and `credential`). Fix: make `dedup` an array of `{method, field, scope}` (bounded, say ≤ 4) or define `method: device` as "also key on the device claim" with a matching `dedup-keys: list` in the runtime decision record. Both specs must change together.

**S1 (should fix) — "Validation rules", closing paragraph, and "Issuer key".** The assumption list says a presentation carries the issuer `kid`. Every active key partitions holders into a visible cohort across every context they present in, and the cohort narrows with each rotation. Bound it: at most two `active` issuer keys at once (rule), rotate on a declared cadence, and record the leak in Security considerations. Also tell `credentials.md` that credential expiry must be proven in zero knowledge as "not expired", never disclosed as a value, because the runtime lets `valid-for` shorten validity per decision and a disclosed expiry would be a per-person fingerprint.

**S2 (should fix) — "Disclosure summary", `expires`, and "Validation rules" closing paragraph: assurance mix in releases.** "Releases carry the assurance mix of their voters." `deck.md` lists eight release parts and none is an assurance or verifier histogram. An exact count per `(verifier, assurance)` published beside noised tallies is an unnoised sum of per-person one-hots; with a rare verifier and the 100-voter minimum it exposes individual membership. Either make it a noised part with its own ρ in the release plan (it is already a sum of bounded per-person vectors, so it moves to two-server aggregation unchanged) or publish only the accepted-set rows from the context version, which come from manifests and cost nothing. Flag to W0-01 for `release.md`.

**S3 (should fix) — "Validation rules" closing paragraph, class `agent`.** "Voting policies accept only `person`" is delegated to `credentials.md`, which does not exist. A context can name a `class: agent` verifier directly in `issuers[]` and nothing in `context.md` rule C5/C6 or `trust-list.md` resolution step 3 filters it. Put the rule where resolution happens: a row from a verifier whose `class` is `agent` never satisfies the `vote` policy. See the matching finding in `reviews/trust-list.md`.

**N1 (note) — "Dataset", private commitments.** A Merkle root over unsalted `[key, fields]` records lets anyone holding the root and a few sibling hashes confirm guesses against small rosters of emails or phone numbers. Recommend a per-dataset 32-byte random salt mixed into every leaf, with the salt held by the host and given to auditors with the records. Belongs in `verifier-runtime.md` "Datasets"; noted here because `commitment` is defined here.

### Floors

No field in this spec can loosen a protocol floor or spend budget. `validity` ≤ 366 days and `kept` ≤ `validity` + 30 days are the only bounds and they are enforced by rules 11 and 15. OK.

### Sums

Only S2 applies. Breakdown values reach the aggregator as per-person disclosed values beside the ballot; `deck.md` part 7 already treats them as bounded one-hot sums. OK once S2 lands.

### Federation

Hosts are named by `hostKeys`, location hints are unsigned, datasets are pinned by CID or commitment, `code.source` and `toolchain` are informational text with the hash binding. OK.

**S4 (should fix) — "Host key".** The host key is HPKE but `services.md` says evidence travels over direct TLS, and nothing says what the HPKE key encrypts. If evidence is only TLS-protected, any TLS terminator in front of the host (the platform's edge, a CDN) reads it, and the manifest-named key does not bind the session. State that session payloads (evidence and the blind request) are HPKE-sealed to a listed `hostKeys` entry and that TLS is transport only. This makes invariant 6 hold for issuance.

### Consistency

**S5 (should fix) — attribute names and value types vs `context.md` and `deck.md`.** `context.md` ("Entry policy" table and the example) and `deck.md` (vector `deck-valid-breakdown`) use attribute `district` with text values `"ward-1"`. This spec issues `ward` as an `enum` whose values are uints `v`. A text predicate can never match a uint value. The assumption list says W0-01 "has been told", but the files on disk still disagree. One side must change and the predicate value type must be fixed as uint for `enum`, `band` and `uint` attributes. Also `deck.md` names the breakdown attribute as `{source, name, values}` (a policy-leaf source), while this spec's assumption says `release.md` names it by `(verifier authority, attribute name)`. Align on the policy-leaf form.

**S6 (should fix) — "Attribute", `uint` type.** The table says `values` is "absent for `bool` and `uint`", then the next paragraph puts a `uint` attribute's `max` in `values[0].hi`. Add a separate key `max` (uint, required for `uint`, absent otherwise) and validate it.

**S7 (should fix) — "Attribute", `band` and `bool` value semantics.** The runtime says a `band` value is "a band index" but this spec never says whether the credential carries the index or the `lo` bound. Fix: the value is the 0-based index into `values`. For `bool`, a policy predicate `[0]` (present) on `invite` is satisfied by a credential carrying `invite = 0` unless the spec says bool attributes are issued only when true. Say that: a `bool` attribute is present in a credential only with value 1, or require policies to use `[1, [1]]`. Flag to `context.md`.

**S8 (should fix) — "Validation rules" rule 7 and rule 22.** Rule 7 requires unique labels but not unique `v`. Add: `v` values are unique within an attribute, and for `band` the index is the value so order is frozen. Rule 22 should say the `(v, label)` pairs of the previous version are present unchanged (labels may be edited? decide; recommend frozen `v`, editable `label`).

**S9 (should fix) — rule 24.** "No issuer key ID from any previous version is reused" needs the whole lineage, but step 10 compares only to `prev`. Either require every kid ever used to stay listed (as `verify-only` or in a new `retiredKids` array) so the check is `prev`-local, or state that the verifier walks the lineage and that `reference/` does the same.

**S10 (should fix) — text limits.** `text ≤ 64`, `≤ 140` etc. do not say bytes or characters. `context.md` conventions fix UTF-8, NFC, no control characters, byte limits. Adopt the same sentence here and in `trust-list.md`, or two implementations will disagree on a 140-character purpose with multibyte text.

**N2 (note) — "Terms" and "Validation rules": retired lineages.** This spec relies on "an unretired version" but `manifest.md` assigns no envelope key for retired or successor markers (`context.md` raised the same gap). Say what happens to credentials when a verifier lineage retires (they stop verifying at the next presentation) and depend on the manifest spec fixing the key.

**N3 (note) — "Revocation".** `period` is required to equal `validity` (rule 14), so it carries no information. Drop it or let it be shorter than `validity` to mean "renew early".

**N4 (note) — "Attribute" `status`.** Nothing says whether `deprecated` can go back to `active`. Decide (recommend: no) and add it to rule 22.

**N5 (note) — size bounds.** No maximum on the number of attributes, evidence items, datasets, issuer keys, host keys or enum values. The 64 KiB envelope bounds them indirectly, but parsers want explicit limits. Suggest attributes ≤ 32 (matches `MAX_POLICY_LEAVES`), evidence ≤ 16, datasets ≤ 16, keys ≤ 8 each, values ≤ 1024.

### Implementability

**S11 (should fix) — "Disclosure summary".** Vectors require a client to "produce exactly these fields", but the rendering rules are not deterministic: `keptFor` as "n days" or "n months" (threshold? 180 days became "6 months" in the example), `expires` "in days or months", `learns` rows with the verifier name interpolated, the `who.assurance` label in English regardless of `lang`. Either give exact rules (days unless divisible by 30 days, then months; sentences are English in vectors and localized by the app) or make the vector fields structured (`keptFor: {seconds}`, `expires: {seconds, renewal: "reissue"}`) and leave prose to the UI. The second is better: it keeps localization out of conformance.

**S12 (should fix) — "Disclosure summary" vs `verifier-runtime.md` "Reproducible builds".** The runtime says the summary shows "whether any pinned trust list attests" the code CID. The summary table here has no such field. Add `code.attestedBy: [trust-list authority CIDs]` computed from the context's pinned lists, or drop the sentence in the runtime spec.

**N6 (note) — "Dataset", `public` commitment.** "The blob's CID digest" is 32 bytes without the algorithm byte, and the same CID is in `refs`. Add a rule that `commitment` equals the digest of `refs["dataset.<name>"]`. See `reviews/verifier-runtime.md` for the larger problem that `dataset.lookup` cannot return Merkle proofs for a plain blob.

**N7 (note) — "Issuer key" `key` length.** Rule 3 checks the suite name but not the key length. Add per-suite lengths once `credentials.md` fixes the suite (BBS over BLS12-381 G2 is 96 bytes compressed).

### Testability

The vector list covers rules 1–24 with one failing case each and adds useful extras. Gaps:

- Rule 24 needs a three-version lineage vector (kid used in v1, dropped in v2, reused with a different key in v3).
- Rule 20 has five sub-rules; name one failing vector per sub-rule.
- Rule 7 has three sub-conditions (two values, unique labels, ascending non-overlapping bands); name one vector each.
- Disclosure summary vectors cannot be generated until S11 is decided.
- No vector exercises an `agent`-class verifier; add one valid `agent` manifest and one check that it yields no `vote` row (with S3).

## Re-review (2026-10-06, revised spec, 440 lines)

**Verdict: approve with one should-fix.** Every blocker and every should-fix from the first review is addressed in the text on disk. Cross-spec claims were checked against the files, not the author's summary.

Blocker status:

- **B1 fixed.** "Code" says a module takes no build-time parameters; "Refs" and rule 20e say `code` equals `profile` and that one fixed binary per profile exists. `verifier-runtime.md` "One binary per profile" matches and its recipe has no `parameters` field. Codes and rosters are private datasets.
- **B2 fixed.** Evidence item key 7 `accepts` is structured and validated by rule 13. The issuance scope `hum/issuance/1 ‖ verifier authority CID` is defined in "Evidence item" and the label is unique across the specs on disk. The `credential` dedup key is the issuance-scope nullifier. `credentials.md` still does not exist, so the scope and the kid-in-presentation assumption remain unverified against it; the assumption list states both plainly.
- **B3 fixed.** `dedup` is an array of up to four items with per-method key definitions; rule 14 checks field kinds; the uniqueness profile declares two items. `verifier-runtime.md` step 4 assembles the matching key list.

Should-fix status: S1 (two active keys, cohort leak recorded, expiry proven in ZK), S4 (HPKE-sealed payloads), S6 (`max` key), S7 (bool present only when true, band is index), S8 (unique `v`, positions frozen), S9 (`retiredKids`, rules 24–26 are `prev`-local), S10 (byte limits, NFC), S11 (structured summary, prose out of conformance), S12 (attestation moved out of the summary) are all in the text. S2 is resolved by `release.md` R12, which lists accepted verifiers with manifest-declared assurance, not per-voter counts. S3 is resolved by `trust-list.md` resolution rule 5 plus `context.md` C15, both on disk. S5 is resolved: `context.md` line 193 and its example, and `deck.md` line 232, now use `ward` with uint values.

Remaining finding:

**S13 (should fix) — "Validation rules", closing paragraph, and "Issuer key".** `minVersion` now depends on "the version a `kid` first appeared in", found "by walking the lineage". A phone evaluating a vote policy would have to fetch every historical version of each accepted verifier, which is a network dependency at presentation time and a lookup-privacy cost (`manifest.md` open questions). Add a `since: uint` field to each issuer key (the version that introduced it) with two `prev`-local rules: a `kid` present in both versions has the same `since`, and a new `kid` has `since` equal to the current version. Then `trust-list.md` step 4 reads `since` from the version in force and never walks. One failing vector each.

Notes, no action required for approval:

- The scope string should say whether "verifier authority CID" is the raw CID bytes (algorithm byte plus digest) or the text form. Recommend raw bytes, matching how `issue-map.md` scopes concatenate CIDs.
- `retiredKids` ≤ 64 allows about 16 years of two keys rotating every six months. Fine for draft 0.1; say what a lineage does when it fills (retire and name a successor).
