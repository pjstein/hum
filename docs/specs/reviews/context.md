# Review: `docs/specs/context.md` (Draft 0.1, W0-01)

Reviewed 2026-10-06 against `CLAUDE.md`, `docs/design.md`, `docs/specs/manifest.md`, `docs/specs/deck.md`, `docs/specs/release.md`, `docs/specs/verifier.md`, `docs/specs/trust-list.md`, `docs/specs/services.md`, `docs/specs/storage.md`, `docs/specs/chat.md`, `docs/specs/issue-map.md`, `docs/specs/agent-sponsor.md`, `docs/specs/take.md`, and decisions 0010 to 0015.

Dependencies not yet written: `credentials.md`, `ballot.md`, `shield.md`. Findings that depend on them say so. I did not guess their content.

## Verdict

**Approve with fixes.** The body is complete, nothing in it names a person, floors are layered correctly, and the rule list is close to vector-ready. Three blockers: a version can drop `rhoYear` and so loosen a floor (C10); policy predicate values are text while every verifier value is a uint, so no policy can match a credential; and the members-only results key is undefined for organizers-only results and unreachable for newcomers. All three are local edits.

## Findings

### Invariants

**B1 (blocker) — "Body fields" keys 13 and 14, "Security considerations", ADR 0011: the results key cannot be derived as written.** Three gaps:

- `resultsKey` for `perms.results` = 2 is derived "from the organizers group" at a "keyring epoch". `storage.md` §4.1 and `chat.md` §1.2 define the keyring and the `keyring/1` export for the all-members group only. The organizers group has no keyring epochs, so `resultsEpoch` has no meaning for it.
- The seed is a separate MLS export (`hum/results-key/1`) taken at the MLS epoch that created keyring epoch k. `storage.md` §4.1 says a past exporter secret is not recoverable later, so every phone would have to run this second export at every keyring-advancing commit, forever, in every context, in case organizers later point `resultsEpoch` at that epoch. Nothing says so.
- Newcomers receive keyring secrets through `keyring-share` (`storage.md` §4.2), which carries `secret_k` only. A member who joins after epoch k can never derive the results private key for releases sealed to epoch k, even though the context's history policy may let them read everything else.

Fix: derive the seed from the keyring epoch secret rather than from a new export: `seed = HKDF-Expand(HKDF-Extract(salt = empty, IKM = secret_k), info = "hum/results-key/1", L = 32)`, then X25519 clamping as ADR 0011 says. Newcomers then get it for free through `keyring-share`, no new `chat.md` label is needed, and the derivation runs on demand. For `results` = 2, either define an organizers-group keyring (new, costs `chat.md` and `storage.md` work) or state that organizers-only results use a key the organizers group exports under its own label at the MLS epoch named by `resultsEpoch`, with the export rule and the newcomer path spelled out. Recommend the first option for members and deferring `results` = 2 to a later draft if the organizers keyring is too much for 0.1. This is a seam (key derivation) and needs owner review either way.

**S1 (should fix) — "Body fields" key 3 `vote`, rule C6, and `services.md` "Ballot intake" step 3.** `vote` may be looser than `entry` ("the protocol only requires that it names a credential"). `services.md` says a ballot carries "a membership presentation under the context's entry policy". If a ballot proves only `vote`, a non-member can vote wherever `vote` is satisfiable without `entry`; if it proves only `entry`, `vote` is dead. Fix: define the effective voting policy as `[1, [entry, vote]]` (both must hold) and say that a ballot proves that conjunction. Then C6 applies to the conjunction. Depends on `credentials.md` adopting it.

**S2 (should fix) — "Entry policy" and rule C6: which leaf yields the nullifier.** The per-context pseudonym and nullifier come from "a credential". A vote policy such as `[2, [ward from tl/0, approved from issuers/0]]` is satisfiable by two different credentials, and nothing says which one the nullifier is bound to. A person holding both could present twice with two nullifiers, which breaks the one-contribution-per-person assumption that every sensitivity in `deck.md` rests on. The design doc accepts sybil risk from weak issuers, but the spec should make the choice explicit. Fix: require the vote policy to contain a designated nullifier leaf (for example, key the leaf as `[3, source, name, pred, 1]` with a flag, or add body key `nullifier` naming a leaf path) that lies on every satisfying path, and make C6 check that instead of "no `true` node". Depends on `credentials.md`.

**N1 (note) — "Body fields" key 11 `chat.organizers`.** Publishing the organizers group ID in a public manifest lets anyone who can observe the delivery service's traffic pattern (the DS already knows group IDs, but a mirror of the log does not) see which group is the organizers'. Group IDs are random and name nobody, so this is not an invariant break. Say in Security considerations that both group IDs are public and what that reveals.

**N2 (note) — "Roles and signing".** The set of organizers is the set of `sign` keys in a logged keyset, so it is public as keys. Fine, but say so, since the design doc's who-sees-what table does not.

### Floors

**B2 (blocker) — rule C10.** "`rhoYear` absent or ≤ prev's `rhoYear` when prev had one" lets version 2 drop `rhoYear` entirely after version 1 set it, which removes the yearly cap. That is a floor loosening by configuration. Fix: "if prev had `rhoYear`, this version has `rhoYear` ≤ prev's." Add vector `context-invalid-C10-drop-rhoyear`.

**S3 (should fix) — "Body fields" key 16 `map`, rule C15, and `issue-map.md` "Rate limits".** `issue-map.md` fixes `UNSIGNED_PER_WINDOW` = 20, `SIGNED_PER_WINDOW` = 60 and `AUTHOR_WINDOW` = 86,400 as protocol constants that a context "may lower, never raise", and the unsigned slot scope is computed at the log with the constant window. C15 only requires the four values to be ≥ 1, so a context can set `unsignedPerWindow` = 1000 or `unsignedWindow` = 60. Fix: C15 caps `unsignedPerWindow` ≤ 20 and `signedPerWindow` ≤ 60, and either drops `unsignedWindow` (the log cannot honor a per-context window in the scope string) or asks `issue-map.md` to read it. `agentObjects` is new and has no enforcer; name the rule (IM-15 per context) or drop it.

**N3 (note) — rule C14 and "`count` (key 15)".** `count.rhoMax` may be as high as `RHO_MAX`. That does not loosen any floor, because the part is inside the plan's total, but it lets an organizer spend the whole release on a daily count. Consider a protocol cap (1/50) so the default of 1/200 cannot be raised 50 times over.

**N4 (note) — rule C13 and "Floors".** A child must be no looser than the parent version it pins. The parent can later tighten (C10), after which the child is looser than the parent's current version. Pinning makes this correct, but say it: the parent relation is checked once, against the pinned version.

**N5 (note) — "The noised daily count".** A deck that is abandoned before release has spent its `count` ρ on the live series, and nothing is logged for it, so `rhoYear` (R14) never sees it. The shield is unaffected (charged at first ballot). Record this as a known gap, or require aggregators to publish a final release version even for abandoned decks.

### Sums

The daily count is a one-hot over day buckets per pseudonym, sensitivity 1 for the whole series. Correct, and it moves to DAP time-interval batches unchanged. One definition problem under Implementability (S9).

### Federation

Logs, aggregators, stores and the delivery service are named by authority CID; witnesses by raw Ed25519 keys; trust lists and the parent by CID. Nothing names a hostname. OK.

### Consistency

**B3 (blocker) — "Entry policy" `pred` values, the example, and `verifier.md` "Attribute".** `pred` `[1, [value, …]]` allows "text or uint values" and the example uses `"ward-1"`. `verifier.md` says every credential value is a uint (`enum` carries `v`, `band` carries the index, `bool` carries 1). A text predicate can never match, and `reference/` cannot generate a consistent policy-evaluation vector. The attribute name is already `ward` on both sides; only the value type is still wrong. Fix: `pred` values are uints only; the example becomes `[1, [1, 2, 3]]`; add the same rule to `deck.md` `breakdown.values` and to `release.md` `breakdown_cells.value` (see those reviews).

**S4 (should fix) — "Conventions", `rat`.** "Not in lowest terms is a canonical-form failure (step 2)". Step 2 is decode, re-encode, compare bytes; a non-reduced `[2, 4]` re-encodes to the same bytes and passes. The check belongs in step 4 (schema). Say so, or define that decoding a `rat` normalizes it so step 2 catches it. Either way add vector `context-invalid-rat-not-reduced`.

**S5 (should fix) — "`agents` (key 17)" `addRole` vs `chat.md` §3.1 and `agent-sponsor.md` "The membership event".** This spec lets moderators (`addRole` = 1) or any member (`addRole` = 2) add a shared agent. `chat.md` hardcodes the `agents` capability to organizers and `agent-sponsor.md` requires "the chat `agents` capability (admin or organizer)". One of the three must change. Recommend `chat.md` reads `addRole` from the pinned context version; otherwise drop the field.

**S6 (should fix) — rule C1 and the `map` and `agents` tables.** C1 lists keys 16 and 17 as required, but both tables give defaults for every sub-key. Either the maps are optional (with the defaults applying when absent) or they are required and the Default columns go. Pick one; implementers will otherwise disagree on whether `{}` is valid.

**S7 (should fix) — `refs["about"]` when `sealed`.** A sealed blob needs a keyring epoch to decrypt (`storage.md` §3, keyring form), and `issue-map.md` carries it as a body field. This spec has no `aboutEpoch`. Add it, required iff `sealed` and `about` present.

**N6 (note) — "The noised daily count" says "Noise is Gaussian"; `release.md` says discrete Gaussian on integers.** Say discrete here too.

**N7 (note) — `services.md` "Opening a deck" cites "context.md's C1 to C14".** This spec has C15. Flag to W0-07.

**N8 (note) — "Roles and signing" mentions "a release-key rotation".** No such manifest exists; a `resultsKey` change is a context version. Reword.

**N9 (note) — `perms.memberList`.** `chat.md` open question 4 says MLS members always see their group's leaves, so this setting can hide a screen but not the tree. Say that here, since this is where organizers set it.

### Implementability

**S8 (should fix) — "Entry policy", `all` nodes over different sources.** The example's `vote` is `all[ward from tl/0, unique from tl/0]`, two attributes from two different verifiers, so two credentials in one proof. Say explicitly that children of `all` may be satisfied by different credentials held by the same prover, and that children of `any` need only one. `credentials.md` needs this stated to build the proof.

**S9 (should fix) — "The noised daily count", day buckets.** "Each UTC day d since the deck opened" and `release.md`'s `count.day` ("days since `opens`") disagree: a calendar UTC day and an 86,400-second window from `opens` give different buckets. Also unsaid: when the last bucket is noised when `closes` falls mid-day, and whether a `closes` extension adds buckets. Fix: `day = ⌊(t_received − opens) / 86400⌋`; the bucket containing `closes` is noised at `closes`; an extension continues the series.

**S10 (should fix) — "Validation rules", rule C5 "predicates well-formed".** Define it: `[1, …]` has 1 to 64 distinct uints; `[2, lo, hi]` has `lo ≤ hi`; `[0]` only on attributes whose type allows "present" (bool, or any). Depth and leaf counts: say whether `[0]` counts as a leaf.

**N10 (note) — `expires` on a context manifest.** Not mentioned. Say it is optional and, if present, gates only new decks pinning this version.

### Testability

The list has one failing vector per rule C1 to C15, which is good. Gaps:

- C5 has at least five sub-conditions (unknown kind, empty children, depth, leaves, bad source index, `lo > hi`); name one vector each.
- C7 has four (gapped `tl/`, unused trust list, equal aggregators, duplicates); C9 has five; C15 has four. One vector each.
- No vector for a `rat` not in lowest terms (S4).
- No vector for the version-2 `rhoYear` drop (B2) or for C10's other four comparisons.
- No policy-evaluation vectors: given a tree and a set of `(authority, attribute, value)` triples, the expected satisfied/unsatisfied result. The tree semantics live here even if the proof lives in `credentials.md`. Suggest `context-policy-eval-*` with the `all`, `any`, range and set cases.
- The daily-count series (S9) needs a deterministic vector: ballot timestamps in, bucket increments out, with noise supplied as input as `release.md` does.

## Summary for the author

Fix B2 (one clause in C10) and B3 (uint predicate values, same change in `deck.md` and `release.md`) now; both block vectors. B1 needs a decision with W0-05 and W0-06 on where the results key comes from; the HKDF-from-`secret_k` route needs no new label and reaches newcomers. S1 and S2 are requests to `credentials.md` that this spec should state as requirements rather than assumptions.

## Re-review (2026-10-06, after the author's fixes)

Read the whole spec again, plus ADRs 0010 and 0011 and `storage.md` §9.1.

**Resolved.** B1 (results key now HKDF from `secret_k`, `results` = 2 rejected by C12), B2 (C10 requires `rhoYear` to persist and shrink), B3 (uint predicates, example `[1, [1, 2, 3]]`), S1 (effective voting policy is the conjunction), S2 (`nullifier` body key and C6), S3 (`map` counts capped at the constants, window removed), S4 (`rat` in step 4), S6 (`map` and `agents` optional with defaults), S7 (`aboutEpoch`, C12), S8 (`all` across credentials), S9 (bucket formula, close mid-bucket, extension), S10 (C5 spelled out), N1 to N10 (all addressed in text), and the vector list now has one case per sub-condition plus policy-evaluation, daily-count and results-key vectors.

**The results key, checked.** `seed = HKDF-Expand(HKDF-Extract("", secret_k), "hum/results-key/1", 32)` with X25519 clamping. A non-member cannot reach it: `secret_k` exists only on phones present at the commit that created keyring epoch k or that received it in `keyring-share`, and the exporter secret is never sent anywhere. The aggregators hold the public key only and cannot invert X25519. The derivation is domain-separated from the blob key in `storage.md` §4.3 (different salt and different `info`), so no blob key equals the seed. `secret_k` is 16 bytes, so the private key has 128 bits of entropy, which matches the rest of the profile.

**New blocker — rule C6 rejects the spec's own example.** C6 says the nullifier leaf must be "a direct child of its top-level `all`" in the effective policy `[1, [entry, vote]]`. In the example the nullifier leaf (`unique`) is a child of `vote`, which is itself a child of the top-level `all`, so it is a grandchild and C6 fails. `context-valid-sealed-parent` would be rejected by a literal implementation. Fix: "the nullifier leaf is reachable from the root of the effective policy through `all` nodes only (no `any` on the path)". That is the property the text wants ("every satisfying presentation includes that credential") and it is what the invalid vector "nullifier leaf only under an `any`" already tests. One sentence.

**S11 (should fix) — "The results key": members should verify it.** Only members can check that `resultsKey` equals the derivation from `secret_k`; the ledger and non-members cannot. An organizer quorum could publish a key whose private half they hold outside the keyring. They can read results anyway as members, but it would survive their removal. Add: a member phone that holds epoch `resultsEpoch` MUST recompute `resultsKey` and, on mismatch, refuse to treat the context version as valid and warn. Add a failing vector `context-results-key-mismatch`.

**N11 (note) — `resultsEpoch` under `keyringHistory` = 1.** A newcomer who receives only the current epoch cannot open releases sealed to an older `resultsEpoch`. Say that organizers should republish `resultsKey` at the current epoch after each removal when `keyringHistory` is 1.

**N12 (note) — ADR 0010 item 7 still calls `hum/results-key/1` an "exporter label".** ADR 0011 now says it is an HKDF `info` string. Align 0010, and ask W0-06 to reword `storage.md` §4.4's reservation the same way.

**N13 (note) — `agents.addRole` still disagrees with `chat.md` §3.1 and `agent-sponsor.md`.** The spec now says so in its differences list, which is the right place; it stays open for the cross-spec pass.

**Updated verdict: approve with fixes.** One remaining blocker (C6 wording), one should-fix (S11), both one-line edits.
