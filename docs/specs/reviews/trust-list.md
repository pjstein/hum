# Review: `docs/specs/trust-list.md` (Draft 0.1, W0-03)

Reviewed 2026-10-06 against `CLAUDE.md`, `docs/design.md`, `docs/specs/manifest.md`, `docs/specs/context.md`, `docs/specs/verifier.md`, `docs/specs/verifier-runtime.md` and decision 0034.

Dependencies not yet written at first review: `credentials.md`, `agent-sponsor.md`. Resolution step 3 and the agent-list sentence depend on them.

## Verdict

**First review: approve with fixes.** **Re-review (see the end of this file): approve.** The blocker is fixed; one should-fix lives in `verifier.md`.

## Findings (first review)

### Invariants

**N1 (note) — "Entry" and "Removal" `note` fields.** `publisher` says "not a person's name"; `note` does not. A 140-byte free-text note is where "reviewed by Jane Doe" will end up. Add the same sentence and a vector that shows a note is opaque text.

No field links identities. A list sees no credential and no session. OK.

### Floors

No field touches a release floor. `minAssurance` can only raise acceptance strictness. OK.

### Sums

Not applicable.

### Federation

Entries name authorities by CID with algorithm byte `0x01`; nothing names a hostname. The core list is "nothing distinguishes the operator's lists from anyone else's except who signed them". OK.

### Consistency

**B1 (blocker) — "Entry" `minVersion` and resolution step 3.** A credential carries an issuer `kid`, not a verifier version. The step-3 check compares the row's minimum against "the verifier version the credential's issuer key appears in", and step 4 says that is the version in force at presentation. So once a verifier publishes version 2 and keeps kid K active, every credential issued under version 1 with kid K passes `minVersion: 2`. The example ("Version 1 had a dedup flaw, fixed in version 2") expects the opposite. Fix: define `minVersion` against the key: a credential satisfies the row only if its issuer `kid` first appeared in a verifier version with number at least `minVersion`. Add to `verifier.md` that fixing a flaw requires a new issuer key, and add a vector: kid introduced in v1, `minVersion` 2, expected not accepted.

**S1 (should fix) — resolution step 2 vs step 5.** Step 2 expands an empty `attributes` array into "one row per attribute the verifier's current version declares"; step 5 says the accepted set "is fixed once the context version is logged". These disagree whenever a verifier adds an attribute. Say that rows are `(authority, attribute filter, minAssurance, minVersion)` with the filter either a name set or "all", and that "all" is evaluated against the verifier version in force at presentation. That is the intended behavior and is what step 4 already implies.

**S2 (should fix) — resolution, class filtering.** `scope.classes` filters the list as a whole but nothing checks an entry's verifier `class` against it, and nothing filters a `class: agent` verifier named directly in `context.md` `issuers[]`. Add two resolver rules: an entry whose verifier's `class` is not in `scope.classes` yields no rows; a row from a `class: agent` verifier never satisfies the `vote` policy. The second is where "agents never vote" is enforced structurally rather than left to `credentials.md`.

**S3 (should fix) — "Removal" and rules 6 and 11.** The field description says `removed` is "cleared in the version after" but no rule requires it. Decide: either rule 12 "every `removed` authority was in the previous version's `entries`" (so stale removals fail) or say stale entries are allowed and ignored. The first makes the log cleaner and is one vector.

**S4 (should fix) — rule 9 and all text limits.** "140 characters" here, "text ≤ 64" elsewhere, bytes in `context.md`. Adopt `context.md`'s convention (UTF-8, NFC, no control characters, byte limit) in the Body fields section.

**S5 (should fix) — rule 8 limits.** 512 entries at roughly 250 bytes each is 128 KiB, twice the envelope limit, so the rule is unreachable. State 256 so the limit is honest, or say the envelope bound governs and keep 512 as a parser bound only.

**N2 (note) — `lang`.** Declared BCP 47 but no rule validates it. Either validate the shape (`^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$`) or mark it informational.

**N3 (note) — "Taking effect" and `expires`.** The envelope's `expires` is not mentioned. Say whether a list may carry one and what a context does when its pinned list version expires (recommend: nothing; the context version pins it, and expiry on a list is informational).

**N4 (note) — "How a context uses trust lists", step 1.** A single authority in `issuers[i]` is accepted at assurance 0 and version 1. That is intended for organizer-run invite verifiers; say so, because a context that names a core verifier directly in `issuers[]` bypasses the core list's assurance floor.

### Implementability

**S6 (should fix) — resolution output format.** Vectors promise "the expected accepted-set rows" but the row encoding is prose. Give the vector row shape, for example `[authority CID text, attribute name or "*", minAssurance, minVersion, classes]`, sorted bytewise, so two resolvers can be diffed.

**N5 (note) — step 3 "attribute names exist in the verifier's current version".** A list naming an attribute the verifier does not declare makes the row inert. A context whose policy leaf then matches no row is unsatisfiable, and `context.md` rule C5 does not catch it. Suggest the organizer tooling warns; no protocol rule needed.

**N6 (note) — `attested` and B1 of `reviews/verifier.md`.** Attestation only works if each profile is one fixed binary. If `verifier-runtime.md` keeps baked parameters, no organizer's invite verifier can ever be attested by the core list.

### Testability

The vector list covers rules 1–11 and adds three good edge cases. Gaps:

- The `minVersion` vector from B1.
- An `agent` list resolving to zero `vote` rows (with S2).
- A removal that is also still in `entries` (rule 6) is listed; add the stale-removal case if S3 picks the strict option.
- The resolution vector depends on three verifier manifests and a context manifest from other workstreams; name which valid vectors from `verifier.md` and `context.md` it reuses so W0-08 can build it once.

## Re-review (2026-10-06, revised spec, 207 lines)

**Verdict: approve.**

Blocker status:

- **B1 fixed.** Entry `minVersion` is defined as "its issuer `kid` first appeared in a verifier version numbered at least this"; resolution step 4 checks exactly that; the example explains why the old key must be retired; `verifier.md` "Issuer key" requires a new `kid` when a flaw is fixed. The vector list has the kid-in-v1 against `minVersion` 2 case and its accepted counterpart.

Should-fix status: S1 (rows with `"*"` filter, expansion at presentation time, step 3), S2 (class in every row, step 4 class check, rule 5 for `vote`), S3 (rule 13, strict), S4 (byte limits, NFC), S5 (256 with rule 10 naming the envelope as the real bound), S6 (row shape and bytewise sort) are all in the text. N1 through N4 are addressed. `context.md` C15 and the `ward` spelling the spec now relies on are on disk; `agent-sponsor.md` exists and agrees that voting policies accept only `person`.

Carried over: the one remaining should-fix is S13 in `reviews/verifier.md`. Step 4 of this spec reads "the version in which the credential's issuer `kid` first appeared in the lineage", which today requires walking the verifier lineage. If `verifier.md` adds a per-key `since` field, change that bullet to read `since` from the version in force. No change to this spec is needed for approval.

Note: `credentials.md` still does not exist, so the assumption that a presentation carries the issuer `kid` is unverified. Step 4 cannot be evaluated without it.
