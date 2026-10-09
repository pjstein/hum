# Wave 0 closeout review

2026-10-09. Review of the W0-11 disagreement tail; earlier reviews remain unchanged. This review covers the proposed edits before implementation and will record the final diff review separately. It does not replace the owner's review of security seams before merge.

## Pre-edit findings

1. **Blocker — `chat.md` §2.5 step 4, `JOIN_PENDING` boundary.** The reference treats an earlier record as pending only for an age below 3,600 seconds, but lets its owner commit at age exactly 3,600. At that boundary the first greeter may still commit while the second treats its record as inert. Make own-record usability strictly less than `JOIN_PENDING`, including reuse by a retried ticket; require a fresh sequenced record at or beyond it. Test 3,599, 3,600 and 3,601 seconds. Sequence numbers determine priority; delivery receive times determine age. This aligns the boundary; the duplicate-removal backstop remains necessary for delayed or nonconforming commits.

2. **Blocker — `chat.md` §2.5 no-record backstop and §5.17 expiry/snapshots.** Merely saying that retained expired records count as evidence of a record is insufficient. Expired records can be deleted and must be omitted from snapshots; a new greeter could otherwise treat their absence as proof that an old legitimate member was admitted without a record. Limit this backstop to newly observed Adds after the greeter has current all-members state and an organizers snapshot. Do not infer historical noncompliance from snapshot omission or pruning. Once a record naming the identity was observed for an Add, retain that outcome for that Add even if the record expires or is pruned. No expired nullifier retention or new wire field is needed. Keep the existing identity-only record test for this bounded closeout; the owner's broader identity policy remains open. Required cases: old member seen through a snapshot, a previously observed record subsequently pruned, and a genuinely new Add with no record at 599 and 600 seconds.

3. **Should fix — `release.md` part-record table, R1 and R6.** Keeping `n` in rating part 3 is consistent with the existing field table, but the reference currently only validates the field if present. Explicitly require it on recorded parts 0–3 whenever `nHat` is present and reject a missing field or a CBOR boolean in place of the integer. Rating part 3's value does not decide its unlock: part 3 unlocks with part 0. Below the minimum there is no part 3 record and the surviving part records carry no `n`. Add missing-`n` rejections and a valid rating case where part 3's `n` is below the ordinary map threshold.

4. **Should fix — `services.md` L-6 domains.** Confirming the reference's intended domains also requires making its validators enforce them. CID/session hexadecimal strings must contain valid lowercase hexadecimal digits, date strings must be real dates, non-string enumeration values must reject rather than raise a type error, and a resolver count line must have exactly `cid` and `count`. Each tightened rejection needs a generated vector. Field/type permission does not relax L-1 through L-5 or the owning spec's semantic restrictions: public/noised counts only, fixed host session fields and resource buckets, and no sensitive values hidden in a query-shape string.

   The existing host outcome predicate's 0–255 bound is inconsistent with `verifier-runtime.md`, Exports: true rejection codes span 0–999. Use that bound and test 999/1,000. The host's session opening day is the integer `time.day` value; a general allowance for ISO date strings must not override that owning rule. Host resource fields describe bucketed use, not fine-grained timing.

5. **Note — `release.md` R5 and Vectors; disagreements 20 and 29.** Comparing a rating `groupsK` with the source only when part 0 unlocks resolves R5 versus R7 without changing release bytes. Name `release-valid-rating-nhat-400` and limit its coverage claim to the manifest/unlock record. Parquet group-cell filtering remains a gap.

6. **Note — `services.md` V-4; disagreement 31.** Every evidence-open failure must issue nothing and end the session with `rejected`, rule V-4, including wrong session, request, item name, verifier or malformed ciphertext. Keep the diagnostic detail reference-only; no new protocol error string is needed. Structural binding vectors do not prove HPKE seal interoperability.

7. **Note — `services.md` O-6 and Vectors; disagreement 32.** Keep relay eligibility, uniform selection, retry from remaining eligible relays and no direct fallback normative. Set ordering, the fixed random stream and helper kind names are reference devices, not wire requirements. This adds no new domain-separation label to the protocol and does not broaden the context-relay eligibility list.

The proposed changes preserve the minimum-release floor, one-release accounting, bounded per-person sums, key-based service identity and the separation of chat, credentials and votes. No change to `CLAUDE.md`, `docs/design.md`, owner decisions or primitive/library choices is proposed by this review.

Pre-edit verdict: **approve with fixes** as listed above. Final diff review is pending.

## Final diff review

The fixes above are applied in the reviewed source and generated corpus. The strict own-record interval applies before every Add, including an initial admission; it is not limited to retries. The no-record helper now takes explicit snapshot-readiness and per-Add prior-observation inputs, preserves an observed admission after pruning, and still permits a retained expired record to establish identity existence. Expiry continues to disable duplicate-nullifier removal and snapshot inclusion.

The release reference enforces `n` on recorded parts 0–3 when `nHat` is present and rejects booleans. Generated rating cases reject missing and boolean part-3 `n` at step 10, rule R1. The rating-at-400 vector is explicitly limited to manifest structure; it does not certify Parquet filtering.

The logging reference now checks actual lowercase hexadecimal encodings, real calendar dates, exact host fields, integer host days, outcome codes through 999, safe enumeration types and complete resolver count rows. These are structural checks, not proof that a production log obeys provenance or retention constraints. V-4 generated rejections carry the required rule and code without requiring the reference's diagnostic bytes. Relay random streams remain harness fixtures. The relay helper assumes a shipped list of distinct authorities and a context list already validated under C7; under those inputs it removes overlap between the lists. It is not a validator for duplicate entries in malformed input lists.

Independently checked on disk:

- `uv run --project reference pytest reference/tests/test_chat.py reference/tests/test_services.py -q`: **31 passed in 8.68s**.
- The generated corpus contains **908 accepting and 839 rejecting cases**, counted directly from its JSON files.
- Inspected emitted own-record cases at 3,599/3,600/3,601 seconds, pending-boundary cases, historical-Add and pruned-observation cases, and the retained 397-day-old-record case. The latter keeps the member; historical or pruned absence does not become removal evidence.
- Inspected emitted host date/outcome, rating missing/boolean `n`, and V-4 rejection cases. The changed sets contain `chat/join-records` 32+6, `services/logging` 19+35 and `release/rating` 3+7 accepting/rejecting cases.
- No diff to `CLAUDE.md` or `docs/design.md`. The accepted owner decisions and Open section of `docs/DECISIONS.md` are unchanged; its Adopted section records the reviewed closeout clarifications in ADR 0111.

No remaining blocker in the reviewed closeout changes. Full `just check` and `just sim-fast` are the orchestrator's separate frozen-tree gate; this review does not claim their result. Live MLS, BBS, HPKE seals and Parquet verification remain the documented gaps, and the owner's seam review remains required before merge.

The subsequent docs-only ADR `0111-w0-11-closeout-clarifications.md` accurately records these changes and their limitations. Its Adopted entry does not accept an unanswered owner decision or add behavior beyond the reviewed specs.

Final verdict: **approve**.
