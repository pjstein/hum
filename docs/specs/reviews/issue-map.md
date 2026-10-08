# Review: `docs/specs/issue-map.md` (Draft 0.1, W0-04)

Reviewed 2026-10-06 against `CLAUDE.md`, `docs/design.md`, `docs/specs/manifest.md`, `docs/specs/context.md`, `docs/specs/deck.md`, `docs/specs/release.md`, `docs/specs/chat.md`, `docs/specs/storage.md`, `docs/specs/services.md`, `docs/specs/verifier.md`, `docs/specs/trust-list.md`, `docs/specs/take.md`, `docs/specs/agent-sponsor.md`, and decisions 0041, 0042, 0043, 0010 and 0015.

Not on disk: `credentials.md`, `ballot.md`, `shield.md` (W0-02). Findings that depend on them are marked. I did not guess their content.

## Verdict

**Approve with fixes.** The four authorship forms, the per-object scope for signed authors, the per-slot scope for unsigned authors and the per-object edit key are the right shape. Nothing in the body links a vote, a hand or a shield to anyone, and no sealed key appears in a manifest. Five blockers below are local edits plus two cross-spec alignments (with `chat.md` and `context.md`). None needs a redesign.

Answers to the questions the lead asked:

- The `hum/author-once/1` and `hum/author-slot/1` scopes cannot be linked to the voting pseudonym or the chat name as long as `credentials.md` delivers nullifiers that are unlinkable across scopes. The prefixes differ from every ballot scope. The two residual leaks are B2 (slot proofs are not bound to the object, so they can be replayed) and S1 (a signed object publishes a cross-context stable key).
- The edit key links nothing beyond the lineage, which already links versions. See S4 for the multi-device gap.
- The signing key is settled: this spec says the chat identity key (`chat.md` section 2.1 `identity`), and `chat.md` agrees in its Terms and section 6. `chat.md` open question 12 is stale and should be closed.
- Enum encoding: this spec uses text, W0-01 and `chat.md` use uints. See S9.

## Findings

### Invariants

**B1 (blocker) — "Body" (`author` frozen) against "States and moderation" and IM-6, IM-9, IM-11.** `author` is marked frozen, and "the proof's form must match it" (IM-6). A moderation version is published by the context authority with `signatures` in place of `authorship`. So version 2 of a member-authored object cannot both keep `author` = `member` (frozen) and match the authority proof form (IM-6). Every `im-ok-authority-activate` style vector is unsatisfiable as written. Fix: `author` names the lineage's author and stays frozen. Add a separate rule: a version whose bundle carries the context's `sign` threshold and no `authorship` is a moderation version, allowed only when `moderation` is set and `version` > 1. IM-6 becomes "the bundle matches `author`, or the version is a moderation version". IM-9 becomes "`moderation` present iff the version is authority-signed and `version` > 1". IM-11's "unless `author` = `authority`" becomes "unless the version is a moderation version". Keep `author` = `authority` for objects the context writes at version 1.

**B2 (blocker) — "Membership proofs", the slot scope, and services.md "Submitting a manifest".** The unsigned form's proof has scope `hum/author-slot/1 ‖ context ‖ window ‖ slot` and nothing binds it to the object CID. Bundles are public (the resolver serves them with their `authorship`). Anyone who fetches an unsigned object's bundle holds a valid membership proof for that `(window, slot)` and can attach it to an object of their own: in a second log the context names (IM-7 is per log), or in the same log by submitting first and burning the honest author's slot. The second case lets a non-member publish as "some member". Fix: the membership proof primitive must take a bound message beside the scope, in the way Semaphore binds a signal. Set the message to `hum/author/1 ‖ object CID` for both proof forms. State it here as the requirement on `credentials.md`, and add IM-6 text: "the proof's bound message equals `hum/author/1` ‖ this CID". Marked as depending on `credentials.md`.

**B3 (blocker) — "Body" key 7 `origin`, against `chat.md` sections 5.4 and 6.** The two specs disagree on what `origin` is. This spec: "Message ID (as `chat.md` defines it)". `chat.md`: "the quoted message's franking tag". Two implementers produce different bytes. The franking tag is the wrong choice for privacy: the delivery service sees the tag in `authenticated_data`, the log sees the tag in the body and the chat identity key in the bundle, and `chat.md` section 12.9 promises the delivery service never learns who sent a message. With the tag as `origin`, an operator running both learns the sender, group, sequence number and time of every promoted message. The MIMI message ID is computed from the plaintext and a random salt the delivery service never sees, so it reveals nothing to it. Fix: keep this spec's definition (message ID), and ask W0-05 to change `chat.md` 5.4, 6 step 2, the Terms table and the `chat/promote` vector to match.

**B4 (blocker) — "Authority and authorship", "Rate limits" and the open question "Admitted agents in public contexts", against `context.md` keys 16 and 17.** This spec says "`context.md` has no per-context overrides in draft 0.1" and asks for an agent policy. `context.md` on disk has both: `map` (`unsignedWindow`, `unsignedPerWindow`, `signedPerWindow`, `agentObjects`) and `agents` (`anySponsor`, `sponsors`, `addRole`). Three consequences:

- IM-15 must read limits from the pinned context's `map`, not from protocol constants. Say which wins when they differ. Recommendation: the constants are ceilings and the effective limit is the smaller of the two, because `context.md` rule C15 only requires the fields to be at least 1 and would otherwise let a context raise them.
- `context.md` caps agents at `map.agentObjects` per context across all sponsors; this spec caps per sponsor at `rateLimits.mapObjects`. Both must hold. Say so in IM-15.
- IM-6's agent case should check the sponsor's authority against `ctx.agents` (`anySponsor`, or listed in `sponsors`). Anyone can check it, including logs, so the open question closes and non-members stop seeing proposals from agents the context never admitted. Then drop "Members additionally require ... kind 2 leaf" or keep it as a second, members-only check.

**B5 (blocker) — IM-6, unsigned form: "`window` within one window of the verifier's clock".** Phones run IM-6 when they sync (the "Validation rules" paragraph says so). A phone syncing a two-day-old object rejects it under this clause, and two implementations with different clocks disagree. `manifest.md` also says `issued` is "never trusted for ordering", yet `window` derives from `issued`. Fix: the clock check runs at the log on submission only; on sync a phone checks `window` against the log entry's checkpoint time (within one window) or skips the clause. Say which. Note the burst: an author may use windows w−1, w and w+1 at any moment, so the instantaneous cap is 60, not 20. Say that is accepted or tighten to the current window.

**S1 (should fix) — "The four forms", member form, and "Security considerations".** The chat identity key is one key per person across every context (`chat.md`, Terms). A signed object puts that key in a public bundle, in members-only contexts too. Anyone who knows the key from one place (a public context's signed object, a shared safety code) learns the person is a member of every context where they signed, including sealed ones. Fix: say it in Security considerations and on the privacy screen, or derive a per-context signing key from the chat identity key and have members verify the derivation inside the group. The second is a `chat.md` change; raise it with W0-05.

**S2 (should fix) — "Membership proofs": "The membership group for authoring is the same admitted set as for voting."** `context.md` separates `entry` (chat, map, files) from `vote`, and its roles table says members author issue-map objects. Authoring should prove the `entry` policy. Two problems follow: an `entry` policy of `[0]` (anyone) has no credential leaf and so no nullifier, which makes the slot form impossible in open contexts; and `context.md` rule C6 only forbids `true` nodes in `vote`. Say which policy authoring proves, and what the unsigned form does when `entry` yields no nullifier (fall back to signed only, or require a credential for unsigned authoring). Marked as depending on `credentials.md`.

**S3 (should fix) — IM-3.** The pinned context version decides `perms.cards` (IM-10) and `sealed` (IM-5). Nothing requires it to be current. An author pins an old version with `cards` = 2 and lands `active` in a context that now says 1. Fix: `refs.context` must be the latest version of the context lineage logged before the object, or at least IM-10 reads `perms.cards` from the latest version at the object's log position.

**S4 (should fix) — "Edit keys".** The edit key is "kept on the author's phone". The chat identity key moves between devices through the backup `credentials.md` owns, but nothing says the edit keys do. A person with two phones cannot revise or withdraw from the second, and a lost phone leaves only the context authority able to act. Say whether edit keys travel in the same backup, or derive each one from a per-person secret and the object's first-version inputs so any device can recompute it.

**N1 (note) — `lang`.** BCP 47 allows private-use subtags of any length, which is a covert channel into a public manifest. Bound it as `verifier.md` does: text ≤ 16, pattern `^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$`.

**N2 (note) — Rate limiting the member form.** Counting `SIGNED_PER_WINDOW` per chat identity key means the log keeps every signing key for a window. `services.md`'s logging table forbids keeping "authorship proofs ... beyond the per-log nullifier set issue-map.md requires". Say the log keeps `(chat identity key, count)` for one window and nothing longer, so the table can name it.

### Floors

This spec spends no budget and loosens no floor. Annotations are post-processing. The authoring limits are not privacy floors, but the spec says a context may only lower them; see B4 for how `context.md` fails to enforce that.

### Sums

Nothing here feeds a release. Annotations read noised sums by CID. OK.

### Federation

The context, logs and stores are named by key. The Global lineage is a shipped constant. OK.

### Consistency

**S5 (should fix) — IM-7 and IM-15 are "per log".** A context names up to 8 logs. The same person can spend slot `(w, 3)` once in each, so the real unsigned cap is 20 × logs, and the signed cap 60 × logs. Fix: a phone that syncs from several logs rejects a nullifier it has seen under a different CID in any of the context's logs (earliest log position wins) and counts IM-15 across them. Say that the log-side check stays per log.

**S6 (should fix) — `refs.parent`, `replaces`, `mergedInto` as lineage CIDs.** `manifest.md` says refs name versions. These three name version 1 CIDs, which are versions, so the letter holds, but nothing rejects a version 2 CID used as a parent. Add to IM-2 and IM-11: these refs MUST resolve to a manifest with no `prev`. Add vector `im-bad-parent-not-v1`.

**S7 (should fix) — IM-4 at the log.** `services.md` says logs do not resolve blobs. The log cannot check the first byte of the sealed blob, the media type or the text length. Split IM-4 into the part a log runs (refs and `epoch` present and consistent) and the part a phone runs (blob bytes), and say so in the "Validation rules" paragraph that asks logs to run IM-1 to IM-5.

**S8 (should fix) — IM-10 and the active caps.** "Beyond `MAX_POSITIONS_ACTIVE` ... new objects land `proposed` regardless of policy" is not in IM-10, and the count depends on log position. Add it to IM-10 with the count defined as active children at the object's log position in the submitting log.

**S9 (should fix) — Enum encoding.** `kind`, `author`, `state`, `moderation` are text. `context.md` conventions say enumerations are uints; `chat.md`'s `promote-proposal` already numbers kinds 1 position, 2 pro, 3 con, 4 sub-question; this spec's own `authorship.form` is a uint. Recommendation for the cross-spec pass: uints everywhere, with `kind` numbered to match `chat.md` (add 0 or 5 for `issue`). Flag for W0-10, with `take.md`, `agent-sponsor.md`, `verifier.md` and `trust-list.md` in the same decision.

**S10 (should fix) — Text limits in scalar values.** W0-01 and W0-03 limit text in bytes. This spec counts Unicode scalar values with a four-times byte bound. Pick one unit across the protocol. `chat.md`'s `promote-proposal` text is 2,000 bytes while an argument is 1,000 scalars; fine because the author edits, but say it.

**N3 (note) — `authorship` key 3 `scope`.** The scope is derivable from the CID (signed form) or from `(context, issued, slot)` (unsigned form). Carrying it invites a mismatch. Either drop it and carry `slot` as a uint, or require the verifier to recompute it and reject a difference. Also say CID bytes are the 33-byte form (algorithm byte plus digest) wherever a scope or signed payload includes one.

**N4 (note) — `services.md` bundle table.** It says `signatures` is "empty for participant-authored types". The authority form uses `signatures` and no `authorship`. Tell W0-07.

**N5 (note) — IM-11 reparenting against IM-12.** After an object is dealt, `parent` is frozen, so an argument under a merged, dealt position cannot move. Say which rule wins (IM-12).

### Implementability

**S11 (should fix) — The dealt test (IM-12).** "Any deck manifest version logged before the new version's log position" needs a definition of "logged" across several logs, and an index from object version to the decks that pin it. Say: dealt in a log when a deck pinning the version has a lower leaf index in that log; a phone treats an object as dealt if any of the context's logs says so. Say the log builds the index from the envelopes it keeps.

**S12 (should fix) — Annotation labels.** "The noise-aware consensus test from the research pipeline passes" is not a rule two implementers reproduce. Write the test out with `take.md`'s σ_p formula and z values, say what happens with one group (no `group_tallies`), and fix binary64 and the order of clamping, as `release.md` does for round computations.

**N6 (note) — `im-dup-detect`.** The token-set ratio at 0.8 is "the reference implementation's" and "clients may do better", so it cannot be a conformance vector. Either make the normalization normative (NFKC, case fold, tokenization) or mark the vector informative.

**N7 (note) — Authority-authored version 1.** `editKey` is required and frozen. Say who keeps the key for an object the context authority writes (any organizer phone, or none, with later versions always authority-signed).

### Testability

The list has one failing vector per rule and the bundle encodings. Gaps:

- B1: `im-ok-authority-activate` needs a member-authored version 1; add `im-bad-moderation-form-mismatch` (authority signature with `moderation` absent).
- B2: `im-bad-proof-unbound` (a valid slot proof from another object's bundle).
- B3: the `chat/promote` vector and `im-ok-argument-pro-member-origin` must agree on the `origin` bytes.
- B4: `im-bad-agent-not-admitted` (sponsor not in `ctx.agents`), `im-bad-rate-limit-context` (over `ctx.map` but under the constant).
- S3: `im-bad-stale-context-version`.
- S5: a two-log case for IM-7 and IM-15.
- S6: `im-bad-parent-not-v1`.
- N1: `im-bad-lang`.
- IM-12 vectors need a deck and leaf indexes as inputs; say so.

## Summary for the author

Fix B1 and B5 in this spec. B2 is one sentence here and a requirement on `credentials.md`; raise it with W0-02 now because it changes the proof primitive. B3 needs W0-05 to change `chat.md` to the message ID. B4 is reading `context.md` keys 16 and 17 as they exist. Then settle S2 and S9 with W0-01 and W0-02 before W0-08 generates vectors.

## Re-review (2026-10-06, revised draft, 416 lines)

Re-read the revised spec in full, ADR 0042, `chat.md` (881 lines) and `release.md` (316 lines) as they are now.

**Status of the first-round findings.** B1 fixed: the moderation-version rule is stated once in "The four forms" and applied consistently in IM-6, IM-9 and IM-11, and a moderation version may change only `state`, `moderation`, `mergedInto` and (for reparent) `parent`. B2 fixed: both proof forms carry the bound message `hum/author/1 ‖ CID`, `authorship` no longer carries the scope, and `im-bad-proof-unbound` exists. B3 fixed and confirmed on the other side: `chat.md` sections 5.1, 5.4, 6 and 11.1 now say `origin` is the message ID and say why. B4 fixed: limits come from `ctx.map` with protocol ceilings as the smaller-wins rule, both agent caps hold, and IM-6 checks `ctx.agents`. B5 fixed: the clock check runs only at the log and the doubled burst is stated and accepted. S1 to S12 and N1 to N7 are all addressed; S1 and the per-context signing key remain an open question for `chat.md`, which is the right place. Enums are uints and `kind` numbering matches `chat.md`.

**New findings on the new text.**

**B6 (blocker) — "Edit keys", the derivation.** The edit secret is `HKDF-SHA256(IKM = edit root, salt = "hum/edit-key/1", info = version 1 CID)`. The version 1 CID hashes the body, and the body contains `editKey` (key 2). The public key therefore depends on the CID and the CID on the public key, so no version 1 can be built, and the `im-edit-key-derive` vector cannot be generated. Fix: use as `info` something fixed before the edit key is chosen and recoverable from the logged object. Recommendation: `info` = SHA-256 of the canonical envelope bytes with body key 2 removed. Every device can recompute it from the logged version 1 by stripping key 2 and hashing. Keep the salt as the domain string. Cross-device and cross-context linkage are fine either way: the output is a PRF of a secret root, so two public keys reveal nothing about sharing a root, and the root never leaves the backup.

**S13 (should fix) — "Membership proofs", `window` and `ctx.map.unsignedWindow`.** The effective per-window counts have ceilings, but the window length has no floor. `context.md` C15 only requires `unsignedWindow` ≥ 1, so a context can set a 60-second window and give every member 20 unsigned objects a minute. Add `UNSIGNED_WINDOW_MIN` = 86,400 to the constants table and define the effective window as the larger of the context's value and the floor. Also note that changing `unsignedWindow` changes every slot scope, so a tightening hands everyone a fresh set of slots once; say that is accepted.

**N8 (note) — "Membership proofs", last paragraph.** "The membership group for authoring is the context's admitted set, which is also what votes prove" sits under a section that now says authoring proves `entry` and votes prove `vote`. Reword to "the `entry` set; ballots prove `vote` under different scopes".

**N9 (note) — `chat.md` section 9.** It still says phones enforce "`messages` and `proposals` limits"; section 3.3 of the same spec already says proposals count under `messages`. Stale sentence for W0-05, not this spec.

**Testability.** The vector list now has one failing case per rule including the new IM-4b split, two-log cases, the bound-message case and the context-limit case. After B6 is fixed, `im-edit-key-derive` needs the stripped-envelope input spelled out.

**Updated verdict: approve with fixes.** One blocker (B6, a derivation that cannot be computed) and one should-fix (S13, a missing floor on the window). Both are a few lines. Everything else from the first round is closed.
