# Review: `docs/specs/chat.md` (Draft 0.1, W0-05)

Reviewed 2026-10-06 against `CLAUDE.md`, `docs/design.md`, `docs/threat-model.md`, `docs/specs/manifest.md`, `docs/specs/storage.md`, `docs/specs/context.md`, `docs/specs/services.md`, `docs/specs/issue-map.md`, `docs/specs/agent-sponsor.md`, `docs/specs/deck.md`, `docs/specs/release.md` and decisions 0050–0052.

Dependencies not yet written: `credentials.md` (context membership proof, chat identity backup), `ballot.md` and `shield.md` (the structures the `no-votes` scan looks for). Findings that depend on them are marked. I did not guess their content.

## Verdict

**Rework, limited to section 12 (the delivery service) and the missing admission flow. Sections 1 to 11 and 13 to 16 are approve with fixes.**

The MLS profile, the credential, franking and the content types are close to buildable. Three problems in the delivery service are structural: a member or a removed member can permanently brick a channel with one invalid commit (B7), the per-channel token issuer key is handed to one device and never checked by the others, which lets the DS turn tokens into device identifiers (B6), and the only path a joiner's KeyPackage handle is assumed to take runs through a verifier, which would join a resident card to a chat identity (B8). Everything else is a local edit or a cross-spec alignment.

## Findings

### Invariants

**B1 (blocker) — Terms, §5.4, §6, §11.1, §15: `origin` is the franking tag, and that lets the DS identify senders.** `issue-map.md` body key 7 says `origin` is the message ID. This spec says it is the franking tag (Terms, §5.4 key 3, §6 step 2, §11.1 last paragraph). The two specs disagree, and this spec's §17 claims they agree. The franking tag is the wrong choice on privacy grounds, not only consistency: the DS stores every tag beside its `group_id`, `seq` and `received` time (§12.8), and a signed issue-map object is logged in public with the author's chat identity key in the bundle's `authorship` (`issue-map.md`, "The four forms"). Joining the two tables tells the DS, and anyone who obtains its data, that this chat identity key sent a message in that group at that time. That is the "who sent it" column of §12.9 and the "who sees what" table in `docs/design.md`. The message ID has no such join: it is a salted hash whose salt lives inside the ciphertext. Fix: `origin` = the 32-byte MIMI message ID, matching `issue-map.md`, `promote-proposal.source` and `promote-confirm.proposal`. Phones in the channel verify `origin` against the ID they computed for the quoted message. Update Terms, §5.4, §6 step 2, §11.1, §15 and §17 together.

**B8 (blocker) — §2.4, §17 assumptions: the admission flow is undefined, and the assumed route breaks invariant 2.** §2.4 says a KeyPackage handle travels "inside an existing MLS group, a QR code, or the admission flow that `context.md` defines". §17 assumes that flow is "part of its invite and approval verifiers". `context.md` ("Open questions", "Admission flow") refuses ownership and says it belongs here. So no spec defines how a joiner who is in no group yet gets a handle to a greeter. The assumed route is unsafe: an invite or approval verifier sees the joiner's evidence, and a KeyPackage carries the chat identity key and display name, so a verifier that relayed handles would hold the resident-card side and the chat side of one person. Fix: define the flow in this spec and state the rule that a handle MUST NOT pass through any party that sees issuance evidence. A workable shape that fits the existing pieces: a per-context join inbox at the DS, written with a context token (§12.2 already issues these against the membership proof), holding the handle HPKE-sealed to a context greeting key published in the `roles` message; devices with `members` or `join-open` poll it. The DS learns only that some member of the context asked to join. Mark it `seam: what leaves the phone`. Depends on `credentials.md` for the proof.

**B6 (blocker) — §12.3, §12.4: the per-channel issuer public key reaches only the registering device.** `POST /v1/channels` returns `issuer_key`. Nothing delivers it to the other members, who need it to verify the VOPRF proof in every `TokenResponse` (RFC 9578 §5). A DS that answers each device's first `channel-tokens` call with a different key makes every token from that device verifiable under a key only that device holds, so sends and fetches become linkable per device. That is the "which token belongs to which member" column and the "who fetched" claim of §12.9, and the key-consistency attack `storage.md` §6.1 already defends against for stores. Phones cannot check the HKDF derivation because they do not hold the master secret. Fix: the creator puts `issuer_key` in the channel's `directory` entry (§5.9), every phone verifies token responses against that key only, and a phone that sees a different key from the DS stops using the channel and shows a warning. Add a failing vector: token response under a key that differs from the directory entry.

**S1 (should fix) — §12.4: multi-use tokens link up to 60 sends.** "A token is spent on one `send`" and "60 sends ... per token" contradict each other and `services.md` T-1. A token that authorizes 60 sends is a 60-message session identifier, so the DS learns that those messages share a device, and with timing across channels it narrows who. Issuance is cheap (64 per request). Fix: one token per send, one token per fetch session of at most 15 minutes, and say the fetch session is the one place a token spans several requests.

**S2 (should fix) — §12.5, §12.9: two leaks are missing from the metadata table, and the table goes past the design doc.** `revoke_prior` tells the DS which commits are removals, so it sees join and leave events separately, not just churn. Long-poll fetch sessions under one token each tell the DS how many devices are online in a channel at once. Add both to §12.9 and the "remaining leaks" paragraph. Separately, §12.9 is wider than the `docs/design.md` row ("ciphertext, timing, which channel" / "content, the member list"): the DS also learns which context every channel belongs to, the message class, the epoch rate, Welcome counts and issuance counts. The threat model's row is closer but omits the context. Per `CLAUDE.md` the spec wins; flag the disagreement to the owner and update the design and threat-model rows rather than narrowing the table.

**S14 (should fix) — §5.7, §8: a sealed reference in public issue-map text.** §8 says citing a file on the map "puts the reference in the object's sealed text". In a context whose `sealed` is false the text blob is public (`issue-map.md`, "Sealed text"), and a direct-form reference carries the file key. Say: in a public context the author first makes a public copy (§5.7 `public-copy`) and cites it as `evidence/<n>`; only sealed contexts nest references. Also, §5.7's rule that a `public-copy` sender must be the `added_by` of a folder version has no answer for a plain chat attachment; say "the sender of the message or folder operation that first carried the reference".

**N8 (note) — §5.11: handles in `join-request` expose delete secrets to every member.** The handle carries the KeyPackage blob's delete secret, and the all-members group holds everyone. Any member can delete a requester's KeyPackages and stall their join. Cheap to repeat, cheap to recover from, but say so, or seal the handles to the greeting key from B8.

**N10 (note) — Terms, §2.1: one chat identity key for all contexts.** The key, device ID and safety code are global, so two contexts that share a member can be joined by anyone in both. The design doc describes one chat name, so this is a design choice, not a bug, but it should be stated in §15 next to open question 4, which already points at per-context pseudonymous credentials.

Votes, hands and shields: no Hum type has a field that could carry one, `deck-dealt` and `release-digest` carry no numbers and are not trusted, and the `no-votes` scan is the right check. OK, pending `ballot.md` and `shield.md`.

### Floors and sums

Nothing in this spec reads or writes ρ, δ, voter minimums, caps or a shield, and nothing feeds a release. `deck-dealt` hints are explicitly untrusted. Floors and sums do not apply. OK.

### Federation

The DS is named by authority in `chat.delivery`; stamps are checked against a keyset; `senderUri` and `roomUri` are key- and group-derived; `ExternalPart.url` is a CID. OK.

**S4 (should fix) — §12.1, §11.3 step 4: which key stamps.** This spec says "any `sign` key of its keyset" with a `key_id`; `services.md` `service` body key 10 `stamp` is a single dedicated Ed25519 key. Pick one. Step 4's "keyset in force at the stamp time" selects a keyset by time, which `manifest.md` forbids ("log order decides; the `issued` time never does"). A stamp is never logged, so there is no log position. Fix: a stamp verifies if its `key_id` names a key in any logged keyset version of the DS authority that is not revoked at the verifier's latest witnessed checkpoint; carry `key_id` in the report (see B5).

### Consistency

**B2 (blocker) — §5.1 vs `storage.md` §3.2: `ExternalPart.url` bytes differ.** This spec: "`url` is the bare CID text form (`c` followed by base32)". `storage.md` §3.2: "`hum:blob:` followed by the CID text form". Two implementers produce different bytes and reject each other's attachments. Pick one in both files; `hum:blob:` is consistent with `hum:member:` and `hum:channel:` and gives the phone a scheme to match. Also fix `storage.md`'s pointers to "`chat.md` §4.6" and "§4.5" (now §5.1) and "§7" (now §10); note for W0-06.

**B3 (blocker) — §1.2 vs `storage.md` §4.1 and ADR 0050: the `keyring/1` export differs.** This spec: context `uint64_be(k)`, length 32. `storage.md`: context empty, length 16, "the ones `chat.md` §1.2 fixes". ADR 0050: 16 bytes. Two phones derive different keyring secrets. Pick one and change the other file. Recommend `storage.md`'s (empty context, 16 bytes, MLS epoch already distinguishes exports) since its vectors assume it, and keep this spec's statement that it is HKDF input only.

**B4 (blocker) — §5.7 vs `storage.md` §5.2: nobody defines the folder operation bytes.** This spec: payload is "exactly the operation map of `storage.md` §5.2: `op, entry, parent, name, kind, ref, target, as_of`" with ops `add, rename, move, version, delete, index`. `storage.md` §5.2: "`file-op` fields (`chat.md` §5.7): `v, op, file, name, path, prev, origin` plus one `ExternalPart`" with seven numbered ops including `pin` and `unpin`, and §5.5 wants a separate `folder-index` announcement that this spec does not have. Each spec says the other owns the bytes. Fix: this spec owns framing, so define the map here with integer keys and the seven ops `storage.md` lists, add `application/hum.folder-index+cbor` (or fold the announcement into a `folder-op` op 8 `index` carrying a direct-form reference), and have `storage.md` §5.2 cite the table. Also align the right names: this spec has `files-write` and `files-manage`; `storage.md` §5.3 has `files-write` and `files-delete-any`.

**B9 (blocker) — §3.1, §9 vs `agent-sponsor.md` "Capabilities": the agent capability names disagree in both directions.** This spec says sponsor capabilities are `read, post, propose, digest, author-map, take` and that `agent-sponsor.md` "defines no greeting or archiving capability". `agent-sponsor.md` defines `post, greeter, history, author-map, take`, says `post` covers proposals and digests, and says it adopted `greeter` and `history` from this spec. Neither `propose`, `digest` nor `read` exists there. The agent column's intersection is therefore undefined and the `chat/roles` vectors cannot be generated. Fix: adopt `agent-sponsor.md`'s five names, map `post` to this spec's `post`, `propose` and `digest`, `greeter` to `join-open`, `history` to `history`, and delete the sentence that says the capabilities do not exist. Also §3.1 gives `digest` to members while §7 says "an organizer, or a shared agent"; make them agree.

**S3 (should fix) — §12.1, §12.7 vs `services.md` "Errors" and media types.** Error codes here are `bad_request`, `too_large`, `rate_limited`, `epoch_conflict`, `not_padded`; the common table uses `malformed`, `too-large`, `rate-limited`, `conflict`, hyphenated, as RFC 9457 problem details under `urn:hum:delivery:<code>`. Use the common codes with `detail` strings `not-padded` and `epoch`. Media types: this spec uses `application/hum.<name>+cbor`, `application/hum.ds+cbor`, `application/hum.history+cbor-seq`; `storage.md` and `services.md` use `application/vnd.hum.*`. Pick `vnd.hum.` everywhere.

**S7 (should fix) — §1.2, §2.1, §2.2, §5.8, §11.1, §12.4, §12.5: domain strings are not namespaced.** Strings here: `keyring/1`, `delivery/1`, `device/1`, `safety/1`, `chat-roles/1`, `frank/1`, `pp-issuer/1`, `token-request/1`, `welcome/1`, `stamp/1`. Across all specs no two strings are equal and none is a prefix of another, so there is no collision today. But `issue-map.md`, `services.md`, `verifier.md` and `context.md` use `hum/…/1` while this spec, `storage.md`, `release.md` and `manifest.md` do not. Rename this spec's strings under `hum/` (for example `hum/frank/1`, `hum/stamp/1`, `hum/chat-roles/1`) and keep the table in §1.2 as the one place that lists every exporter label, including `hum/results-key/1`. Raise the convention with the cross-spec pass; `manifest/1` is the only one that is expensive to change.

**S10 (should fix) — §10: `storage.history` governs keyring delivery.** `context.md` now has `storage.keyringHistory` (key 4) for that, separate from message history. Point `keyring-share` at `keyringHistory` and leave `history` for archives.

**S11 (should fix) — §5.6, §7: `deck-dealt.context` and when `release-digest` is sent.** "Must equal the group's context" is ambiguous: decks pin a context version, and the context may have moved on. Say "a version of the context lineage the group belongs to". `release.md` publishes several release versions ("One release, several versions") and `services.md` says the context posts the digest once it holds the final version's proof. Say whether one `release-digest` per version is allowed and what phones deduplicate on (recommend: final version only, dedup on release lineage and group).

**S12 (should fix) — §2.1 key 4 vs `agent-sponsor.md` key 7.** `name` is 1 to 64 bytes; an agent's `label` is up to 40 scalar values, which can be 160 bytes. Raise `name` to 256 bytes or cap `label` in bytes.

**S15 (should fix) — §5.10: the store token-key gossip has no carrier.** `storage.md` §6.1 and `services.md` ("Tokens follow storage.md §6.1 exactly") require phones to post each service's current `token_key_id` in the all-members channel. No content type here carries it (`storage.md` A2 asks for one). Add an optional key to `checkpoint`: `4: tokenKeys map of service authority CID to key id`, or a new `token-keys` type.

**S16 (should fix) — §5.12 vs `agent-sponsor.md` "The membership event".** This spec: `runtime` 1 `member-hardware`, 2 `enclave`. That spec: field `runs` with 1 phone, 2 member hardware, 3 enclave. Same bytes, two names, two codings. Fix in both; this spec's is right since a personal agent is never a leaf.

**N3 (note) — §17 open question 12 is stale.** `issue-map.md` on disk already says the chat identity key, not the leaf key. Close it.

**N5 (note, for W0-01) — `context.md` "Where this spec and its siblings differ" says this spec calls the group `chat_group`.** It does not; it uses `chat.allMembers`.

**N11 (note) — §5.1 `encAlg` 1.** A MIMI client that read `encAlg` 1 would attempt one AES-128-GCM over the whole file with `nonce` and `aad`; Hum's blob is chunked with derived nonces and the `sealed/1` AAD. Say that `encAlg` 1 here means "Hum sealed format 1" and that interop with non-Hum MIMI decryptors is not a goal.

### Implementability

**B5 (blocker) — §11.3: a report as defined cannot be verified.** Step 4 checks the stamp "over the same group, sequence, time and `authenticated_data`", but the `report` map has no `seq`, no `received` and no `key_id`. Step 2 checks the `FramedContent` signature under `leaf_key`, but for a member sender the signed `FramedContentTBS` includes the `GroupContext` of that epoch (RFC 9420 §6.1), which a moderator who is not in the channel does not have. Fix: add `seq uint`, `received uint`, `key_id bstr` and `group_context bstr` (the TLS-serialized `GroupContext`) to `report` and to the history record in §10.1, and say the moderator rebuilds `FramedContentTBS` from them. Note that `group_context` reveals the channel's tree hash and transcript hash to the organizers group, which is acceptable and should be stated. Also §10.1 says `AuthenticatedContent` carries a "membership tag"; it does not for `PrivateMessage` (that tag belongs to `PublicMessage`); it carries the signature and, for commits, the confirmation tag.

**B7 (blocker) — §12.5: any member, or a removed member within 48 hours, bricks a channel.** The DS advances its epoch on any accepted commit without being able to validate it. A member sends a syntactically fine commit that honest phones reject (bad credential, no capability) with any `next_secret`. Honest phones stay on epoch `e`; the DS now holds `e+1` and rejects every honest message as `epoch_conflict`, and no honest commit for `e` can ever be accepted again. §12.4 says a removed device can only do harmless things; this is not harmless, and a removed device's leftover token suffices. Fix, in order of preference: (a) stop treating DS epoch state as authoritative: the DS sequences every message and accepts commits for the current epoch and the previous one, phones apply the first valid commit in sequence order and skip invalid ones (the RFC 9750 pattern for a non-validating DS), and the DS accepts the delivery secret from the last `k` commits in sequence order for token issuance; or (b) keep one-commit-per-epoch and define a recovery: a device presents the delivery secret of the honest epoch to reset the DS's epoch, with the reset itself sequenced. Either way, add a row to §15 and a `chat/ds-api` vector: an invalid commit followed by a valid one.

**S5 (should fix) — §4.3, §12.5: what gets padded, and how a Welcome is padded.** §4.3 pads "the serialized `PrivateMessage`"; §12.5 sends "the serialized `MLSMessage`", which adds a version and wire-format prefix, so the two differ by a few bytes and only one can land on a bucket. Say which. §4.3 also puts Welcomes in buckets up to 1 MiB, but a `Welcome` has no padding field. Define it (for example: the `welcome` byte string is the TLS-serialized `Welcome` followed by zero bytes to the bucket, and the receiver parses the `Welcome` and ignores the tail) or exempt Welcomes and say the relay's O-3 padding is what covers them. Also say whether a commit that adds several members stores one `Welcome` under several handles or one per joiner; RFC 9420 allows one `Welcome` for all, and its `secrets` list exposes every joiner's `KeyPackageRef` in the clear to the DS, which is fine but should be in §12.9.

**S6 (should fix) — §12.4: the issuer key derivation is not the RFC's.** "HKDF ... L = 48, reduced to a P-384 scalar as RFC 9578 prescribes" is not what RFC 9578 prescribes; it points to `DeriveKeyPair(seed, info)` of RFC 9497 §3.2, which uses hash-to-scalar with a counter and is unbiased. A 48-byte reduction mod the group order is slightly biased and two implementers will not match. Fix: `seed = HKDF-Expand(master, "hum/pp-issuer/1" ‖ group_id, 32)`, then `DeriveKeyPair(seed, info = group_id)` per RFC 9497 for the P-384 suite RFC 9578 names.

**S8 (should fix) — §5.8, §5.9: serial ties and snapshot semantics.** "The highest `serial` wins" has no rule for two messages with the same serial from two `channels` holders, which will happen. Tie-break on DS sequence order of the all-members group. Say that a `snapshot` replaces the whole list and later ops apply on top, and what a phone does with an op whose `serial` is below the snapshot's.

**S9 (should fix) — §3.3, §9: agent rate-limit windows are unanchored.** "Per window, counted in channel order" needs a window boundary every phone computes the same way. Say: window index = `floor(received_ms / 1000 / window)` using the stamp time, and that phones count only messages with a stamp.

**S13 (should fix) — §1.3: removal from channels with no `members` holder.** MLS lets only a member of a group commit to it. If no device with `members` is in a channel, a removed person stays able to decrypt it. Either require that every channel contains at least one organizer or moderator device (and have `channels` holders check it at create) or state the limitation in §15.

**S17 (should fix) — §2.1 step 3: commit processing depends on a log fetch.** Validating an agent Add requires resolving the sponsor manifest with proofs. An offline phone cannot, and "reject" would split it from the group. Say the phone holds the commit as pending until the bundle resolves, and that the committer includes the sponsor bundle CID in `agent-membership` so phones can fetch it through the relay.

**S18 (should fix) — size limits.** No bounds on `roles.grants`, `overrides`, `channel_grants`, `directory.channels`, `join-request.handles`, `deck-dealt.from_here`, `welcomes`, or the credential `identity` as a whole. Add explicit maxima so parsers agree before the 64 KiB bucket does it for them.

**S19 (should fix) — §12.5: strict epoch equality on application messages.** MLS senders legitimately emit application messages for epoch `e` for a short time after a commit to `e+1` lands, and receivers keep old keys for that reason. Rejecting them as `epoch_conflict` forces a retry storm after every commit. Accept the current epoch and the one before for application messages and proposals; keep strictness for commits (subject to B7).

**N2 (note) — §4.2, §5.2: "reject" for an application message.** For handshake, reject means stay on the old epoch. For an application message that fails a frank check or re-encoding, say "drop it and do not render it", and whether it still consumes a `seq` for folder ordering (it must, since the DS already assigned one).

**N7 (note) — §2.1 key 5.** The binding covers the leaf key, device ID and kind but not the group ID, so one leaf key and binding can be reused across groups despite "per device, per group" in Terms. Harmless; either bind the group or drop the per-group claim.

**N12 (note) — §12.3.** The `limits` map keys ("channels per context", "bytes per channel") are not named anywhere; `services.md` leaves `limits` as "see Rate limits" with no schema. Name them here.

**N1 (note) — §2.2.** The safety code uses SHA-512 where everything else uses SHA-256; fine, but say why or switch. The modulo of a 40-bit value by 100000 has negligible bias.

### Testability

The vector list is good in shape. Gaps:

- `chat/credential` needs: `authenticated_data` of the wrong length; a kind 2 leaf whose sponsor `tier` is `public`; an expired sponsor.
- `chat/frank` needs the report round trip once B5 lands, including a report with a wrong `group_context`.
- `chat/tokens` needs the B6 case (issuer key differs from the directory entry) and an RFC 9497 `DeriveKeyPair` vector (S6).
- `chat/ds-api` needs the B7 sequence (invalid commit then valid commit) and a `revoke_prior` sequence.
- `chat/padding` needs one vector that fixes S5 (bucket measured on `MLSMessage` or `PrivateMessage`) and one Welcome.
- `chat/directory` and `chat/roles` need a same-serial tie (S8).
- `chat/agent-limits` needs a window-boundary case (S9).
- `chat/content/*` needs `deck-dealt` with a context from another lineage and `release-digest` whose deck does not match the release.
- No vector covers the §3.3 application-message ignore list beyond agents and promotion: add muted sender, `replaces` by another key, `moderate` from a sender without the capability.
- No vector covers `join-request` or the Welcome handle derivation.
- Several vectors (`chat/exporter`, `chat/roles` commit matrix, `chat/frank` with real `AuthenticatedContent`) need live MLS group state. `reference/` is Python; which MLS implementation generates them needs an ADR in `docs/DECISIONS.md` before W0-08 starts.

## Summary for the author

Do B7, B6 and B8 first; they change section 12 and add an admission section, and the lead should see the new design before vectors. Then the local blockers: B1 (`origin` is the message ID), B2 (`hum:blob:`), B3 (`keyring/1` parameters), B4 (own the folder-op bytes), B5 (report fields), B9 (agent capability names). B2, B3, B4 need matching edits in `storage.md` and B9 in `agent-sponsor.md`; file one note in `docs/decisions/` naming both owners for each. S1, S2 and S4 change what the threat model says about the DS and should land in the same pass.

---

# Re-review (2026-10-06, after rework)

Re-read the reworked `chat.md` (881 lines) in full, plus `storage.md`, `agent-sponsor.md`, `context.md`, `services.md`, `issue-map.md` and ADR 0051 as they are now on disk. §2.5 (admission) and §12 (non-validating DS) got a fresh adversarial read, not a diff check.

## Updated verdict

**Approve with fixes.** Section 12 no longer needs a redesign: the non-validating DS with first-valid-commit-wins is the right shape and the first-draft bricking attack is gone. Four blockers remain. Each is a local edit with a clear fix, but each must land before W0-08 generates vectors, because each changes bytes or lets a protocol rule be bypassed.

## Status of the first-round blockers

| Item | Status | Evidence |
| --- | --- | --- |
| B1 `origin` = message ID | Resolved | §5.1, §5.4, §6 step 2, §11.1, §15 all say message ID; `issue-map.md` key 7 and "Promotion from chat" agree |
| B2 `hum:blob:` | Resolved | §5.1; `storage.md` §3.2 table and reverse rule agree |
| B3 `keyring/1` | Resolved | §1.2 empty context, 16 bytes; `storage.md` §4.1 and A4 agree |
| B4 folder-op bytes | Resolved | §5.7 owns `file-op` (7 ops, keys 0–6) and `folder-index`; `storage.md` §5.2, §5.3 and §5.5 cite it; rights are `files-write` and `files-delete-any` in both |
| B5 report verifiability | Resolved in this spec, reopened cross-spec | `report` carries `seq`, `received`, `group_context`, `key_id`, `ds`; step 2 rebuilds `FramedContentTBS`. But step 4 depends on a `stamp` field `services.md` now says does not exist (R1 below) |
| B6 issuer key in directory | Mostly resolved; one gap | `directory` key 8, `roles.issuer_keys`, phones verify VOPRF proofs against it (§12.5). The gap is the all-members group's own key (R3 below) |
| B7 channel bricking | Resolved in design; one rule inverted | DS sequences everything, phones skip invalid commits, commits need a MAC under a held secret, organizer reset exists. The held-secret expiry rule as written still lets a removed member expire the honest secrets (R2 below) |
| B8 admission flow | Defined; one hole | §2.5 keeps the KeyPackage away from every verifier. The ticket carries no membership proof, so any member can admit anyone (R4 below) |
| B9 capability names | Resolved | §3.1 and §9 use `post`, `greeter`, `history`, `author-map`, `take`, matching `agent-sponsor.md` "Capabilities" on disk |

All nineteen should-fix items from the first round are addressed in the text. S1 (one token per send), S5 (bucket on `MLSMessage`, Welcome zero-tail), S6 (`DeriveKeyPair`), S8 (serial ties, snapshot semantics), S9 (window index), S10 (`keyringHistory`), S11, S12 (`name` 256 bytes), S13 (organizer device per channel), S14, S15 (`token-key`), S17 (pending sponsor resolution), S18 (array maxima), S19 (epoch grace) are each in place.

## Remaining blockers

**R1 (blocker) — §11.2, §11.3 step 4, §12.1, §12.6, §17 vs `services.md` "Services are named by key".** This spec now says the DS stamps with "the `stamp` key of its `service` manifest (body key 11)" and step 4 resolves `ds` to the manifest version that holds it. `services.md` on disk says the opposite: "There is no `stamp` field: the delivery service stamps with any `sign` key of its keyset and names the key in each response". The two specs have swapped positions since the first round. Report verification cannot be implemented until one wins. Either is sound; a dedicated `stamp` key is cleaner because a keyset `sign` key also signs `manifest/1` and `hum/service-request/1`. Pick one, change the other spec, and keep step 4's rule that the key must come from a logged manifest in the lineage `chat.delivery` names.

**R2 (blocker) — §12.6 "Held secrets" and "Why this cannot brick a channel": the expiry rule is keyed on epoch number, so a dead branch outlives the honest one.** A secret is usable "while it is among the highest-epoch secrets the channel has, and for 48 hours after the DS records any secret with a higher epoch". A member, or a removed member whose secret for epoch `r` is still held, posts an invalid commit for `r` registering `r+1'`, then MACs under `r+1'` to register `r+2'`, and so on to `r+1000` in minutes (`commitsPerHour` is 600). Every honest secret is now below `r+1000`, so every honest secret expires 48 hours later, and every future honest secret expires 48 hours after it is registered. Honest members lose token issuance and the ability to commit; only a reset recovers. The paragraph that says "dead branches expire 48 hours after honest members' next commit" has it backwards: the rule as written makes the honest branch the one that dies. The reset backstop still works (after the attacker is removed, they hold no honest secret), so this is 48 hours of denial per incident, not permanent, but the spec's own rationale is wrong and a removed member should not be able to cause it. Fix: do not rank held secrets by epoch. A held secret stays usable for 48 hours after it was registered or last used for a successful commit or token issuance, whichever is later; the DS caps held secrets per channel (for example 64) and evicts the least recently used. The honest branch stays alive because honest members use it; dead branches go unused and age out. Keep the reset. Add a `chat/ds-api` vector: a 1,000-commit dead branch followed by honest issuance succeeding.

**R3 (blocker) — §1.5, §5.8 key 6, §12.5: a newcomer cannot verify the all-members group's issuer key before its first fetch.** The all-members and organizers groups' issuer keys live in the `roles` message. A newcomer reaches the `roles` message only by fetching the all-members queue, and a fetch needs a channel token, and verifying that token's `TokenResponse` needs the issuer key. The only way through is to accept the first response unverified, which is exactly the moment the DS can tell a specific new device apart (it just served that device's Welcome by handle). A DS that hands that device a unique key links every later fetch session of that device in the all-members group. Fix: carry the two keys somewhere the newcomer has before its first token request. The cleanest is the context manifest: `chat.issuerKeys` (`allMembers`, `organizers`) beside `allMembers` and `organizers`, since those groups are registered once at context creation and the keys are public. A GroupInfo extension in the Welcome also works. Keep `roles.issuer_keys` only if it is redundant with that source, and say a mismatch between the two is a warning. Add the request to §17's list for `context.md`.

**R4 (blocker) — §2.5 step 3 and 4: the join ticket proves nothing to the greeter, so any member can admit anyone.** The ticket is HPKE base mode with no membership proof inside; the only policy check is that the poster held a context token, and the DS does not and cannot convey that to the greeter. Any current member can obtain a context token and post a ticket holding a non-member's handles. The greeter opens it, fetches the KeyPackages and commits the Add. The entry policy, which `docs/design.md` and `context.md` make the gate on chat membership ("People you approve", "Verified residents"), is bypassed by one cooperating member. Fix: the ticket plaintext carries a membership proof whose scope binds it to this ticket, for example scope `hum/join/1 ‖ context lineage CID ‖ SHA-256(handles)` (or `‖ nonce` with the nonce in the plaintext), and the greeter's phone verifies the proof against the context version's entry policy before committing. This does not create an identity link: a membership proof is zero knowledge and shows only that the policy holds plus a nullifier under the join scope, which `credentials.md` must keep unlinkable from ballot and token scopes like the other scopes already listed. The organizer already sees the chat identity in the tree. Depends on `credentials.md` for the proof encoding; state the scope here now so `credentials.md` can adopt it. Mark the vector `chat/join` with a failing case: ticket without a proof, and ticket whose proof scope names another context.

## Adversarial read of §2.5 (admission)

What I checked and what holds:

- **Verifier and the KeyPackage.** The verifier's role ends at credential issuance. Nothing in steps 1 to 5 touches a verifier. The membership proof goes to the DS token endpoint and the store token endpoint; neither sees a KeyPackage (sealed blob) or a handle (inside the HPKE ciphertext). Holds.
- **The policy presentation and the chat identity.** The same phone presents a membership proof to the DS and the store within minutes, then posts a ticket, then fetches a Welcome, then starts fetch sessions. All four are anonymous on their own; the join is timing across operator services, which the threat model already names as the residual. The context token's nullifier is per `delivery-tokens/<key>/<day>`, so a day's issuances share a nullifier, which `storage.md` accepted for stores. Holds.
- **The DS inbox and a later chat identity.** The DS sees: ticket at time T under an anonymous token; a commit in the all-members group with N Welcome handles; `POST /v1/welcome/{handle}` fetches; new fetch sessions. None carries the chat identity key, a name or a device ID. The DS can chain "this ticket produced this Welcome produced this new session" by timing, which is a device-level pseudonym for the life of the session only, provided R3 is fixed so the session's tokens are verified. Holds, conditional on R3.
- **Ticket length leaks device count.** The ticket is "at most 2 KiB" and the relay pads the request, but the gateway and DS see the decrypted OHTTP request and so the exact ciphertext length, which reveals the number of handles, which is the number of devices. Pad the ticket plaintext to a fixed size (8 handles' worth) before HPKE. Should fix.
- **Step 4 cannot be executed as written.** A KeyPackage is used once (§2.4). The ticket carries one handle per device, all consumed by the all-members Add. "The greeter then adds the joiner to the channels the context opens to everyone by default" needs more KeyPackages the greeter does not have. Fix: after joining the all-members group, the joiner's phone sends a `join-request` (§5.11) for each `default` channel with fresh handles, automatically; drop the sentence from step 4. The same gap exists in §2.3: the QR holds one handle but the existing device commits "an Add in every group the person is in, each with a fresh KeyPackage fetched by handle". Say the QR holds a list of handles, one per group plus spares, or that the new device sends `join-request`s itself once in the all-members group. Should fix.
- **Greeting key custody.** The private key is in every organizer, moderator and greeter-agent device. A moderator who is demoted keeps it until rotation; rotation is a context manifest version plus a `greeting-key` message. Say that a demotion SHOULD rotate the greeting key, as removal rotates the keyring. Note.
- **`chat.greeting` does not exist in `context.md`** on disk. Open question 14 and §17 request it; until W0-01 adds it, §2.5 is unimplementable. Dependency, not a finding against this spec.
- **Inbox fetch cursor.** `after bstr(16)` is a ticket ID, but ticket IDs are random. Say IDs are assigned monotonically (or that the cursor is `received`), or the cursor has no order to follow. Should fix.

## Adversarial read of §12.6 (non-validating DS)

What I checked and what holds, beyond R2:

- **First valid commit per epoch.** A current attacker's invalid commit sequenced before the honest one is decrypted, fails §3.3 or MLS validation, and is skipped; the honest one is applied. An attacker's commit for epoch `h` sequenced after the honest one is ignored because the phone already holds a commit for `h`. A phone's own pending commit loses to an earlier-sequenced valid one and the phone re-derives. Standard and sound.
- **Commit MAC.** `HMAC(secret_h, "hum/commit/1" ‖ message)` over the padded `MLSMessage` bytes; header epoch `h` is in the clear. A removed member cannot derive the secret of the epoch that removed them. Holds, subject to R2 for how long their old secrets live.
- **Reset.** `organizer` class signature over the request (A-1 covers the body hash, so the secret is bound), nonce and time per A-3, sequenced with a `reset` flag so phones see it. The resetting organizer must be a channel member to know the current secret, which §1.3 now guarantees. Holds. The DS learns which organizer key acted; that key also reads the daily count, so one organizer's actions across services share a public key. Already stated; fine.
- **Fetch session binding is undefined.** "One token per fetch session of at most 15 minutes" with "spent token nonces rejected" leaves no way to make a second request in the session. Define it: the first fetch spends the token and the response carries a 16-byte session cookie valid 15 minutes, presented on later fetches; or the session is one long-poll connection and every new connection costs a token. Should fix, and it determines what §12.10 means by "how many devices hold a fetch session open".
- **`HKDF-Expand(PRK = DS master secret, …)`.** Fine if the master secret is 32 uniform bytes; say so, or run `HKDF-Extract` first. Note.

## §12.10 against `docs/design.md`

The table now states that it is wider than the design doc's row and the threat model's row, lists every addition (context per channel, message class, commit rate, Welcome handle and `KeyPackageRef` counts, ticket counts, resets, fetch-session counts, issuance counts), and asks the owner to update both rows. The "never sees" column is accurate given R3 and R4. One addition for the leaks paragraph: ticket ciphertext length reveals the joiner's device count (above). Otherwise this item is closed.

## Cross-spec drift found on disk this round

- `services.md` "Services are named by key": no `stamp` field (R1). Its summary row for the DS still lists the old endpoint set and says `/v1/tokens` without `{context}`; its domain-string table still lists `device/1`, `safety/1`, `frank/1` and the rest without the `hum/` prefix. For W0-07.
- `agent-sponsor.md` "The membership event" and its assumptions still say the field is `runs` with codes 1 phone, 2 member hardware, 3 enclave; this spec has `runtime` 1 and 2 and asks for the change. `label` is still capped in scalar values only. For W0-04.
- `agent-sponsor.md` rate limits are `window`, `mapObjects`, `messages`, `takes`. This spec §3.3 and §9 enforce "`messages` or `proposals`"; there is no `proposals` limit. Drop `proposals` here or request it there. Should fix.
- `context.md` `agents.addRole` lets a context widen who may add an agent to moderators or members; this spec's `agents` capability is organizer-only, and `context.md` says this spec should read `addRole` from the pinned context version. Should fix here: the `agents` row becomes "organizer; moderator when `addRole` ≥ 1; member when `addRole` = 2".
- `context.md` still carries the stale `chat_group` note; this spec's §17 flags it. For W0-01.
- `storage.md` open question 3 still says the DS token mechanism is open; §12.3 and §12.5 settle it. For W0-06.

## Testability, remaining

The vector list now covers every rejection rule I listed in the first round. Add: `chat/join` without a membership proof and with a wrong-scope proof (R4); `chat/ds-api` dead-branch run followed by honest issuance (R2); `chat/tokens` first-fetch case where the all-members issuer key comes from the context manifest (R3); a fetch-session vector once its binding is defined. The MLS-implementation dependency for group-state vectors is now open question 12 and needs the ADR before W0-08 starts.

## Summary for the author

R1 is one sentence in one of two specs; settle it with W0-07 today. R2 is a rewrite of the "Held secrets" paragraph and the rationale under it. R3 adds two public keys to the context manifest (request to W0-01) and one sentence in §12.5. R4 adds a membership proof and its scope to the ticket; name the scope now so `credentials.md` can adopt it. Then the should-fixes: fixed-size tickets, step 4 and §2.3 KeyPackage counts, inbox cursor order, fetch-session binding, `proposals`, `addRole`.

---

# Re-review 2 (2026-10-06, targeted check of R1 to R4)

Checked §2.5, §11.2, §11.3, §12.3 to §12.6 of `chat.md` and `context.md` chat keys 3 and 4, rule C11 and its vector list. Not a full re-read.

## Verdict

**Approve with fixes.** R1, R3 and R4 are resolved. R2 is improved but still fails the test the lead asked for: a removed member can still evict the honest secret through the LRU cap, and can keep their own secrets alive indefinitely by using them. One blocker remains, with a concrete fix.

## R1 — stamp key. Resolved.

§11.2 and §12.6 now stamp with a `sign` key of the DS keyset and return its `key_id`; `services.md` "Services are named by key" says the same. `report` key 10 is `keyset`, the DS authority's `keyset` version listing `key_id`, and step 4 requires it to be a logged version of the authority `chat.delivery` names with the key unrevoked at the verifier's latest witnessed checkpoint. That follows `manifest.md`'s revocation rule without selecting a keyset by time. The `chat/frank` failing case still says "`ds` not in the context's delivery lineage"; rename it to `keyset`.

## R3 — issuer keys in the manifest. Resolved.

`context.md` chat key 4 `issuerKeys` `{0: allMembers, 1: organizers}` exists on disk, rule C11 requires both entries in every version, and the vector list has the one-entry failing case. §12.4 makes the creator place both keys there; §12.5 makes a newcomer verify its first `TokenResponse` against the manifest; `roles.issuer_keys` is a copy and the manifest wins on mismatch (§5.8 key 6, §12.4). The newcomer holds the context bundle before it has any token, so the gap is closed. The DS is still named by key; the manifest carries a DS-derived public key, which reveals nothing.

## R4 — join-ticket proof. Resolved, two notes.

Step 3 puts a membership proof in the plaintext with scope `hum/join/1 ‖ context lineage CID ‖ SHA-256(canonical CBOR of handles)` and pads the plaintext to exactly 2,048 bytes. Step 4 makes the greeter verify the proof against the entry policy before touching the handles. The handles hash binds the proof to this ticket, so a member cannot post a non-member's handles under their own proof, and the nullifier is unique per ticket so it links nothing. The verifier still sees no KeyPackage. Holds.

- **N (note) — step 3 and 4: which context version.** The joiner proves against the version it holds and the greeter verifies against "the context version it holds". Across a context version change the two can differ (a trust list added or dropped). Put the context version CID in the ticket plaintext and let the greeter accept the current version or the one before.
- **S (should fix) — step 3: 2,048 bytes may not fit.** Eight direct-form handles are about 1,200 bytes and the proof size is unknown until `credentials.md` lands (a BBS presentation with a policy proof can run to several kilobytes). Make the fixed size a named protocol constant to be set with `credentials.md`, and say a ticket whose plaintext does not fit is split into two tickets, or raise it to 4,096 now.
- **N (note) — `hum/join/1` is both the HPKE `info` prefix and the proof scope prefix.** Different primitives, so no replay, but the domain-string table promises uniqueness. Use `hum/join-ticket/1` for the HPKE info.

## R2 — held secrets. Still a blocker.

The new rule: at most 64 `(epoch, secret, last_used)` entries per channel; a secret is usable for 48 hours after registration or last successful use; when a 65th is registered the least recently used is evicted. Two things the lead asked me to confirm do not hold.

**R2a (blocker) — the LRU cap evicts the honest secret.** A fresh registration has `last_used` = now. An attacker who registers 64 secrets in a row makes every one of them more recently used than any honest secret not used in that interval. At `commitsPerHour` 600 that interval is about six and a half minutes. Any channel whose members have not issued tokens or committed in the last six minutes (every channel at night) loses its honest secret on the 65th registration. Honest members then cannot issue tokens or MAC a commit, because a commit MAC needs a held secret whose epoch label matches the header epoch, and the only secrets the DS now holds are the attacker's. The sentence "a flood of 1,000 fresh secrets cannot evict the one honest members used a minute ago" is false under the rule as written: a minute ago is older than 64 entries registered in the last minute. A removed member can do this for as long as they hold any usable secret (next item).

**R2b (blocker) — a removed member's secrets never age out while they use them.** "Usable for 48 hours after it was registered or last used for a successful commit or token issuance" lets the attacker refresh their own secret by issuing tokens under it every 47 hours, and every garbage commit they MAC registers a new secret they control. The sentence "ages out 48 hours after they stop" is true only if they stop. The spec cannot make them stop; it can only make them harmless.

Fix, three parts:

1. **Evict newest-registered first, never by last use.** When the table is full, the entry registered most recently is dropped. A flood then evicts only itself: the attacker's own newest registrations churn while old honest entries, kept alive by honest use under the 48-hour sliding rule, are untouched. The cost is that an honest commit's new secret registered during a flood may be evicted too, which the next part absorbs.
2. **Let the commit MAC use any held secret, not one whose epoch label equals the header epoch.** The MAC exists to prove the sender holds a secret the DS holds for this channel; the epoch label adds nothing to that proof and is what turns "the newest honest secret was evicted" into "no honest member can commit". With this change honest members, who hold every delivery secret since they joined, MAC under the oldest honest secret still held, and the `epoch` field in the issuance request and the `(epoch, secret)` pair at the DS become informational. Keep the label for the `top_epoch` hint only.
3. **Say what a removed member can still do, plainly.** With 1 and 2, a removed member who keeps using their old secrets can keep posting junk commits and junk application messages that honest phones skip, bounded by `commitsPerHour` and `sendsPerMinute`, until an organizer resets or the attacker stops for 48 hours. They cannot evict honest secrets and cannot stop honest token issuance. Replace the "ages out 48 hours after they stop" and "cannot evict the one honest members used a minute ago" sentences with that statement, and add the residual to §15: "a removed member can waste a channel's rate budget until a reset".

One degradation to state with the fix: a member who joined after the oldest surviving honest secret's epoch holds only newer secrets, which a sustained flood keeps evicting, so that member cannot issue tokens until the flood stops or an organizer resets. Older members are unaffected. That is acceptable and should be written down.

Vectors: replace the `chat/ds-api` dead-branch case with two: a 64-registration flood after which an honest issuance under a secret last used ten minutes earlier still succeeds; and a commit MAC under a held secret whose epoch label differs from the header epoch, accepted.

## Also noted

- §12.5's fetch-session cookie (16 bytes, 15 minutes from the first fetch) closes the session-binding gap. Good.
- §3.3 now counts proposals as messages against the sponsor's `messages` limit, which matches `agent-sponsor.md`. Good.
- `agent-sponsor.md` moving `label` to 64 bytes fits inside the credential's 256-byte `name`. Good.
- §12.3's context-token scope `hum/delivery-tokens/1 ‖ token_key_id ‖ day` matches `services.md`'s token table and domain-string table. Good.

## Summary for the author

R2 needs three edits in §12.6: newest-first eviction, a commit MAC that accepts any held secret, and honest prose about what a removed member can still do. Everything else from this round is a note or a size constant.

---

# Re-review 3 (2026-10-06, final check of §12.5, §12.6 and §15)

**Approve.** R2 is closed. §12.6 now evicts the most recently registered entry when the 64-entry table is full, so a flood of registrations churns only its own newest entries and cannot reach an older honest secret that honest use keeps alive under the 48-hour sliding rule; the epoch label is informational and never selects, ranks or evicts a secret. The commit MAC and the issuance MAC may both be computed under any held secret of the channel, and the DS tries each, so an honest member who holds every delivery secret since joining can always act under the oldest surviving one even while newer honest registrations are being dropped. The removed-member residual is stated plainly in §12.6 and in the §15 "keeps sending" row: rate-limited junk and ciphertext fetches until a reset or 48 hours of inactivity, with the degradation that a member who joined after the oldest surviving honest secret cannot issue tokens during a sustained flood. The `chat/ds-api` vectors cover the 64-entry flood, the old-secret issuance and MAC during a 1,000-commit dead branch, and the 48-hour expiry. §2.5 now carries the context version CID in the ticket, `TICKET_BYTES` = 4,096 as a named constant with the split rule, and `hum/join-ticket/1` as the HPKE info, and §12.4 fixes the ticket ciphertext size. One stale sentence remains, not a blocker: the §15 "keeps reading" row still says a removed member's secrets "expire 48 hours after the next honest commit", which §12.6 no longer says; change it to "48 hours after their last use, or at a reset". The spec is ready for W0-08 vectors once `credentials.md` lands the proof encoding and `context.md`'s chat keys 3 and 4 are approved.
