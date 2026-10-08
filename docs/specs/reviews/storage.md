# Review: `docs/specs/storage.md` (Draft 0.1, W0-06)

Reviewed 2026-10-06 against `CLAUDE.md`, `docs/design.md`, `docs/specs/manifest.md`, `docs/specs/chat.md`, `docs/specs/context.md`, `docs/specs/services.md`, `docs/specs/issue-map.md`, decisions 0060–0062, and the Python reference (`reference/src/hum_reference/storage.py`, `reference/src/hum_reference/vectors/storage_vectors.py`).

Dependencies not yet written: `credentials.md` (membership proof and its scope), `conformance.md`, `simulator.md`. Findings that depend on them are marked. I did not guess their content.

## Verdict (first pass)

**Approve with fixes.** The sealed format itself (§1) is sound: the chunk index and last flag in the nonce, the header in the AAD, the self-delimiting Padmé pad and the per-blob key give truncation, reordering, extension and cross-file splice resistance, and I found no way to make two careful implementers produce different ciphertext bytes from the same key, salt and plaintext. The keyring derivation (§4.3) correctly refuses to use the exporter output as an AES key. The problems are around the format: one logic flaw in the store API that lets any member delete any blob they can fetch, a manifest body that cannot be encoded as written, a reference implementation that still encodes the pre-spec format, and one cross-spec gap for members-only release tables. All four are local edits or sibling-spec coordination, not a redesign.

See "Re-review" at the end for the current verdict.

## Blockers

**B1 (blocker) — §6.3 "200 OK" and §8.1: a re-put grants a delete capability to anyone who can fetch the blob.** §6.3 says a put of a CID the store already holds for this context "adds the new delete commitment to the tuple's set (at most 8 per tuple)". §6.5 deletes when the presented secret matches any commitment in the set. So any member of the context fetches a sealed blob (every member has a token, and every CID pinned by an issue-map manifest is public in the log), re-puts the same bytes with a commitment of their own, then deletes it. This contradicts §8.1 ("a recipient who holds the reference cannot delete the file") and §13's threat row. Fix: a put to an existing `(cid, context)` tuple changes nothing. Return `200`, do not add a commitment, do not extend retention. The author's secret and the context order remain the only deleters. If retention extension by the author is wanted, require the original secret in a `Hum-Delete-Secret` header on the re-put. Add a failing vector `store-reput-no-new-commitment`: re-put with a new commitment, then delete with that secret, expect `403 forbidden` detail `secret`.

**B2 (blocker) — §7: the `blob-store` body cannot be encoded as written.** The section says the common fields are "`endpoints`, `apiVersion`, `ohttp`, `tokenIssuers`, `jurisdiction` ... the ones `services.md` defines". `services.md` defines keys 0 `kind`, 1 `endpoints`, 2 `apiVersion`, 3 `issuer`, 4 `limits`, 7 `jurisdiction`, 8 `retention`; it has no `ohttp` field (the gateway key lives inside `endpoints[]`) and no `tokenIssuers`. §6.1 also relies on `tokenIssuers` to say which issuer keys the store accepts, so that field is load-bearing and undefined. Key 16 `issuer` duplicates `services.md` key 3 `issuer` with the identical shape. W0-08 cannot generate a manifest vector from this. Fix: write the full key table for `blob-store` in this spec (every key, type, required, frozen), reusing `services.md` keys 1, 2, 3, 7 and 8 by number, dropping key 16, and adding `tokenIssuers` (array of `{0: key (bstr), 1: token_key_id (bstr 32)}` or an authority CID per issuer) as a numbered key. Mark `issuer.name` frozen (see S9). Add a valid vector and one failing vector per validation rule in §7 (four rules, none has a vector today).

**B3 (blocker for W0-08, not a spec defect) — the reference implementation encodes a different format.** The spec is authoritative and `reference/` must follow it, but today they disagree byte for byte, and `storage_vectors.py` would emit vectors that contradict the spec. The differences, with the file and line:

| Spec | `reference/src/hum_reference/storage.py` |
| --- | --- |
| Pad is `0x80` then zeros to `padme(L + 1)` (§1.2) | Zero pad to `padme(L)`, no marker, length comes from the reference (line 94) |
| AAD is `sealed/1` followed by the header (§1.1) | AAD is the header byte alone (line 100) |
| Format 2 with a 17-byte header exists (§1.1) | Only format 1; `0x02` is rejected as "unknown" (line 106) |
| Last chunk is never empty because `P ≥ 1` (§1.3) | An empty plaintext yields one empty chunk (line 84) |
| Reference `digest` is 33 bytes, `0x01 ‖ SHA-256` (§2, §3.1) | 32 bytes (line 162) |
| Reference keys 8 `store`, 9 `description`, 10 `epoch`; rejection rules for both forms (§3.1) | Keys 0–7 only, no validation (lines 168–197) |
| Exporter context empty; blob key by HKDF with the header salt (§4.1, §4.3) | Context is the epoch as 8-byte big-endian and the exporter output is used as the AES key directly (lines 260–262) |

The module docstring cites "ADR 0005-w0-08" for its choices; no file matching `docs/decisions/0005*` exists. Fix: W0-08 rewrites `storage.py` and `storage_vectors.py` to this spec after B1, B2 and the should-fix items below land, and either writes ADR 0005 or removes the citation. Until then, `just vectors` would produce wrong vectors for storage.

**B4 (blocker, cross-spec with W0-01 and W0-07) — members-only release tables have no sealed format and no put path.** `services.md` ("Publishing a release") has the Leader upload tables "sealed to the context's `resultsKey`, an X25519 key" with media type `application/vnd.hum.sealed`, using an `authority` signature instead of a token. This spec's formats 1 and 2 cannot express a blob sealed to a public key, so §6.3 would answer `415 malformed` detail `format` (the first byte is not 1 or 2). §6.3 also requires a token on every put and has no `authority` path, so the put fails authentication before that. Fix, pick one: (a) define format `0x03` here: header `0x03 ‖ enc (32 bytes, the HPKE encapsulated key)`, key by HPKE base mode (DHKEM X25519, HKDF-SHA256, exporter to 16 bytes with info `hum/sealed-pk/1`), same chunk layout and AAD rule; and add an `authority`-signed put to §6.3 that counts against the named context's quota, as `services.md` already says; or (b) have `release.md` use its own media type and `services.md` give aggregators a token. (a) keeps one sealed format and one store. Either way this spec must say which.

## Should fix

### Invariants

**S1 (should fix) — §4.2: any member can poison a newcomer's keyring.** A `keyring-share` is accepted from any sender. "Ignore an entry whose `k` it already holds with a different secret" protects entries already held, so the first sender wins. A malicious member who races the committer gives the newcomer a wrong secret for an epoch they do not hold, and every manifest-sealed text under that epoch is unreadable for them with no error that points at the cause. Fix: a phone accepts a `keyring-share` only from the leaf that committed its Add (for the current epoch) or from a leaf whose chat identity holds `members` (for earlier epochs). Add: a phone that fails a tag on a format 2 blob under a shared secret marks the entry suspect and asks for a re-share; a second, different secret from a `members` holder replaces it. Add a failing vector `keyring-share-unauthorized-sender`.

**S2 (should fix) — §4.2 and `chat.md` §10: keyring secrets must never enter a history archive.** A history archive records the `AuthenticatedContent` of application messages. Nothing says the context group is never archived, and a `keyring-share` is an application message. Under `history = 2` an archive of the context group would hand every keyring epoch to every newcomer regardless of `keyringHistory`, and would put keyring secrets inside a blob whose key travels in `history-offer` messages. Fix: state here that `keyring-share` and `folder-index` announcements are never archived, and ask W0-05 to add the rule to `chat.md` §10.1.

**S3 (should fix) — §16 versus `chat.md` §2.4: the conformance claim is already false.** §16 says a client never sends a sealed reference or delete secret "anywhere except inside an MLS application message, inside a sealed blob, or (for the delete secret) in a delete request". `chat.md` §2.4 puts a KeyPackage handle, which holds a sealed reference and the delete secret, in a QR code and the admission flow, and `chat.md` §1.1 puts a sealed reference in a GroupInfo extension. Fix: list the allowed carriers exhaustively (MLS application message, sealed blob, Welcome or GroupInfo, a QR code shown on the device, the delete request) and make the conformance check enumerate them.

**S4 (should fix) — §8.2: a delete order is not bound to the token's context.** The store verifies the order against `authority`'s keyset and deletes "that context's tuple only", where "that context" is the token's. Nothing says the two must agree. A context whose organizers sign an order listing CIDs that another context also holds cannot delete the other context's tuple only because the token names their own context, which is the right outcome, but it is reached by accident. Fix: the store MUST check that the context the token key belongs to has `authority` equal to the order's `authority`, else `403 forbidden` detail `order`. Add a failing vector. Also add an `expires` field to the order (or reject orders older than `blobRetention.tombstone`), because an order replayed after the tombstone window would delete a legitimately re-uploaded CID.

### Floors

No field in this spec touches ρ, δ, voter minimums or the shield. Retention, size and quota settings can only be lowered by a context below the store's ceilings (§6.6, §7). OK.

**N1 (note) — §6.2: a tightened context policy takes effect late.** "A newer context version takes effect when the issuer next rotates the key or when the store learns of the version" means up to 30 days of the old retention or quota. Say the number and say that the phone enforces the new version immediately, so the lag only affects a modified client.

### Sums

Not applicable to this spec; nothing here feeds a release. The only aggregate the store produces is per-context counters, which never leave the store. OK.

### Federation

Stores are named by authority CID; `issuer.name` is only an input to the TokenChallenge. OK.

**S9 (should fix) — §6.1 and §7: `issuer.name` must be frozen, or redemption breaks on rotation.** The phone builds a fixed TokenChallenge from `issuer.name`, and the store verifies a token by recomputing the challenge digest from the same name. If a store version changes the name, every token issued under the old name fails at redemption. §7 says "Frozen between versions: nothing". Fix: freeze `issuer.name`, and `formats.sealed` may only grow.

**S10 (should fix) — §6.1 and §6.2: the phone cannot find its context's issuer key.** An RFC 9578 `TokenRequest` carries `truncated_token_key_id`, so the phone must choose the key before issuance, but the directory is "one entry per context key" with no mapping from context to entry. Fix: either the directory entries carry an extension member with the context lineage CID in text form (contexts are public in the log, so this leaks nothing new), or `POST /v1/tokens` accepts a request with no `requests` and answers the `token_key_id` for the context in the body. Say which. Also say what the phone does when the directory key and the gossiped key differ (today only "stops using the store and shows a warning").

### Consistency

**S5 (should fix) — this spec and `services.md` disagree on five token and error details.** Both are drafts, so one owner must pick, but the files on disk conflict:

| Item | `storage.md` | `services.md` |
| --- | --- | --- |
| Token type | `0x0002` (blind RSA) §6.1 | `0x0001` (VOPRF) "Authentication classes" |
| Issuer | store or a separate issuer | "the service as both Issuer and Origin" |
| Issuance path | `POST /v1/tokens`, context in the body §6.2 | `POST /v1/tokens/{context}` |
| Error body | CBOR map `application/vnd.hum.error+cbor` §6.7 | RFC 9457 `application/problem+json`, described as "the format storage.md §6.7 already uses" |
| Code spelling | `not_found`, `rate_limited`, `too_large`, `token_spent` | `not-found`, `rate-limited`, `too-large`, no `token_spent` |

A7 says `services.md` T-2 puts the context in token metadata; T-2 says the opposite ("no metadata"), so that part of A7 is stale and can be dropped. Recommend: storage keeps `0x0002` and the separate-issuer option (ADR 0061's reasoning holds), `services.md` adopts them; storage adopts `services.md`'s error format and hyphenated codes and adds `token-spent` to the common table.

**S6 (should fix) — §4.2, §10, A3: `context.md` already has the fields this spec says it lacks.** `context.md` `storage` has key 4 `keyringHistory` (0 every epoch, 1 current only; default 0) and key 5 `sensitiveMax` (rule C9: ≥ 1 MiB). This spec keys keyring delivery off `storage.history` and uses a 256 MiB protocol default. Fix: §4.2 follows `keyringHistory` (0 sends every epoch, 1 sends only the current one), §10 reads `sensitiveMax`, A3 and open question 1 are closed.

**S7 (should fix) — §3.2: ExternalPart field names and a missing reject rule.** The table uses `enc_alg`, `hash_alg`, `content_hash`; draft-ietf-mimi-content-08 and `chat.md` §5.1 use `encAlg`, `hashAlg`, `contentHash`. Use the draft's names. The mapping also needs the reverse rule: a phone MUST ignore an ExternalPart whose `encAlg` is not 1, whose `hashAlg` is not 1, whose `key` is not 16 bytes, whose `nonce` or `aad` is non-empty, or whose `url` is not `hum:blob:` plus a 33-byte CID. `chat.md`'s `chat/external-part` vectors cover only the URL and `encAlg`; ask W0-05 to add the rest, or list them here under §12.

**S8 (should fix) — §5.3 versus `chat.md` §3.1: who may rename another member's file.** This spec requires `files-delete-any` for `rename`, `move` and `new version` on another member's file. `chat.md` §3.1 says `files-write` covers "add, rename, move, version files in a folder" with no own/other split. Two phones following different specs compute different folder states. Pick one (this spec's stricter reading is better) and make `chat.md` say it.

**S11 (should fix) — domain strings are not namespaced.** `sealed/1`, `keyring/1`, `keyring/1/blob`, `delete/1`, `blob-delete/1` and the proof scope `blob-tokens/<id>/<day>` have no `hum/` prefix. `issue-map.md`, `services.md` and `context.md` use `hum/author/1`, `hum/service-request/1`, `hum/results-key/1`. `chat.md` and `manifest.md` are also unprefixed, so this is a cross-spec pass item, but this spec is a seam and should not add more. Proposed: `hum/sealed/1`, `hum/keyring/1` (exporter label), `hum/keyring-blob/1` (HKDF info), `hum/delete/1`, `hum/blob-delete/1`, `hum/blob-tokens/1 ‖ token_key_id ‖ day`. Within this spec the strings are mutually distinct and the `delete-order-wrong-domain` vector checks `blob-delete/1` against `manifest/1`. OK on uniqueness.

**S12 (should fix) — §8.1 names an error that §6.5 does not define.** §8.1's vector expects `403 bad-secret`; §6.5 answers `403 forbidden` detail `secret`. Use the §6.5 form.

**N2 (note) — §8.2 says "COSE_Sign ... exactly as manifests are signed"; `services.md`'s bundle uses COSE_Sign1 per signer.** `manifest.md` says COSE_Sign. Not this spec's to resolve, but the delete order should name the structure it means once the manifest spec does.

**N3 (note) — §6.3 and `chat.md` §2.4: two meanings of "media type".** `chat.md` says a KeyPackage is a sealed blob of "media type `application/mls-key-package`". That is the plaintext media type in the reference; the store sees `application/vnd.hum.sealed`. Say so in §2 so nobody puts the plaintext type in `Content-Type`.

**N4 (note) — §10 step 2 says "a `version` operation"; §5.2 calls it `new version` (op 4).** Use the table name.

### Implementability

**S13 (should fix) — §1.4, §1.5: where `C` comes from is unstated, and a range reader needs it.** Decrypting chunk `i` needs to know whether `i` is the last chunk, which needs `n`, which needs `C`. The reference carries `size` (message form) or nothing (keyring form), never `C`. Fix: for message form, `C = H + padme(size + 1) + 16 × ceil(padme(size + 1) / CHUNK)` and the store's `Content-Length` MUST equal it, else `size-mismatch` before any fetch; for keyring form, `C` is the `Content-Length` from a `HEAD` or the first response, untrusted, so a wrong value surfaces as `bad-tag`. Add `range-c-from-size` and a failing `range-content-length-mismatch` vector.

**S14 (should fix) — §6.3: the order of put checks is unspecified, and one order leaks.** If the tombstone check runs before the body is hashed, a member of context D can probe whether CID X was recently deleted from any context by putting X with a junk body: `410` means yes, `409 cid_mismatch` means no. §8.4 limits `410` to "any context that held it" but §6.3 does not. Fix: fix the order as token, `Content-Length` versus `maxBlob`, `Hum-Delete` syntax, retention, stream and hash, CID mismatch, class, media type, tombstone for this context only, quota. Add a vector `store-put-tombstone-other-context` expecting `201`.

**S15 (should fix) — §5.3, §5.4: "every honest phone reaches the same state" is not true as written.** Folder ops are ordered by the folder channel's DS sequence; rights come from `roles` messages in the context group, a different channel with its own order. Two phones that apply op `N` having seen different `roles` serials reach different states, and §5.4's determinism claim fails. Fix, pick one: (a) say rights are evaluated against the highest `roles` serial the phone holds when it applies the op, that phones may transiently differ, and that a phone re-derives the folder from the last index it trusts when a `roles` message lowers someone's rights; or (b) ask W0-05 to add a `roles_serial` field to `file-op` so the sender names the roles version it acted under, and phones evaluate against that serial once they hold it (and queue the op until they do). (b) restores determinism; (a) is honest about losing it. Either way, `folder-rights` needs the roles input stated.

**S16 (should fix) — §6.1, §6.2: `<day>` has no encoding.** The scope string is "`blob-tokens/<token_key_id>/<day>`". Say whether `token_key_id` is 32 raw bytes or hex, and whether `day` is `floor(now / 86400)` as ASCII decimal or uint64 big-endian. `issue-map.md` uses raw bytes and uint64 big-endian for its window; match it. Marked as depending on `credentials.md` for the proof encoding itself.

**S17 (should fix) — §5.5: the interim `folder-index` announcement consumes a file id and relies on an empty name.** `chat.md` §5.7 requires `name` for op 1 and says nothing about empty names, and §5.4 rule 2 means the announcement's `file` id can never be reused. Workable, but say explicitly that an op 1 whose `ExternalPart.contentType` is `application/vnd.hum.folder-index+cbor` is an index announcement, is not a file, is exempt from rule 2's id reservation, and is accepted only from a sender who committed the most recent Add or holds `files-delete-any`. Otherwise any member can announce a bogus index that newcomers trust.

**N5 (note) — §9: "the local user is the blob's author" is undefined.** A second device of the same person has neither the delete secret nor the original message. Define author as: holds the delete secret for the CID, or is the sender (by chat identity key) of the message that first carried the reference in this context.

**N6 (note) — §1.7: GCM invocation limit.** SP 800-38D caps authenticated-encryption invocations per key at 2³². With 64 KiB chunks that is 256 TiB per blob, far above any `maxBlob`, but the format allows a 64-bit index. State `n ≤ 2³²` as a format rule so a future `maxBlob` cannot cross it unnoticed.

**N7 (note) — §4.2: nobody re-sends the current epoch if the committer's share is lost.** Add that any member MAY send a `keyring-share` holding only the current epoch to a newcomer, and that a newcomer with no current-epoch entry after its first fetch asks for one.

### Residual leaks worth stating in §13

- **Padmé granularity on short text.** For a 280-byte position, `padme` rounds to 16 bytes, so the store and anyone with a context token learns a sealed text's length to within 16 bytes. The design accepts Padmé; say the number.
- **Same ciphertext in two contexts.** A member who re-shares a reference into a second context puts the same CID under two `(cid, context)` tuples, so the store learns the two contexts share a member. Not a person-level link, but say it.
- **Redeemed-nonce storage.** 5,000 tokens per member per day for a 30-day key means a 10,000-member context can leave 1.5 × 10⁹ nonces per key. Fine, but §6.1 should say stores may lower `tokensPerMemberDay` and that the default is a ceiling.

## Invariant and format checks that pass

For the record, so the next reviewer does not redo them:

- **Nonce uniqueness.** Format 1 uses a fresh random key per blob; format 2 uses a fresh 16-byte salt per blob through HKDF-Extract, so two blobs under one epoch share a key only on a 128-bit salt collision. Within a blob, nonces are `index ‖ flag`, distinct by construction. Across keyring epochs, the MLS exporter secret differs per epoch, so the same salt under two epochs gives different keys. The exporter output is never an AES key. OK.
- **AAD.** `sealed/1 ‖ header` binds the format byte and, for format 2, the salt, to every chunk. The reference's `size`, `digest`, `name` and `media` are not bound to the blob and the spec says so; they are bound by the MLS message or sealed blob that carries the reference. OK.
- **Truncation, reordering, extension, splice.** Checked each case in §1.6 against the layout rule `n = ceil((C − H) / (CHUNK + TAG))`. Appending fewer than 65,553 bytes lengthens the last chunk and fails its tag; appending more raises `n` and the old last chunk fails on `flags = 0`. Swapping chunks between files fails on the key. OK.
- **Padmé.** The eight table values in §1.2 recompute correctly from the integer algorithm. The `padme(L + 1)` length check on unpad closes the covert channel a free-form pad length would open. OK.
- **Keys in manifests, logs, store requests.** The keyring form carries no key; the salt is public by design; the delete commitment is a hash of a random secret independent of the file key; `Hum-Delete-Secret` is the only secret that touches a store request and it is not a blob key. The folder index holds chat identity keys but lives in a sealed blob. OK.
- **Identity linkage.** The store learns a context and a per-`(key, day)` nullifier at issuance; the nullifier's unlinkability from the voting pseudonym depends on `credentials.md`. Nothing in this spec places a chat identity key next to a pseudonym or resident card. OK, with A6 open.
- **Votes never touch storage.** The closed source-tag set in §11 and the store's lack of any non-blob class are the right shape. OK.

## Testability

§12 is the best vector list among the specs I have read. Gaps:

- No vector for any §7 manifest rule (see B2).
- No failing vector for the re-put rule (B1), the put check order (S14), the order-authority-versus-token check (S4), or the unauthorized `keyring-share` sender (S1).
- `seal-trailing-data` appends 16 bytes; add `seal-appended-chunk` (a full 65,552-byte chunk appended) so the `n` recomputation path is tested.
- `ref-*` failing cases lack `ref-media-too-long`, `ref-description-too-long`, `ref-key-wrong-length`, `ref-unknown-key`, `ref-format-3`.
- `folder-replay` says it includes "every conflict rule in §5.4"; list which op index exercises which rule, or W0-08 cannot show coverage.
- `keyring-share` has a passing vector only; add `keyring-share-conflicting-secret` (same `k`, different secret, expect flag).
- `range-*` needs the `C` derivation vectors from S13.
- Promotion has no client-side failing vector; add `promote-digest-mismatch`.
- The §6.4 visibility table and the §6.8 log scan depend on `conformance.md` and `simulator.md`, which do not exist yet. Name them as dependencies in §12.

## Summary for the author (first pass)

Fix B1 (re-put adds no commitment) and B2 (full `blob-store` key table) in this spec now. Raise B4 with W0-01 and W0-07 before `release.md` and `services.md` settle, because it decides whether format 3 exists. Tell W0-08 that `reference/` must be rewritten to this spec (B3) and not the other way round. Then S1 through S17 are mostly single-sentence edits, and S5, S6, S8 and S11 go to the cross-spec pass.

---

## Re-review (2026-10-06, revised draft, 735 lines)

Re-read `storage.md` in full and the current `services.md` (common fields, authentication classes, errors, blob store row), `chat.md` (§1.2, §1.3, §3.1, §3.3, §5.7, §5.15, §10) and `release.md` ("Members-only results", refs table, alignment notes). Checked each blocker against the text, then every should-fix item.

### Verdict

**Approve.** B1, B2 and B4 are fixed in the text and the fixes agree with the sibling specs. B3 is in progress in `reference/` and remains the one gate before `just vectors`; it is W0-08's, not this spec's. Two consistency items are still open across specs and one of them changes vector bytes, so they are listed below as must-settle-before-vectors rather than blockers on the spec.

### Blockers, verified

**B1 fixed.** §6.3 "200 OK" now reads "The put changes nothing: no new delete commitment, no retention change, no new bytes", with the single exception of a re-put carrying the tuple's own `Hum-Delete-Secret` to extend retention. §6.3 closes with "A tuple holds exactly one delete commitment, the one from the put that created it", and §6.5 rejects when the secret's commitment "is not the tuple's commitment". Vector `store-reput-no-new-commitment` is in §12. §16 lists the re-put as an allowed carrier of the delete secret. Correct and complete.

**B2 fixed.** §7 now carries a full key table. I compared it key by key with `services.md`'s common table: 0 `kind`, 1 `endpoints` (array of text), 2 `apiVersion`, 3 `ohttp` (bstr), 4 `tokenIssuers` (array of CID), 5 `limits`, 8 `jurisdiction`, 9 `retention` match in number, type and meaning; 6, 7, 10, 11 are correctly excluded as other kinds' fields (BS-6); 12 to 15 are reserved in both (`services.md` S-1). Store fields 16 to 19 start where `services.md` says kind fields start, and `services.md` line 35 names exactly `issuer`, `blobLimits`, `blobRetention`, `formats` for `blob-store`. The duplicate `issuer` is gone (the common table no longer has one). BS-1 to BS-6 each name a failing vector and `service-blob-store-valid` is the passing one. `issuer.name` is frozen (BS-5), which closes S9. `kind` is `blob-store` in `services.md`'s enumeration. Encodable.

**B4 fixed, and consistently across three specs.** `storage.md` §1.7 says there is no public-key format; §6.3 adds the `authority`-signed put with `Hum-Context`, restricted to the context authority (public class only) and the context's aggregator authorities (either class), counted against the context's quota; §9.1 defines the two-layer form. `release.md` "Members-only results" says each table is a sealed blob under a fresh key and the keybox is a public blob of media type `application/vnd.hum.keybox+hpke` with the HPKE suite and `info` string spelled out, "not a sealed blob in storage's sense". `services.md` line 512 says an `authority` put "carries `Hum-Context` and counts against that context's quota". `formats.public` in §7 lists the keybox media type, so the store accepts it. The store never sees a third format byte. Correct.

One stale sentence remains in `release.md` line 288: "the aggregators act as a store client with a context token". Aggregators have no membership proof and cannot get a token; the put is `authority`-signed. For W0-01, one sentence.

**B3 in progress; one new mismatch to fix before vectors.** `reference/src/hum_reference/storage.py` now has format 2, the `0x80` pad marker, the 33-byte plaintext digest, reference keys 8 to 10 with form validation, HKDF-Extract with the salt, and a delete commitment. It still uses the pre-namespacing strings: `AAD_PREFIX = b"sealed/1"` (line 64), `KEYRING_BLOB_INFO = b"keyring/1/blob"` (line 69), and `b"delete/1"` in the commitment (line 480). The spec now says `hum/sealed/1` (§1.1), `hum/keyring-blob/1` (§4.3) and `hum/delete/1` (§8.1). Every sealed vector, keyring vector and delete vector would differ from the spec until those three constants change. Tell W0-08.

### Should-fix items, verified

Applied as proposed and checked against the sibling text: S1 (§4.2 sender rule, suspect marking, two vectors), S2 (§4.2 and `chat.md` §10.1 both exclude `keyring-share` and `folder-index` from archives and never archive the all-members group), S3 (§16 enumerates carriers including Welcome, GroupInfo, QR handle and the keybox), S4 (§6.5 token-context check, §8.2 `expires`, two vectors), S6 (`keyringHistory`, `sensitiveMax`, A3 closed), S7 (draft field names and the reverse rule with seven vectors), S8 (`chat.md` §3.1 lines 184 to 185 now state the own-or-other split), S9 (BS-5), S10 (`hum-context` directory member and the conflict rule), S12, S13 (§1.4 derivation of `C` and two vectors), S14 (§6.3 check order, `store-put-tombstone-other-context`), S15 (option (a), stated in §5.4), S16 (raw 32-byte key id, uint64 big-endian day), S17 (`chat.md` §5.7 now has a real `folder-index` type and a sender rule), N1, N5, N6, N7, and the three residual leaks in §13.

S5 is half done. Token type, issuer and issuance path now agree (`services.md` lines 117 to 118 defer to this spec). The error format still conflicts: `storage.md` §6.7 says a CBOR map with media type `application/vnd.hum.error+cbor`; `services.md` "Errors" says RFC 9457 `application/problem+json` and still claims that is "the format storage.md §6.7 already uses". Code spelling still conflicts: this spec writes `not_found`, `rate_limited`, `too_large`, `token_spent`, `cid_mismatch`; `services.md` writes `not-found`, `rate-limited`, `too-large` and even cites storage's own details as `cid-mismatch`, `quota-stored`. `store-put-mismatch` in §12 expects detail `cid_mismatch`, so this changes vector bytes. **Settle before vectors:** W0-06 and W0-07 pick one body format and one spelling. My recommendation stands: `services.md` owns the common format, so storage adopts problem+json and hyphens and `services.md` adds `token-spent`.

S11 is done for every string this spec owns. The exporter label stays `keyring/1` because `chat.md` §1.2 owns it and both specs agree; renaming it to `hum/keyring/1` is for the cross-spec pass with `delivery/1`, `frank/1`, `stamp/1` and `manifest/1`.

### New small items from the re-read

- **N8 (note) — `chat.md` §10 line 505** still says `storage.history` "governs which keyring epochs a `keyring-share` carries". This spec and `context.md` now say `storage.keyringHistory`. One word, for W0-05.
- **N9 (note) — `chat.md` §5.2 table and §5.7** still describe `public-copy` as "the message that `storage.md` §9 calls `promote`". This spec's §9 now says `public-copy`. Drop the parenthetical, for W0-05.
- **N10 (note) — `chat.md` §5.2 table** lists the `keyring-share` sender as "The committer of an Add" only, and §3.3's ignore list does not mention `keyring-share`. This spec's §4.2 also accepts shares from `members` holders for re-shares. Ask W0-05 to add `keyring-share` to the §3.3 ignore list with "per `storage.md` §4.2".
- **N11 (note) — §8.2 `expires`** is bounded by "the store's `blobRetention.tombstone`". An order sent to two stores with different windows must satisfy the smaller. Say "the smallest tombstone window among the context's stores", or bound it by the §7 minimum of 86,400 seconds so an order is valid everywhere.
- **N12 (note) — §5.3** still ends "every honest phone reaches the same state" without the qualification §5.4 now gives. Add "given the same `roles` serial" so the two sections agree.

### Summary for the author

Nothing in the spec blocks approval. Before W0-08 runs `just vectors`: settle the error body format and code spelling with W0-07 (S5 residual), and have W0-08 change the three domain-string constants in `reference/src/hum_reference/storage.py` to `hum/sealed/1`, `hum/keyring-blob/1` and `hum/delete/1` (B3 residual). Pass N8 to N10 and the `release.md` line 288 sentence to W0-05 and W0-01.
