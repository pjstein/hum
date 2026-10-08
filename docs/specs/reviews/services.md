# Review: `docs/specs/services.md` (Draft 0.1, W0-07)

Reviewed 2026-10-06 against `CLAUDE.md`, `docs/design.md`, `docs/specs/manifest.md`, `docs/specs/context.md`, `docs/specs/deck.md`, `docs/specs/release.md`, `docs/specs/chat.md`, `docs/specs/storage.md`, `docs/specs/verifier.md`, `docs/specs/verifier-runtime.md`, `docs/specs/trust-list.md`, `docs/specs/issue-map.md`, `docs/specs/take.md`, `docs/specs/agent-sponsor.md`, ADRs 0071 to 0073, the C2SP tlog-tiles, tlog-checkpoint, tlog-cosignature and tlog-witness formats, and the reference implementation's `reference/src/hum_reference/cose.py`.

Not on disk: `credentials.md`, `ballot.md`, `shield.md` (W0-02), `simulator.md` and `conformance.md` (referenced by this spec and by `storage.md`; W0-09 owns `sim/`). Findings that depend on them are marked. I did not guess their content.

## Verdict (first review)

**Rework**, confined to four areas: the shared conventions (tokens, errors, bundle signatures), the relay routing table, what the log checks at submission, and the aggregator round and release rules. The service boundaries, the one-log decision, the `service` manifest type, the C2SP alignment and the logging discipline are right and should stay. Seven blockers below. Each is a bounded edit, but three of them need the sibling owners (W0-02, W0-05, W0-06) to agree, which is why this is rework rather than approve with fixes.

See the [Re-review](#re-review-2026-10-06-after-rework) at the end for the current verdict.

## Blockers

**B1 (blocker) — "Authentication classes", token paragraph and T-1 to T-3; also "Delivery service and blob store".** The spec contradicts itself and both sibling specs on tokens:

- It says the `token` class is Privacy Pass type `0x0001`, "issued by the service itself", and in the same paragraph says tokens "follow storage.md §6.1 exactly: privately verifiable tokens". `storage.md` §6.1 and ADR 0061 fix the store on type `0x0002` (blind RSA, publicly verifiable) precisely so a separate issuer is possible. `chat.md` §12.4 uses `0x0001` for channel tokens and a per-context key only for registration.
- Issuance is `POST /v1/tokens/{context}` here and in `chat.md` §12.2, but `POST /v1/tokens` with the context in the body in `storage.md` §6.2.
- `storage.md` §6.1, §6.1's last paragraph, §14 A7 and the threat model all cite rule **T-4** for "issuance and spend never share a connection". This spec numbers that rule T-3. `storage.md` A7 also says this spec's T-2 puts the context in token metadata; T-2 now says the opposite.
- The delivery service row lists `POST /v1/context-tokens` and `GET /v1/manifest`, which `chat.md` §12.2 does not define, and the routing table lists "key packages" as a delivery operation, which `chat.md` open question 13 says does not exist (KeyPackages are sealed blobs).

Fix: make the `token` class table say per service which type is used (store `0x0002`, delivery `0x0001`), who issues it, and the issuance path, and point at each sibling section as normative. Renumber or add T-4 so the three cross-references resolve. Replace the delivery row with `chat.md` §12.2's six endpoints verbatim and drop "key packages" from the routing table.

**B2 (blocker) — "Errors"; also the open question "Error formats".** The spec says every error is RFC 9457 `application/problem+json`, "the format storage.md §6.7 already uses". `storage.md` §6.7 says errors are "a CBOR map, media type `application/vnd.hum.error+cbor`, the common format of services.md". `chat.md` §12.7 says "the error format is the common one in services.md" and uses its own codes. Each spec defers to the other and no one defines the bytes, so W0-08 cannot generate the "one body per code" vector this spec promises. Code spellings also differ: hyphens here (`too-large`, `rate-limited`, `not-found`), underscores in `storage.md` (`token_spent`, `not_found`, `cid_mismatch`) and `chat.md` (`bad_request`, `not_padded`, `epoch_conflict`); `malformed` is 400 here and 415 in `storage.md` §6.3. Fix: define one deterministic CBOR map here, for example `{0: code (tstr), 1: detail (tstr, optional), 2: step (uint, optional), 3: rule (tstr, optional), 4: retryAfter (uint, optional)}` with media type `application/vnd.hum.error+cbor`, one spelling convention, and a table that lists every code any service uses. CBOR is the better choice because every other body is CBOR and phones should not need a JSON parser on the error path. Tell W0-05 and W0-06 to point here and delete their local definitions.

**B3 (blocker) — "The bundle", key 1 `signatures`.** The bundle carries "an array of bstr, one COSE_Sign1 structure per signer, detached payload, over `manifest/1` plus the CID". `manifest.md` ("The envelope") says COSE_Sign, and the reference implementation (`cose.py`, `manifest_vectors.py`) emits one tagged COSE_Sign structure holding every signer's `COSE_Signature`, with `manifest/1` as external AAD. Two implementers following this spec and the reference would produce different bundle bytes and neither would verify the other's. Fix: key 1 is a single bstr holding the COSE_Sign structure as `manifest.md` and `reference/` define it; this spec does not restate the signature construction. The same applies to the `authority` and `organizer` request signatures (A-2), which say "a CBOR array of COSE_Sign1 structures": use one COSE_Sign structure there too, so there is one signature encoder in the whole protocol.

**B4 (blocker) — "Which requests go through the relay".** The table is organized by request type and misses several requests a person's phone makes. Each one hands the operator a client IP joined to an identity that the protocol otherwise keeps anonymous:

- `POST /v1/log/add` by a phone submitting an `issue`, `position`, `argument` or `take`. The `anonymous` form's slot nullifier and the `member` form's chat key would arrive with the submitter's IP. The "Log lookups" row covers reads only.
- `POST /v1/log/add` and `POST /v1/agg/decks` by an organizer's phone (context versions, decks, delete orders). The table's last row says "authorities, not people", but organizers and take authors are people holding 1-of-1 or 2-of-3 keysets on phones.
- `GET /v1/agg/decks/{cid}/daily` by an organizer.
- `GET /v1/agg/decks/{cid}` (deck status) and `GET /v1/verifier/manifest`.

Fix: invert the rule. "Every request a phone makes goes through the relay, except evidence submission and the blind issuance request to a verifier host, which are direct TLS by design." Then list the exceptions. Keep the per-row "why" column for the reader, but make the conformance check "a client opens no direct connection to any service other than a verifier host's session endpoints".

**B5 (blocker) — "Submitting a manifest", the step 9 and step 10 paragraphs.** Two things prevent two log implementations from agreeing on what to append:

- Step 9 is replaced by "every CID in `refs` that names a manifest is already in this log; blobs are not resolved". Nothing tells the log which ref names are manifests. If the log decides by "is it in the log already", the rule is vacuous: an unlogged manifest ref looks like a blob and passes. Fix: a per-type table of manifest-valued ref names (`deck.context`, `deck.card/<i>` when the card kind is 0 or 2, `release.deck`, `context.parent`, `context.tl/<i>`, `issue-map.context`, `issue-map.parent`, `issue-map.sponsor`, `issue-map.replaces`, `issue-map.mergedInto`, `issue-map.take`, `take.release/<n>`, `take.sponsor`, `take.forkOf`, `agent-sponsor.verifier`). Everything else is a blob.
- The release paragraph says the log runs release.md's rules, and "Publishing a release" step 3 says the log "runs R1 to R15 again". R15 reads the Parquet table blobs. The same spec says the log resolves no blobs. Fix: either the log runs R1 to R14 and R15 belongs to the Helper (before signing) and to phones (when they open a table), or the log fetches public table blobs from a store the context names before appending. State which, and update release.md's "The ledger runs R1–R15" sentence through W0-01.

Also say, per type, which step 10 rules the log runs. The spec names `context`, `deck`, `release` and the participant-authored types. `agent-sponsor.md` asks the log to count `takes` per sponsor per window and `take.md` has TK-1 to TK-9; `verifier`, `trust-list`, `agent-sponsor`, `keyset` and `service` are unaddressed. A logged-but-invalid version breaks a lineage for honest clients (issue-map.md says why), so the default should be "the log runs every type's step 10 rules that need only the log's own copy of referenced manifests", with an explicit list of the rules it skips because they need blobs or live state.

**B6 (blocker) — "Aggregator", task ID, "Opening a deck" and "Ballot intake" checks 4 and 5.** Three internal contradictions, all of which decide bytes:

- "A deck is a DAP task" with `taskId = SHA-256("hum/dap-task/1" || deckCid)`, but the DAP mapping table says "Task: a deck round" and `release.md` says "the DAP tasks for rounds 1–3". If each round is a task the ID needs the round number; if the deck is one task, batch selection by round needs saying. Pick one. Recommendation: one task per round, `SHA-256("hum/dap-task/1" || deckCid || round as uint8)`, because DAP batch intervals and the per-round receipt roots then line up.
- Check 4 says "the nullifier is new for this deck and round" and check 5 says the Leader checks that the pseudonym cast a round-0 ballot. If nullifiers differ per round (unlinkable scopes), the Leader cannot do check 5. If they are the same across rounds, the public per-round receipt blobs link a pseudonym's participation across rounds, unless the receipt leaf excludes the nullifier. State the requirement for `ballot.md`: one nullifier per (context, deck), reused in every round; the round and a phone-chosen random receipt nonce go in the receipt leaf; the leaf never contains the nullifier. Marked as depending on `ballot.md`.
- `POST /v1/agg/decks` returns `rounds: [{n, opens, closes, parts}]` at deck open, but `release.md` ("Rounds") says round n opens when version n is logged and closes at that version's `roundDeadline`. The schedule cannot be known at open. Fix: at open, return round 0 only; `GET /v1/agg/decks/{cid}` returns each later round's window once its version is logged, copying `roundDeadline`.

Also say whether a ballot rejected at check 6 (bounds) consumes its nullifier. It must not, or a voter whose first attempt was malformed is locked out with no receipt. Add "the nullifier is recorded only when the ballot is accepted" and a vector for it.

**B7 (blocker) — AG-4 and the logging-table row for the issuer host.**

- AG-4 says "a release is published only when the noised participant count is at or above the minimum". `release.md` R6 and vector `release-valid-below-minimum` publish version 1 with `nHat` absent, `unlocked` empty and no tables when the count is below `minVoters`, so the budget spend is on the ledger. The simulator would fail a conforming aggregator. Fix: "no table is published unless `nHat` ≥ `minVoters`; exactly one release lineage per deck".
- The issuer row says the host may log "verifier authority, version, day-granular timestamp, outcome, module resource use" and "evidence only as its manifest declares". `verifier-runtime.md` ("Transparency", host logging rules; rules 13 and 14) fixes the line as exactly: a random 16-byte session ID, authority, version, opening day, true outcome, resource use rounded to buckets. Rule 14 and this spec's own V-4 say "exactly", so the two tables cannot both be true. Evidence retention is host storage, not a log line, and listing it under "may log" invites writing it to a log. Fix: the row reads "the session log line of verifier-runtime.md, exactly; evidence is stored, never logged, as the manifest's `kept` and `storedAs` declare".

## Should fix

**S1 — "Issuer and verifier host", sessions, `sessionCap`.** "A host opens at most `sessionCap` sessions per phone per day, counted as verifier.md says." `verifier.md` does not say, and `verifier-runtime.md` lists this as an open question for this spec. Sessions are `public` and the logging table forbids keeping a transport address. Define the counter: for example, an in-memory count keyed by client IP, discarded after 24 hours, never written to a log; or count only when a `device` evidence item binds the phone; or drop `sessionCap` from the manifest. Say which and add it to the host's "stores" list with its retention.

**S2 — V-1 and the `asks` cross-reference.** `verifier.md` ("Disclosure summary") and `verifier-runtime.md` (assumptions) both say "services.md rule V-1 requires the host's `asks` to equal the phone's". This spec's session start says the host sends no list of asks, and V-1 is about undeclared evidence names. The three specs disagree on what V-1 is. This spec's design is better (nothing to compare). Say so explicitly in the sessions paragraph and ask W0-03 to delete the `asks` sentences. Both W0-03 specs also still say this spec keys evidence by `kind`; it keys by `name` now, so their open-question entries are stale.

**S3 — `service` body, validation rules S-1 to S-4.** Rules are missing for fields the rest of the spec depends on: `issuer` present when `kind` is `delivery`; `hpke` present for `aggregator` when `phase` is 2; `endpoints[].ohttp_key_config` non-empty and a well-formed RFC 9458 `KeyConfig` for every kind a phone reaches through the relay (O-2 has nothing to pin otherwise); `retention` keys drawn from a named set. Add S-5 to S-8 with one failing vector each.

**S4 — `service` body, key 10 `stamp`; and `kind` `gateway`.** `chat.md` §12.1 says the stamp key is "any `sign` key of its keyset" and the send response returns the `key_id`; `chat.md` §11.3 step 4 verifies "under a `sign` key of the DS's keyset". The dedicated `stamp` field here conflicts; drop it or get W0-05 to adopt it. Separately, the `gateway` kind has no stated contents: O-2 pins the gateway key configuration inside each service's `endpoints`, so a gateway manifest carries nothing a phone reads. Either give it a purpose (the relay list, see S5) or remove the kind.

**S5 — "OHTTP relay", "Who runs it" and ADR 0073.** Nothing says how a phone learns a relay's URL and that it is a relay the operator does not run. ADR 0073 says the relay operator is named "in the gateway's `service` manifest as an unsigned hint", but a manifest is signed bytes; there is no unsigned field. Fix: add `kind: relay` to the `service` type (endpoints and jurisdiction, no key configuration), have the app ship the reference relay authorities as constants beside the Global context CID, and let a context name additional relays. Say that a phone refuses to use a relay whose manifest is signed by the same authority as the gateway it is paired with.

**S6 — "Checkpoints", acceptance rule.** A phone accepts a checkpoint "with cosignatures from at least `floors.minWitnesses` distinct keys in that context's `logs[].witnesses`". A phone verifying a `verifier`, `trust-list`, `agent-sponsor`, `take` or `service` manifest with no context in hand (before joining, or browsing the gallery) has no witness list, and the log's own `service` manifest is itself proven by a checkpoint. State the bootstrap rule: the app ships the reference log's authority CID and its witness keys as protocol constants, and uses `MIN_WITNESSES` when no context applies. Add the log's own signature key ID rule for completeness: name equals the origin line, algorithm byte `0x01`, so `keyID = SHA-256(origin || "\n" || 0x01 || pubkey)[0..4]`. The `0x04` rule for cosignatures is correct per tlog-cosignature.

**S7 — "Witness", status table.** tlog-witness returns 409 when `old` equals the new size and the root hash differs (a same-size conflict), with the body being the witness's size. The table covers 409 only for a stale `old`, and the prose says "equal roots when sizes are equal" without a code. Add the row. The rest of the table and the check order match tlog-witness.

**S8 — "Receipts".** The receipt page scheme ("fixed-size pages, the phone fetches the page its leaf's prefix selects") has no page size, no page-count rule and no path. Two aggregators would publish different blobs and phones would fetch different things. Fix: page count `P = 2^k` with `k` fixed by a rule on the round's leaf count (for example the smallest `k` with `n / 2^k ≤ 4096`), page `i` holds leaves whose first `k` bits equal `i`, published as `receipts/<round>/<i>` blobs plus a root blob listing their CIDs; put `k` in the response. The 4 KiB request bucket (O-3) then bounds what a page fetch reveals. Also state the invariant the leaf must satisfy, per B6.

**S9 — "What services log", gateway row.** The gateway may log "relay connection, decrypted request's path". A path carries the CID or deck CID. Connection plus path for 30 days is exactly the join the resolver row forbids ("which connection asked for which CID"). O-4 limits multiplexing per class, but one lookup connection still carries a sequence of CIDs. Fix: the gateway logs path and result code without the connection identifier, or counts per path only.

**S10 — "What services log", log row.** IM-15 counts `member`-form objects per chat identity key per window, so the log keeps a per-chat-key counter. That is one identity, not a join, but it is a stored identifier with a lifetime and must appear in the "may log" column with its retention (one window), or the simulator's leak check and the implementer will disagree.

**S11 — A-1 and A-3, signed request payload.** The payload is "method, space, path, zero byte, SHA-256 of body, then `Hum-Nonce` and `Hum-Issued` appended". Unspecified: whether `path` includes the query string and the endpoint prefix; whether the nonce is appended as the 16 raw bytes or its base64url text; whether `Hum-Issued` is decimal ASCII or a big-endian uint64. Fix: `path` is the request target as sent, including query, excluding scheme and host; nonce raw 16 bytes; issued as uint64 big-endian; and add the exact byte layout to the vector.

**S12 — "Publishing a release", step 2.** `POST /v1/agg/decks/{cid}/propose` is not in the endpoint table and its request and response bodies are undefined. Add it: request is the proposed bundle with the Leader's signature and the table blob CIDs; response is the Helper's COSE_Sign signature over `manifest/1 || CID` or `rejected` with `rule`. Also say which store the aggregator puts a sealed table to needs a context CID in the request, since the store's visibility table keys tuples by the token's context and an `authority`-signed put has no token.

**S13 — Deck `state` values.** `abandoned` appears in `GET /v1/agg/decks/{cid}` and nowhere else. Define when a deck becomes abandoned (for example: `expires` passes with no version 1 logged) and what the ledger shows, since `release.md` publishes a version 1 even below the minimum.

**S14 — "Resolver and mirrors", RS-2 and `GET /v1/bundle/{cid}`.** RS-2 says the resolver answers 401 with no body for sealed, absent or tombstoned CIDs. A missing manifest bundle is public data; say `GET /v1/bundle/{cid}` answers 404 for an unknown manifest, and 401 applies to `/v1/blobs` only.

**S15 — O-3, response padding.** Responses are "padded the same way" to buckets up to 256 KiB, but `deps=1` responses reach 16 MiB and entry tiles are 256 × 128 bytes. Say what happens above the largest bucket (next multiple of 256 KiB) so two gateways agree.

**S16 — Scope string namespacing.** Token scopes `blob-tokens/<key>/<day>` and `delivery-tokens/<key>/<day>` are not under `hum/`; the issue-map scopes `hum/author-once/1` and `hum/author-slot/1` are. Domain strings this spec defines (`hum/service-request/1`, `hum/receipt/1`, `hum/dap-task/1`) are namespaced; `stamp/1`, `frank/1`, `sealed/1`, `delete/1`, `blob-delete/1`, `manifest/1` in sibling specs are not. All are unique today, but there is no registry. Recommend this spec, as the cross-service spec, carry a table of every domain string and scope prefix in the protocol with its owning spec, and ask W0-10 to settle the `hum/` convention.

## Notes

**N1 — Leaf size.** "A leaf is under 128 bytes" is false for `agent-sponsor` (13-byte type) at version ≥ 2³² : 1 + 35 + 14 + 35 + 35 + 9 = 129. Say "at most 160 bytes" or drop the claim; the uint16 length prefix is what matters.

**N2 — Multiple logs.** Step 3 of release publication submits to "every log the context names", and R10 and R14 are checked "against its own history" per log. Two logs can disagree on the yearly total. Say that the first log in `ctx.logs` is authoritative for R10 and R14, or that the ledger checks are per log and the stricter answer wins.

**N3 — `GET /v1/log/lineage/{cid}` fork rule.** "A fork appears as two entries with the same version; the lower index wins" matches manifest.md. Add that the response includes the `authority` so a reader can detect a lineage whose authority changed, which step 8 forbids.

**N4 — Phase 1 Helper visibility.** "In phase 1 the Helper does not see ballots or raw sums" is right, but the threat model has no row for the Helper as a party. Raised there.

**N5 — Daily count.** Serving "the same series to every caller" is what makes repeated reads free; say that the aggregator computes each day's increment once at UTC midnight and never recomputes, and that a day with no ballots still gets a noised increment (otherwise the absence of a row leaks a zero).

**N6 — `release.md` open question 1 and 6 are stale** on release.md's side: it still says this spec has two rounds and unlogged `round-publish/1` blobs and a single receipt root. This spec is aligned to versions and per-round roots. Tell W0-01.

**N7 — `storage.md` §7 and §6.1 name fields this spec does not define:** `ohttp`, `tokenIssuers`. Either add `tokenIssuers` (array of issuer authority CIDs) to the `service` body or have W0-06 drop them.

**N8 — Jurisdiction and retention are unsigned promises.** Fine, but say the app shows them on the context's services screen so the choice is visible, matching the threat model's "every such choice is in a logged manifest members can read".

## Invariants, floors, sums, federation (summary)

- **Invariants.** No field in the `service` manifest, bundle or leaf carries personal data. The joins that worry me are all in the logging and routing rules, not in the data model: B4 (IP joined to an anonymous author or organizer), S9 (gateway connection plus path), S1 (session counting), and the receipt leaf dependency in B6. No sealed-blob key reaches a manifest, log or store request; the keybox path is right.
- **Floors.** Nothing here loosens a floor. AG-3, LG-2 and the `floor` error are correct. B7's AG-4 is too strict rather than too loose, which still breaks conformance.
- **Sums.** The DAP mapping keeps every part a sum of bounded per-person vectors, and "each aggregator adds its share of the noise" is the right phase 2 statement. The daily count's one-hot-over-days mapping matches context.md.
- **Federation.** Services are named by authority CID throughout; URLs are hints; the OHTTP key configuration comes from a logged manifest (O-2). Two gaps: relay discovery (S5) and witness bootstrap without a context (S6).

## Testability

The vector list covers the `service` rules, bundles, leaves, checkpoints, witness bodies, authority signatures, task ID, receipt, errors and padding. Missing failing vectors: A-2 (signature count below threshold), T-1 (replayed token), a receipt with the wrong key or wrong task ID, a checkpoint missing the log's own signature, a cosignature whose key ID does not match any listed key, a leaf whose hash is computed without the `0x00` prefix, B6's "rejected ballot does not consume the nullifier", and one per new S-rule from S3. V-1 appears in neither the vector list nor the simulator list. The error vector cannot be generated until B2 is settled, and the bundle vector until B3 is.

## Summary for the author (first review)

Settle B1 to B3 with W0-05, W0-06 and W0-08 first, because they decide bytes that every other workstream encodes. B4 and B5 are local edits. B6 needs a one-paragraph agreement with W0-02 on the nullifier and receipt leaf before `ballot.md` is written. B7 is two sentence changes. After those, S3 to S8 are the items that stop two implementations from agreeing; the rest can land in the cross-spec pass.

---

## Re-review (2026-10-06, after rework)

Re-read the reworked `services.md` (768 lines) in full, and the current `storage.md`, `chat.md`, `release.md` and `verifier-runtime.md` where the first review's findings touched them.

### Verdict

**Approve with fixes.** All seven blockers are resolved in a way the sibling specs now agree with. The should-fix list from the first review is closed except where noted below. No new blocker. The remaining items are one definitional gap in rule O-5 that the threat model over-relies on, a stale domain-string registry, two gaps in the step 9 table, and stale cross-references.

### Blockers from the first review

| | Status | Evidence |
| --- | --- | --- |
| B1 tokens | Fixed | "Tokens" table gives type, issuer and path per service; T-4 exists; `storage.md` §6.1 and `chat.md` §12.3 cite T-4 and both use `POST /v1/tokens` with the context in the body. The delivery row now mirrors `chat.md` §12.2. |
| B2 errors | Fixed | One CBOR map, `application/vnd.hum.error+cbor`, snake_case, one code table. `storage.md` §6.7 and `chat.md` §12.8 point at it and only add `detail` strings. |
| B3 bundle signatures | Fixed | Key 1 is one COSE_Sign as `manifest.md` and `cose.py` define; A-2 reuses it with external AAD `hum/service-request/1`. |
| B4 relay routing | Fixed | Inverted rule; every phone request through the relay except the two verifier-host calls; conformance check restated. |
| B5 log checks | Fixed, two gaps | Per-type step 9 and step 10 tables; R15 moved to Helper and phones. Gaps in N1 below. |
| B6 rounds, tasks, nullifiers | Fixed | One task per round with the round byte in the ID; one nullifier per (context, deck); receipt leaf requirement stated for `ballot.md`; round windows announced as versions are logged; AG-8 covers the unrecorded-nullifier rule. Agrees with `release.md` "Rounds" and "Receipts". |
| B7 AG-4 and issuer logging | Fixed | AG-4 matches `release.md` R6; the issuer row quotes `verifier-runtime.md`'s exact field list; V-4 and rule 14 now agree. |

### Should-fix from the first review

S1 through S15 are closed: session counting is defined with its retention (S1); V-1 and the `asks` claim are reconciled and `verifier-runtime.md` now says "confirmed on disk" (S2); S-5 to S-8 exist with vectors (S3); `stamp` and `gateway` are gone and `chat.md` §11.2 agrees (S4); `kind: relay` plus constants plus O-5 (S5); bootstrap rule and the log's own key ID (S6); the same-size 409 (S7); receipt pages with a `k` rule (S8); gateway logs no connection identifier (S9); the log's per-chat-key counter is listed with its retention (S10); A-1 is byte-exact with a vector (S11); `propose` is in the endpoint table with bodies, and `storage.md` §6.3 defines the `Hum-Context` put (S12); `abandoned` is defined (S13); `/v1/bundle` answers 404 (S14); padding above 256 KiB (S15). S16 became the registry, which is the subject of F1.

### New findings

**F1 (should fix) — "Domain strings and scopes".** The threat model now says this registry is the seam and "a string not in it is a finding". The registry is already behind the siblings. `chat.md` moved its strings under `hum/` (`hum/device/1`, `hum/safety/1`, `hum/chat-roles/1`, `hum/frank/1`, `hum/stamp/1`, `hum/token-request/1`, `hum/pp-issuer/1`, `hum/welcome/1`) and added `hum/commit/1`, `hum/join/1` and `hum/attest/1`; `storage.md` moved to `hum/sealed/1` and `hum/blob-delete/1`. The registry lists the old unprefixed names and lacks the three new ones. Nothing collides, so this is not an invariant problem, but the registry fails its stated job on the day it was declared. Fix: update the rows to what the owning specs say today, and add a line that the owning spec's text wins over the registry when they disagree, so the registry cannot silently become a second source of truth. Also drop the "W0-10 decides whether the older strings move" sentence for chat and storage, which have already moved; only `manifest/1`, `keyring/1` and `delivery/1` remain unprefixed.

**F2 (should fix) — Rule O-5.** Two problems. First, "the same authority as the gateway it is paired with" is undefined now that the gateway has no manifest and no authority: the gateway's key configuration sits in each fronted service's manifest under that service's authority. Rewrite as "the same authority as any service the phone reaches through that relay". Second, O-5 cannot stop a colluding operator: authorities are free, so an operator who wants to run the relay signs its relay manifest with a fresh keyset and O-5 passes. O-5 catches an honest misconfiguration and a context that openly names its gateway operator's relay, which is worth having. It does not provide the relay-gateway separation; the relay operator choice (ADR 0073), the app-shipped relay constants and the visible services screen do. Say that in the rule's own text, because the threat model's assumptions table currently reads as if O-5 closes the hole (see the threat-model re-review).

**F3 (note) — Bootstrap constants against invariant 6.** Shipping the reference log's authority CID, origin line and launch witness keys as app constants is naming by key, not by hostname, and some trust anchor is unavoidable; the Global context CID already ships the same way. Two refinements keep the steady state inside "keys a manifest names". First, use the constants only to verify the first checkpoint and resolve the Global context's current version; from then on, Global's `logs[].witnesses` and `floors.minWitnesses` are the context-less rule, so witness keys rotate through a logged lineage rather than an app update. Second, state that a context-less verification never accepts fewer than `MIN_WITNESSES` even if the constants list more keys than needed. Neither changes bytes; both belong in the "Bootstrap" bullet.

**F4 (should fix) — Step 9 table, two gaps.** The `deck` row lists `card/<i>` as manifest-valued only when the card's `kind` is 0; a rating deck's cards are `take` manifests (`kind` 2, `deck.md` D15), which the log should also require to be present. And the release row will need `receipts/<n>` added to the blob column once `release.md` adopts the requested ref, so an implementer does not treat it as a manifest ref by default. One line each.

**F5 (note) — Receipt pages against `release.md` "Receipts".** `release.md` now pads each round's tree with dummy leaves (part 8) and sorts leaves bytewise. The paging rule is compatible, but say that `L` is the padded leaf count, and change "the leaf holds the round number, a nonce and a commitment" to "the leaf is a fixed-length hash over the round number, a phone-chosen nonce and a commitment", because `release.md` requires dummies to be indistinguishable from real leaves and a structured leaf would not be. AG-6 should also say the root is over the padded tree.

**F6 (note) — Stale cross-references.** The "Tokens" paragraph says `chat.md` §12.2 still spells the path `/v1/tokens/{context}`; it no longer does, except in its assumptions list. The delivery row is missing `chat.md` §12.2's `reset`, `join/{context}` and `join/{context}/fetch` endpoints; the `organizer` class's "Used for" column should add the channel reset. The error table lists `epoch_conflict` as used by delivery; `chat.md` §12.8 says the DS never answers it. `storage.md` §7 says store manifests run "after S-1 to S-4" while S-5 and S-6 now apply to `blob-store`; tell W0-06. `release.md` line 203 still says the ledger runs R1 to R15; the spec notes it was sent to W0-01.

**F7 (note) — Auth class table.** The reissue endpoint's auth is `credential`, which is not a row in the class table. Add it, or fold it into `ballot`-style wording ("the presentation itself is the credential").

### Invariants, floors, sums, federation after rework

- **Invariants.** The routing inversion, the gateway logging fix and the receipt-leaf requirement close the three joins the first review found. No new join introduced. The registry (F1) is a bookkeeping gap, not a leak.
- **Floors.** AG-4 now matches `release.md`. Nothing loosens a floor.
- **Sums.** One task per round keeps every batch a sum over one round's bounded vectors. Receipt padding (part 8) is itself a noised sum of per-person one-hots, which `release.md` accounts for.
- **Federation.** The `relay` kind and O-2 keep every key a phone encrypts to inside a logged manifest. F2 and F3 are the two places the text claims slightly more than the mechanism gives.

### Testability after rework

The vector list now covers S-1 to S-8, B-4, LG-8, the log key ID, the same-size witness 409, A-2 and A-3 failures, T-1, receipt failures, page assignment, every error code and the two bare forms, and padding above 256 KiB. V-1 to V-4 are in the simulator list. Remaining gap: no failing vector for O-5 or for the bootstrap rule, both of which have bytes (a relay manifest signed by a named service's authority; a checkpoint cosigned by keys outside the constants). Add one each.
