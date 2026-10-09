# Hum Services Spec — Draft 0.1

Oct 6, 2026 · W0-07

## Scope

This spec fixes the APIs between Hum's services and the things that call them: phones, other services, mirrors, witnesses and tools. Wave 1 builds each service and the apps in parallel, so every boundary here is a contract. The [manifest spec](manifest.md) defines the objects that cross these boundaries. The type specs define their bodies. This spec defines how they move, how callers are authenticated, what each service checks, what it answers when something fails, how it limits callers, and what it is allowed to write to its own logs.

Services covered:

| Service | Runs at launch | Section |
| --- | --- | --- |
| Log and ledger | One reference log (Go, Tessera) | [Log and ledger](#log-and-ledger) |
| Witness | At least two independent organizations | [Witness](#witness) |
| Aggregators (Leader and Helper) | The operator and one Helper partner | [Aggregator](#aggregator) |
| Issuer and verifier host | The platform's core verifiers; anyone else's | [Issuer and verifier host](#issuer-and-verifier-host) |
| Delivery service | The reference delivery service | [Delivery service and blob store](#delivery-service-and-blob-store) |
| Blob store | The reference blob store | [Delivery service and blob store](#delivery-service-and-blob-store) |
| Resolver and mirrors | The reference resolver; anyone may mirror | [Resolver and mirrors](#resolver-and-mirrors) |
| Gallery index and open data | The reference gallery | [Gallery index and open data](#gallery-index-and-open-data) |
| OHTTP relay and gateway | Relay by an independent party; gateway by the operator | [OHTTP relay](#ohttp-relay) |

Out of scope: the body schemas of manifests (their own specs), the ballot encoding ([ballot.md](ballot.md)), credentials and the per-deck pseudonym ([credentials.md](credentials.md)), the shield ([shield.md](shield.md)), the sealed blob format ([storage.md](storage.md)), MLS message formats ([chat.md](chat.md)), and operations (keys, hosting, deployment, which W1-13 covers in `docs/ops/`).

The threat model that every rule here answers to is [docs/threat-model.md](../threat-model.md).

## Conventions shared by every service

Every service follows the same rules for naming, transport, encoding, authentication, errors, rate limits and logging. A service-specific section only says what differs.

### Services are named by key

A service is an authority: a `keyset` lineage, identified by the CID of its first keyset ([manifest.md, Authorities and keys](manifest.md#authorities-and-keys)). A context names the logs, aggregators and stores it accepts by authority CID. Hostnames are location hints and are never signed.

Each service publishes a `service` manifest, a type new in this draft ([ADR 0072](../decisions/0072-w0-07-service-manifest-type.md)), that says what kind of service it is and where it can be reached. The common fields below use keys 0 to 15. A kind's own fields start at key 16 and are defined in the spec that owns that service: [storage.md §7](storage.md#7-the-blob-store-manifest-body) for `blob-store` (`issuer`, `blobLimits`, `blobRetention`, `formats`). The manifest spec's registry now lists `service` and retires the `blob-store` type name, so a store is a `service` with `kind: blob-store` and nothing else.

Common `service` body fields:

| Key | Name | Type | Required | Frozen | Meaning |
| --- | --- | --- | --- | --- | --- |
| 0 | kind | text | yes | yes | One of `log`, `witness`, `aggregator`, `issuer`, `delivery`, `blob-store`, `resolver`, `relay`, `gallery` |
| 1 | endpoints | array of text | yes | no | HTTPS URL prefixes where the API is served. Hints, never trusted |
| 2 | apiVersion | uint | yes | no | 1 for this draft |
| 3 | ohttp | bstr | kinds phones reach through the relay | no | The OHTTP gateway `KeyConfig` (RFC 9458 §3) a phone encrypts requests to for this service |
| 4 | tokenIssuers | array of CID | kinds that take tokens | no | Keyset authorities whose anonymous tokens this service accepts; may include the service itself |
| 5 | limits | map | optional | no | Declared rate limits, see [Rate limits](#rate-limits) |
| 6 | witnesses | array of `{0: name (tstr), 1: key (bstr 32)}` | `log` only | no | The witnesses this log asks to cosign, see [Witness](#witness) |
| 7 | origin | text | `log` only | yes | The checkpoint origin line, see [Checkpoints](#checkpoints) |
| 8 | jurisdiction | text | optional | no | ISO 3166 country or region where the service runs and keeps data |
| 9 | retention | map of class (text) → uint seconds | optional | no | How long each class of data is kept; classes are `requests`, `errors`, `counters`, `content`, see [Logging](#what-services-log) |
| 10 | hpke | bstr | `aggregator` only | no | The DAP `HpkeConfigList` for phase 2, see [Phase 2](#phase-2-dap) |
| 11 | phase | uint | `aggregator` only | no | 1 or 2, the aggregation phase this aggregator runs |

There is no `stamp` field: the delivery service stamps with any `sign` key of its keyset and names the key in each response ([chat.md §12.6](chat.md#126-send-sequencing-and-the-stamp)). There is no `gateway` kind: a gateway's key configuration lives in the `ohttp` field of each service it fronts, so a gateway manifest would carry nothing a phone reads. A `relay` manifest carries `endpoints` and `jurisdiction` and no `ohttp`, because the relay holds no key a phone encrypts to.

Validation rules (verification step 10 for type `service`, before the kind's own rules):

- S-1. `kind` is one of the nine values above, and no key from 12 to 15 is present.
- S-2. `endpoints` has at least one entry, each an absolute `https` URL with no query or fragment.
- S-3. When `kind` is `log`, `origin` and `witnesses` are present and `witnesses` has at least `MIN_WITNESSES` (2, [context.md](context.md#protocol-constants-draft-01)) entries with distinct keys.
- S-4. `kind` and `origin` never change between versions.
- S-5. `ohttp` is present, non-empty and a well-formed RFC 9458 `KeyConfig` for every kind a phone reaches through the relay (`log`, `aggregator`, `issuer`, `delivery`, `blob-store`, `resolver`, `gallery`), and absent for `witness` and `relay`.
- S-6. `tokenIssuers` is present and non-empty for `delivery` and `blob-store`; the kind-specific `issuer` map (key 16, per storage.md for stores and the same shape for delivery) is present for the same kinds.
- S-7. For `aggregator`, `phase` is 1 or 2, and `hpke` is present iff `phase` is 2.
- S-8. `retention` keys are drawn from the four classes above, and each value is at most the ceiling in the [logging table](#what-services-log) for that service.

A context names the services its members use by authority CID: `logs[].log`, `aggregators`, `stores`, `chat.delivery` and the issuers in its entry policy ([context.md, Body fields](context.md#body-fields)). A phone resolves an authority to its current `service` manifest through the log, like any lineage. The app shows each named service's `jurisdiction` and `retention` on the context's services screen, so these unsigned promises are at least visible.

### Transport and encoding

- All APIs are HTTPS. Phones reach the services in the OHTTP column of the [routing table](#which-requests-go-through-the-relay) only through an OHTTP relay.
- Every path in this spec is under a service's endpoint prefix and starts with `/v1/`. A service that changes an API incompatibly adds `/v2/` and keeps `/v1/` for as long as its manifest lists `apiVersion` 1.
- Request and response bodies are deterministic CBOR ([manifest.md, Encoding](manifest.md#encoding-and-content-addressing)) unless a section says otherwise. The media type is `application/cbor`. Public read endpoints that exist for tools also serve a JSON view with the `Accept: application/json` header. The JSON view is never signed and is never the form a client verifies.
- Tiles, checkpoints and witness requests use the exact text and binary formats of the C2SP specs ([tlog-tiles](https://c2sp.org/tlog-tiles), [tlog-checkpoint](https://c2sp.org/tlog-checkpoint), [tlog-cosignature](https://c2sp.org/tlog-cosignature), [tlog-witness](https://c2sp.org/tlog-witness)), not CBOR, so existing witnesses, monitors and mirrors work unchanged.
- Blobs are served as their own bytes with the media type the manifest declares.
- Request bodies are capped per endpoint. A service rejects a larger body with error `too_large` before reading the rest.

### Body keys

Request and response bodies this spec defines are deterministic CBOR maps with integer keys, like every other map in the protocol. The endpoint sections write them with names for readability; this table is the encoding. Keys follow the order the fields are written. The JSON view uses the names. Bodies owned by `chat.md` and `storage.md` carry their own keys there.

| Body | Keys |
| --- | --- |
| `POST /v1/log/add` response (also `GET /v1/log/add/{cid}`) | `{0: index, 1: checkpoint, 2: path}` |
| `GET /v1/log/entry/{cid}` | `{0: index, 1: type, 2: authority}` |
| `GET /v1/log/lineage/{cid}`, each element | `{0: index, 1: cid, 2: version, 3: authority}` |
| `POST /v1/agg/decks` response | `{0: taskIds, 1: round0 {0: opens, 1: closes}, 2: cap, 3: phase, 4: leader, 5: helper}` |
| `GET /v1/agg/decks/{cid}` | The keys above, plus `{6: state, 7: rounds [{0: n, 1: opens, 2: closes, 3: version}], 8: versions}` |
| Ballot receipt | `{0: leaf, 1: signature, 2: kid}`; `kid` is the key ID of the aggregator `sign` key that made the signature |
| `GET .../rounds/{n}/receipts` | `{0: root, 1: k, 2: pages}`. A different body from the root blob below, on purpose: the response adds `root` for the phone's convenience, and the phone checks it against the release body |
| Receipt root blob, pinned as `refs["receipts/<n>"]` | `{0: k, 1: pages}`, with `pages` the array of page CIDs in page order; media type `application/cbor`. It carries no `root`, because it is the object the release commits to and the root is already in the release body |
| `GET .../daily` | `{0: sigma, 1: buckets [{0: bucket, 1: increment}], 2: total}` |
| `POST .../propose` request; response | `{0: bundle, 1: tables, 2: pages}`; `{0: signature}` |
| `POST /v1/verifier/sessions` request; response | `{0: manifest}`; `{0: id, 1: expires}` |
| `POST .../evidence` | `{0: name, 1: kid, 2: ciphertext}` |
| `POST .../issue` | `{0: kid, 1: ciphertext}`; the sealed plaintexts keep the keys `credentials.md` gives |
| `GET /v1/verifier/revocation` | `{0: method, 1: accumulator}` |
| `GET /v1/releases`, each element | `{0: cid, 1: index, 2: deck, 3: context, 4: issued, 5: parts}` |
| `GET /v1/log/proof/inclusion` | `{0: index, 1: size, 2: path}`, `path` an array of 32-byte hashes |
| `GET /v1/log/proof/consistency` | `{0: from, 1: to, 2: path}` |
| `GET /v1/gallery/takes` | `{0: takes [{0: cid, 1: logIndex, 2: rated, 3: hasGroupScore, 4: score, 5: forkCount}], 1: ratings, 2: next}`. The names are take.md's sort key. `score` is the take.md score rounded to six decimals as take.md rounds it (half to even, in binary64) and multiplied by 10⁶, as a CBOR integer that may be negative; for an unrated take (`rated` false) `score` is absent. `ratings` is the rating release CIDs the order was computed from, `next` the cursor or absent |
| `GET /v1/gallery/takes/{cid}` | `{0: bundle, 1: ratings, 2: versions, 3: releases}`: the take bundle, the rating release CIDs, the pooled `queryHash` version CIDs, the release CIDs it uses |
| `GET /v1/gallery/takes/{cid}/forks` | `{0: takes, 1: next}`, `takes` an array of CIDs |
| `GET /v1/gallery/ratings` | `{0: releases}`, an array of CIDs |

W0-08 fixes each body in a vector (`service-body-*`).

### The bundle

A manifest travels as a bundle: the envelope bytes, the signatures, and the log proofs ([manifest.md, The envelope](manifest.md#the-envelope)). The manifest spec names the parts but not their wire form, so this spec fixes it. If the manifest spec later defines one, that definition wins and this section is removed.

A bundle is a deterministic CBOR map:

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | envelope | bstr | The canonical unsigned envelope bytes. Hashing them gives the CID |
| 1 | signatures | bstr | One COSE_Sign structure holding every signer's `COSE_Signature`, detached payload equal to the CID, external AAD `hum/manifest/1`, exactly as [manifest.md](manifest.md#the-envelope) and the reference implementation (`reference/src/hum_reference/cose.py`) define it. This spec does not restate the construction. Absent for participant-authored types, which carry `authorship` instead |
| 2 | proofs | array of proof | Inclusion proofs, one per log that holds this manifest. Empty only while the manifest is being submitted |
| 3 | hints | array of text | Unsigned location hints: URL prefixes where referenced bytes may be fetched |
| 4 | authorship | bstr, optional | The authorship proof for `issue`, `position`, `argument` and `take` manifests, encoded as [issue-map.md, Authority and authorship](issue-map.md#authority-and-authorship) and [take.md](take.md#authority-and-authorship) define. It travels beside the envelope and is never hashed into the CID |

A proof is a CBOR map:

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | log | CID | The log authority |
| 1 | index | uint | The leaf index in that log |
| 2 | checkpoint | text | A checkpoint note with the log's signature and witness cosignatures, as served at `/checkpoint` |
| 3 | path | array of bstr | The RFC 6962 inclusion path from the leaf to the checkpoint's root, 32 bytes per hash |

Bundle rules:

- B-1. A bundle is at most 96 KiB on the wire: a 64 KiB envelope plus signatures and proofs. Larger bundles are rejected with `too_large`.
- B-2. The media type is `application/vnd.hum.bundle+cbor`.
- B-3. A client ignores `hints` for everything except where to try fetching. Hints never change a verification result.
- B-4. Exactly one of `signatures` and `authorship` is present, according to the manifest's type.

### Authentication classes

Every endpoint names one of these classes. There are no accounts for people anywhere in the protocol.

| Class | Who it identifies | How | Used for |
| --- | --- | --- | --- |
| `public` | Nobody | No credential | Reading logs, tiles, public blobs, releases, the gallery |
| `token` | A member of some context (or channel), not which one | A Privacy Pass token ([RFC 9576](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577](https://www.rfc-editor.org/rfc/rfc9577.html), [RFC 9578](https://www.rfc-editor.org/rfc/rfc9578.html)); the type, issuer and issuance path per service are in the table below | Blob store, delivery service |
| `ballot` | A voting pseudonym in one deck | The ballot's own membership proof and nullifier, defined in [ballot.md](ballot.md) | Ballot intake |
| `authorship` | Some member of a context, or an agent, as the author of an object | The bundle's `authorship` proof, defined in [issue-map.md](issue-map.md#authority-and-authorship) | Submitting participant-authored manifests to a log |
| `organizer` | One organizer of a context | A COSE_Sign by any single `sign` key of the context's keyset, in the `authority` form below. One key, not the threshold | Reading the noised daily count; a channel reset at the delivery service ([chat.md §12.2](chat.md#122-endpoints)) |
| `authority` | A service or context authority | A COSE_Sign over the request under the signer's keyset at the `sign` threshold, external AAD `hum/service-request/1` | Submissions between services, aggregator uploads, Leader to Helper calls. Not context delete orders, which are standalone signed objects any member carries with a token ([storage.md §8.2](storage.md#82-context-delete-orders)), because organizers sign from different phones |
| `witness` | A log, to a witness | The log's checkpoint signature, per tlog-witness | `add-checkpoint` |
| `session` | One issuance session at a verifier host | The 16-byte session ID the host returned | Evidence and issue calls within that session |

#### Tokens

Each token-taking service picks the Privacy Pass type that fits how it is run. The sibling section named is normative for that service's tokens; this spec fixes what they share.

| Service | Type | Issuer | Issuance | Proves | Normative section |
| --- | --- | --- | --- | --- | --- |
| Blob store | `0x0002`, blind RSA, publicly verifiable | The store, or a separate issuer the store's `tokenIssuers` names; one key per context | `POST /v1/tokens` with the context CID in the body and up to 64 `TokenRequest`s, against a membership proof scoped `hum/blob-tokens/1 ‖ token_key_id ‖ day` | Membership in the context the key names | [storage.md §6.1, §6.2](storage.md#61-tokens) |
| Delivery service, context tokens | `0x0001`, VOPRF, privately verifiable | The delivery service; one key per context | `POST /v1/tokens` with the context CID in the body, against a membership proof scoped `hum/delivery-tokens/1 ‖ token_key_id ‖ day` | Membership in the context; used to register channels, post join tickets and fetch the join inbox | [chat.md §12.3](chat.md#123-context-tokens) |
| Delivery service, channel tokens | `0x0001` | The delivery service; one key per channel, derived from a master secret | `POST /v1/channel-tokens` with a MAC under the group's per-epoch delivery secret | Membership in the channel at a recent epoch | [chat.md §12.5](chat.md#125-channel-tokens) |

What every token shares: `Authorization: PrivateToken token="…"` (RFC 9577), a fixed `TokenChallenge` the phone builds itself with empty `redemption_context` and `origin_info`, an issuer directory at `/.well-known/private-token-issuer-directory`, and these rules:

- T-1. A token is single-use. A service keeps the nonce of every redeemed token for the lifetime of the issuing key (48 hours for channel tokens) and rejects a repeat with `401 token_spent`.
- T-2. A token carries nothing but its type, key ID and nonce. The context or channel a token belongs to is identified by its issuer key, never by metadata, because RFC 9578 tokens carry none. Issuer keys are per context or per channel, never per member, and phones gossip the context key ID in the all-members channel (chat.md §5.15 `token-key`) so a per-member key would be noticed.
- T-3. The issuers a service accepts are the authorities in its `tokenIssuers`, and an issuer sees a membership proof and the per-day count under its scope, nothing else.
- T-4. A token issuance request never travels on the same relay connection as a request that spends a token (see rule O-4).

#### Signed requests

The `authority` and `organizer` classes sign the request itself, with the same COSE_Sign structure manifests use, so the protocol has one signature encoder.

- A-1. The signed payload is the SHA-256 of the ASCII string `hum/service-request/1`, a zero byte, the request method, a space, the request target as sent (path and query, without scheme or host), a zero byte, the SHA-256 of the request body (of the empty string when there is none), the 16 raw nonce bytes, and the issued time as a big-endian uint64 of seconds. The vector `service-request-payload` fixes the layout byte for byte.
- A-2. The signature is one COSE_Sign structure, built exactly as a manifest's ([manifest.md, The envelope](manifest.md#the-envelope); `reference/.../cose.py`) with the detached payload equal to the A-1 hash and external AAD `hum/service-request/1` in place of `hum/manifest/1`. One `COSE_Signature` per signer; `authority` needs the keyset's `sign` threshold, `organizer` needs one. It is sent in the `Hum-Authority` header, base64url without padding.
- A-3. The request carries `Hum-Nonce` (the 16 nonce bytes, base64url) and `Hum-Issued` (decimal ASCII seconds). A service rejects a request older than 300 seconds, or a nonce it has seen in that window, with `replay`.
- A-4. The keyset version that applies is the one in force at the service's latest witnessed checkpoint, as [storage.md §8.2](storage.md#82-context-delete-orders) does for delete orders.

### Errors

This section defines the one error format every Hum service uses: the log, witnesses, aggregators, verifier hosts, the delivery service, blob stores, resolvers, the gallery and the gateway. Sibling specs point here and add only `detail` strings. Every other body in the protocol is CBOR, so errors are too, and a phone needs no second parser on the error path.

An error response is a deterministic CBOR map with media type `application/vnd.hum.error+cbor` and the matching HTTP status:

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | code | tstr | One of the codes below |
| 1 | detail | tstr, optional | A fixed string from the endpoint's list. Never echoes request content |
| 2 | step | uint, optional | The verification step that failed, 1 to 11, for manifest rejections |
| 3 | rule | tstr, optional | The rule ID from the type spec that failed, such as `D12` or `IM-7`. A verifier host's rejection carries the phone-visible (masked) rejection code of verifier-runtime.md as `vr-<code>`, for example `vr-0` |
| 4 | retryAfter | uint, optional | Seconds to wait, for `rate_limited` and `pending`; also sent as the `Retry-After` header |

Codes are lower snake case. This table lists every code any service uses; a service may not invent one.

| Code | HTTP | Used by | Meaning |
| --- | --- | --- | --- |
| `malformed` | 400, or 415 | all | Not valid CBOR, not canonical, missing a field, or (415) an unsupported media type or format byte |
| `too_large` | 413 | all | Over the endpoint's size cap or a byte quota |
| `unauthorized` | 401 | all | No credential of the required class, an unknown group or handle at the delivery service. No body beyond `code` |
| `token_spent` | 401 | token services | The token was already redeemed. No body beyond `code` |
| `forbidden` | 403 | all | The credential is valid but does not allow this |
| `not_found` | 404 | all | See rule E-2. No body beyond `code` on endpoints that take a token |
| `rejected` | 422 | log, aggregator, host, store | A manifest, ballot, order or request failed verification; `step` or `rule` says where |
| `floor` | 422 | log, aggregator | A floor check failed; `rule` names the floor |
| `conflict` | 409 | all | The object exists with different content, or the state does not allow the action |
| `not_padded` | 400 | delivery, gateway | A message or relayed request is not a padding bucket |
| `replay` | 409 | signed requests | A signed request's nonce was seen before |
| `closed` | 410 | aggregator, store | The deck or round no longer accepts this, or the CID is tombstoned |
| `pending` | 202 | log, aggregator | Accepted, not yet done; poll after `retryAfter` |
| `rate_limited` | 429 | all | Over a limit; `retryAfter` is set |
| `unavailable` | 503 | all | Temporary; safe to retry |

Error rules:

- E-1. A service never puts a CID, a key, a token, a nullifier or any request field into an error. `detail` is one of the fixed strings the endpoint lists.
- E-2. Non-leaking lookups: an endpoint that takes a `token` answers `401` with only the code when there is no valid token, and `404` with only the code both when the object is missing and when it belongs to another context, byte-identical and in the same time ([storage.md §6.4](storage.md#64-get-and-range-get)). Only `public` endpoints distinguish missing from present.
- E-3. Errors are the only place a verification step number appears. A service does not say which signer, which key or which reference failed.

W0-08 generates one vector per code (`error-<code>`), plus `error-401-bare` and `error-404-bare` for the two body-less forms.

### Rate limits

Limits are enforced per credential, never per person, because no service knows a person.

| Class | Limited by | Default in draft 0.1 |
| --- | --- | --- |
| `public` | The relay's per-client limit, and a per-connection limit at the gateway | 600 requests per minute per connection |
| `token` | Issuance per membership proof per day; one request per token; per-context quotas | `blobLimits.tokensPerMemberDay` and the quotas in the store manifest and the context's storage policy; chat.md's per-token send and fetch counts |
| `ballot` | Per deck round: one ballot per nullifier | One, by construction |
| `authorship` | Per author form, counted at the log over the proof's window | [issue-map.md, Rate limits](issue-map.md#rate-limits): `signedPerWindow`, `unsignedPerWindow`, the sponsor's `rateLimits.mapObjects` |
| `authority` | Per authority | 60 submissions per minute per authority |
| `witness` | Per log origin | One `add-checkpoint` per second per origin |

Rules:

- R-1. A limited response carries `retryAfter`.
- R-2. A service never rate-limits by client IP, because it never sees one for relayed requests. The relay rate-limits by client IP and the gateway rate-limits by relay connection.
- R-3. Limits never depend on the content of a request, so an attacker cannot learn whether a CID exists by timing or counting.

### What services log

Each service may write only the fields in its row of this table to any log, metric, trace or crash report. The simulator searches everything a service writes for forbidden values ([simulator.md, Leak checks](simulator.md#leak-checks)). This is how invariants 1 and 2 are tested continuously.

| Service | May log | Must never log | Retention of logs |
| --- | --- | --- | --- |
| Log | Submitted CID, type, authority, result code, leaf index, timing, size; for rate limiting only, a per-chat-identity-key counter for `member`-form objects and the set of every nullifier each authorship proof yields (the log derives them from the proof; the `authorship` field carries none), each kept for the current and the previous `AUTHOR_WINDOW` (issue-map.md IM-7, IM-15) | Request bodies, authorship proofs beyond the counters named, which relay connection submitted what | 90 days; counters two windows |
| Witness | Origin, tree size, result code, timing | Anything about who fetched a checkpoint | 90 days |
| Aggregator | Deck CID, round, counts of rejected requests by code, and the already-noised public values in place of any count of accepted ballots (L-5), the final release. For ballot intake: no line per request, no timing per request, and no count per deck, round or path. Rejections whose code depends on a pseudonym having voted before (`closed` on a different round-0 body, `conflict` with detail `duplicate` or `nullifiers`) are not counted by code at all, since with one open deck a per-service count is a per-deck count; they appear only in the service's daily total of rejected requests of every code; `malformed`, `too_large`, `rejected` and `forbidden` may be counted per deck | A ballot, a nullifier, a share, a receipt, a pseudonym, a vote, anything paired with a timestamp fine enough to single out one ballot | Request logs 7 days; ballots and nullifier sets deleted after release, see [Aggregator](#aggregator) |
| Issuer and verifier host | The session log line of [verifier-runtime.md](verifier-runtime.md#transparency-who-sees-what), exactly: a random 16-byte session ID, verifier authority, version, the session's opening day, the true outcome, module resource use in buckets. Evidence is stored, never logged, as the manifest's `kept` and `storedAs` declare | Evidence in any log, a dedup key or its hash, a transport address, the blind signature request, the issued credential | Per the verifier manifest |
| Delivery service | Per [chat.md §12.9](chat.md#129-what-the-ds-stores) | Member lists, plaintext, sender identity, fetch cursors | Per chat.md |
| Blob store | Per-context counters and per-key redeemed nonces ([storage.md §6.8](storage.md#68-what-the-store-sees)) | Request bodies, tokens, CIDs in log lines, sealed keys, file names, which member or channel | Per storage.md |
| Resolver and mirrors | CID requested, result code, size, timing | Which connection asked for which CID, in any form that joins two requests | 30 days, counts only after 24 hours |
| Gallery | Query shape, result code, timing | Any per-viewer identifier or sequence | 30 days |
| Relay | Client IP and request count per window, gateway, result code | Request bodies, gateway responses, anything that pairs a client with a request's content | Counts only; IPs for 24 hours |
| Gateway | Decrypted request's path and result code, with no connection identifier; or counts per path. For ballot-intake paths, neither: nothing is logged per request and no counter is kept for intake. A counter per service per day would equal one deck's accepted sends whenever an aggregator had one open deck that day. Ballot requests appear only inside the gateway's daily total of all requests to all services it fronts | Client IP (it never sees one), bodies, a relay connection joined to a path, anything that counts the requests answered `200` on one deck's ballot path | 30 days |

Logging rules:

- L-1. Timestamps in logs are rounded to the minute for any request made with a `token`, `ballot` or `authorship` credential.
- L-2. No service logs a request body or a response body.
- L-3. Crash reports go through the same filter as logs.
- L-4. A service's `retention` field in its manifest states these values or shorter ones, and a context may require shorter still.
- L-5. An aggregator's logs and metrics never hold a count of accepted ballots for a deck or a round, exact or bucketed from the exact value, before or after the final release version. Rounding an exact count is not noise: at a bucket edge one ballot moves the logged value. Where a log needs a size, it carries only values that are already public or already noised: `nHat`, a part's `n`, the padded leaf count, the noised daily series. The rule covers the gateway in front of the aggregator as well: one log line per accepted request, or a count of `200` answers per ballot path, is a count of accepted ballots. Counts of rejected requests by error code are allowed per deck only for codes that say nothing about a voter (`malformed`, `too_large`, `rejected`, `forbidden`); codes that only a pseudonym that already voted can cause are not counted separately and appear only in a daily total of all rejections.
- L-6. Field schema. A log line is a map of named fields. The table below is the complete set of field names each service may write; a line with any other field is forbidden, and a line whose field holds a value outside its stated domain is forbidden. W0-08's `services/logging` vectors test one allowed and one forbidden line per service.

| Service | Allowed fields and their domains |
| --- | --- |
| Log | `service`, `day`, `cid`, `type`, `authority`, `code`, `index`, `minute` (timestamp rounded to the minute), `size`, `window` and `chat_key_count` (the per-chat-key counter for one window), `nullifier_set_size` |
| Witness | `service`, `day`, `origin`, `tree_size`, `code`, `minute` |
| Aggregator | `service`, `day`, `deck` (CID), `round`, `state`, `code` (one of `malformed`, `too_large`, `rejected`, `forbidden` when `deck` is present; any code when it is not), `rejected_count` (per deck only for those four codes; otherwise the service's daily total), `n_hat`, `part`, `part_n`, `padded_leaves`, `k`, `daily_bucket`, `daily_increment` (the noised value), `release` (CID), `version`. No `accepted`, `ballots`, `leaves`, `nullifiers`, `received` or any other count of accepted ballots, no per-request `minute`, no `nonce`, `leaf`, `receipt`, `nullifier` or `pseudonym` |
| Issuer and verifier host | `session_id` (16 random bytes), `authority`, `version`, `day`, `outcome`, `memory_bucket`, `fuel_bucket` ([verifier-runtime.md](verifier-runtime.md#transparency-who-sees-what)) |
| Delivery service | Per [chat.md §12.9](chat.md#129-what-the-ds-stores) |
| Blob store | `context` (CID), `counter` name and value, `token_key_id`, `nonce_count` ([storage.md §6.8](storage.md#68-what-the-store-sees)) |
| Resolver and mirrors | `service`, `day`, `cid`, `code`, `size`, `minute`; after 24 hours only `cid`, `count` |
| Gallery | `service`, `day`, `query_shape`, `code`, `minute` |
| Relay | `day`, `client_ip` (24 hours), `window`, `request_count`, `gateway`, `code` |
| Gateway | `service`, `day`, `path` (never a ballot-intake path), `code`, `count`; no `connection` |


### Domain strings and scopes

Every domain-separation string, membership-proof scope prefix, exporter label and HKDF info string in the protocol, with its owner, as the owning specs read on disk on 2026-10-06. A new one is added here before it is used. The owning spec's text wins over this table when they disagree, and a disagreement is itself a finding for the cross-spec pass; this table is an index, never a second source of truth. Every string starts with `hum/`; `manifest/1`, `keyring/1` and `delivery/1` were renamed under it on 2026-10-06 (ADR 0105).

| String | Kind | Used for | Owner |
| --- | --- | --- | --- |
| `hum/manifest/1` | COSE external AAD | Manifest signatures | manifest.md |
| `hum/service-request/1` | COSE external AAD and payload prefix | Signed service requests (A-1, A-2) | services.md |
| `hum/receipt/1` | Signature prefix | Ballot receipts | services.md |
| `hum/dap-task/1` | Hash prefix | DAP task IDs per round and part | services.md |
| `hum/log/`, `hum/witness/` | Name prefixes | Checkpoint origin lines and witness names | services.md |
| `hum/blob-tokens/1` | Proof scope | Store token issuance | storage.md |
| `hum/delivery-tokens/1` | Proof scope | Delivery context-token issuance | chat.md |
| `hum/sealed/1` | AEAD AAD prefix | Sealed blob chunks | storage.md |
| `hum/delete/1`, `hum/blob-delete/1` | Hash prefix, signature prefix | Delete-secret commitments, context delete orders | storage.md |
| `hum/keyring-blob/1` | HKDF info | Blob keys derived from the keyring | storage.md |
| `hum/results-key/1` | HKDF info | The context's results key from a keyring epoch | context.md, storage.md |
| `hum/results-keybox/1` | HPKE info | Members-only release keybox | release.md |
| `hum/author/1`, `hum/edit/1` | Signature prefixes | Authored objects and their edits | issue-map.md |
| `hum/edit-key/1` | HKDF salt | Per-object edit keys | issue-map.md |
| `hum/author-once/1`, `hum/author-slot/1` | Proof scopes | Signed and unsigned authorship | issue-map.md |
| `hum/take-query/1` | Hash prefix | A take's `queryHash` | take.md |
| `hum/sponsor/1` | Proof scope | Agent sponsor credential presentation | agent-sponsor.md |
| `hum/attest/1` | Hash prefix | Enclave attestation report data binding | agent-sponsor.md |
| `hum/issuance/1` | Proof scope | Issuance evidence of kind `credential` | verifier.md, credentials.md |
| `hum/issue/1`, `hum/issue-response/1` | HPKE info, HPKE export labels | The issuance request and response | credentials.md |
| `hum/evidence/1` | HPKE info | Evidence items sealed to a host key, with the verifier authority CID and the item name | verifier.md |
| `hum/nym-share/1` | HKDF salt | The signer's nym share, a deterministic function of a host secret and the request hash, so an identical retry returns the identical response | credentials.md |
| `hum/ballot/1`, `hum/ballot-bound/1`, `hum/nullifier/1`, `hum/receipt-leaf/1` | Proof scope, bound-message prefix, nullifier derivation, leaf hash prefix | Ballots per deck lineage, their bound message and nullifiers, receipt leaves | ballot.md |
| `hum/credential/1`, `hum/presentation/1`, `hum/backup/1` | BBS header, presentation header, HPKE info | Resident cards, presentations, encrypted backup | credentials.md |
| `hum/keyring/1`, `hum/delivery/1` | MLS exporter labels | Context keyring, delivery secret | chat.md |
| `hum/device/1`, `hum/safety/1`, `hum/chat-roles/1`, `hum/frank/1`, `hum/stamp/1`, `hum/commit/1`, `hum/token-request/1`, `hum/pp-issuer/1`, `hum/welcome/1`, `hum/join/1`, `hum/join-ticket/1` | Signature, hash and HMAC prefixes, HKDF and HPKE info, proof scope | Chat credentials, safety codes, roles, franking, stamps, commit MACs, channel-token issuance, Welcome handles, admission; chat.md's "Domain strings and labels" table is the full list | chat.md |

Ballot scopes are owned by ballot.md and must not start with `hum/author-` (issue-map.md's assumption).

## Log and ledger

The log is an append-only Merkle tree whose leaves are manifest CIDs with their type and authority. It serves tiles and checkpoints in the C2SP formats, so Tessera, existing witnesses and existing monitors work without Hum-specific code. The release ledger is this same log: release entries are the entries of type `release`, and the extra checks the manifest spec asks of the ledger run on those entries ([ADR 0071](../decisions/0071-w0-07-one-log.md)).

### Leaves

A leaf is a deterministic CBOR array:

```
[ cid: bstr, type: text, authority: bstr, lineage: bstr or null, version: uint ]
```

- `cid` and `authority` are CID bytes (algorithm byte plus digest), 33 bytes for `0x01`.
- `lineage` is the lineage CID, or `null` for version 1.
- The leaf hash is RFC 6962: SHA-256 of `0x00` followed by the leaf bytes.
- Entry bundles ([tlog-tiles](https://c2sp.org/tlog-tiles)) carry leaves as big-endian uint16 length-prefixed records. A leaf is under 128 bytes.

Leaves hold hashes, never content. Content lives with the resolver and the blob stores, so it can be deleted while the commitment stays.

### Checkpoints

A checkpoint is a signed note in the [tlog-checkpoint](https://c2sp.org/tlog-checkpoint) format: origin line, tree size, base64 root hash, then signature lines.

- The origin line is `hum/log/` followed by the log authority's CID in text form, for example `hum/log/c4f7q2…k2a`. It is frozen in the `service` manifest.
- The log signs with an Ed25519 key from its keyset's `sign` role, using the note signature format. The key name in the signature line equals the origin line, and the four-byte key ID is the first four bytes of SHA-256 over the origin, a newline, the algorithm byte `0x01` and the 32-byte public key, per the signed-note convention.
- Witness cosignatures are [tlog-cosignature/v1](https://c2sp.org/tlog-cosignature) lines appended to the same note. The log republishes its checkpoint with every cosignature it has collected.
- A phone acting for a context accepts a checkpoint only when it carries the log's signature and cosignatures from at least `floors.minWitnesses` distinct keys in that context's `logs[].witnesses` entry for this log ([context.md, Log entries](context.md#log-entries-key-7)). The log's own `service` manifest lists the witnesses it asks; a context may list a subset or require more.
- **Bootstrap.** A phone verifying a manifest with no context in hand (a `verifier`, `trust-list`, `agent-sponsor`, `take` or `service` manifest before joining anything, or the reference log's own `service` manifest) uses protocol constants the app ships beside the Global context CID: the reference log's authority CID, its origin line and its launch witness keys. The constants serve only to verify the first checkpoint and to resolve the Global context's current version. From then on Global's `logs[].witnesses` and `floors.minWitnesses` are the context-less rule, so witness keys rotate through a logged lineage rather than an app update. A context-less verification never accepts fewer than `MIN_WITNESSES` (2) cosignatures, however many keys the constants or Global list. Once a context applies, its own list and `floors.minWitnesses` govern that context's objects.

The log publishes a new checkpoint at most every 10 seconds and whenever it has pending entries. It asks every witness in its manifest to cosign each new checkpoint before serving it.

### Endpoints

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /v1/log/add` | `authority` or `authorship` | Submit a manifest bundle |
| `GET /v1/log/add/{cid}` | `public` | Poll a pending submission |
| `GET /v1/log/checkpoint` | `public` | The latest cosigned checkpoint, as text |
| `GET /v1/log/tile/{L}/{N}[.p/{W}]` | `public` | Merkle tree tiles, tlog-tiles |
| `GET /v1/log/tile/entries/{N}[.p/{W}]` | `public` | Entry bundles, tlog-tiles |
| `GET /v1/log/proof/inclusion?index={i}&size={n}` | `public` | Convenience inclusion proof against a checkpoint of size `n` |
| `GET /v1/log/proof/consistency?from={m}&to={n}` | `public` | Convenience consistency proof |
| `GET /v1/log/entry/{cid}` | `public` | The leaf index of a CID |
| `GET /v1/log/lineage/{cid}` | `public` | Every logged version of a lineage |

The tile and checkpoint paths are exactly the tlog-tiles paths under the prefix `/v1/log`, so a mirror can serve the same tree from static files.

#### Submitting a manifest

`POST /v1/log/add` takes a bundle with an empty `proofs` array. Who may submit:

- A service or context authority signs the request (`authority` class). Keysets, contexts, decks, releases, verifiers, trust lists, services and agent sponsors arrive this way. The bundle's own signatures already prove the authority; the request signature stops a third party replaying someone else's bundle to run up their rate limit.
- A member or an agent submits participant-authored objects (issue, position, argument, take) with the bundle's `authorship` proof and no other credential. The log checks the proof as issue-map.md's rule IM-6 and take.md's TK-5 say and learns that some member, or which chat identity key or sponsored agent, authored it.

Every submission from a phone, including an organizer's, goes through the relay ([routing table](#which-requests-go-through-the-relay)).

**What the log runs.** Before appending, the log runs manifest verification steps 1 to 6 and 8 ([manifest.md, Verification](manifest.md#verification)), with step 6 replaced by IM-6 or TK-5 for participant-authored types; step 9 as the ref rule below; and the type's step 10 rules as the table below says. Step 7 is skipped because the entry is not logged yet. Step 11 is skipped because logging is not an action under the manifest. For an object that carries a membership proof or a sponsor proof (issue-map forms 1 and 2, an `agent-sponsor` version with `sponsorProof`), the log is the one verifier that uses a clock: the proof's disclosed epoch must be the log's current epoch for that issuer, or the previous period's epoch while the log's clock is less than 3,600 seconds into a period, and the envelope `issued` must be within 3,600 seconds of the log's clock, bounds included, else `rejected` with rule `P5`. This check is made by the context's log of record (the first entry of its `logs`), which also refuses the object when the issuer's `verifier` lineage is not in its history; another listed log accepts the object without a clock check when the bundle carries an inclusion proof from the log of record ([credentials.md, Validity](credentials.md#validity); ADR 0101). Later verifiers check against `issued` and the log position. Rules that need a referenced manifest's body read it from the log's own copy: the log keeps the envelope bytes of every manifest it has accepted for exactly this purpose.

**Step 9 at the log.** The log resolves no blobs. It requires that every ref whose name is in this table is already in this log and is of the type named; a ref with any other name is a blob and is not checked. A missing or wrong-typed manifest ref answers `rejected`, step 9, detail `unresolved_ref`.

| Type | Manifest-valued refs | Everything else |
| --- | --- | --- |
| `context` | `parent` (context), `tl/<i>` (trust-list) | `about` is a blob |
| `deck` | `context` (context), `card/<i>` when the card's `kind` is 0 (position) or 2 (take, rating decks), `card/<i>/pro` and `card/<i>/con` (argument), `source` (release, rating decks) | `card/<i>` with `kind` 1 is a blob |
| `release` | `deck` (deck) | `t/<table>`, `keybox` and `receipts/<n>` are blobs |
| `issue`, `position`, `argument` | `context` (context), `parent` (issue or position, by lineage), `sponsor` (agent-sponsor), `replaces` and `mergedInto` (same type, by lineage), `take` (take) | `text` and `evidence/<n>` are blobs |
| `take` | `release/<n>` (release), `sponsor` (agent-sponsor), `forkOf` (take), `statement/<k>` (position, or a blob when the deck's card was a blob) | `text` is a blob |
| `agent-sponsor` | `verifier` (verifier) | `report` is a blob |
| `verifier` | none | `code`, `build`, `profile` and dataset refs are blobs |
| `trust-list`, `keyset`, `service` | none | — |

Refs that name a lineage rather than a version (`parent`, `replaces`, `mergedInto` in issue-map.md) resolve when any version of that lineage is in the log.

**Step 10 at the log.** The default is that the log runs every rule of the type's spec that needs only the envelope, the previous version, the log's own history and its copies of referenced manifests, and skips every rule that needs a blob or live state. A logged-but-invalid version would break a lineage for honest clients, which is why the log runs as much as it can. By type:

| Type | The log runs | The log skips (checked by phones, aggregators or the Helper) |
| --- | --- | --- |
| `keyset` | Rotate threshold of the previous version, revocation positions, pre-rotation commitment ([manifest.md, Authorities and keys](manifest.md#authorities-and-keys)) | — |
| `context` | C1 to C16 ([context.md](context.md#validation-rules-verification-step-10-for-context)) | Nothing; `about` is not validated |
| `deck` | D1 to D15, and D16 by the log's clock: a version above 1 is refused once the previous version's `closes` has passed ([deck.md](deck.md#validation-rules-verification-step-10-for-deck)) | Statement blob size (phones) |
| `release` | R1 to R14 ([release.md](release.md#validation-rules-verification-step-10-for-release)); R10 and R14 against this log's own history; for R13 the log also compares its own clock with the `expires` of the deck version in `refs["deck"]` and refuses a release version submitted after it (`rejected`, rule `R13`) | R15, which reads the Parquet blobs: the Helper runs it before signing and phones run it on tables they open, as release.md now says |
| `issue`, `position`, `argument` | IM-1 to IM-15 except the parts named at right ([issue-map.md](issue-map.md#validation-rules)) | Text length and sealed-text format inside IM-4 (blob); duplicate detection (phones) |
| `take` | TK-1 and TK-3 to TK-9 ([take.md](take.md#validation-rules)); TK-4's statement check against the pinned release's deck, which is in the log; sponsor take counts per window ([agent-sponsor.md](agent-sponsor.md#rate-limits)) | TK-2's text length (blob) |
| `agent-sponsor` | AS-1 to AS-9 ([agent-sponsor.md](agent-sponsor.md#validation-rules)) | Verifying the attestation report blob against `attestation.measurement` (phones) |
| `verifier` | Its numbered rules that read the body and the previous version, plus rule 30 (a new attribute's `fromEpoch` against the log's clock) and rule 31 (one `verifier` lineage per authority, against this log's history) ([verifier.md](verifier.md#validation-rules)) | Rules that hash the `code` blob or read a dataset blob (phones and trust-list publishers) |
| `trust-list` | Its numbered rules that read the body and the previous version ([trust-list.md](trust-list.md#validation-rules)) | Live-state checks (attribute names exist in the verifier's current version, attested CIDs match a logged `code` ref), which trust-list.md says make a row inert rather than the list invalid |
| `service` | S-1 to S-8 and the kind's own rules (storage.md BS-1 to BS-6 for stores, chat.md DL-1 to DL-5 for delivery services) | — |

When a context names more than one log, the first entry of its `logs` is the ledger of record: a release, and every deck version, must be in it, and R10, R14 and deck.md D16 are decided there by every party (ADR 0103). Another listed log may hold the same entries and runs the same rules against its own history; a release it refuses is still valid when the ledger of record accepted it. For a `release` or `deck` manifest, the inclusion proof verification step 7 requires is one against the ledger of record, whichever log the phone fetched the bundle from; a bundle whose only proof is from another listed log fails at step 7, before R10 is reached. R10 restates the same requirement for the ledger's own check. One expected result, so the conformance vector for a release only in a context's second log fails at step 7 (release.md R10, context.md; conformance.md disagreement 21).

Responses:

| Outcome | Response |
| --- | --- |
| Accepted and sequenced | 200 with `{ index: uint, checkpoint: text, path: [bstr] }`, a complete proof |
| Accepted, awaiting sequencing or cosignatures | 202 `pending` with `retryAfter`; poll `GET /v1/log/add/{cid}` |
| Same CID already logged | 200 with the existing proof |
| Same lineage and version, different CID, already logged | 409 `conflict`, detail `equivocation` |
| A verification step failed | 422 `rejected` with `step`, and `rule` for step 10 |
| A release or deck broke a floor | 422 `floor` with `rule` |
| A referenced manifest is not in the log | 422 `rejected`, step 9, detail `unresolved_ref` |
| An authored object is over its author form's rate limit | 429 `rate_limited`, `rule` `IM-15`, with `retryAfter` |

Log rules the conformance suite tests:

- LG-1. A bundle whose envelope fails any of steps 1 to 6 or 8 is not appended, and the response names the step.
- LG-2. A release, deck or context that fails its step 10 rules is not appended.
- LG-3. Two submissions with the same lineage and version and different CIDs: the first is appended, the second gets `conflict`.
- LG-4. A keyset version is appended only when signed by the rotate threshold of the previous version.
- LG-5. The response proof verifies against the returned checkpoint, and the checkpoint carries at least 2 witness cosignatures.
- LG-6. The leaf bytes for an accepted manifest equal the leaf encoding above.
- LG-7. An authored object whose `hum/author-once/1` or `hum/author-slot/1` nullifier was seen before in this log is refused (IM-7).
- LG-8. A manifest whose table-listed ref is absent from the log, or present with another type, is refused at step 9; a manifest whose only unresolvable ref is a blob is accepted.

#### Reading proofs

Clients build inclusion and consistency proofs from tiles themselves; that is the privacy-preserving path, since tile fetches reveal little about which entry a client cares about. The two `proof` endpoints exist for tools and the simulator. A phone uses them only through the relay.

`GET /v1/log/entry/{cid}` returns `{ index: uint, type: text, authority: CID }` or `404`.

`GET /v1/log/lineage/{cid}` returns, for the lineage whose version 1 has that CID, the array `[ { index, cid, version, authority } ]` in log order. The caller checks the chain from version 1 and takes the highest valid version ([manifest.md, References and resolution](manifest.md#references-and-resolution)). A fork appears as two entries with the same version; the lower index wins. An entry whose `authority` differs from version 1's is invalid under step 8 and is shown so the reader can see the attempt. This endpoint reveals interest in a lineage, which is the manifest spec's lookup-privacy open question; a phone calls it only through the relay, and a context's phones share results inside their channels.

### Mirrors and monitors

Anyone may mirror the log by fetching tiles and entry bundles; they are immutable and carry long cache headers. A monitor that wants content fetches each leaf's bundle from a resolver. A mirror of the log serves the same paths under its own prefix and is listed as a hint, never trusted; the checkpoint's signatures are what a client checks.

## Witness

A witness cosigns a log's checkpoints after checking that each one extends the last it saw. Hum witnesses implement [tlog-witness](https://c2sp.org/tlog-witness) exactly, so witnesses already run for other logs can add a Hum log by configuring its origin and public key, and Hum's witnesses can serve other logs.

### Endpoint

`POST {witness prefix}/add-checkpoint`, auth class `witness`. The body is the tlog-witness request: an `old <size>` line, up to 63 base64 consistency proof hashes, an empty line, then the checkpoint note. The log is the only caller.

| Status | Meaning |
| --- | --- |
| 200 | Body holds one or more cosignature lines for this checkpoint |
| 400 | `old` is larger than the checkpoint's size |
| 403 | No checkpoint signature verifies against the keys the witness holds for this origin |
| 404 | Unknown origin |
| 409 | `old` does not match the witness's latest size for this origin, or `old` equals the new size and the root hash differs; the body is the witness's size in decimal |
| 422 | The consistency proof does not verify |

The witness checks, in order: the log's signature against its configured key for the origin; `old` at most the new size; `old` equal to its stored size (or zero); the consistency proof; equal roots when sizes are equal. It persists the new checkpoint before answering.

### Cosignatures and names

- A cosignature line is `— <witness name> base64(key ID || timestamped signature)` per tlog-cosignature/v1. The signed message is `cosignature/v1\ntime <seconds>\n` followed by the checkpoint body.
- A witness name is `hum/witness/` followed by the witness authority's CID in text form, or, for a witness that predates Hum, whatever name it already uses. The log's `service` manifest lists each witness's name and verifying key. A context lists only keys ([context.md, Log entries](context.md#log-entries-key-7)); a phone takes the name from the cosignature line, recomputes the key ID from that name and each listed key, and accepts the line when one matches and the signature verifies.
- The key ID is the first four bytes of SHA-256 over the name, a newline, the byte `0x04` and the 32-byte Ed25519 public key, as the C2SP spec says.
- A witness's timestamp is informational. Validity follows the checkpoint's position in the log, never the time.

### Joining as a witness

An organization that wants to witness the reference log publishes a `service` manifest of kind `witness`, configures the log's origin and verifying key, and asks the log's operator to add its name and key to the log's `service` manifest. The log asks every listed witness for each checkpoint and serves whatever cosignatures arrive within 5 seconds, then keeps collecting late ones for the next republish. Who runs the witnesses at launch is an open decision in [DECISIONS.md](../DECISIONS.md).

Witness rules the conformance suite tests:

- W-1. A cosignature from a listed witness verifies over the exact message above.
- W-2. A checkpoint with fewer than the context's `floors.minWitnesses` cosignatures from the context's listed keys is not accepted by a client; `MIN_WITNESSES` is 2.
- W-3. A witness returns 409 with its known size when `old` is stale, and 422 when the proof is wrong.

## Aggregator

Aggregators receive ballots, add noise, and publish releases. Every context names two aggregator authorities, `aggregators[0]` the Leader and `aggregators[1]` the Helper, and every deck inherits the pair from the context version it pins ([context.md, Body fields](context.md#body-fields); [deck.md](deck.md#body-fields)). In phase 1 one operator does the adding under the Leader authority and the Helper signs what [release.md, Who signs](release.md#who-signs) says it attests; at launch one operator may run both. In phase 2 the two run the IETF DAP protocol and neither sees a vote. Both expose the same public endpoints, and the Helper additionally exposes the DAP Helper endpoints. A rating deck ([take.md, Ratings](take.md#ratings)) is a deck and uses the same endpoints.

### Rounds, tasks and nullifiers

A deck has a vote round, round 0, between `opens` and `closes`, and up to three post-close rounds. Each post-close round opens when the release version that publishes its inputs is logged and closes at that version's `roundDeadline` ([release.md, Rounds](release.md#rounds)). Everything under a deck ends at the envelope's `expires`.

Each release part of a round is one DAP task, so DAP batches and the per-round receipt roots line up:

```
taskId(round, part) = SHA-256("hum/dap-task/1" || deckLineageCid || round as uint8 || part as uint8)
```

`deckLineageCid` is the CID of the deck's version 1, so a `closes` extension does not change the task. One DAP task per release part within a round, so each part's weight bound is enforced by its own Prio3 type ([ballot.md](ballot.md), ADR 0024). A report's `report_id` is the first 16 bytes of `SHA-256(nonce ‖ uint8(part))`. A round's receipt signature uses the task ID of the round's first part. This is a domain-separation string and is marked `seam: ballot construction`.

What this spec requires of [ballot.md](ballot.md), confirmed there (scope `hum/ballot/1 ‖ deck lineage CID`; leaf `SHA-256("hum/receipt-leaf/1" ‖ uint8(round) ‖ nonce ‖ SHA-256(payload))`; the round-0 receipt as the DAP public extension `hum-authorization`):

- One primary nullifier per deck lineage, plus one per other card in the presentation, the same in every round, so the Leader in phase 1 can check that a round 1 to 3 contribution comes from a pseudonym that voted in round 0, and so one pseudonym contributes once per round.
- The receipt leaf never contains the nullifier or the pseudonym. It is a fixed-length hash over the round number, a phone-chosen random 32-byte receipt nonce and a commitment to the contribution, so the public per-round receipt pages cannot link one pseudonym's participation across rounds, and so a dummy leaf ([release.md, Receipts](release.md#receipts)) is indistinguishable from a real one.
- In phase 2, rounds 1 to 3 carry the round-0 receipt as the report's authorization, as release.md says.

### Endpoints

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /v1/agg/decks` | `authority` (context) | Register a deck version for intake |
| `GET /v1/agg/decks/{cid}` | `public` | Deck state, the rounds known so far, intake parameters |
| `POST /v1/agg/decks/{cid}/rounds/{n}/ballots` | `ballot` | Submit a contribution for round `n` |
| `GET /v1/agg/decks/{cid}/rounds/{n}/published` | `public` | The release version published after round `n`, as a bundle |
| `GET /v1/agg/decks/{cid}/rounds/{n}/receipts` | `public` | Round `n`'s receipt pages |
| `GET /v1/agg/decks/{cid}/daily` | `organizer` | The noised daily count |
| `GET /v1/agg/decks/{cid}/release` | `public` | The final release bundle |
| `POST /v1/agg/decks/{cid}/propose` | `authority` (Leader, to the Helper) | Propose a release version for the Helper's signature (phase 1) |
| `GET /v1/agg/hpke` | `public` | DAP `HpkeConfigList` (phase 2) |
| DAP aggregation and collection endpoints under `/v1/dap/` | `authority` (Leader to Helper) | Phase 2, see [Phase 2](#phase-2-dap) |

#### Opening a deck

The context authority submits the deck bundle, with proofs, to each aggregator, through the relay since organizers hold their keys on phones. The aggregator runs all eleven verification steps on the deck and its context ([manifest.md, Verification](manifest.md#verification)), including deck.md's rules D1 to D15 and context.md's C1 to C16 at step 10, and the check that this aggregator's authority is one of the two the context names. It answers 200 with:

```
{ taskIds: [[bstr(32)]] (taskIds[round][partIndex], parts in plan order),
  round0: { opens: uint, closes: uint }, cap: uint, phase: 1 or 2,
  leader: CID, helper: CID }
```

Only round 0's window is known at open. Later rounds are announced by `GET /v1/agg/decks/{cid}` once their version is logged. The aggregator refuses a deck with `floor` when the plan breaks a floor (D8, D10, D11), with `rejected`, rule `B9`, when the plan has part 7 (breakdown), because the plan is valid but the part is deferred until the owner decides on phase 1 breakdowns ([ballot.md](ballot.md)); and `rejected` with the step and rule for everything else. A deck already registered answers 200 again with the same parameters. The context submits every later version the same way; the aggregator accepts a version that only extends `closes`, provided its own clock is still before the `closes` it holds (deck.md D16), and refuses one that changes a frozen field after a ballot was accepted, as deck.md's frozen-field rules say, and keeps serving the version it holds. An aggregator that sees a deck naming it in the log before the context submits it may register the deck on its own. Both aggregators must have registered before the context announces the deck in chat; the phone checks both before voting.

`GET /v1/agg/decks/{cid}` returns the open response plus:

```
{ state: text, rounds: [ { n: uint, opens: uint, closes: uint, version: CID or null } ],
  versions: [CID] }
```

`state` is one of `scheduled`, `open`, `round n` (round `n` is accepting contributions), `releasing` (a round closed and the aggregators are computing), `final`, or `abandoned`. `rounds` lists round 0 and every later round whose version has been logged, with `closes` copied from that version's `roundDeadline`. A deck is `abandoned` when `expires` passes without a final version: the aggregators then publish nothing further, and whatever versions were logged stand on the ledger with their spent budget, as release.md requires. A deck below the minimum still gets a logged version 1 with no tables and no receipt pages ([release.md](release.md), rules R6 and R13), so `abandoned` only happens when the aggregators fail to act at all.

#### Ballot intake

`POST /v1/agg/decks/{cid}/rounds/{n}/ballots` takes a contribution as [ballot.md](ballot.md) encodes it. The request body is the ballot frame: `uint32be(len(ballot)) ‖ canonical ballot ‖ zero bytes`, exactly `BALLOT_BYTES` = 49,152 bytes in every round; there is no padding key inside the ballot. The credential is the ballot itself: a presentation satisfying the context's policy `[1, [entry, vote]]`, the deck's nullifiers, and the round's vector (phase 1) or this aggregator's share of it (phase 2). A presentation larger than 8 KiB is refused at intake with `too_large`. Every ballot goes through the relay. There is no retry token; a phone that does not get a receipt resubmits the identical ballot, and the nullifier makes it idempotent.

Checks, in order:

1. The body is exactly 49,152 bytes, the length prefix is in range, the ballot parses and is canonical, and the presentation is at most 8 KiB; else `malformed` or `too_large`.
2. Round 0 retry: the primary nullifier is looked up first. A known primary nullifier with a ballot body (keys 0 to 4) byte-identical to the accepted one returns the original receipt at any time until the deck's nullifier set is deleted, including after `closes`; the presentation may have been re-proved and the nonce is reused ([ballot.md, Replacement in round 0](ballot.md#replacement-in-round-0)).
3. Round `n` is accepting contributions: round 0 between `opens` and `closes`, a later round between its version's log time and its `roundDeadline`; else `closed`. A different round-0 body after `closes` is therefore `closed`.
4. The presentation verifies against the context version the deck pins, the credentials come from issuers on the context's trust lists, and each card's disclosed `epoch` equals `epoch(period(closes₁))` where `closes₁` is `closes` of the deck lineage's version 1 (not the version in force) and the card has started ([credentials.md, Validity](credentials.md#validity)); else `rejected`, rule from ballot.md.
5. For rounds 1 to 3, the primary nullifier appears in round 0's accepted set (phase 1), or the report carries a valid round-0 receipt (phase 2); else `forbidden`.
6. The vector respects the contribution cap and the round's integer bounds (release.md's `Δ_cov` for round 1, a one-hot for round 2), and in phase 2 the share decrypts under this aggregator's HPKE key and each report names `taskId(n, part)` for its part; else `rejected`, rule from ballot.md.
7. Nullifiers. The deck's nullifier set holds every nullifier a presentation yields, not only the primary, and each must be new for the deck (ballot.md B3), else `conflict`, detail `nullifier`. Round 0, before `closes`: a known primary nullifier with a different body replaces the earlier ballot, and must carry the same nullifier set; the last accepted ballot counts, the earlier leaf is not in the receipt tree, the earlier payload is deleted at once, and the daily count still counts only the first ballot (ADR 0024; the results screen promises re-sorting until close, and an offline phone must not lose votes). Rounds 1 to 3: a known primary nullifier with a different body is `conflict`, detail `duplicate`, with the original receipt in the response.

Nullifiers are recorded only when every check passes. A ballot rejected at any step consumes nothing, so a phone whose first attempt was malformed is not locked out (vector `ballot-rejected-keeps-nullifier`).

On success the aggregator answers 200 with a receipt: `{ leaf: bstr(32), signature: bstr, kid: bstr }`, where `kid` names the `sign` key of the aggregator's keyset that signed, where `leaf` is `SHA-256("hum/receipt-leaf/1" ‖ uint8(round) ‖ nonce ‖ commitment)` ([ballot.md, Receipts](ballot.md#receipts)) and `signature` is the aggregator's Ed25519 signature over `hum/receipt/1 || taskId(n, firstPart) || leaf`. The phone keeps the receipt; nothing identifies it to anyone else.

What the aggregator stores during a round: the nullifier set for the deck, the contributions (phase 1) or shares (phase 2) keyed by receipt leaf with their exact arrival times, and nothing else. A replaced round-0 payload and its leaf are deleted the moment the replacement is accepted. In phase 1 the aggregator sees pseudonymous votes, which is the design doc's who-sees-what row; what it never learns is which person holds a pseudonym.

After the final version is logged, the aggregator deletes every contribution, share and nullifier for the deck within 24 hours and keeps only the release versions, the receipt pages and the counts in the logging table. The simulator checks this. A person whose results deck shows "not counted" for round 0 must raise the dispute, with the signed receipt as evidence, before that deletion at final plus 24 hours, because afterwards the Leader can no longer show which ballot replaced which.

#### Between rounds

What phones need for the next round is a release version, not an interim blob ([release.md, One release, several versions](release.md#one-release-several-versions)): version 1 publishes the tallies after round 0, version 2 the axes after round 1, version 3 the centroids after round 2, and version 4 is final. Each version is signed by both aggregators, logged, and spends part of the one budget the deck's plan declared, so an abandoned round still shows on the ledger and the yearly floor counts it. `GET .../rounds/{n}/published` returns the bundle of release version `n + 1` with its log proof, or `pending` with `retryAfter` while the aggregators are still computing or the log has not answered. A phone fetches it through the relay, runs the full verification on it like any manifest, and only then computes its next-round contribution from the published tables.

#### Receipts

Each round has its own receipt root in the release's `receipts` map, a Merkle root over that round's accepted receipt leaves built as ballot.md defines and padded with dummy leaves to a noised size, paid for by the plan's part 8, so the exact ballot count is never published ([release.md, Receipts](release.md#receipts)). Once the version carrying round `n`'s root is logged, the aggregators publish the padded tree as pages so that a phone can check its own leaf without asking for it by name:

- Let `L` be the padded tree's leaf count, never the accepted count. The page count is `P = 2^k` with `k` the smallest integer such that `L / 2^k ≤ 4096`, and `k = 0` when `L ≤ 4096`.
- The leaf list is the padded list: real and dummy leaves together, sorted bytewise before the tree is built, so a leaf's position says nothing about when it arrived. Page `i` (`0 ≤ i < P`) holds, in that sorted order, every leaf whose first `k` bits equal `i`, as a public blob of 32-byte leaves concatenated; the pages are therefore contiguous ranges of the sorted list and of the tree.
- A root blob, the CBOR map `{0: k, 1: [page CIDs in order]}`, lists `k` and the `P` page CIDs in order, and its CID is pinned in the release version as `refs["receipts/<n>"]`; release.md's rule R13 requires one per completed round.
- `GET .../rounds/{n}/receipts` answers `404` for a release that is below the minimum, which has no receipt tree (release.md R13). Otherwise it returns `{ root: bstr(32), k: uint, pages: [CID] }` and nothing else. The response and the pinned root blob are two distinct bodies by design: the blob is `{0: k, 1: pages}` and never carries the root, since the release body already holds it and the blob is what the release pins; the response repeats `k` and `pages` from the blob and adds `root` so a phone can check all three against the logged release before fetching a page. A phone rejects a response whose `k` or `pages` differ from the pinned blob's. No exact count appears in this response, in the root blob or in any log line, and dummy leaves are indistinguishable from real ones in the pages.

A phone fetches the root blob and the one page its leaf's first `k` bits select, through the relay on a connection of its own at a random delay (rule O-4), inside the 4 KiB request bucket (rule O-3). What the fetch reveals is a `k`-bit prefix shared with about 4,096 other leaves; it never asks for a proof of one leaf. The phone then checks that its leaf is in the page and that the pages hash to the root.

#### The daily count

`GET .../daily` returns `{ sigma: rat, buckets: [ { bucket: uint, increment: int } ], total: int }`, or one entry with `?bucket={d}`: for each bucket `d = floor((t_received − opens) / 86400)` since the deck opened, the noised number of first ballots per pseudonym received in that bucket, with the σ the plan's `count` part implies, and the running sum ([context.md, The noised daily count](context.md#the-noised-daily-count)). The aggregator draws a bucket's noise once, when the bucket ends; the bucket containing `closes` is noised at `closes`, and an extension of `closes` continues the series with new buckets. It stores each noised value and never recomputes it; a bucket with no ballots still gets a noised increment, so a missing row never leaks a zero. It serves the same series to every caller, so repeated reads cost nothing more. The request is signed by one `sign` key of the context's keyset (`organizer` class) and goes through the relay. The aggregator learns which organizer key asked, which is a public key in a logged keyset and nothing about any voter. A deck whose plan has no `count` part answers `404`. The same series is in the release as the `count` table, so at release time it is public.

#### Publishing a release

When a round closes, the aggregators compute that stage's parts, add the noise the plan declares, and assemble the next release version and its table blobs ([release.md](release.md)). For every version the Leader:

1. Uploads each table as a public blob to a store the context names, with an `authority` signature and a `Hum-Context` header naming the context version, which storage.md accepts from the context authority (public blobs) or one of that version's aggregator authorities (public or sealed), counted against the context's quota ([storage.md §6.3, Puts by services](storage.md#63-put)). When the context's `perms.results` is members-only, the Leader puts each table as a format 1 sealed blob (`application/vnd.hum.sealed`, fresh key per table) and the keybox, which holds the tables' sealed references HPKE-encrypted to the context's `resultsKey`, as a public blob of media type `application/vnd.hum.keybox+hpke` ([storage.md §9.1](storage.md#91-release-tables-and-the-keybox); [release.md, Members-only results](release.md#members-only-results)). The aggregators never hold a keyring.
2. Sends the proposal to the Helper: `POST /v1/agg/decks/{cid}/propose` with body `{ bundle: bstr, tables: [CID], pages: [CID] }`, the bundle carrying the Leader's signature only. The Helper fetches the table blobs it can read, runs release.md's rules R1 to R15 (R15 on public tables) and checks what [release.md, Who signs](release.md#who-signs) says it attests in each phase, then answers 200 with `{ signature: bstr }`, its `COSE_Signature` over `hum/manifest/1 || CID` to be merged into the bundle's COSE_Sign, or `rejected` with `rule`. In phase 2 the same exchange rides the DAP collection flow.
3. Submits the bundle with both signatures to the context's ledger of record first (the first entry of `logs`), then to every other log the context names (`POST /v1/log/add`); each runs R1 to R14 again, and the ledger of record's answer decides.
4. Serves the logged bundle at `GET .../rounds/{n}/published` and, for the final version, at `GET .../release`.

In phase 1 the Helper does not see ballots or raw sums and does not attest that the noise was drawn fairly; its signature is a separately keyed check of the parameters, the floors and one-release-per-deck, exactly as release.md states.

The context posts the release digest into chat once it holds the log proof of the final version ([chat.md §5.6](chat.md#56-release-digest)).

### Phase 2 (DAP)

In phase 2 the Leader and Helper run the IETF DAP protocol ([draft-ietf-ppm-dap](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/)) with a Prio3 VDAF ([draft-irtf-cfrg-vdaf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/)) whose type ballot.md specifies, so every release part is still a sum of bounded per-person vectors.

How Hum maps onto DAP:

| DAP role or object | In Hum |
| --- | --- |
| Task | One release part of one deck round; task ID as above; task parameters come from the deck manifest, not from a task-provisioning API |
| Client | A phone |
| Leader | The Leader aggregator authority named in the context |
| Helper | The Helper aggregator authority |
| Collector | Both aggregators, each of which verifies the aggregate before signing the release. There is no third-party collector |
| Report upload | `POST .../rounds/{n}/ballots`, whose body carries the DAP report inside the Hum ballot so that the membership proof and nullifier travel with it |
| HPKE configs | `GET /v1/agg/hpke` on each aggregator, and pinned in the `hpke` field of each aggregator's `service` manifest; a phone uses the pinned one |
| Aggregation jobs and collection | The DAP endpoints as the draft defines them, called by the Leader on the Helper with `authority` auth, under the prefix `/v1/dap/` |
| Batch | One batch per task, so one per part per round; the minimum batch size is the deck's `minVoters` |
| Noise | Each aggregator adds its share of the noise to its aggregate share before revealing it, as the draft's DP mechanism describes; the mechanism and parameters are the deck's |

The DAP draft's own authentication between Leader and Helper is replaced by `authority` signatures so that the Helper trusts a key the context named, not a bearer token.

Aggregator rules the conformance suite and the simulator test:

- AG-1. A contribution for a round that is not accepting is refused with `closed`.
- AG-2. Two contributions with the same nullifier in one round yield one counted contribution: in round 0 before `closes`, the last accepted one, with the earlier leaf absent from the tree; in rounds 1 to 3 the first, with the same receipt returned.
- AG-3. A deck whose plan breaks a protocol or context floor is refused at open with `floor`.
- AG-4. No table is published unless `nHat` is at or above `minVoters`; below it, version 1 is final with `unlocked` empty, no tables, no receipt root and no receipt pages, and part 8's noise is not drawn (release.md R6, R13). The daily count is the one output with no voter minimum (context.md). Exactly one release lineage is published per deck.
- AG-5. Everything in the aggregator's logs and storage after the final version matches the logging table, no contribution, share or nullifier remains after 24 hours, and a replaced round-0 payload is gone as soon as its replacement is accepted.
- AG-6. Each round's receipt root in the release equals the root over the padded tree the round's receipt pages hold, and the pages follow the `k` rule.
- AG-7. A round 1 to 3 contribution from a nullifier with no round-0 ballot is refused.
- AG-8. A contribution rejected at any check leaves the nullifier unrecorded, and the same nullifier is then accepted with a valid contribution (ballot.md's premise for B1 to B13).

## Issuer and verifier host

A verifier collects evidence, deduplicates people, and issues a resident card: a blind-signed BBS credential whose attributes the verifier manifest declares ([verifier.md](verifier.md), [credentials.md](credentials.md)). The host is the server that holds the issuer key and the `hostKeys` transport keys, runs the verifier's module in the sandbox [verifier-runtime.md](verifier-runtime.md) defines, and exposes the API below. The platform host (the `issuer` service) and a self-run host are the same code and the same API ([verifier-runtime.md, Where code runs](verifier-runtime.md#where-code-runs)). A host is named by the `hostKeys` in the verifier manifest and reached through unsigned hints; its `service` manifest of kind `issuer` carries those hints.

### Endpoints

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `GET /v1/verifier/manifest` | `public` | The current verifier manifest bundle |
| `POST /v1/verifier/sessions` | `public` | Start an issuance session |
| `POST /v1/verifier/sessions/{id}/evidence` | session | Submit evidence the manifest asked for |
| `POST /v1/verifier/sessions/{id}/issue` | session | Submit the blind issuance request and receive the blind signature |
| `GET /v1/verifier/revocation` | `public` | The current revocation publication |

#### Sessions and evidence

`POST /v1/verifier/sessions` takes `{ manifest: CID }`, the verifier version the phone showed the person, and returns `{ id: bstr(16), expires: uint }`. The phone builds the disclosure summary from the manifest alone before this call ([verifier.md, Disclosure summary](verifier.md#disclosure-summary)); the host sends no list of asks, so it cannot change one. The session ID is the `session` credential for the following calls and is worthless after `expires` (at most one hour). There is no `asks` list to compare, which is why rule V-1 below is about undeclared names rather than a list match; verifier.md and verifier-runtime.md agree. `sessionCap` (verifier.md, default 5 per day) is counted by the `device` evidence item's per-verifier device key hash when the profile requires one; otherwise by an in-memory counter keyed by client address, discarded after 24 hours and never written to a log. The counter is listed in the host's stored data with that retention.

`POST .../evidence` takes `{ name: text, kid: bstr, ciphertext: bstr }` per evidence item, keyed by the item's unique `name` in the manifest. `ciphertext` is the item's kind-specific encoding, HPKE-sealed by the phone to the `hostKeys` entry named by `kid` (`hpke-x25519-sha256-chacha20poly1305`, base mode, `info` = `hum/evidence/1` ‖ verifier authority CID (33 bytes) ‖ the item's `name` as UTF-8, `aad` = the 16-byte session ID ‖ SHA-256(the issuance request plaintext, canonical CBOR), 48 bytes, so an item opens only in its session and only beside the issuance request the phone built before sealing it; [verifier.md, Host key](verifier.md#host-key)). TLS is transport only, so an edge in front of the host sees ciphertext, and the API carries it opaque. The host rejects an item the manifest did not declare with `forbidden`, and an oversized or unstripped image before the module runs ([verifier-runtime.md, Imports](verifier-runtime.md#imports-what-the-module-may-call)). The host holds the items sealed; it cannot open them until the issue call gives it the request whose hash is in the `aad`. When every required item and the issuance request have arrived, the host opens the request, opens each item under the session ID and the request's hash, and runs the module's `decide` once. An item that does not open under that hash ends the session with `rejected`, rule `V-4`. Evidence transport is direct TLS, not OHTTP, because the verifier learns who the person is by design; what the protocol guarantees is that it never learns what they do afterwards.

#### Issuance

`POST .../issue` takes `{ kid: bstr, ciphertext: bstr }`, where `ciphertext` seals `{0: v, 1: manifest CID, 2: kid, 3: commits (array of 1 or 2 outputs of the pseudonym draft's `CommitWithNym` with `prover_nyms` of length 1; two for a first card during a handover), 4: approved [message indexes `1 + i` for attribute `i`, since epoch is message 0 and the nym secret is the last message]}` to the host key `kid` names with HPKE info `hum/issue/1 ‖ verifier authority CID` ([credentials.md, Issuance request and response](credentials.md#issuance)). The response is `{0: v, 1: kid, 2: values, 3: cards [{0: epoch, 1: kid, 2: signature, 3: nymShare}]}` (the host signs with `BlindSignWithNym`, `nymShare` is the draft's `signer_nym_entropy`, and the phone finalizes with `VerifyFinalizeWithNym`), where the top-level `kid` is the key the phone expected for the current epoch and each card carries its own `kid`, because the two cards of a handover session may be under the two issuer keys verifier.md designates for their epochs, sealed back inside the same HPKE context (RFC 9180 §9.8 export with the `hum/issue-response/1` labels, ChaCha20-Poly1305, the 16-byte session ID as AAD), or `rejected` with a rejection code from verifier-runtime.md. The signer's nym share is a deterministic function of a host secret and the request hash (`hum/nym-share/1`), so an identical retry of the issue call returns the identical response. The code the phone sees is the masked one: a duplicate reaches the phone as code 0 unless every required evidence item binds the submitter, and the true code goes only to the host's session log ([verifier-runtime.md, What the host does with a decision](verifier-runtime.md#what-the-host-does-with-a-decision)). Implementations keep the phone-visible code and the logged code as separate values. One session answers one issuance request, with one card, or two in a first session during handover (V-2). After the session the host keeps only what verifier-runtime.md's decision handling lists: the keyed dedup row until 30 days after its `lastEpoch` ends (verifier.md, "Dedup item") and the evidence items whose `kept` is non-zero, as declared. It never keeps the blind request or the signature.

#### Renewal and revocation

Draft 0.1 verifiers revoke by expiry: `revocation.method` is `reissue` and the accumulator method is reserved ([verifier.md, Revocation](verifier.md#revocation); [ADR 0032](../decisions/0032-w0-03-revocation-reissue-only.md)). The emergency path is removing an issuer key from `issuerKeys` in a new verifier version.

There is no evidence-free renewal in draft 0.1. A card is good for one epoch of its issuer, and a person renews by opening an ordinary evidence session during the last two periods of the epoch, the handover, in which the host issues the next epoch's card ([credentials.md, Validity and Renewal](credentials.md#validity)). A first card obtained during a handover carries two commitments and receives two cards, one per epoch, in the same response. The session, evidence and issue endpoints above are the whole API.

`GET /v1/verifier/revocation` returns `{ method: text, accumulator: CID or null }`. In draft 0.1 `method` is always `reissue` and `accumulator` is `null`; the endpoint exists so phones have one place to look when the accumulator method is defined.

Verifier host rules the conformance suite tests:

- V-1. An evidence item whose `name` is not in the manifest is refused and never reaches the module.
- V-2. A session answers at most one issuance request. The response holds one card, or two in a first session during handover. An identical request, in the session or in a later one that maps to the same dedup row, gets the identical response. A different request in the same session answers `conflict`. A different request in a later session that maps to a spent dedup row is a duplicate: the dedup rule applies and the phone gets the masked rejection code of verifier-runtime.md, never `conflict`, so the answer does not reveal that the evidence already holds a card.
- V-3. The host's per-session log line has exactly the fields verifier-runtime.md lists, and nothing from the `issue` request is in any log or store other than the keyed dedup hash.
- V-4. Evidence opens only under `aad` = session ID ‖ SHA-256(issuance request plaintext) for the request submitted in the same session; a session whose request differs from the one its evidence was sealed for issues nothing.

## Delivery service and blob store

Both services see only ciphertext, both authenticate with anonymous tokens through the relay, and both are named by key. Their APIs are owned by sibling specs and are summarized here so the boundary is in one place.

| Service | Spec | Operations | Auth |
| --- | --- | --- | --- |
| Delivery service | [chat.md §12.2](chat.md#122-endpoints) | `POST /v1/tokens` (context tokens); `POST /v1/channels`; `POST /v1/channel-tokens`; `POST /v1/channels/{group_id}/send`; `POST /v1/channels/{group_id}/fetch`; `POST /v1/channels/{group_id}/reset`; `POST /v1/welcome/{handle}`; `POST /v1/join/{context}` and `POST /v1/join/{context}/fetch` (the admission flow, chat.md §2.5) | Context token to register a channel and for the join flow; channel tokens for send and fetch; `organizer` for a reset; none for a Welcome fetch |
| Blob store | [storage.md §6](storage.md#6-blob-store-api) | `POST /v1/tokens`; `PUT /v1/blobs/{cid}` (the store recomputes the CID); `GET /v1/blobs/{cid}` with optional `Range`; `DELETE /v1/blobs/{cid}` with the delete secret or a signed context order | `token` per context for puts, sealed gets and deletes; `authority` for service puts; none for public gets |

Both are reached only through the relay from a phone, both are named by key in the context manifest, and both keep the retention and visibility their specs' tables state ([chat.md §12.9 and §12.10](chat.md#129-what-the-ds-stores), [storage.md §6.8](storage.md#68-what-the-store-sees)). Both use the error format and codes of this spec's [Errors](#errors) section; chat.md §12.8 names the subset it uses. The delivery service's manifest is `service` with `kind: delivery`, carrying `tokenIssuers`, its `issuer` parameters at key 16, endpoints, retention and limits. KeyPackages are sealed blobs in storage, not a delivery-service operation.

#### Wake service (proposed, not in draft 0.1)

chat.md's first open question is push notifications: every design that wakes a device for a channel gives the delivery service a per-device list. Its recommendation, which this spec adopts as a proposal, is a separate wake service that learns only that some device should poll. Sketch: a phone registers an opaque push handle with the wake service through the relay and receives a wake key; the delivery service, on a new message, sends the wake service the channel's wake key and nothing else; the wake service pushes an empty signal to every handle under that key. The wake service learns handle-to-key, the delivery service learns neither, and neither learns which context a handle belongs to. It is filed as an open question rather than specified because the platform push services (APNs, FCM) see the handle and the timing, and whether that is acceptable needs the owner.

Public blobs (release tables, takes, public issue-map text and statement blobs) are put to a store with a `token`, or with an `authority` signature when an aggregator or a context authority uploads them, and read from any store, resolver or mirror without a credential ([storage.md §6.4](storage.md#64-get-and-range-get)). A put with an `authority` signature carries `Hum-Context` and counts against that context's quota like any other.

## Resolver and mirrors

A resolver serves bytes by CID. Any copy that hashes to the CID is as good as any other, so phones, mirrors and the reference resolver are interchangeable, and a context's phones share cached bytes inside their channels.

### Endpoints

| Method and path | Auth | Returns |
| --- | --- | --- |
| `GET /v1/blobs/{cid}` | `public` | A public blob's bytes with the declared media type; the same path and behavior as a store's public get ([storage.md §6.4](storage.md#64-get-and-range-get)), so a store, a mirror and the resolver are interchangeable |
| `GET /v1/blobs/{cid}` with `Range` | `public` | A single byte range, `206`, as storage.md defines |
| `HEAD /v1/blobs/{cid}` | `public` | Size and media type |
| `GET /v1/bundle/{cid}` | `public` | The manifest bundle for the CID, with every proof the resolver holds |
| `GET /v1/bundle/{cid}?deps=1` | `public` | The bundle and, as a CBOR array, the bundles of every manifest it references transitively, to depth 16 |

The CID in the path is the text form (`c` plus base32). Responses are immutable: `Cache-Control: public, max-age=31536000, immutable`, and `ETag` equal to the CID. A client takes a blob's media type from the manifest or reference that pointed at it, never from the `Content-Type` header ([storage.md §2](storage.md#2-content-ids)).

Rules:

- RS-1. A client checks every response against the CID before using it. A mismatch is treated as `not_found` and the client tries the next hint or source.
- RS-2. The resolver serves only public bytes: manifest envelopes and public blobs. Sealed blobs come from a blob store with a token. On `/v1/blobs`, the resolver answers `401` with only the code for a sealed, absent or tombstoned CID, exactly as a store answers a token-less request, so the two are indistinguishable. On `/v1/bundle`, an unknown manifest answers `404`, because manifests are public data.
- RS-3. The `deps=1` form returns at most 1,024 bundles and at most 16 MiB; above that it returns the first bundle alone. A client fetching a context fetches it this way so one request covers the whole bundle and the resolver learns nothing about which part mattered.
- RS-4. A tombstoned public blob answers `410` for the store's tombstone window and `401` afterwards, as a store does. Clients show both as removed ([storage.md §8.4](storage.md#84-tombstones-and-what-clients-show)).

### Location hints

A bundle's `hints` array lists URL prefixes. A client tries the resolvers its context names first (`resolvers`, context.md body key 20; the app's shipped defaults when absent), then the hints, then asks its channel. Hints are never signed and never affect verification.

### Mirroring

A mirror replays the log: it fetches entry bundles from the log's tiles, and for each leaf fetches `/v1/bundle/{cid}` and every public blob the manifest references from an upstream resolver or store, checking each against its CID. It serves the same `/v1/blobs` and `/v1/bundle` paths under its own prefix and may be listed as a hint or named as a resolver in a context manifest. A mirror must honor deletion: when an upstream answers `410` for a blob, the mirror deletes its copy within 24 hours. How a mirror learns of deletions it did not observe is an open question filed below.

### Through the relay

A phone fetches from resolvers through the relay, fetches whole bundles with `deps=1`, and shares cached manifests with other members, which together are the manifest spec's answer to fetch-pattern leakage ([manifest.md, Security considerations](manifest.md#security-considerations)).

## Gallery index and open data

The gallery index lists takes and ranks them. The open data API serves releases and their tables. Neither is trusted for anything: both serve manifests and blobs that a client verifies from the log, and ranking is post-processing of releases. Everything here is `public`.

### Open data

| Method and path | Returns |
| --- | --- |
| `GET /v1/releases?context={cid}&after={index}&limit={n}` | Releases in log order: `[ { cid, index, deck, context, issued, parts: [text] } ]` |
| `GET /v1/releases/{cid}` | The release bundle |
| `GET /v1/releases/{cid}/tables/{part}` | The Parquet table blob for a part, served by redirect to `/v1/blobs/{blobCid}` |
| `GET /v1/releases/{cid}.json` | The release's readable JSON view, never signed |
| `GET /v1/contexts/{cid}/releases` | The same listing for one context |

Table schemas per part are defined in [release.md](release.md), and the table names takes query are in [take.md, Query spec](take.md#query-spec). For a members-only release the manifest is listed, `parts` are named, and `tables` answers `404` with detail `sealed`.

### Gallery

| Method and path | Returns |
| --- | --- |
| `GET /v1/gallery/takes?release={cid}&sort={fair,new,forks}&after={cursor}&limit={n}` | Takes pinned to a release, ranked |
| `GET /v1/gallery/takes/{cid}` | The take bundle, the rating release CIDs and pooled `queryHash` versions behind its score, and the releases it uses |
| `GET /v1/gallery/takes/{cid}/forks` | Takes whose `refs.forkOf` names a version of this take |
| `GET /v1/gallery/ratings?release={cid}` | The rating releases dealt for a source release |

Ranking: `fair` orders takes by the score [take.md, Gallery ranking](take.md#gallery-ranking) defines, the lower bound of the fair share in the group that finds the take least fair, pooled across versions with the same `queryHash`. The gallery computes it as post-processing from the rating releases and serves the release CIDs it used, so any phone recomputes the same order; the conformance suite checks the phone does (`take-rank-*`). `new` is log order. The gallery indexes takes and rating releases by watching the log; authors submit takes to the log like any manifest, not to the gallery, and ratings reach the gallery only as a release. A take whose text blob was deleted is listed as removed, and a take built on a superseded release version is marked as such.

Rules:

- G-1. Every ranking response names the rating releases it was computed from, and recomputing from them with take.md's formula gives the same order.
- G-2. The gallery serves nothing it cannot point to in the log.

## OHTTP relay

The relay hides which phone made a request; the gateway, in front of the services, decrypts it. The relay sees a client IP and an encrypted request. The gateway sees the request and a relay connection. Neither sees both ([RFC 9458](https://www.rfc-editor.org/rfc/rfc9458.html)).

### Which requests go through the relay

The rule: **every request a phone makes goes through the relay**, except evidence submission and the blind issuance request to a verifier host, which are direct TLS because the verifier learns who the person is by design. The table explains why for each class of request; the rule is what the conformance suite checks.

| Request | Through the relay | Why |
| --- | --- | --- |
| Ballots, round publications, receipt pages, deck status | MUST | A ballot's network origin plus its time would link a pseudonym to a phone; a status poll says which deck a phone cares about |
| Blob store put, get, delete; token issuance | MUST | A store must not learn which member or channel |
| Delivery service send, fetch, register, token issuance, Welcome fetch | MUST | The service must not learn who is in a channel |
| Log submissions by a phone: authored objects, takes, and an organizer's contexts, decks and keysets | MUST | An authorship proof or an organizer's key with an IP joins an identity to a network address |
| Log lookups: entry, lineage, proof endpoints, checkpoint, tiles | MUST | They reveal which contexts a phone is in |
| Resolver and mirror fetches, gallery and open data reads | MUST | Same; public data still reveals interest |
| Organizer calls: deck registration at the aggregators, the daily count | MUST | Organizers are people holding keys on phones |
| Revocation fetch, a verifier's manifest | MUST | Nothing in the request identifies the holder, so the network must not either. A renewal is an evidence session and follows the row below |
| Evidence submission and the blind issue call to a verifier host | Direct TLS | The host learns identity by design, and the payloads are HPKE-sealed to its key. A client MAY still use the relay |
| Service to service (log submissions by services, Leader to Helper, witness calls, mirror syncs) | No | Authorities on servers, not people |

A phone that cannot reach a relay does not fall back to a direct connection. It waits and tells the person why. The conformance suite checks that a client opens no direct connection to any service other than a verifier host's session endpoints.

### Who runs it, and how a phone finds one

The relay is run by a party independent of the operator, because the relay and gateway together see everything, and the design doc counts the operator as an adversary. At launch the recommendation is two relays, a commercial OHTTP relay with a published no-logging policy and a partner's, with phones rotating between them ([ADR 0073](../decisions/0073-w0-07-ohttp-relay-operator.md)). The gateway is run by the operator in front of its services, and each service's manifest pins the gateway's key configuration in its `ohttp` field, so a client never accepts a key configuration from an unsigned source.

A relay is a service: it publishes a `service` manifest of `kind: relay` with its endpoints and jurisdiction, signed by its own authority. A phone learns relays from two places and nowhere else: the app ships the reference relays' authority CIDs as protocol constants beside the Global context CID and the reference log's keys, and a context may name additional relays in its manifest (`relays`, context.md body key 21). So that the first request needs nothing unsigned, the app also ships, beside the constants, the signed bundles with log proofs of the reference log's and the reference relays' `service` manifests; they verify offline against the shipped constants, which satisfies rule O-2 before the phone has read the log. Endpoints in those bundles are hints as always. A shipped bundle carries the gateway key configuration of the day the build was made, so two rules keep a fresh install working after a key rotation: the reference gateway keeps decrypting under every key configuration shipped in a build that is still supported; and at first contact the phone replaces each shipped bundle with the latest version of its lineage from the log, and uses that from then on. The app shows each relay's operator and jurisdiction on the context's services screen. Beside a relay the context names it says: "This context chose this relay. Its operator can see your network address and that you are a member here, and roughly when you are active in chat and files. It cannot see what you send. Nothing about voting and nothing you post to the issue map passes through it."

Relay rules:

- O-1. The relay rate-limits by client IP and keeps counts, not request logs, beyond 24 hours.
- O-2. The `ohttp` key configuration in a logged `service` manifest is what a client encrypts to; the `/.well-known/ohttp-gateway` endpoint ([RFC 9540](https://www.rfc-editor.org/rfc/rfc9540.html)) is a hint for discovering a new one, and a client accepts it only once it appears in a logged manifest.
- O-3. Requests through the relay are padded to the next of these sizes: 1, 4, 16, 64, 256 KiB, and above 256 KiB to the next multiple of 256 KiB. Responses are padded the same way. A ballot frame is exactly `BALLOT_BYTES` = 49,152 bytes in every round ([ballot.md, The ballot](ballot.md#the-ballot)), so a ballot request with its OHTTP and HTTP overhead lands in the 64 KiB bucket; the conformance suite checks that, and that a receipt-page fetch lands in the 4 KiB bucket or smaller.
- O-4. A phone uses a fresh relay connection per request class (ballot, store, delivery, token issuance, lookup, submission) and never multiplexes a ballot with any other request on one connection. Each receipt-page fetch uses its own fresh connection carrying nothing else, at a random delay of up to 24 hours after the round's version is logged, so the fetch cannot be paired with the ballot that produced the leaf.
- O-5. A phone refuses to use a relay whose manifest is signed by the same authority as any service the phone reaches through that relay. This catches an honest misconfiguration and a context that openly names its gateway operator's relay; it does not catch collusion, because authorities are free and an operator can sign a relay manifest with a fresh keyset. The relay-gateway separation rests on who runs the relay ([ADR 0073](../decisions/0073-w0-07-ohttp-relay-operator.md)), the app-shipped relay constants, and the services screen making a context's relay choice visible.
- O-6. Relay selection. A phone's relay set for a request is the app's shipped relays, plus the pinned context version's `relays` when the request is that context's and is not one of the shipped-only kinds below. The requests a context relay may carry are exactly these four, and nothing else: (1) any request to the context's delivery service (`chat.delivery`), token issuance included; (2) any request to a store the context names, and to that store's token issuer, except the puts of an authored object's text and evidence blobs (below); (3) a read from a log the context names (checkpoint, tiles, entry, lineage and proof endpoints) for the context's own lineage or an object that pins it; (4) a read from a resolver or mirror of a bundle or public blob of the context. Every other request uses the shipped relays only. Two kinds of request always use the shipped relays only, whichever context they belong to. First, every request to an aggregator: ballots, receipt lookups and receipt pages, and also deck status and published rounds. A ballot's fixed size is recognisable, and a status poll before a vote or a fetch of a round's publication marks an address as a probable voter even when the ballot went elsewhere; a relay the organizer chose must not be able to time who voted. Second, every submission to a log (`POST /v1/log/add` and its poll): the log is public and publishes a checkpoint about every 10 seconds, so a relay that sees which address wrote to the log's gateway in that window could tie an unsigned object to an address by itself, and the organizer is who the unsigned form protects against. The authorship path as a whole is shipped-only: the put of an issue-map object's or a take's text blob and of its evidence blobs to a store, and the token issuance that pays for those puts, use the shipped relays too, although other store requests may use a context relay. Otherwise a context relay would see an address write to the store a few seconds before the object appears in the log. Requests that belong to no context (the Global context, verifier and trust-list manifests, a context the person has not yet joined, the gallery and open data) use the shipped relays only. For each new connection (rule O-4) the phone picks one relay from the set uniformly at random with its CSPRNG. The set is built per request, so a relay named by context A is never used for a request of context B unless B names it too. If the chosen relay is unreachable or fails O-5, the phone picks again from the rest of the set; if every relay in the set fails it waits, and it never connects directly.

## Conformance and vectors

W0-08's reference implementation generates vectors for every rule in this spec that has bytes in it. Rules with no bytes are tested in the simulator.

Vectors (in `vectors/services/`):

- The `service` manifest: one valid per kind, one failing per rule S-1 to S-8.
- Bundle encoding: a valid bundle with two proofs; one with an `authorship` proof and no signatures; failing B-1 (too large), B-4 (both or neither of `signatures` and `authorship`), and a proof whose path does not verify.
- Log leaves: the leaf bytes and RFC 6962 leaf hash for each manifest type; an entry bundle of three leaves; a failing leaf hashed without the `0x00` prefix.
- Step 9 at the log: one accepted bundle per type with every manifest-valued ref present, and one refused per type with one such ref absent (LG-8).
- Checkpoints: a valid note with the log signature and two cosignatures; one with one cosignature (reject, W-2); one missing the log's own signature; one with a cosignature from an unlisted witness; one whose cosignature key ID matches no listed key; one whose cosignature timestamp line is tampered; the log's key ID derivation.
- Witness protocol: request and response bodies for 200, 409 stale size, 409 same size with a different root, and 422.
- Signed requests: `service-request-payload` (the exact A-1 bytes), a valid `authority` request, and failing A-1 (wrong target), A-2 (signatures below threshold), A-3 (stale, and replayed nonce).
- Tokens: a replayed token (T-1), using the RFC 9578 test vectors for types 0x0001 and 0x0002 unchanged.
- Task ID derivation for a given deck CID, each round and each part.
- Receipt signature over fixed inputs; failing with the wrong key and with another round's task ID.
- Receipt pages: `k` and page assignment for leaf counts 100, 4,096, 4,097 and 1,000,000.
- Error encoding: one body per code, and the two bare forms.
- Padding: the bucket for request sizes including one above 256 KiB.
- O-5: a relay manifest signed by the authority of a service named in the test context (reject) and one under its own authority (accept).
- O-6: for a fixed random stream and a context naming one relay, the relay chosen for a delivery fetch (from the set of shipped plus context relays), for a ballot, a deck status poll, an unsigned object's text-blob put and its log submission (shipped only, each), for a request of a second context (never the first context's relay), and after the chosen relay fails (next pick from the rest). The simulator checks that no request to an aggregator and no log submission ever reaches a context-named relay and that no request of context B reaches a relay only context A names.
- Bootstrap bundles: a first request made with a shipped gateway configuration one rotation old (accepted by the gateway; the phone then holds the current bundle).
- Bootstrap: a first checkpoint cosigned by two keys outside the shipped constants (reject), and one cosigned by one constant key only (reject, `MIN_WITNESSES`).

Simulator checks (in `sim/`, per [simulator.md](simulator.md)): LG-1 to LG-8, AG-1 to AG-8, V-1 to V-4, RS-1, RS-2, G-1, O-3 to O-5, and the logging table for every service.

## Open questions

Filed in `docs/decisions/` where a decision is needed; listed here so implementers see them.

- **One log or two.** This spec treats the release ledger as the release entries of the one reference log ([ADR 0071](../decisions/0071-w0-07-one-log.md)). If the owner prefers a separate ledger log, the only change is a second `service` manifest of kind `log` and a second `proofs` entry on releases.
- **`service` manifest type.** One type with a `kind` field for every service, blob stores included, with kind-specific fields from key 16 ([ADR 0072](../decisions/0072-w0-07-service-manifest-type.md)). The manifest spec's type registry now has the row, and `blob-store` is retired there.
- **Two token types.** Stores use type `0x0002` and the delivery service `0x0001`, for reasons each spec gives. One type for both would simplify phones; W0-10 may propose it.
- **Who runs the relay** ([ADR 0073](../decisions/0073-w0-07-ohttp-relay-operator.md)), and the `relays` field, now context.md body key 21.
- **Bundle wire format.** Defined here because the manifest spec names the parts without an encoding, and issue-map.md and take.md put authorship proofs "in the bundle". If the manifest spec's owner wants it there instead, move the two tables.
- **Lineage lookup privacy.** The `lineage` endpoint reveals interest even through the relay, by timing and by which lineages are asked together. Full mirrors on phones for small contexts, or private information retrieval, remain open from the manifest spec.
- **Mirror deletion.** How a mirror learns of a deletion it did not observe. Options: the resolver publishes a signed deletion feed by CID, or mirrors re-check upstream on a schedule.
- **Daily count readers.** Organizer-only during the deck, public at release as the `count` table (context.md). Whether to make it public during the deck too, which would remove the `organizer` class, stays open.
- **Session counting at a verifier host.** `sessionCap` is counted by a `device` evidence binding when the profile has one and otherwise by an in-memory per-address counter discarded after 24 hours and never logged ([Sessions and evidence](#sessions-and-evidence)). verifier-runtime.md accepts this for draft 0.1 and records dropping `sessionCap` for profiles without `device` as the alternative for the owner.
- **Wake service.** Whether to specify the wake service sketched above for draft 0.1 or ship with polling only.
- **DAP draft version.** Which draft version of DAP and VDAF to pin, decided when W1 picks a library.
- **Breakdown contributions in phase 1.** A breakdown ballot tells the phase 1 aggregator a pseudonym's attribute value (deck.md's open question). Until the owner decides, aggregators refuse decks with part 7 at open (`rejected`, rule B9), per ballot.md.
