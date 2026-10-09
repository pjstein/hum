# Hum Credentials Spec — Draft 0.1

Oct 6, 2026 · W0-02 · revised after two reviews · `seam:` credential issuance and presentation, pseudonyms and nullifiers, key storage and backup

## Scope

This spec defines how a person gets the right to act in a context without being identifiable: the resident card, the per-deck voting pseudonym and its nullifier, the policy presentation, the chat identity, agent sponsor credentials, and the per-person backup. It lists every identifier these produce, where each is stored, and who can see it.

Draft 0.1 is built from these documents alone and adds no cryptography of its own:

| Piece | Document | Version assumed |
| --- | --- | --- |
| Credential signature, selective disclosure, proof of knowledge | [draft-irtf-cfrg-bbs-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/) | -12 (Sept 2026), ciphersuite `BLS12-381-SHA-256` |
| Blind issuance of a committed message | [draft-irtf-cfrg-bbs-blind-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-blind-signatures/) | -03 (June 2026) |
| Per-scope pseudonyms from a hidden, blindly issued secret | [draft-irtf-cfrg-bbs-per-verifier-linkability](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-per-verifier-linkability/) | -03 (June 2026) |
| Sealing between phone and host | HPKE, [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html), including §9.8 bidirectional encryption |
| Chat identity | MLS, [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html), profiled in [`chat.md`](chat.md) §2.1 |

W0-08 should confirm that the function names used here exist at the cited versions; the reviewer could not read the drafts.

A set-membership predicate over a hidden message (for policies such as "ward in {1, 2, 3}" without revealing the ward) is **not in draft 0.1 conformance**. It is described under "Future: hidden predicates" so the outside cryptography review can judge it, and ADR 0022 records it. Draft 0.1 supports exactly the policies that selective disclosure supports, listed under "What is proven".

What a verifier declares is [`verifier.md`](verifier.md). Which issuers a context accepts is [`trust-list.md`](trust-list.md) and [`context.md`](context.md). How a ballot carries a presentation is [`ballot.md`](ballot.md). The pseudonym recommendation is [`0020-w0-02-pseudonyms-bbs-not-semaphore.md`](../decisions/0020-w0-02-pseudonyms-bbs-not-semaphore.md).

## Three identities, never linked

| Identity | What it is | Signs or proves | Who can see it |
| --- | --- | --- | --- |
| Resident card | A BBS credential from a verifier, carrying attributes and a hidden pseudonym secret, good for one epoch of that verifier | Nothing directly; it is only ever shown through presentations | The phone. The issuer computed the signature and knows the attributes it signed; it never learns the pseudonym secret, and a presentation reveals nothing about which signature it was made from |
| Voting pseudonym | A per-scope pseudonym derived from the card's hidden secret; for a ballot the scope is one deck | A ballot, through the presentation it carries | The party that verifies that one presentation, under that one scope |
| Chat name | A per-person Ed25519 key in an MLS leaf credential | Messages, signed authorship, device bindings | Members of the person's MLS groups; anyone, for a signed issue-map object |

Nothing connects them by construction: the card never carries the chat key or anything derived from it, the chat credential never carries a card, a pseudonym or a nullifier, and pseudonyms under two scopes are unlinkable. Every valid card from one issuer presents the same public fields at any moment, and `context.md` rule C16 gives a context one issuer per policy leaf and no `any` node in draft 0.1, so every member of a context presents the same public fields for a given use: they form no cohort smaller than the context's membership (see "Every identifier" for the two residuals). No code path, log line, cache key or metric may hold two identities at once; that table is what reviewers check against.

## Terms

| Term | Meaning |
| --- | --- |
| Issuer | A verifier's host, holding an issuer key named by `kid` in the verifier manifest |
| Credential, card | A BBS signature over a fixed message vector, held with its messages on the phone |
| Nym secret | The hidden scalar that is the last message of every card (the pseudonym draft's `nym_secret`, the sum of the prover's `prover_nyms[0]` and the signer's `signer_nym_entropy`); the only input to pseudonyms besides the scope |
| Period | A 28-day interval: `period(t) = floor(t / 2419200)` for a Unix time `t`; `p_now` is the current period |
| `V` | A verifier's validity in periods: `floor(validity / 2419200)`, at least 1 (`verifier.md`) |
| Epoch | `V` consecutive periods aligned to the Unix epoch: epoch `E` is periods `E·V` to `E·V + V − 1`; `epoch(p) = floor(p / V)`; `E_now = epoch(p_now)` |
| Handover | The last two periods of an epoch, when the next epoch's cards are issued |
| Scope | Public bytes that name one use of a card; pseudonyms are per scope |
| Pseudonym | The G1 point the pseudonym draft computes from the nym secret and a scope |
| Nullifier | The 32-byte hash of a pseudonym; what verifiers store and compare |
| Presentation | A proof that a set of cards satisfies a policy, under one scope, bound to one message |
| Bound message | Public bytes a presentation commits to, so it cannot be moved to another use |
| Policy | The condition tree in a context manifest ([`context.md`](context.md), "Entry policy") |

## The resident card

### Message layout

A card is a BBS signature over `L` messages, in the order the pseudonym draft's `VerifyFinalizeWithNym` builds the scalar vector: the signer's messages first, then the prover's committed messages (none in Hum), then the nym secret last. Indexes below are positions in that vector and are the indexes `disclosed` uses.

| Index | Message | Hidden or disclosed | Bytes before `messages_to_scalars` |
| --- | --- | --- | --- |
| 0 | `epoch` | Disclosed in every presentation (see "Validity") | 8 bytes big-endian |
| 1 + i | Attribute `i`, in the manifest's `attributes` array order, for `i` = 0..A−1 | Hidden unless a use allows disclosure | 8 bytes big-endian: the attribute's uint value per `verifier.md`, or `0xFFFFFFFFFFFFFFFF` when absent |
| L − 1 = 1 + A | Nym secret | Always hidden; the draft's `nym_secret`, committed by the prover and completed by the signer | The scalar itself; no octet encoding |

`L = A + 2`, where `A` is the attribute count of the layout. The layout of epoch `E` is the attributes whose `fromEpoch` is at most `E`, in array order (`verifier.md`, "Attribute"), so `L(E) = 2 + (number of attributes with fromEpoch ≤ E)` and `L` is the same for every card of an epoch. `fromEpoch` is set once and frozen, so any manifest version that lists the attribute gives the same answer, with no clock and no log position; a verifier of a logged proof computes `L` from the version in force at the object's log position or any later one. A new attribute's `fromEpoch` is never an epoch whose cards may already exist (`verifier.md` rule 30). Attributes are only ever appended (`verifier.md` rule 22), so an index means the same attribute in every later version. A presentation states `L`; a verifier rejects an `L` that is not the epoch's. The absent value collides with a `uint` attribute whose `max` is 2⁶⁴ − 1; `verifier.md` caps `max` below it.

The BBS `header` for every signature is the ASCII string `hum/credential/1` followed by the verifier authority CID (33 bytes) and the `kid`. A card therefore verifies only under the issuer it names. Every card of an epoch is signed under one `kid`, **the key of epoch `E`**: the listed issuer key with the largest `fromEpoch ≤ E`, read from the manifest version in force at the start of `E`'s handover; if that key has since been removed from `issuerKeys`, the key of `E` is the one the current version selects (`verifier.md`, "Issuer key"). So the `kid`, like `L`, is the same for every valid card of an issuer at any moment. Two cards issued in one handover session (this epoch's and the next's) may be under two keys; the response names the `kid` per card. The epoch grid depends on `V`, so `validity` is frozen within a verifier lineage (`verifier.md` rule 21); a verifier that needs a different `V` retires the lineage and names a successor.

Ciphersuite `BLS12-381-SHA-256`. The verifier manifest's issuer `alg` is `bbs-bls12381-sha256` and `key` is the 96-byte compressed G2 public key (`verifier.md`). The pseudonym draft's `N` (number of nym secrets) is 1.

### Validity

A card of epoch `E` is valid in the periods of epoch `E` and in no others: `epoch(p_now) = E`. A card issued mid-epoch is shorter-lived; one issued in the last period of an epoch lives at most 28 days, and verifiers with `validity` under 56 days should know that. Lifetime is never more than `V` periods, which is never more than `validity`.

`epoch` is disclosed in every presentation, and the verifier checks it against its own clock. Because every valid card from an issuer carries the same `epoch`, the same `kid` and the same `L`, the disclosure tells a verifier nothing that the issuer identity did not: the anonymity set of a presentation's public fields is the issuer's whole set of current holders, and within one context it is every member (`context.md` C16; see "Every identifier"). The outside review may later replace the disclosed epoch with a hidden predicate; nothing else changes if it does. `verifier.md`'s "expiry is never disclosed" becomes "the card's epoch is disclosed, and every valid card shares it".

Which check a verifier applies depends on the use:

| Use | Accepted `epoch` | Why |
| --- | --- | --- |
| Ballots, every round | `epoch = epoch(period(closes₁))`, where `closes₁` is `closes` of the deck lineage's **version 1**; and `p_now ≥ epoch · V` (the card has started) | The card is the one valid at the deck's original close, which a `closes` extension cannot move. One person holds at most one card per issuer per epoch (dedup, below), so one person has exactly one deck nullifier per card slot in the policy. In rounds 1 to 3 the card may have expired since; it was valid at close, which is what counts |
| Logged presentations: signed authorship, unsigned authorship, a sponsor proof (the proof is stored in a bundle and verified again later) | **At submission, the log:** `epoch = E_now` by the log's own clock `T`, or the previous period's epoch while `T` is less than 3,600 seconds into a period (the same first-hour grace as every other use); and the object's envelope `issued` satisfies `|issued − T| ≤ 3600`, bounds included. **Any later verifier, with no clock:** `epoch = epoch(period(issued − 7200))` or `epoch = epoch(period(issued + 3600))`, with `V` from the issuer's manifest | The log is the one party that sees the proof when it is made. Everyone after it checks the proof against the time the object states, which the log bounded, so an object does not stop verifying when its author's card expires (ADR 0101). The two values differ only when `issued` is within two hours after or one hour before an epoch boundary `B`: the old epoch is accepted for `issued ≤ B + 7199` and the new one for `issued ≥ B − 3600`, which is exactly what an honest log can have admitted. `issued` is chosen by the author and bounded only by that one log's clock; no witness checks it. See "Security considerations" for what a lax log admits |
| Everything else (join tickets, token requests, issuance evidence) | `epoch = E_now` | Valid now; verified once |

`p_now` is the verifier's own period. During the first hour of a period a verifier also accepts the previous period's value, which covers a proof made just before a boundary. At an epoch boundary this means a dying card and its successor are both accepted for one hour by token issuers, greeters and logs; that doubles a day's token quota and a window's unsigned slots for that hour, which is accepted. The prover carries no clock value.

A deck whose original `closes` falls in an issuer's epoch `E + 1` counts only cards of epoch `E + 1`, which no one holds as a started card until that epoch begins. Members cannot vote until then, however early the deck opened: the wait is the time from `opens` to the start of `E + 1`, which for a long deck can be most of an epoch (up to `V` periods). `ballot.md` holds the ballot and the deck card says "counting starts <date>". Epoch grids are public (`V` and the Unix-aligned grid, from the verifier manifest), and an organizer has two levers, both visible in the log and neither able to single out a person: placing the original `closes` just after a boundary makes the electorate the members who renewed in handover, and placing it on an epoch's last day and extending afterwards freezes the electorate to that epoch's holders.

A card pinned to a deck (`shield.md`, `cards`) stays usable for that deck after its epoch ends: later rounds and replacements of an extended deck present it with its own epoch, which the ballot rule accepts because it is the epoch of the original close. Nothing else accepts it, since every other use checks `epoch = E_now`.

### Issuance

Every card, first or renewed, is issued by a session with evidence, inside the session flow of [`services.md`](services.md), "Issuer and verifier host". There is no evidence-free renewal in draft 0.1 (ADR 0026).

1. The phone shows the disclosure summary derived from the manifest alone (`verifier.md`) and the person approves which attributes the card may carry (the `P-Verify` screen). An attribute left unchecked is issued as absent.
2. The phone runs the pseudonym draft's `CommitWithNym` once per card it requests, with a fresh `prover_nyms` of length 1 and no other committed messages, builds the issuance request below first, then seals each evidence item with `aad` = session ID ‖ SHA-256(request plaintext) (`verifier.md`, "Host key"), HPKE-seals the request to a host key, and submits the evidence and then the request (`POST .../evidence`, `POST .../issue`). The hash covers the one request plaintext, whether it holds one commitment or the two of a first session in handover.
3. The host opens the request, recomputes its hash, opens each evidence item under it, and refuses the session if any item was sealed for another request. It then runs the module, which outputs attribute values and a dedup key, and exits. The host then decides which epochs to issue (below), and for each one signs with `BlindSignWithNym`: it derives `signer_nym_entropy` as "Lost responses" says, sets `epoch`, sets each attribute message to the module's value or to absent for attributes the person did not approve or the module did not grant, and passes the signer's messages in the layout order. The module never sees the request, the signature, the nym entropy or the finished card (`verifier-runtime.md`).
4. The phone runs `VerifyFinalizeWithNym` on each card, which verifies the signature and completes `nym_secret = prover_nyms[0] + signer_nym_entropy`, and checks the response before storing anything: the signature verifies under the manifest key named by that card's `kid`; that `kid` is the key the manifest version the person was shown designates for the card's epoch (`verifier.md`, "Issuer key"); `epoch` is `E_now`, or `E_now + 1` during handover; every attribute value is in the manifest's declared set for that attribute, or absent; every attribute the person did not approve is absent. A card failing any check is discarded and the session reported as failed.

**Which epochs a session issues.** The host's dedup row for a person (`verifier.md`, keyed hash) stores `lastEpoch`, the epoch of the newest card issued under it, and is kept until 30 days after that epoch ends (`verifier.md` is asked to replace "`validity` plus 30 days from issuance" with this). A session:

- with no row, outside handover: issues one card, epoch `E_now`; `lastEpoch = E_now`;
- with no row, during handover: issues two cards, epochs `E_now` and `E_now + 1`, each with its own nym share and request commitment; `lastEpoch = E_now + 1`;
- with a row where `lastEpoch < E_now`: as if no row (the old card is dead);
- with a row where `lastEpoch = E_now`, during handover: issues one card, epoch `E_now + 1` (this is renewal); `lastEpoch = E_now + 1`;
- with a row where `lastEpoch = E_now` outside handover, or `lastEpoch = E_now + 1`: refuses with the dedup code (`verifier-runtime.md`, masked to the phone as that spec says).

So one dedup key yields at most one card per epoch, two cards are never valid at once, and the row outlives every card issued under it. Three details:

- **Several dedup items** (a uniqueness verifier has two): the host matches every item's row, takes the largest `lastEpoch` over the matched rows as the person's state, uses that governing row's request hash for the retry check, and writes the result to every item's row, so a new device beside a known document does not reopen the epoch. A row also stores the `kid` of the card it issued; a row whose `kid` is no longer in `issuerKeys` counts as no row, so an emergency key removal does not lock holders out until handover (`verifier.md`).
- **A `credential` dedup item is never the only dedup item** (`verifier.md`, raised as T1). Its key is the presented card's `hum/issuance/1` nullifier, which changes with the presented issuer's epoch; an asker with a longer epoch that deduped on it alone would see a new key mid-epoch and issue twice. Every named profile already pairs it with an `evidence` or `device` item.
- **Renewal needs no new evidence artefact.** A renewal session presents the same code, roster entry, document or device, which maps to the same row; a one-time-code verifier does not issue a new code each epoch. District example (`validity` 180 days, `V` = 6, epochs of 168 days): a card issued in period 2 of epoch 0 lives periods 2 to 5; in periods 4 and 5 the person renews with evidence and receives the epoch-1 card, valid periods 6 to 11; the row says `lastEpoch = 1` until 30 days after period 11, so a fresh session in period 7 with the same evidence is refused, and a session in period 10 or 11 issues epoch 2. Nothing a holder does can produce two cards of one epoch from one dedup key; two dedup keys for one person are the issuer's dedup quality, as before.

The host sees the signature value it computed and the attributes it signed; it never sees the nym secret (it knows only its own `signer_nym_entropy`), and a presentation reveals nothing about which signature it came from. What the host keeps is what `verifier.md` and `verifier-runtime.md` allow: the dedup row and declared evidence, plus the request hash below. It never keeps the request, the signature or its nym share.

**Lost responses.** The signer's `signer_nym_entropy` for a card is `HKDF-SHA256(IKM = host secret, salt = "hum/nym-share/1", info = SHA-256(request plaintext) ‖ uint64be(epoch))`, reduced to a scalar as the draft's `hash_to_scalar` does, so re-signing the same request yields the same card. The pseudonym draft allows `signer_nym_entropy` to be reused for the same prover (its §6.1.2 says so for re-issuance); deriving it from the request is one way to do that deterministically. The host stores the request hash in the session and in the dedup row with `lastEpoch`. An identical request resubmitted within the session, or in a new session whose evidence maps to the same dedup row while the row's hash matches, receives the identical response rather than a dedup refusal. A different request against a spent row is refused as above.

The resident card is optional (`P-Verify`: "Skip for now"). A person with no card can join contexts whose entry policy is `[0]` and cannot vote anywhere, because every effective voting policy names a card (`context.md` rule C6).

#### Issuance request and response

Both cross the phone-to-host boundary and are deterministic CBOR. The request is HPKE-sealed by the phone to the `hostKeys` entry it names, to a host key as evidence is (`verifier.md`, "Host key"), under its own `info`; evidence uses `hum/evidence/1`, with the session ID and the hash of this request as `aad`. A lost-response retry in a new session re-seals the evidence under the new session ID and the same request hash, and the identical request still gets the identical response. The response is sealed back inside the same HPKE context using RFC 9180 §9.8: the host's receiver context exports `key = Export("hum/issue-response/1 key", 32)` and `nonce = Export("hum/issue-response/1 nonce", 12)` and encrypts the response with the same AEAD as the suite, with the 16-byte session ID as AAD. A TLS terminator in front of the host sees ciphertext in both directions.

HPKE suites, one per use, so a library can be checked against each:

| Use | KEM | KDF | AEAD | Mode | `info` | Owner |
| --- | --- | --- | --- | --- | --- | --- |
| Issuance request to a host (`hostKeys` alg `hpke-x25519-sha256-chacha20poly1305`) and the §9.8 response | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | ChaCha20-Poly1305 | base | `hum/issue/1` ‖ verifier authority CID | `verifier.md`, this spec |
| Evidence item to a host (same `hostKeys` alg) | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | ChaCha20-Poly1305 | base | `hum/evidence/1` ‖ verifier authority CID ‖ item name, with `aad` = the 16-byte session ID ‖ SHA-256(issuance request plaintext) | `verifier.md` "Host key", `services.md` |
| Backup key wrap to the phrase-derived key | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | AES-128-GCM | base | `hum/backup/1` | this spec |
| Chat-only export to the one-time QR key | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | AES-128-GCM | base | `hum/backup/1` | this spec |
| Join ticket and results keybox | as `chat.md` §2.5 and `release.md` define (AES-128-GCM) | | | | | those specs |

Two AEADs are used on purpose: the host path keeps `verifier.md`'s ChaCha20-Poly1305 suite, and everything the phone seals for itself uses AES-128-GCM like the sealed-blob format. Both need the export interface for the §9.8 response and a fixed ephemeral key for vectors.

Request plaintext:

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | `v` | uint | 1 |
| 1 | `manifest` | bytes(33) | The verifier manifest version shown to the person |
| 2 | `kid` | bytes | The key of the current epoch by the rule in "Message layout", as the phone computes it from `manifest` |
| 3 | `commits` | array of bytes, 1 or 2 | One `commitment_with_proof` per card requested, the output of `CommitWithNym` with `prover_nyms` of length 1 and no other committed messages; two during handover for a first card |
| 4 | `approved` | array of uint, ascending | Attribute indexes (1 + i) the person approved |

Response plaintext (`200`):

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | `v` | uint | 1 |
| 1 | `kid` | bytes | Equal to the request's |
| 2 | `values` | map uint → uint | Message index → value for every present attribute; absent attributes omitted; the same for every card issued |
| 3 | `cards` | array of `{0: epoch (uint), 1: kid (bytes), 2: signature (bytes), 3: nymShare (bytes(32))}` | One per card issued, in the order of `commits`; fewer than requested when the host issues only the next epoch. `kid` is the key of that card's epoch, and the phone checks that rule |

A rejection is `services.md`'s `rejected` with the masked code and no plaintext body.

### Renewal

Renewal is a session with evidence during handover, as the issuance rules say. `POST /v1/verifier/reissue`, the renewal presentation, the `hum/reissue/1` scope and the reissue rule `services.md` once numbered V-3 are withdrawn from draft 0.1 (raised with W0-07 and W0-03). The evidence-free alternative, which needs either a longer dedup retention or a construction outside the drafts to keep nullifiers stable, is filed in [`0026-w0-02-renewal-and-ballot-window.md`](../decisions/0026-w0-02-renewal-and-ballot-window.md).

Every new card has a new nym secret, so every pseudonym changes at each epoch: a person's deck nullifiers for decks closing in different epochs are unrelated (they were anyway, by scope), and their join, token and authorship nullifiers change too. `chat.md`'s one-chat-identity-per-card rule therefore holds within an epoch, and a member could present a new card for a second identity in the next epoch (raised with W0-05).

Revocation in draft 0.1 is expiry and issuer-key removal only ([`0032-w0-03-revocation-reissue-only.md`](../decisions/0032-w0-03-revocation-reissue-only.md)). An accumulator method, when defined, adds a non-membership proof to the presentation and nothing else here changes.

## Scopes and nullifiers

A scope is the pseudonym draft's `context_id`. Every presentation uses exactly one scope, and every card in it yields a pseudonym under that scope.

```
pseudonym = OP · nym_secret, OP = hash_to_curve_g1(scope)     the pseudonym draft §4 with N = 1 (its polynomial has one term),
                                                             computed inside ProofGenWithNym and checked by ProofVerifyWithNym
nullifier = SHA-256("hum/nullifier/1" ‖ pseudonym_octets)    pseudonym_octets: 48-byte compressed G1
```

### The uses

This table is the whole contract between a use and this spec. A scope's bytes are the ASCII prefix followed by the raw suffix bytes with no separators. Byte widths: CID 33, hash 32, `token_key_id` 32, day and window uint64 big-endian 8, slot uint16 big-endian 2, `agentKey` 32.

| Use | Scope bytes | Bound message | `context` field | Policy proven | Disclosures allowed | Class | Owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Ballot | `hum/ballot/1` ‖ deck lineage CID | `hum/ballot-bound/1` ‖ SHA-256(ballot keys 0–4) | The deck's pinned context version | `[1, [entry, vote]]` | What leaves require; `epoch` | `person` | `ballot.md` |
| Join ticket | `hum/join/1` ‖ context lineage CID | SHA-256(canonical CBOR of the handles) | Current or previous context version | `entry` | Same | `person` | `chat.md` §2.5 |
| Blob tokens | `hum/blob-tokens/1` ‖ `token_key_id` ‖ day | SHA-256(canonical CBOR of the `requests` array) | The version `storage.md` §6.2 names | `entry` | Same | `person` | `storage.md` |
| Delivery tokens | `hum/delivery-tokens/1` ‖ `token_key_id` ‖ day | SHA-256(canonical CBOR of the `requests` array) | The version `chat.md` §12.3 names | `entry` | Same | `person` | `chat.md` |
| Signed authorship | `hum/author-once/1` ‖ object CID | `hum/author/1` ‖ object CID | The object's pinned context version | `entry` | Same | `person` | `issue-map.md` |
| Unsigned authorship | `hum/author-slot/1` ‖ context lineage CID ‖ window ‖ slot | `hum/author/1` ‖ object CID | Same | `entry` | Same | `person` | `issue-map.md` |
| Sponsor proof | `hum/sponsor/1` ‖ sponsor authority CID | `agentKey` | absent | The possession leaf `[4, A]`, `A` the agent-class verifier authority the sponsor manifest names | `epoch` only | `agent` | `agent-sponsor.md` |
| Issuance evidence | `hum/issuance/1` ‖ asking verifier's authority CID | SHA-256(the session's issuance request **plaintext**, canonical CBOR) | absent | Exactly one card, satisfying the possession leaf `[4, accepts[k].authority]` of one `accepts` entry of the evidence item: the lowest-index entry the phone holds a valid card for. The entries are alternatives, not a conjunction, and this use is not a context policy, so P6's no-`any` rule does not apply to it. The asking host learns which entry was used; it already sees the person's evidence (`verifier.md`, "Evidence item") | The attributes that `accepts` entry lists; `epoch` | `person` | `verifier.md` |

Rules:

- Prefixes are distinct and none is a prefix of another, so two scopes never collide. The only ballot scope is `hum/ballot/1`, and no ballot scope starts with `hum/author-`.
- Pseudonyms under different scopes are unlinkable without the nym secret (the pseudonym draft's claim, under DDH in G1), whoever verifies them. The issuer that sees an issuance-evidence nullifier can no more link it to a ballot than an aggregator can.
- **Every nullifier counts.** A presentation yields one nullifier per card in it. A verifier that deduplicates or rate-limits treats a presentation as seen if any of its nullifiers was seen, and for ballots every nullifier must be new for the deck (`ballot.md` B3). This is what stops two people pooling cards under an `all` node: a card lent into someone else's presentation is spent for its owner in that deck. The policy's designated leaf (`context.md` `nullifier`, rule C6) names the **primary** nullifier, which `ballot.md` uses as the key for replacement, later rounds and the receipt; it is not the only one checked.
- A policy `[0]` yields an empty presentation with no card and no nullifier. Services that rate-limit by nullifier fall back to per-context limits for such a context (`storage.md`, `chat.md`).
- The join scope is per context, so one card yields one join nullifier per context and admits one chat identity there for the card's epoch (`chat.md` §2.5 and its `join-record` message). The handles are the bound message, so a ticket cannot be replayed with other KeyPackages.

The design doc calls the voting identity a per-context pseudonym; this spec makes it per deck, so an aggregator cannot build one pseudonym's profile across a context's decks. The design-doc wording is the owner's to change; see [`0021-w0-02-per-deck-nullifier.md`](../decisions/0021-w0-02-per-deck-nullifier.md).

## Presentations

A presentation proves that the cards the phone holds satisfy a use's policy, under the use's scope, bound to the use's message, against one context version when the use has one. It is one deterministic CBOR map.

### Format

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | `v` | uint | 1 |
| 1 | `context` | bytes(33) | The context version whose policy is proven; present exactly when the use's row says so |
| 2 | `creds` | array of card proof, 0..8 | One per card used, in the order the policy walk first needs them |
| 3 | `branches` | array of uint | For each `any` node the walk visits, in walk order, the index of the child taken |

A card proof:

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | `issuer` | bytes(33) | The verifier authority CID |
| 1 | `kid` | bytes | The issuer key ID; must be in `issuerKeys` of the verifier version in force (defined under "Verification rules": at the object's log position for a logged presentation, otherwise the latest version the verifier holds) |
| 2 | `len` | uint | `L` |
| 3 | `disclosed` | map uint → uint | Message index (the layout's) → value for every disclosed message. Index 0 (`epoch`) is always present; index `L − 1` (the nym secret) never |
| 4 | `proof` | bytes | The BBS proof with pseudonym, the output of the pseudonym draft's `ProofGenWithNym` |
| 5 | `pseudonym` | bytes(48) | The pseudonym under the presentation's scope |

The scope and the bound message are never carried. The verifier recomputes both from what it knows and fails if the proof does not verify under them.

The BBS `presentation_header` for every proof in a presentation is:

```
ph = "hum/presentation/1" ‖ uint16be(len(scope)) ‖ scope ‖ uint16be(len(bound)) ‖ bound ‖ context (33 bytes, or 33 zero bytes when absent)
```

`ph` is hashed into the BBS challenge, so a proof made for one scope, bound message or context verifies under no other. This is how `issue-map.md`'s bound message and the ballot's commitment to its own body are enforced, with no change to the drafts.

A card proof is about 600 bytes. A presentation is at most 16 KiB; a ballot's is at most 8 KiB (`ballot.md`).

### What is proven

Given the use's policy tree `P` and the accepted set that `trust-list.md` derives for the context version (which verifier authorities are accepted for which attribute, with `minVersion`), a verifier walks `P`:

- `[0]` is satisfied with nothing.
- `[1, children]` requires every child satisfied; children may use different cards.
- `[2, children]` reads the next entry of `branches` and requires that child satisfied. Which child was taken is visible, and because the phone takes the lowest satisfiable child, so is the fact that the person holds no card for any earlier child. For that reason no context policy has an `any` node in draft 0.1 (`context.md` C16, ADR 0100): a verifier rejects a presentation whose policy contains one (P6), and `branches` is always the empty array. The node and the field stay in the format for a later draft that hides the branch.
- `[3, source, name, pred]` requires a card proof whose `issuer` is accepted by `source` for `name` at the verifier version in force, whose `kid` is the key of the card's epoch, or any key listed in that version's `issuerKeys` (not in `retiredKids`) for a card of an earlier epoch, whose key's `since` (read from the version in force) is at least the row's `minVersion` (`trust-list.md` step 4; tested under P6), whose `len` is the epoch's, whose `class` is the row's, and whose message for `name` satisfies `pred` as the table below says.
- `[4, authority]`, the **possession leaf**: `authority` is a verifier authority CID (33 bytes) given directly, not through a context's `refs` or `issuers`. It requires a card proof whose `issuer` is that authority, with the same `kid`, `len` and `class` conditions as an attribute leaf, and discloses nothing but index 0 (`epoch`). There is no `minVersion` test: a possession leaf names an authority directly, so no trust-list row supplies one; the only key condition is that `kid` is the key of the card's epoch (or a still-listed key for a card of an earlier epoch). A use that needs to refuse cards issued before a fix sets that in its own manifest (`verifier.md` retires the key), not through this leaf. It exists for policies a use states itself rather than a context manifest: the sponsor row (`[4, the agent-class verifier the sponsor manifest names]`) and each `accepts` alternative of issuance evidence (`[4, accepts[k].authority]`, with that entry's attributes disclosed in addition). Context manifests do not carry it in draft 0.1 (`context.md` C5 knows kinds 0 to 3), so it never appears in a ballot, join, token or authorship presentation.

Which card a phone uses is fixed so a person's presentations do not vary: for a leaf, the satisfying card with the bytewise-smallest `issuer ‖ kid` among the cards the use's epoch rule accepts. Under C16 a leaf's source names one verifier, so the choice is between that verifier's cards and the epoch rule leaves one. (Were `any` allowed, the phone would take the lowest-index satisfiable child.) For a deck, the phone pins the cards it used in its shield entry (`shield.md`) and reuses them for every replacement and round; the ballot window makes any other choice fail anyway, because one person has one card per issuer per epoch. The same card proof may satisfy several leaves. A card proof that satisfies no leaf and discloses nothing a use allows makes the presentation invalid (P6), so a presentation cannot carry a decoy pseudonym.

Each card proof is verified with the pseudonym draft's `ProofVerifyWithNym` under the issuer's key, `header` as in "Message layout", `ph` as above, the disclosed messages at the layout's indexes, and `context_id` = scope. The verifier checks `pseudonym` is the one the proof commits to, derives the nullifier, and checks the disclosed `epoch` against the use's rule in "Validity".

Satisfying a predicate in draft 0.1:

| Predicate | How | What the verifier learns beyond "the leaf holds" |
| --- | --- | --- |
| `[0]` on a bool | Disclose the message; it must be 1 | Nothing: every satisfying card has it |
| `[1, [v]]` with one value | Disclose; it must be `v` | Nothing |
| `[2, lo, lo]` | Disclose; it must be `lo` | Nothing |
| A message disclosed for another reason (an `accepts` list) | The disclosed value meets `pred` | Already disclosed |
| `[4, authority]`, the possession leaf | A card proof from that authority with nothing disclosed beyond index 0 (plus the `accepts` attributes for issuance evidence) | Nothing: holding a valid card from that issuer is the statement |
| `[1, S]` with two or more values; `[2, lo, hi]` with `lo < hi`; `[0]` on an enum, band or uint | **Not satisfiable in draft 0.1.** `context.md` C5 rejects such policies; a phone that meets one anyway refuses to join or vote and says why; an aggregator or log rejects a presentation that claims to satisfy it (P6) | — |

A context that wants "residents of wards 1 to 3" in draft 0.1 uses a single-valued leaf on an attribute the verifier already coarsened, such as the district profile's `area` = Millbrook (`verifier.md`), or a verifier that issues the exact predicate as a bool. An `any` over equality leaves is not available: `context.md` C16 rejects every `any` node in draft 0.1.

### Verification rules

Each rule is phrased so one vector can test it. A verifier runs them in order and stops at the first failure.

| Rule | Check |
| --- | --- |
| P1 | The presentation is canonical CBOR of at most 16 KiB (8 KiB in a ballot) with the fields above and no unknown keys; `creds` has at most 8 entries |
| P2 | `context` is present exactly when the use's row says, and is the version that row names |
| P3 | Every card proof's `issuer` resolves to a logged `verifier` whose lineage is not retired and whose `class` is the use's row's class; `kid` is in that version's `issuerKeys`; `len` equals `L(E)` for the card's disclosed epoch `E`: 2 plus the number of the verifier's attributes with `fromEpoch ≤ E` ("Message layout"). An authority has one `verifier` lineage (`verifier.md` rule 31) |
| P4 | Every BBS proof verifies under that key, `header`, `ph` with the recomputed scope and bound message, and `context_id` = scope; `pseudonym` matches the proof |
| P5 | `disclosed` has index 0 and not index `L − 1`; the disclosed `epoch` satisfies the use's row in "Validity": for ballots and one-time uses, against the verifier's current period (or, in the first hour of a period, the previous period's); for a logged presentation verified after submission, against the object's `issued` and no clock |
| P6 | The policy walk succeeds with the draft 0.1 predicate table: every leaf is satisfied by a card proof the accepted set admits, the policy contains no `any` node and `branches` is empty (draft 0.1, `context.md` C16; a later draft restores "exactly one entry per visited `any` node in walk order"), every leaf's source resolves to exactly one verifier authority (the static test of `context.md` C16 on the pinned trust-list version, nothing else), and every card proof satisfies at least one leaf or discloses something the use allows |
| P7 | Every disclosed message at an attribute index (1 to L − 2) is required by a satisfied leaf or allowed by the use's row; any other disclosure rejects the presentation |
| P8 | Nullifiers are derived for every card proof; the primary nullifier is the designated leaf's card's when the policy has one; all are returned to the use |

"In force" depends on whether the presentation is logged. For a ballot, a join ticket, a token request or issuance evidence it means the latest verifier version the verifying party holds a witnessed log proof for. For a logged presentation (authorship, sponsor proof) it means the verifier version with the highest log index below the index of the object that carries the proof, **in the log of record**; `kid`, the lineage's retired state and the trust-list checks of `trust-list.md` step 4 are all read there (the layout length needs no position; see "Message layout"). Draft 0.1 fixes one log of record so that phones cannot disagree: for an issue-map object it is the first entry of `logs` in the context version the object pins; for a sponsor manifest, which pins no context, it is the log whose inclusion proof the bundle carries: that log made the clock check at submission and the verifier version is read at the manifest's position in it. A context accepts the sponsor manifest when that log is any entry of its `logs`, so `agent-sponsor.md` AS-8 gives the same answer in every context; a sponsor proof has no slot or uniqueness count that would need a single log. An authored object is valid only if it is in its context's log of record, and a log refuses an authored object or sponsor manifest whose issuer's `verifier` lineage is not in its own history. Another listed log may hold the object too; it accepts it, whatever its clock says about `issued`, when the bundle carries an inclusion proof from the log of record, and then applies the later-verifier rule. If the log of record is unreachable for more than an hour the object's `issued` goes stale; the author's phone rebuilds the object with a fresh `issued` and a fresh proof (an unsigned object keeps its slot, because a nullifier that was never logged was never spent). The phone cannot tell an unreachable log from a lost response, so before rebuilding it asks the log of record for the old CID, and if a rebuilt unsigned object is refused for a reused nullifier (`issue-map.md` IM-7) it treats the first one as logged and moves to the next slot. A key removed or a lineage retired after that position does not invalidate the object; one removed before it does. The log applies the same rule at submission, where the two definitions coincide. Issuer status is not re-checked for ballots already accepted (`release.md` R12).

Where the rules run: aggregators on every ballot (`ballot.md`), logs on authorship proofs (`issue-map.md`) and sponsor proofs (`agent-sponsor.md` AS-8) at submission with the clock check, phones and aggregators on the same logged proofs whenever they verify the object, with the logged-presentation row and no clock, greeter phones on join tickets (`chat.md`), token issuers (`storage.md`, `chat.md`), verifier hosts on issuance-evidence presentations, and phones on sponsor proofs they meet in membership events.

### Future: hidden predicates

*Not in draft 0.1 conformance. Described for the outside review and ADR 0022.*

The planned construction proves that a hidden message `m_j` is one of a public set `S` (at most 64 values) without revealing which: a Pedersen commitment `C` to `m_j` under the card's message generator and an independent generator, a linking proof that the committed `m_j` equals the BBS proof's hidden message, and a Cramer–Damgård–Schoenmakers OR-proof over `S` on `C`, with every commitment folded into the BBS challenge the way the pseudonym draft folds its own extension in. Size about `64|S| + 112` bytes per predicate. It would satisfy multi-valued leaves.

Open before it can be specified: the scalar mapping of set values (`messages_to_scalars` over the 8-byte encoding, so `S` must be mapped the same way), the exact derivation of the independent generator, the transcript order, which verifier version's value set the prover used, and a library that exposes the per-message blinding the linking step needs without forking a BBS implementation inside a seam. The review decides whether this or a range-proof system is the path.

## The chat identity

The chat identity is the per-person Ed25519 key in the MLS leaf credential that [`chat.md`](chat.md) §2.1 defines, with one leaf per device bound to it. It signs messages, device bindings and signed issue-map objects (`hum/author/1`). This spec adds nothing to its format and states three facts:

- It is generated on the phone, is never derived from or mixed with a nym secret, an edit root or any card, and never appears in a presentation, a ballot, a receipt or a token request.
- It is not hardware-bound. It must survive the loss of a device, so it is a software key stored encrypted under a hardware-wrapped key at rest and carried in the per-person backup. The per-device MLS leaf keys, the device attestation key and the backup-wrapping key are the ones in secure hardware. The design doc's "keys in the phone's secure hardware" is read this way ([`0023-w0-02-backup-and-voting-device.md`](../decisions/0023-w0-02-backup-and-voting-device.md)).
- Nothing connects it to the other two identities by construction. Two views place it beside a presentation's public fields; see the identifier table for why those fields no longer form a cohort below the issuer.

## Agent sponsor credentials

An agent credential is a card from a verifier whose `class` is `agent` (`verifier.md`), issued to the sponsor's agent through the same issuance flow, with the single attribute `agent-sponsor` (bool). It is shown under the sponsor row of the uses table: scope `hum/sponsor/1 ‖ sponsor authority CID`, bound to `agentKey`, no attribute disclosed, as [`agent-sponsor.md`](agent-sponsor.md) specifies.

No voting policy accepts it: every policy row requires `class` = `person` (P3); `context.md` rule C15 keeps the `agent-sponsor` attribute out of policies; `trust-list.md` yields no vote rows from an agent-class verifier. An agent holds no `person` card because no `person` verifier issues to a sponsor key, and the ballot format has no slot for anything but a policy presentation (`ballot.md` B3).

## Storage and backup

`seam:` key storage and what leaves the phone.

### On the phone

| Secret | Where | Leaves the phone |
| --- | --- | --- |
| MLS leaf keys, device attestation key, backup-wrapping key | Secure hardware (Secure Enclave, StrongBox or TEE-backed keystore) | Never |
| Chat identity key, edit root, cards with their messages and nym secrets, recovery-phrase salt | Encrypted at rest under the backup-wrapping key, in the app's keystore-protected storage | Only inside the sealed backup or the chat-only export below |
| Hands, shield ledger, receipts, card orders, counted-hand selections, group assignments | App storage, encrypted at rest | Never, in draft 0.1 |

A phone MUST NOT write a hand, a shield entry or a receipt to any backup, export, blob store, delivery service or log (invariant 1; `storage.md` §11). Draft 0.1 has no device-to-device transfer of them either; that alternative is filed for the owner in ADR 0023.

A card and its nym secret are deleted from the phone when its epoch has ended **and** no shield entry that pins it is short of `released` or `dropped` (`shield.md`): a card keeps serving the later rounds and extended `closes` of the decks it voted in, and nothing else. Deleted cards are absent from the next backup. The reason for deleting at all is in the identifier table: an authorship nullifier is public forever, and whoever held a card's nym secret could recompute it.

### The sealed backup

The backup exists so a lost phone does not cost a person their chat identity, their edit keys or their cards, which issuer dedup would stop them re-obtaining until the next handover.

- **Contents:** deterministic CBOR `{0: v 1, 1: chat identity private key, 2: edit root, 3: cards [{issuer, kid, len, messages, signature, nym secret}], 4: contexts [{lineage CID, left (time or absent)}], 5: written (time)}` and no other key. A context stays listed after the person leaves it until 365 days after the latest `expires` among that context's decks dealt before they left (read from the public log, never from the shield), because `shield.md`'s restore must count decks of contexts they were in for as long as their entries stay in the window. No hand, shield, receipt, card order or selection.
- **Encryption:** the plaintext is padded and sealed with the sealed-blob format of [`storage.md`](storage.md) §1 (format 1, fresh key), and that key is wrapped with HPKE (RFC 9180, `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `AES-128-GCM`, `info` = `hum/backup/1`) to a key derived from a recovery phrase: 12 words from the BIP-39 English list, `Argon2id` (RFC 9106; `t = 3`, `m = 64 MiB`, `p = 1`, 32-byte output, salt = 16 random bytes stored beside the file) → X25519 private key by clamping. The phone shows the phrase once and stores no copy.
- **Where it goes:** the app's platform-backed-up container (iCloud backup, Android backup). No Hum service receives it, and no CID or locator for it exists in any Hum store or log. A person may also export it as a file.
- **When it is written:** locally, at once, whenever a context is joined, so that `shield.md`'s restore can never miss a context the person voted in; a phone does not send its first round-0 ballot in a context until a backup listing that context has been written locally. Every other change (a leave, a new card, a key rotation) is folded into a daily write at a time the phone picks at random within the day. The platform uploads the file on its own schedule, which the spec cannot control: a phone lost between the local write and the upload restores an older list, and that residual is accepted. The platform's write times are therefore the join times plus the daily writes; padding buckets still show roughly how many cards and contexts a person has.
- **Restore:** the person installs the app, the platform restores the file, they enter the phrase. The phone decrypts, re-adds its new device to its MLS groups as `chat.md` §2.3 describes, and rebuilds the shield conservatively as `shield.md` "Restore" defines. Hands of open decks are gone; the person re-sorts, and `ballot.md`'s replacement rule makes that harmless. Receipts are gone; past releases can no longer be checked from this device.
- **Chat-only export.** A second device that will only chat receives `{0: v 1, 1: chat identity private key, 2: edit root}` and nothing else, sealed the same way to a one-time key shown as a QR code by the existing device. It carries no card, so it cannot become a voting device by accident (`chat.md` §2.3).

### One voting device

A person's cards and shield live on exactly one device at a time, the voting device. Other devices chat (through the chat-only export) and hold no card. A restore makes the restoring device the voting device. The reason is the shield: two devices voting independently would each charge only what it sent, and no channel may carry a shield between them.

The residual risk, a person who restores the full backup onto a second phone while keeping the first, is a floor an unmodified app can exceed. The owner accepted it for draft 0.1 on 2026-10-08, to be disclosed and not prevented: [`0023-w0-02-backup-and-voting-device.md`](../decisions/0023-w0-02-backup-and-voting-device.md): the duplicate-nullifier rule means it cannot produce a second counted ballot in one deck, but the two ledgers together can spend up to twice one shield across different decks.

## Every identifier, where it lives, who sees it

This table is what reviewers check. "Holds" means stores it; "visible to" means can read the value.

| Identifier | Produced by | Holds | Visible to | Links to |
| --- | --- | --- | --- | --- |
| Nym secret | Phone, with the signer's share | Phone, sealed backup; deleted when the epoch has ended and every pinned deck is final | Nobody | Every pseudonym of this card; nothing else |
| Card (signature + messages) | Issuer and phone | Phone, sealed backup | Nobody after issuance | Its own presentations only through zero-knowledge proofs |
| **Public card fields:** issuer authority, `kid`, `len`, `epoch` | Verifier manifest, issuer | In every presentation | Every presentation verifier | At any moment every valid card from one issuer has the same `kid`, `len` and `epoch`, so these four fields identify the issuer and nothing finer: the anonymity set is the issuer's whole set of current holders. `context.md` C16 fixes one issuer per policy leaf and forbids `any`, so within a context the issuers, their order and the number of cards are the same for every member and every use of one policy. **What remains:** for one hour at an epoch boundary two adjacent epoch values coexist on join, token and authorship presentations (not on ballots, whose epoch is fixed by the deck), so a presentation with the old value in that hour shows its holder had not yet switched cards; and two context versions with different policies show different fields, which says only which version a presentation was made against. A verifier that compares presentations across epochs sees only that both were from that issuer |
| `branches` | Phone | In a presentation | Its verifier | Always empty in draft 0.1 (`context.md` C16). With `any` nodes it would show which child was taken and that no earlier child was satisfiable, a cohort the size of that branch's population, which is why they are refused |
| Public card fields beside the chat identity | Phone | A signed issue-map object's bundle, in logs, permanently; a join ticket, on the greeter's phone, transiently | Anyone, for a signed object; the greeter, for a ticket | Joins the chat name to "a member of this context", and nothing finer: under `context.md` C16 every member's `entry` presentation shows the same issuers, and every ballot of the context shows the same issuers too. The fields therefore cannot pair a chat name with a ballot or with an unsigned object. The exception is the one-hour boundary residual in the row above |
| Attribute values | Issuer | Phone | Nobody, unless disclosed: single-valued predicates reveal nothing new; `accepts` disclosures go to a host that will issue on them | — |
| Pseudonym and nullifier under `hum/ballot/1` | Phone | Aggregator, per deck, until the final version plus 24 hours (`services.md` AG-5); one per card in the presentation | Aggregator (phase 1 beside the votes; phase 2 beside shares) | Nothing outside the deck |
| Nullifiers under `hum/join/1`, one per card in the `entry` proof | Phone | The organizers group, in `join-record` messages, all of them in one record, for as long as the chat identity is a member and at most 396 days | Organizers and moderators | One card to one chat identity in one context for one epoch, inside the organizers group only. This is the one place a card-derived value sits beside a chat identity by design; it is per context, never leaves the group, and is unlinkable to every ballot nullifier |
| Nullifiers under `hum/blob-tokens/1`, `hum/delivery-tokens/1` | Phone | Token issuers, per day | Token issuers | A day's token issuances; nothing across days |
| Nullifiers under `hum/author-once/1`, `hum/author-slot/1` | Phone | Logs, permanently, in bundles | Anyone | One object or one slot; nothing across them (`issue-map.md`). Anyone who later obtains a card's nym secret (the backup and phrase) can recompute them and unmask the person's unsigned objects under that card, which is why expired cards are deleted |
| Nullifier under `hum/sponsor/1` | Agent | Logs, in sponsor bundles | Anyone | One sponsor authority |
| Nullifier under `hum/issuance/1` | Phone | The asking verifier's host, as a keyed hash, with its dedup row | That host | Two issuance attempts at that host |
| Chat identity key | Phone | Phone, sealed backup, chat-only export; MLS trees of the person's groups | Group members; anyone, when it signs an issue-map object | The person's chat name, devices and signed objects |
| Device leaf keys and device ID | Phone | MLS groups | Group members | One device |
| Edit root and edit keys | Phone | Phone, sealed backup, chat-only export; edit public keys in logged objects | Anyone sees edit public keys | Versions of one object; nothing across objects |
| Receipt nonce and leaf | Phone | Phone; the leaf in the public receipt pages | Anyone sees leaves; only the phone knows its own | Nothing (`ballot.md`) |
| Hand, card order, counted-hand selection, group | Phone | Phone only | Nobody | — |
| Shield ledger | Phone | Phone only | Nobody | — |
| Dedup row (`lastEpoch`, request hash) | Verifier host | Host, under a keyed hash, until 30 days after `lastEpoch` ends | Host | Issuance attempts at that host; never a context |
| Recovery phrase | Phone, once | The person | The person | The backup |
| Backup file | Phone | Platform backup | The platform holds ciphertext | Nothing without the phrase; with it, everything above the line |

What never exists outside the person's own phone and their own sealed backup: any object holding a nym secret beside a chat identity key; any pseudonym under a scope that spans two contexts; any store, service or log row that holds a hand, a shield entry or a receipt.

## Security considerations

| Threat | Mitigation |
| --- | --- |
| The issuer links a card to a later vote | Blind issuance of the nym secret; proofs are zero-knowledge in the signature; the one scope the issuer sees is distinct from every context scope |
| Two contexts, or two decks, link a person | Pseudonyms are per scope and unlinkable under DDH; the ballot scope is per deck; public card fields identify only the issuer |
| A presentation is lifted onto another ballot, object, ticket or request | `ph` binds scope, bound message and context version; every use has a bound message |
| A person votes twice in a deck | Every nullifier new per deck; one card per issuer per epoch per dedup key; the ballot window pins the epoch of the deck's original `closes`, which no extension moves |
| Two people pool cards under an `all` | Every card's nullifier counts and must be new for the deck, so a lent card is spent for its owner |
| Renewal or re-enrolment yields a second valid card | No evidence-free renewal; the dedup row records the newest epoch and outlives every card under it; handover issues only the next epoch |
| A card outlives its dedup record | A card dies at its epoch's end; the row lives 30 days longer |
| A credential from an agent-class verifier reaches a ballot | P3 per use, C15, trust-list classes, no ballot slot for anything else |
| The disclosed epoch, `kid` or `len` narrows a person | All three are equal across an issuer's valid cards; key rotation and attribute appends take effect at epoch boundaries |
| A quantum adversary links pseudonyms across scopes | The pseudonym draft's §9.1 promises unlinkability against a cryptographically relevant quantum computer only while a prover uses fewer distinct `context_id`s than the nym-secret vector is long. Hum uses `N` = 1 and one scope per deck, token day, join and object, so that promise does not apply; today's unlinkability rests on DDH in G1. The draft marks its own proof as to-do. Recorded for the outside review (ADR 0022); the design is unchanged because the same gap applies to every pairing-based credential system and a card lives one epoch, bounding the exposure window |
| A back-dated or forward-dated `issued` on a logged proof | The log of record checks `issued` against its own clock at submission, within 3,600 seconds. Nothing else bounds it: the author chooses `issued`, witnesses check consistency and never times, and later verifiers have no clock. A log of record that skips the check admits a proof from an expired card for as long as its `kid` stays in `issuerKeys` (the epoch plus `KEY_TAIL`, 520 days, in `verifier.md`), and unlimited unsigned slots by back-dating into old windows. This is wider than the one-hour grace and is a stated trust in that one log (`docs/threat-model.md`, assumptions). An option that bounds forward-dating with cosignature timestamps is filed in ADR 0101 and not specified |
| The issuer, the policy branch or the number of cards narrows a member within a context, beside a vote or a chat name | `context.md` C16: one verifier per policy leaf and no `any` node in draft 0.1, so all three are the same for every member (ADR 0100). Residual: two epoch values for one hour at a boundary on non-ballot uses |
| A host marks a card | The phone checks `kid` is the epoch's key, `epoch` current or next-in-handover, values declared, unapproved attributes absent; the signer's nym share is a deterministic function of the request |
| A TLS terminator reads issuance traffic | Request HPKE-sealed to the host key; response sealed in the same context (RFC 9180 §9.8) |
| A lost issuance response | Identical retry yields the identical response; a different request against a spent row is refused |
| The phrase-derived backup key is brute-forced | Argon2id at 64 MiB and 12 words; the file must also be obtained |
| A stolen phone | Keys at rest under a hardware-wrapped key; cards expire at the epoch's end; the ledger is useless to a thief; other devices can remove the stolen device's leaves |
| Clock manipulation | The prover carries no clock; a verifier uses its own period, with a one-hour grace |
| Backup write times reveal activity | Joins are visible as writes (accepted, since the join commit is visible to the delivery service at the same time anyway); everything else is in daily writes at a random time |

## Vectors (for W0-08)

Directory `vectors/credentials/`. Use the BBS, blind-signature and pseudonym drafts' own test vectors for the primitives; generate the rest from fixed keys and seeds. Predicate vectors are not generated in draft 0.1.

Valid:

- `cred-issue-district`: the issuance request and response plaintexts and their sealed bytes under fixed HPKE randomness, the `CommitWithNym`, `BlindSignWithNym` and `VerifyFinalizeWithNym` inputs and outputs with the message vector in layout order (epoch, attributes, nym secret last), the completed card, one absent attribute, the phone's checks passing; the primitive-level values come from the drafts' own fixtures where they exist; `cred-issue-handover`: a first session in handover issuing two cards (`E_now`, `E_now + 1`); `cred-issue-renewal`: a session with `lastEpoch = E_now` in handover issuing one `E_now + 1` card; `cred-issue-retry`: the identical request resubmitted and the identical response returned.
- `cred-present-ballot-two-cards`: an effective voting policy `area = 1` and `unique`, scope `hum/ballot/1 ‖ deck lineage`, bound message from `ballot.md`, both pseudonyms and nullifiers, the primary from `unique`, both `epoch`s equal to the epoch of the deck's version-1 `closes`.
- `cred-present-entry-one-cell`: an `entry` of `area = 1` from a trust list with one verifier for `area`; `branches` = `[]`; two members' presentations with identical public fields.
- One valid presentation per row of the uses table, with the scope bytes and bound message spelled out: `cred-present-join`, `-blob-token`, `-delivery-token`, `-author-once`, `-author-slot`, `-sponsor` (an agent-class card), `-issuance`.
- `cred-epoch-edges`: a card accepted in the first and last period of its epoch, refused one period before and after; a ballot window for a deck whose version-1 `closes` is in the next epoch, refusing the current card and accepting the post-dated one once started; the first-hour grace; an extended deck (`closes` moved into the next epoch) still accepting only the original epoch's card.
- `cred-nullifier-derive`: pseudonym octets in, nullifier out, for three scopes; the same nym secret under two scopes yielding unrelated nullifiers.
- `cred-backup-roundtrip`: a backup plaintext with a left context, phrase, salt, HPKE wrap and sealed blob with fixed randomness; the chat-only export.

Invalid, one per rule, named `cred-invalid-<rule>-<case>`:

- P1: 17 KiB; 9 KiB in a ballot; unknown key; nine card proofs.
- P2: ballot presentation with `context` absent; against a version the deck does not pin; a sponsor presentation with `context` present.
- P3: a retired lineage; an agent-class card in a ballot; a person-class card in a sponsor proof; `kid` in `retiredKids`; `len` of the wrong epoch; a card of an earlier epoch under a key that is still listed but is no longer the current epoch's key, accepted (valid); a new card under a key that is not its epoch's key (rejected).
- P4: a proof under another scope; under another bound message; under another context; a `pseudonym` not matching.
- P5 (logged): an authorship proof verified two epochs after its `issued` (valid); one whose disclosed epoch is not that of `issued` (rejected); `issued` 90 minutes after an epoch boundary with the old epoch (valid) and three hours after (rejected); at the log, `issued` two hours behind the log's clock (rejected).
- P3 (logged): a `kid` removed from `issuerKeys` at a log index above the object's (valid) and below it (rejected); an attribute appended mid-epoch with `fromEpoch` = the next epoch, then an object logged after it in the old epoch carrying the old `len` (valid); the same object with the new `len` (rejected).
- Log of record: an object present only in a context's second log (invalid); an object whose issuer's verifier lineage is absent from the log of record (refused at submission); a second log accepting an object with a three-hour-old `issued` because the bundle proves inclusion in the log of record (valid).
- P5 (logged) edges, with `B` an epoch boundary. At the log, clock `T`: old epoch at `T = B + 1800` (accepted) and `T = B + 3660` (rejected); `issued = T + 7200` (rejected); `issued = T + 3600` (accepted). For a later verifier: old epoch at `issued = B + 7199` (accepted) and `B + 7200` (rejected); new epoch at `issued = B − 3600` (accepted) and `B − 3601` (rejected).
- Issuance evidence: `accepts` with two entries, the phone holding a card for the second only, presenting one card (valid); two cards, one per entry (rejected).
- P5: index 0 missing; index `L − 1` disclosed; `epoch` one too low; one too high outside the grace; a ballot card of the epoch after the original `closes`; a post-dated card before its epoch starts.
- P6: a leaf with no satisfying card; `cred-invalid-P6-minversion` (`trust-list.md` step 4, attribute leaves only): a card whose key's `since` is below the row's `minVersion`; `cred-valid-P6-possession-no-minversion`: a sponsor presentation whose card's key has a low `since`, accepted because kind 4 has no `minVersion` test; `cred-invalid-P6-possession-issuer`: a sponsor presentation whose card is from a verifier other than the sponsor manifest's; `branches` non-empty; a presentation against a policy `any(approved, area = 1)` with `branches` = `[0]` (was valid before C16); a card from a second verifier that the leaf's trust list also accepts (two authorities for one leaf); a card proof that satisfies nothing; a presentation claiming a two-valued set leaf; a pooled presentation (two cards, one from a second person) which verifies here and is rejected by `ballot.md` B3 when its second nullifier is already in the deck.
- P7: a gate attribute disclosed under a ballot.
- P8: a primary nullifier taken from the wrong card.
- Issuance: a response the phone must refuse, one each for a `kid` that is not the epoch's key, an `epoch` of `E_now + 1` outside handover, `E_now − 1`, a value outside the declared set, an unapproved attribute present, a signature that fails; host side: a fresh session with the same dedup key one period after the epoch-1 card was issued (refused); a session in handover against `lastEpoch = E_now + 1` (refused); a different request against a spent row (refused).
- Backup: wrong phrase; tampered ciphertext; a plaintext with an unknown key; a plaintext carrying a `hand` key, which the reference writer must refuse to produce.

Plus the "agents never vote" vector, which lives in `ballot.md`.

## Open questions

Filed in `docs/decisions/`:

- **BBS with pseudonyms over Semaphore** ([`0020-w0-02-pseudonyms-bbs-not-semaphore.md`](../decisions/0020-w0-02-pseudonyms-bbs-not-semaphore.md)).
- **Per-deck nullifier** ([`0021-w0-02-per-deck-nullifier.md`](../decisions/0021-w0-02-per-deck-nullifier.md)); the design doc's "per-context pseudonym" and "Semaphore-style" wording is the owner's to change.
- **Hidden predicates** ([`0022-w0-02-predicate-proofs.md`](../decisions/0022-w0-02-predicate-proofs.md)): not in 0.1; multi-valued leaves unsatisfiable; the review chooses the path.
- **Backup and one voting device** ([`0023-w0-02-backup-and-voting-device.md`](../decisions/0023-w0-02-backup-and-voting-device.md)): no transfer of hand or shield off the phone in 0.1; the two-phone residual risk was accepted by the owner on 2026-10-08 (accept and disclose); the alternatives stay filed.
- **Epochs, renewal with evidence, and the ballot window** ([`0026-w0-02-renewal-and-ballot-window.md`](../decisions/0026-w0-02-renewal-and-ballot-window.md)): cards live one epoch; renewal is a session with evidence in handover; the alternative (evidence-free renewal with a stable nym secret) is for the review. The cost that a deck straddling an issuer's epoch boundary counts only cards of the later epoch, so members wait until their next card has started.
- **`any` nodes and several issuers per leaf** are refused in draft 0.1 (`context.md` C16, ADR 0100). A CDS proof over the whole formula would hide the branch, and a proof under one of a set of issuer keys would hide the issuer. Both go to the outside review with the predicate question.
- **Device-bound cards:** would stop a backup being used on two phones, at the cost of making every phone loss a re-enrolment that dedup blocks until the next handover. Owner's call with the identity decisions.
- **One chat identity per card per epoch:** a new card each epoch means a member could register a second chat identity in the next epoch; `chat.md`'s rule and open question 16.
- **Phase-2 admission:** forwarding the presentation to the Helper would let both aggregators check membership, at the cost of the Helper seeing nullifiers (`ballot.md`).

Assumptions about sibling specs, checked against the drafts on disk on 2026-10-06, and the changes this revision asks of them:

- `context.md`: C5 selective-disclosure rule and the `any`-of-equality rule, `area = 1` example, every-nullifier wording, per-deck wording. Confirmed on disk.
- `verifier.md`, `verifier-runtime.md`: epochs, handover, the dedup row with `lastEpoch` and request hash, the host's epoch-issuing rule, the deterministic nym share, key-to-epoch alignment, layout at handover start, disclosed-epoch wording: confirmed on disk. Second re-review items confirmed on disk: rule 14 (a non-empty `dedup` has an item whose method is not `credential`); issuer keys carry `fromEpoch` and the key-of-epoch rule replaces `status`; rows store `lastEpoch`, `kid` and the request hash, a removed `kid` counts as no row, and the largest `lastEpoch` governs across rows; `validity` frozen (rule 21); same-artefact renewal in the profile notes.
- `services.md`: issue body with `commits` and a `cards` array, reissue withdrawn, `hum/nym-share/1`, nullifier wording, revocation endpoint: confirmed on disk. Asked now: `kid` per card in the `cards` array. Later-round ballots carry a presentation every round in phase 1 (intake check 4); a receipt-only authorization for rounds 1 to 3 would let a phone drop its card at the epoch's end, and is noted as a possible simplification, not specified.
- `issue-map.md`: author screen text landed. Asked: say that unsigned objects are linkable to each other as "same issuer, same branch" and name the disclosed `epoch` as equal across all valid cards.
- `chat.md`: join scope, bound message and `join-record` confirmed on disk. Asked: note that the one-identity rule holds per epoch because every card is new each epoch.
- `storage.md`: scope and the sealed-blob format reused. P2 defers to §6.2's "latest version" rule.
- `agent-sponsor.md`: sponsor row as confirmed; the log runs P1–P8 for AS-8.
- `deck.md`, `release.md`: the ballot window uses `closes` of the deck lineage's version 1; `ballot.md` B2 says so.
