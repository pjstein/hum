# Hum Chat Spec — Draft 0.1

Oct 6, 2026 · W0-05 · `seam:` domain-separation strings, exporter labels, franking, the admission flow, what leaves the phone

## Scope

This spec defines Hum's chat profile on MLS: how channels map to MLS groups, who may do what in them, the bytes of every message Hum adds on top of the MIMI content format, how a person admitted to a context gets into its groups, how history reaches newcomers, how moderation works without reading everything, and the delivery service that queues ciphertext. It also fixes, in one table, what that service can learn.

It builds on:

- MLS, [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html), for groups, keys and framing.
- The MLS architecture, [RFC 9750](https://www.rfc-editor.org/rfc/rfc9750.html), for the split between an Authentication Service and a Delivery Service, for a Delivery Service that does not validate what it carries, and for groups of thousands.
- The MIMI content format, [draft-ietf-mimi-content](https://datatracker.ietf.org/doc/draft-ietf-mimi-content/), for text, replies, reactions, edits, deletes and external attachments. This draft pins version 09 (July 2026). Version 09 changed no bytes Hum uses relative to 08: its content-relevant change is a clarification that the message-ID URI lengths count octets. A later draft version is adopted by a decision, not silently.
- `manifest.md` for CBOR encoding, CIDs, signatures, logs and the sealed blob format.
- `storage.md` for the sealed reference bytes, the keyring, folder state rules and the blob store. This spec frames how those travel in MLS messages and defines nothing twice.
- `context.md` for the `chat` field of the context manifest (`allMembers`, `organizers`, `delivery`), the roles, and the `storage.history` and `storage.keyringHistory` settings.
- `services.md` for the `service` manifest a delivery service publishes, the OHTTP relay, the common error format and the token rules.
- `issue-map.md` and `agent-sponsor.md` for what a promotion produces and what an agent may do.

Out of scope: voice channels and push notification transport. Both are listed under open questions.

Requirements, each traceable to `docs/design.md`:

1. Only members' phones read messages, files, reactions and the issue map's drafts. Every channel is its own MLS group and keys change on every join and leave.
2. The delivery service sees that an encrypted message arrived for a channel, when, and roughly how big it was. It never sees content, the sender, or the member list.
3. The chat name signs what you say. Nothing in this spec links it to the resident card or the voting pseudonym.
4. Any message can be promoted to the issue map, and only its author can confirm that.
5. Decks and releases post back into the channel they came from, and phones verify them against manifests before showing numbers.
6. Reports carry proof a message was really sent, including its attachments.
7. Each device and each shared agent is a visible member. Adding a shared agent is a membership event everyone sees.
8. Search runs on the phone. Nothing about it leaves.

## At a glance

| Thing | Is | Carried in |
| --- | --- | --- |
| All-members group | One MLS group every member device is in. Carries the keyring, roles, the channel directory, log checkpoints, token-key gossip and join requests. No user text. | `chat.allMembers` in the context manifest |
| Organizers group | One MLS group of organizers and moderators. Reports and the greeting key land here. | `chat.organizers` in the context manifest |
| Channel | One MLS group. Kinds: text, issue, folder. | The channel directory, inside the all-members group |
| Device | One MLS leaf per device per group, with the person's chat identity in its credential | KeyPackages as sealed blobs; Welcome through the delivery service |
| Shared agent | One MLS leaf, credential kind `agent`, whose leaf key is the sponsor manifest's `agentKey` | Same as a device, plus a visible `agent-membership` message |
| Message | An MLS `PrivateMessage` whose plaintext is one MIMI content object | Delivery service queue, 30 days |
| Attachment | A sealed blob in storage; its reference rides as a MIMI `ExternalPart` | Blob store, long-term |
| History archive | A sealed blob of authenticated message records | Blob store; its reference is sent to each newcomer |
| Join ticket | A joiner's KeyPackage handles, sealed to the context's greeting key | The delivery service's per-context join inbox |
| Report | The decrypted authenticated message with what a moderator needs to verify it | The organizers group |

## Terms

- **Chat identity key.** One Ed25519 key per person. It is a software key carried in the per-person sealed backup that `credentials.md` defines (ADR 0023), never in a Hum service; the per-device leaf keys it binds live in secure hardware. It signs device bindings and, per `issue-map.md`, signed issue-map objects. Its hash is the person's safety code. It is the "chat name" key in `docs/design.md`. It is one key across every context the person is in (section 15 says what that reveals).
- **Leaf key.** The per-device MLS signature key. Credentials bind a leaf key to a chat identity key. A device may use one leaf key in several groups. For an agent the leaf key is the `agentKey` itself.
- **Delivery service (DS).** The reference network's queue for MLS messages. It plays the Delivery Service role of RFC 9750 and nothing more: it sequences ciphertext, it validates none of it, and it keeps no member list.
- **Delivery secret.** A per-epoch secret exported from an MLS group. Knowing it is how a device proves to the DS that it belongs to a channel, without saying which member it is.
- **Greeting key.** A per-context X25519 key. Its public half is in the context manifest; its private half is held by the organizers group. Join tickets are sealed to it.
- **Franking tag.** A keyed commitment to a message's plaintext that travels in the clear, so a report can later be opened and checked.
- **Stamp.** The DS's signature over a message's channel, sequence number, arrival time and franking tag.

### Domain strings and labels

Every string this spec uses for domain separation, in one place. Every string, the two MLS exporter labels included, is namespaced under `hum/` (ADR 0105).

| String | Kind | Used in |
| --- | --- | --- |
| `hum/keyring/1` | MLS exporter label | Section 1.2 |
| `hum/delivery/1` | MLS exporter label | Section 1.2 |
| `hum/delivery-tokens/1` | Membership proof scope | Section 12.3 |
| `hum/device/1` | Signature payload prefix | Section 2.1 |
| `hum/safety/1` | Hash prefix | Section 2.2 |
| `hum/chat-roles/1` | Signature payload prefix | Section 5.8 |
| `hum/frank/1` | HMAC payload prefix | Section 11.1 |
| `hum/stamp/1` | Signature payload prefix | Section 12.6 |
| `hum/commit/1` | HMAC payload prefix | Section 12.6 |
| `hum/token-request/1` | HMAC payload prefix | Section 12.5 |
| `hum/pp-issuer/1` | HKDF info prefix | Section 12.5 |
| `hum/welcome/1` | Hash prefix | Section 12.6 |
| `hum/join/1` | Membership proof scope | Section 2.5 |
| `hum/join-ticket/1` | HPKE info | Section 2.5 |
| `hum/attest/1` | Hash prefix | `agent-sponsor.md`; checked in section 2.1 step 3 |

## 1. Groups

### 1.1 MLS profile

Every Hum group uses the same profile. Phones MUST reject a Welcome or GroupInfo that deviates from it.

| Parameter | Value |
| --- | --- |
| Ciphersuite | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001). It matches the Ed25519 signatures and SHA-256 CIDs in `manifest.md`. |
| Protocol version | `mls10` |
| Credential type | `basic` (0x0001), with the identity bytes defined in section 2.1 |
| Wire formats on the delivery service | `mls_private_message` for application messages, proposals and commits; `mls_welcome` for Welcome. `mls_public_message` and `mls_group_info` are never sent to the DS. |
| External commits | Not used in draft 0.1. Every join is an Add by an existing member (section 13 says why). |
| Group ID | 32 bytes from a cryptographic random source, as `context.md` also states |
| KeyPackage and LeafNode lifetime | 90 days. `not_after` beyond 90 days is rejected. |
| Required capabilities | None beyond the ciphersuite and credential type above |
| GroupInfo extension `hum_tree_ref` (0xF001) | A sealed reference (direct form, `storage.md` §3) to a snapshot of the ratchet tree. Present when `ratchet_tree` is omitted from GroupInfo (section 13). |
| Padding | Section 4.3 |

Extension type 0xF001 is in the private-use range of the MLS Extension Types registry. Registering a public value is an open question.

### 1.2 Exporter labels

Hum derives two kinds of secret with `MLS-Exporter(label, context, length)` from RFC 9420 §8.5.

| Label | Context | Length | Group | Use |
| --- | --- | --- | --- | --- |
| `hum/keyring/1` | empty | 16 | All-members group only | Keyring epoch secret `k`, exported once, at the commit that creates keyring epoch `k`, exactly as `storage.md` §4.1 defines. It is HKDF input, never an AES key. |
| `hum/delivery/1` | empty | 32 | Every group | The delivery secret the DS accepts for commits and token issuance (section 12), exported at every MLS epoch |

Keyring epochs are not MLS epochs. The keyring advances only on a commit to the all-members group that removes at least one leaf (`storage.md` §4.1); a phone runs the `hum/keyring/1` export only while processing such a commit, and never at other epochs. The delivery secret, by contrast, is exported at every MLS epoch of every group. These are the only two exporter labels in Hum; `context.md` derives its members-only results key from the keyring epoch secret by HKDF, not by a third export.

### 1.3 The all-members group

Every context has one all-members group, named by `chat.allMembers` in the context manifest. Every member device MUST be a leaf of it. It carries only control content: `roles`, `directory`, `checkpoint`, `token-key`, `join-request`, `keyring-share` and `agent-membership` for context-wide agents. Phones never render user text from it and MUST drop any `text/*` part received in it.

After any commit that adds leaves to the all-members group, the committing device MUST send, in the new epoch and in this order: a `keyring-share` as `storage.md` §4.2 defines (which epochs it carries follows `storage.keyringHistory`), a `directory` snapshot (section 5.9), and, if `storage.history` allows, a `history-offer` for each channel the newcomer is also being added to (section 10).

A device removed from the all-members group loses the keyring and MUST be removed from every channel. The committer of the removal does this; if it cannot reach some channels, any device with the `members` capability that observes the removal removes the stale leaves from the channels it is in. Phones treat a channel leaf whose chat identity key is no longer in the all-members group as removed for display, even before the channel commit lands. Only a member of a group can commit to it, so every channel MUST contain at least one device of an organizer or moderator; a `channels` holder creating a channel adds one, and a phone that sees the last such device leave a channel warns the organizers group.

### 1.4 The organizers group

Named by `chat.organizers` in the context manifest. Its members are the devices of everyone holding the organizer or moderator role (section 3), plus any shared agent granted `greeter`. It is the one place reports land (section 11), it holds the greeting private key (section 2.5), and it is the group whose membership `context.md` means by "a chat credential the organizers group marks as moderator". It is also an ordinary channel for organizers to talk in. It is never archived or deleted while the context lives.

### 1.5 Channels

A channel is one MLS group plus one entry in the channel directory. The directory lives inside the all-members group as `directory` messages (section 5.9), so nobody outside the context can read channel names, kinds or group IDs.

| Kind | Code | Meaning |
| --- | --- | --- |
| text | 1 | An ordinary channel such as `#general` |
| issue | 2 | Tied to one issue lineage; the channel header shows the issue and its map counts |
| folder | 3 | Its messages are file operations (section 5.7), with state rules in `storage.md` §5 |

Lifecycle:

- **Create.** A device with the `channels` capability creates the MLS group, registers it with the DS (section 12.4) and receives the channel's token issuer key, then sends a `directory` message with op `create` carrying that key. Phones that receive a `directory` entry for a group they are not in show the channel as joinable; joining is a `join-request` (section 5.11).
- **Archive.** A `directory` op `archive`. The group stays readable. Phones MUST refuse to send into an archived channel, and the DS keeps serving fetches until the retention window ends.
- **Delete.** A `directory` op `delete`. Phones delete local group state after 7 days, and the context issues deletion orders for the channel's attachments and archives under `storage.md` §8. The DS drops the queue on the next retention sweep. Ciphertext already fetched cannot be recalled; the spec says so and the UI does too.

Every channel group's members MUST be a subset of the all-members group's members, checked by chat identity key.

## 2. Identity, credentials, devices and admission

### 2.1 The credential

Each leaf carries an MLS `basic` credential whose `identity` is the deterministic CBOR map below (encoding rules from `manifest.md`), at most 512 bytes. It carries the chat name and nothing that could tie it to a resident card or a voting pseudonym. Because every handshake message is a `PrivateMessage` and every tree snapshot is sealed, this credential never reaches the DS or the blob store in the clear.

| Key | Field | Type | Meaning |
| --- | --- | --- | --- |
| 0 | v | uint | 1 |
| 1 | kind | uint | 1 human, 2 agent |
| 2 | identity | bstr(32) | Ed25519 public key: the chat identity key for a human; the `agentKey` from the sponsor manifest for an agent |
| 3 | device | bstr(8) | Random device ID, fixed for the device's life. For an agent, an instance ID. |
| 4 | name | tstr | Display name, 1 to 256 bytes of UTF-8, no control characters. For an agent, the sponsor manifest's `label`. |
| 5 | binding | bstr(64) | Ed25519 signature by `identity` over `hum/device/1` ‖ leaf signature public key ‖ `device` ‖ byte(`kind`) |
| 6 | sponsor | CID | Kind 2 only: the `agent-sponsor` manifest version |
| 7 | sponsor_lineage | CID | Kind 2 only: the `agent-sponsor` lineage (its version 1 CID) |

The binding does not name a group, so a device may present the same leaf key and binding in every group it is in.

Validation, run on every LeafNode a phone sees (Add, Update, Welcome, tree snapshot):

1. The map decodes, re-encodes to the same bytes, and has exactly the keys its kind allows.
2. `binding` verifies under `identity` over the leaf node's `signature_key`.
3. For kind 2: the leaf node's `signature_key` equals `identity`, as `agent-sponsor.md` requires; `sponsor` resolves to a logged, unexpired `agent-sponsor` manifest in lineage `sponsor_lineage`, whose `agentKey` equals `identity` and whose `tier` is `shared`; the latest logged version of `sponsor_lineage` is not `retired`, so a sponsor that retires at version 3 also ends a leaf naming version 2; `name` equals its `label`; and the commit passes the rules in `agent-sponsor.md`, "The membership event" (runtime `enclave` needs the attestation and report, with the report data bound to `SHA-256("hum/attest/1" ‖ agentKey ‖ sponsor authority CID)` as that spec's rule AS-2b defines; runtime `member-hardware` needs a committer with the `agents` capability; the context admits the sponsor). The retirement check is repeated whenever a phone learns of a new version in the lineage, and a leaf whose sponsor lineage has retired is treated as removed at the next commit, as `agent-sponsor.md` says for expiry. A phone that cannot resolve the sponsor bundle yet holds the commit as pending, fetches the bundle through the relay by the CID in the credential, and decides when it arrives; it neither applies nor rejects while pending.
4. `name` is within size and character limits.

A phone MUST reject a commit whose Add or Update fails these checks. All honest members apply the same rule, so they stay on the same epoch.

The display name is self-asserted. Two members may claim the same name. Phones show the first 8 characters of the safety code next to a name whenever two leaves in the same group share one. A per-context handle registry is an open question.

### 2.2 Safety code

`code = SHA-512("hum/safety/1" ‖ chat identity key)`, 64 bytes. SHA-512 is used because the code needs 60 bytes of digest and SHA-256 gives 32. The safety code is 12 groups of 5 decimal digits; group `i` (0 to 11) is the big-endian integer of `code[5i .. 5i+5]` modulo 100000, zero-padded to 5 digits. Two people compare it in person. A changed code means a new chat identity key, which the app says in plain words.

### 2.3 Devices

- **Adding a device.** The new device generates a leaf key and a chat-identity-signed binding, publishes KeyPackages as sealed blobs (section 2.4), and shows a QR code holding one KeyPackage handle. The existing device scans it and commits an Add to the all-members group with it. Once in, the new device publishes more KeyPackages and sends a `join-request` for each channel the person is in, which the existing device answers with one Add per channel; it may add the device to channels it lacks `join-open` for because the self-removal rule below has a mirror: a device may add a leaf that shares its own chat identity key to any group it is in. The chat identity private key reaches the new device through the chat-only export that `credentials.md` defines: `{v, chat identity private key, edit root}` sealed to a one-time key the existing device shows as a QR code. The export carries no resident card, so a chat-only device cannot become a voting device by accident. The full sealed backup is for restoring a lost phone, and draft 0.1 has no device-to-device transfer of a hand, shield or receipts.
- **Removing a device.** Any device with the same chat identity key, or any device with the `members` capability, commits a Remove. Phones MUST accept a Remove of a leaf whose credential shares the committer's chat identity key regardless of role.
- **Chat on every device, voting on one.** Every device chats. Voting credentials and the shield live on one voting device (`credentials.md`); other devices chat only, and only restoring the full backup onto a replacement phone moves that role. Nothing in chat marks which device votes.
- **What a new device reads.** Messages from its join epoch onward. Earlier messages only through a history archive (section 10) under the context's history policy. There is no silent copy of history between a person's own devices in draft 0.1; that is an open question.
- **Updates.** A device commits or proposes an Update at least every 30 days and at most once a day. In groups over 1,000 leaves, devices send Update proposals and let the next committer fold them in (section 13).

### 2.4 KeyPackages

KeyPackages contain the credential, so they MUST NOT be stored at the DS in the clear. A device publishes each KeyPackage as a sealed blob (direct form, media type `application/vnd.hum.mls-key-package`, store retention 14 days). The handle an inviter needs is:

| Key | Field | Type | Meaning |
| --- | --- | --- | --- |
| 0 | v | uint | 1 |
| 1 | ref | bstr | The sealed reference, direct form, as `storage.md` §3 encodes it |

A KeyPackage is used once. The device that published it deletes the blob with its own delete secret when it sees itself added with that KeyPackage, or lets retention expire it. The handle carries no delete secret, so nobody who sees a handle can stall a join by deleting the blob. Handles travel inside an existing MLS group, a QR code, or a join ticket (section 2.5). A device keeps at least 5 unused KeyPackages published while it is in any context.

### 2.5 Admission to a context

`seam: what leaves the phone.` This is how a person who has satisfied a context's entry policy gets into its all-members group. The rule that shapes it: a KeyPackage handle MUST NOT pass through any party that sees credential issuance evidence, because a KeyPackage carries the chat identity key and display name and a verifier holds the resident-card side of the same person.

Inputs: the joiner holds the context membership credential that `credentials.md` defines (assumed; see section 17) and can produce a membership proof from it; the context manifest's `chat` map carries `greeting` (key 11.3), a 32-byte X25519 public key required in every context version (`context.md` rule C11); the organizers group holds the matching private key, delivered to each organizer or moderator device as a `greeting-key` message (section 5.16).

Flow:

1. **Tokens.** The joiner's phone obtains context tokens from the DS (section 12.3) and store tokens from a blob store (`storage.md` §6.2), each with a membership proof. Neither service learns which member it is.
2. **KeyPackages.** The phone publishes one KeyPackage per device as sealed blobs (section 2.4).
3. **Ticket.** The phone builds `{0: v 1, 1: context CID, 2: handles [handle, …] (1 to 8), 3: proof bstr, 4: pad bstr}` where `context` is the context version the joiner proved against, `proof` is a membership proof against that version's entry policy with scope `hum/join/1 ‖ context lineage CID` and bound message `SHA-256(canonical CBOR of handles)`, and `pad` brings the plaintext to exactly `TICKET_BYTES`, so a ticket never reveals the device count. The scope is per person per context, so one resident card yields one join nullifier per context and admits one chat identity there (step 4); the bound message ties the proof to these handles, so a member cannot post a non-member's handles under their own proof. `TICKET_BYTES` is a protocol constant, 4,096. With the presentation sizes `credentials.md` gives (about 0.6 KiB per card), that fits eight handles and a three-credential entry proof with wide margin; a plaintext that does not fit is sent as fewer handles per ticket and a second ticket, never by growing the ticket. It seals the plaintext with HPKE (RFC 9180, `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `AES-128-GCM`, base mode, `info` = `hum/join-ticket/1` ‖ context lineage CID) to `greeting`, and posts the ciphertext to the DS join inbox with a context token (section 12.4, `POST /v1/join/{context}`).
4. **Greeting.** Devices with `members` in the all-members group (organizers, moderators, and greeter agents in the organizers group) fetch the inbox with a context token and open what they can. The greeter's phone MUST verify `proof` against the entry policy of the context version the ticket names, with the scope and bound message above, and MUST accept only the current context version or the one before it; a ticket without a valid proof is discarded, which is what stops one cooperating member from admitting a non-member. It then checks every nullifier the proof yields, one per card (`credentials.md`, "Every nullifier counts"), against the `join-record` messages in the organizers group (section 5.17): if any of them is already recorded for a chat identity key that is still in the all-members group, one of these cards already has a chat identity here and the ticket is discarded; nullifiers recorded only for identities that have since been removed admit the new identity. It then sends the `join-record` first, waits until the delivery service has sequenced it, and checks the records once more: an earlier record, by sequence number, that shares a nullifier with this one and names a different identity blocks the commit in exactly two cases: that identity is in the all-members group, or the record is pending, meaning its delivery-service receive time is less than `JOIN_PENDING` = 3,600 seconds before this greeter's own record. In either case the greeter stops and does not commit. An earlier record that is neither live nor pending is inert and blocks nothing. Only then does it fetch the KeyPackages by handle and commit one Add per device of the joiner to the all-members group, batching tickets as section 13 says. The record comes before the commit so that a greeter which fails between the two leaves a record and no member, never a member and no record. A record whose identity is not in the all-members group, and which is older than `JOIN_PENDING`, is inert: it blocks nothing, the same identity may be admitted under it later (a retried ticket matches its own record), and it is dropped after 396 days. A greeter that sent a record therefore commits its Add within `JOIN_PENDING` or sends a fresh record first. Because every Add is preceded by its record and every greeter sees the records in the same order, two tickets from one card cannot both be admitted: the greeter with the later record stops. As a backstop, a greeter that sees two live identities whose records share a nullifier removes the one whose `join-record` has the higher sequence number, and a greeter removes a leaf that was added with no `join-record`, under conditions that keep it from removing a legitimate member. The rule applies only to a kind 1 (human) leaf whose chat identity key was not in the all-members group before the Add, in a context whose `entry` policy yields a nullifier. It never applies to a context with `entry` = `[0]` (no record exists there), to a kind 2 (agent) leaf, or to a new device of an identity that is already a member. Before removing, the greeter must have fetched the organizers group up to a sequence point whose receive time is at least `JOIN_GRACE` = 600 seconds later than the Add commit's receive time, and found no record naming that identity. If it cannot fetch the organizers group that far, it does nothing. The Welcome goes to the DS under the handle derivation of section 12.6.
5. **Welcome.** The joiner's phone polls `POST /v1/welcome/{handle}` for each KeyPackage it published, joins, and runs section 1.3's first-epoch messages from the other side: it applies the `keyring-share`, the `directory` snapshot and the `roles` message. The ticket's KeyPackages are now consumed, so the phone publishes fresh ones and sends a `join-request` (section 5.11) for every `directory` entry with `default` true; a device with `join-open` adds it.

The proof in step 3 is zero knowledge: it shows that the policy holds and yields a nullifier under the join scope, plus each card's issuer and issuer epoch. Every valid card of an issuer shares the epoch, and `context.md` rule C16 makes the issuers the same for every joiner of a context, so a ticket's public fields say "someone who meets this context's entry policy" and nothing finer (ADR 0100). In the first hour after an issuer's epoch turns a ticket may show either of two epoch values. `credentials.md` keeps the join scope's nullifier unlinkable from the ballot, token and authorship scopes, as it does for those scopes among themselves. The greeter learns the joiner's chat identity and name from the KeyPackage, which it would see in the tree anyway, and the organizers group learns which join nullifier that identity used, which links nothing outside the join scope. One chat identity per card per context is a decision this spec takes so that the issue-map's per-chat-key rate limits and the member list mean one person each. Its limit: a card is re-issued with a new nym secret every issuer epoch (`credentials.md`), so the join nullifier changes then too, and the rule holds per issuer epoch. A person can gain one further chat identity per issuer epoch (every 168 days for the district profile), which bounds the rate rather than the count. A greeter deletes a `join-record` when its identity leaves the all-members group, and may drop any record older than 396 days, since by then its card's epoch has ended and its nullifiers can never match again (section 5.17). The alternative (per-ticket nullifiers, any number of chat identities per card) and the epoch limit are open question 16. A demotion from the organizers group SHOULD be followed by a greeting-key rotation, as a removal advances the keyring.

What each party learns: the verifier that issued the credential learns nothing after issuance; the blob store learns that some member of the context uploaded small blobs; the DS learns that some member of the context posted a fixed-size ticket and, within minutes to hours, that a commit with one or more Welcomes landed in the all-members group, which it already learns from any join. No party outside the organizers group sees the handles, and the organizers already see the joiner's name and key in the tree.

A ticket is retried after 14 days if no Welcome arrives. A greeter that opens a ticket whose KeyPackages are gone ignores it. A context whose organizers are offline admits nobody until one returns; a greeter agent is how a large context avoids that.

## 3. Roles and permissions

### 3.1 Roles and capabilities

`context.md` defines three roles: organizer (holds a `sign` key in the context authority's keyset), moderator (a chat credential the organizers group marks), and member. This spec maps them to chat capabilities. The context may override a role's row, and the overrides travel in the same signed `roles` message. Shared agents hold the sponsor capabilities of `agent-sponsor.md` (`post`, `greeter`, `history`, `author-map`, `take`); the last column maps those names onto this table.

| Capability | organizer | moderator | member | Shared agent holds it when its sponsor grants |
| --- | --- | --- | --- | --- |
| `channels`: create, archive, delete channels and folders | yes | no | no | never |
| `members`: add and remove any member in any channel; admit to the context | yes | yes | no | `greeter`, and only while the agent is in the organizers group |
| `join-open`: add a member who asked to join an open channel | yes | yes | yes | `greeter` |
| `post`: send text, reactions, replies and other application messages | yes | yes | yes | `post` |
| `propose`: send `promote-proposal` and `merge-proposal` | yes | yes | yes | `post` |
| `digest`: send `deck-dealt` and `release-digest` | yes | yes | no | `post` |
| `moderate`: hide, unhide, pin, unpin, mute | yes | yes | no | never |
| `files-write`: add and pin files; rename, move, add a version to, unpin and delete files the sender's own chat identity created (`storage.md` §5.3) | yes | yes | per folder | never |
| `files-delete-any`: rename, move, add a version to, unpin and delete files another member created, and announce a folder index at will | yes | yes | no | never |
| `history`: write history archives | yes | no | no | `history` |
| `agents`: add a shared agent | yes | when `agents.addRole` ≥ 1 | when `agents.addRole` = 2 | never |
| `roles`: publish a roles message | yes, with the sign threshold | no | no | never |

Agents never confirm a promotion, because that needs the author's key. The `agents` row reads `agents.addRole` from the context version the `roles` message names (`context.md`, key 17): 0 organizers only, 1 moderators too, 2 any member. `agent-sponsor.md` encodes the five sponsor capabilities as uint codes 0 to 4 in the order listed above.

### 3.2 The roles message

Roles reach phones as a `roles` message (section 5.8) in the all-members group, signed by the context authority's `sign` threshold. Phones keep the message with the highest `serial` whose signature verifies against the keyset in force; two messages with the same `serial` are ordered by DS sequence number and the later one wins. The roles table names chat identity keys, never resident cards or pseudonyms, and it is never logged or placed in a manifest. The organizers group's membership MUST match the set of organizer and moderator keys in the current roles message plus any `greeter` agents; the device that publishes a roles message commits the corresponding Adds and Removes.

### 3.3 Enforcement on phones

MLS has no server to refuse an operation, so every phone applies the same rule and refuses the same things. A handshake message that violates the table is invalid for all honest members, so they all stay on the previous epoch and the next valid commit in sequence order wins (section 12.6).

A phone MUST reject a commit when:

- it Adds a leaf and the committer lacks `members`, unless the Add answers a `join-request` for an open channel and the committer has `join-open`, or the added leaf's chat identity key equals the committer's (a person adding their own device);
- it Removes a leaf whose chat identity key differs from the committer's and the committer lacks `members`;
- it Adds a leaf of kind 2 (agent) and the committer lacks `agents`;
- it Adds a leaf whose chat identity key is not in the all-members group (channel groups only);
- any Add or Update fails credential validation (section 2.1).

A phone MUST drop (not render, not apply, but still count toward sequence order) an application message when:

- it fails the franking check of section 4.2 or does not re-encode to the same bytes;
- the sender is muted for the channel;
- it is a `moderate`, `roles`, `directory`, `history-offer`, `deck-dealt`, `release-digest`, `promote-proposal`, `merge-proposal`, `greeting-key` or `join-record` whose sender lacks the matching capability;
- it is a `file-op` or `folder-index` the sender lacks the right for under `storage.md` §5.3 and §5.5 (`files-write`, `files-delete-any`, or the committer of the Add for an index);
- it is a `keyring-share` whose sender is neither the committer of the Add that brought the receiver into the all-members group nor a `members` holder (`storage.md` §4.2);
- it is a `promote-confirm` whose sender's chat identity key differs from the quoted message's sender (section 6);
- it `replaces` a message whose sender's chat identity key differs from its own, except a `moderate` hide;
- it comes from a kind 2 leaf beyond the sponsor's `messages` limit in the current window (proposals count as messages; `agent-sponsor.md` has no separate field). The window index is `floor(received_ms / 1000 / window)` using the stamp time, and only stamped messages are counted, in sequence order.

A phone MUST also reject an Update from a kind 2 leaf whose new credential names a sponsor version that widens `capabilities`, raises any rate limit, or changes `runtime`, `attestation`, `codeHash` or `label` relative to the version in the leaf's current credential. Such a change needs a Remove and a fresh Add by an `agents` holder. An Update whose new version only extends `expires`, narrows capabilities, lowers limits or changes `description` is accepted after the checks of section 2.1. The version in the leaf credential is the one that applies to that leaf.

Both lists are conformance rules and each has a vector (section 16).

## 4. Framing

### 4.1 Wire format

Every application message, proposal and commit is an MLS `PrivateMessage` (RFC 9420 §6.3), sent as an `MLSMessage`. The plaintext of an application message is exactly one MIMI content object (section 5). Proposals and commits carry nothing of Hum's; the Hum-visible event for a join or leave is derived from the commit itself and, for agents, from an `agent-membership` message that follows it.

The DS therefore sees, per message, the `PrivateMessage` header fields in the clear: `group_id`, `epoch`, `content_type` (application, proposal or commit), `authenticated_data`, and the ciphertext length. Section 12.10 lists what it does with them.

Phones accept application messages and proposals whose header epoch is their current epoch or the one before it, because MLS keeps the previous epoch's keys for exactly this reason and senders legitimately race commits. Commits are applied only for the phone's current epoch.

### 4.2 Authenticated data and the franking tag

`authenticated_data` is exactly 33 bytes for application messages: `0x01` followed by the 32-byte franking tag of section 11.1. For proposals and commits it is 1 byte: `0x00`. Phones MUST drop an application message whose `authenticated_data` has any other length or whose tag does not verify against the decrypted content.

### 4.3 Padding

Before encryption, the sender pads the `PrivateMessageContent.padding` field so the serialized `MLSMessage` (the bytes the DS receives, including its version and wire-format prefix) lands exactly on a size bucket. Buckets are 512 B, 1 KiB, 2 KiB, 4 KiB, 8 KiB, 16 KiB, 32 KiB and 64 KiB for application messages and proposals. Commits may continue to 128 KiB, 256 KiB, 512 KiB and 1 MiB. A sender MUST pick the smallest bucket that fits, and the DS MUST reject a message whose length is not a bucket (section 12.8). Attachments never travel inline, so almost every message lands in the first two buckets.

A `Welcome` has no padding field. The `welcome` byte string sent to the DS is the serialized `MLSMessage` holding the Welcome followed by zero bytes up to the next commit bucket; the receiver parses the `MLSMessage` and ignores the tail.

The OHTTP relay pads the whole request again to its own buckets (`services.md` rule O-3); the two paddings are independent.

### 4.4 Ordering and time

The DS assigns each accepted message a per-channel sequence number and a receive time, both covered by its stamp. Phones display messages in sequence order and show the stamp time. This sequence is the "channel order" that `storage.md` §5.4 relies on, and the MIMI message ID of section 5.1 is its opaque message id. A dropped message still occupies its sequence number. The stamp time is informational, like `issued` in a manifest: it never decides validity. MLS's own epoch and per-sender generation detect a DS that drops or reorders handshake messages; a channel whose commits stop decrypting is shown as out of sync, not silently split.

## 5. Content

### 5.1 MIMI profile

The plaintext is a `MimiContent` CBOR array as draft-ietf-mimi-content-09 defines it: `[salt, replaces, topicId, expires, inReplyTo, extensions, nestedPart]`. `nestedPart` is itself one flat CBOR array: `[disposition, language, cardinality, …part fields in the draft's order]`; for an `ExternalPart` that is `[disposition, language, 2, contentType, url, expires, size, encAlg, key, nonce, aad, hashAlg, contentHash, description, filename]`, fifteen elements, with no nested array or map for the part. Hum pins these choices:

| MIMI field | Hum rule |
| --- | --- |
| `salt` | 16 random bytes per message |
| `replaces` | Null, or the message ID being edited, deleted or un-reacted |
| `topicId` | Empty byte string. Threads are not in draft 0.1. |
| `expires` | Null, or a relative or absolute expiry the phones honor by deleting locally. The DS has its own retention and does not read this. |
| `inReplyTo` | Null, or the message ID replied to or quoted |
| `extensions` | May carry `"hum.frank"` (section 11.1). `senderUri` and `roomUri` are omitted on the wire; both are derived (below). Unknown extensions are ignored. |
| `nestedPart` | One `NestedPart`. Hum types use disposition `render` (1). Reactions use `reaction` (2). |

Message IDs follow draft-09's message-ID section: `messageId = 0x01 ‖ SHA-256(len(senderUri) ‖ senderUri ‖ len(roomUri) ‖ roomUri ‖ message ‖ salt)[0..31]`, where each length is the URI's size in octets as a big-endian unsigned 16-bit integer, `message` is the serialized `MimiContent` (which already contains the salt, so the salt appears twice in the input), the output keeps the first 31 bytes of the digest after the algorithm byte, and:

- `senderUri` = `hum:member:` followed by the lowercase unpadded base32 of the sender's chat identity key (for an agent, its `agentKey`);
- `roomUri` = `hum:channel:` followed by the lowercase unpadded base32 of the group ID.

Both are known to every member from the ratchet tree and the group, so they need not be sent. A conformance vector fixes the derivation. The message ID is what `issue-map.md` stores as `origin` on a promoted object; it is a salted hash whose salt is inside the ciphertext, so nothing the DS holds can be joined to it.

Required content types: `text/markdown;variant=GFM-MIMI` for text, `text/plain;charset=utf-8` accepted on receipt, `application/mimi-content` for nesting, and the Hum types below. Reactions use disposition `reaction` with a `text/plain` single part. Edits set `replaces`; deletes set `replaces` with a `NullPart`. Only a sender's own chat identity key may replace its message (section 3.3).

Attachments are `ExternalPart`s whose fields map onto a direct-form sealed reference exactly as the table in `storage.md` §3.2 says, including its reject rule. This spec fixes the two choices that table leaves to chat: `url` is `hum:blob:` followed by the CID text form (`c` followed by base32), and `encAlg` is 1. Here `encAlg` 1 means "Hum sealed format 1" (chunked AES-128-GCM with derived nonces and the `hum/sealed/1` AAD, `storage.md` §1); a non-Hum MIMI decryptor that read it as one AES-128-GCM call over the file would fail, and interoperating with such a decryptor is not a goal. Phones MUST ignore an `ExternalPart` whose `url` has any other scheme, so a message can never point a phone at a hostname. The `store` hint of the reference is dropped in this framing.

### 5.2 Hum content types

Every Hum type is a `SinglePart` whose `contentType` is `application/vnd.hum.<name>+cbor` and whose `content` is a deterministic CBOR map with integer keys. Key 0 is always the body version, 1 in this draft, except where a sibling spec owns the payload and says otherwise. A phone MUST drop a body with an unknown version, a missing required key, an array over its stated maximum, or bytes that do not re-encode to themselves.

| Name | Payload owner | Sent in | Sender needs | Rendered as |
| --- | --- | --- | --- | --- |
| `promote-proposal` | this spec | Any text or issue channel | `propose` | A card under the quoted message: "Add to the issue map" |
| `promote-confirm` | this spec | Same channel as its proposal | Author of the quoted message | The quoted message gains a map badge |
| `merge-proposal` | this spec | Any text or issue channel | `propose` | A card: "Merge these two positions?" for the author or an organizer to act on |
| `deck-dealt` | this spec | Issue or text channel | `digest`, and verified by manifest | The dealt-deck card (`Chat-Channel.png`) |
| `release-digest` | this spec | Same channel the deck was dealt in | `digest`, and verified by manifest | The release card with a link to the results deck |
| `file-op` | this spec (section 5.7); effects in `storage.md` §5 | Folder channels | `files-write` or `files-delete-any` per `storage.md` §5.3 | A file row or a change line |
| `folder-index` | this spec (section 5.7); snapshot bytes in `storage.md` §5.5 | Folder channels | `files-delete-any`, or the committer of an Add | Not rendered |
| `public-copy` | `storage.md` §9 | The channel the file lives in | The sender of the message or operation that first carried the reference | A note that a public copy exists |
| `keyring-share` | `storage.md` §4.2 | All-members group | The committer of an Add | Not rendered |
| `token-key` | this spec (section 5.15) | All-members group | any member | Not rendered; raises a warning on conflict |
| `greeting-key` | this spec (section 5.16) | Organizers group | `roles` | Not rendered |
| `join-record` | this spec (section 5.17) | Organizers group | `members` | Not rendered |
| `agent-membership` | this spec | Any group | `agents` | A system line: who added which agent, where it runs |
| `roles` | this spec | All-members group | `roles`, plus the context signature | Not rendered |
| `directory` | this spec | All-members group | `channels` | The channel list |
| `checkpoint` | this spec | All-members group | any member | Not rendered; raises an alarm on conflict |
| `history-offer` | this spec | Any channel | `history` | Not rendered; the phone fetches the archive |
| `join-request` | this spec | All-members group | any member | A pending row for members with `join-open` or `members` |
| `report` | this spec | Organizers group | any member | A report with its opened content |
| `moderate` | this spec | Any channel | `moderate` | A system line, and the action applied |

### 5.3 `promote-proposal`

Proposes that a message become an issue-map object. `inReplyTo` MUST be set to the quoted message's ID and that message MUST be in the same group. This is the "promote request" that `issue-map.md` and `agent-sponsor.md` refer to.

| Key | Field | Type | Req | Meaning |
| --- | --- | --- | --- | --- |
| 0 | v | uint | yes | 1 |
| 1 | kind | uint | yes | 1 position, 2 pro, 3 con, 4 sub-question |
| 2 | issue | CID | yes | The issue lineage the object belongs under |
| 3 | parent | CID | yes | The parent lineage: the issue for kinds 1 and 4, a position for kinds 2 and 3 |
| 4 | text | tstr | yes | Proposed wording, 1 to 2,000 bytes, which the author may edit before confirming |
| 5 | source | bstr(32) | yes | The quoted message's ID; equals `inReplyTo` |

### 5.4 `promote-confirm`

Only the quoted message's author may send this (section 3.3). It closes the proposal.

| Key | Field | Type | Req | Meaning |
| --- | --- | --- | --- | --- |
| 0 | v | uint | yes | 1 |
| 1 | proposal | bstr(32) | yes | The `promote-proposal` message ID, or the author's own message ID for self-promotion |
| 2 | outcome | uint | yes | 1 confirmed and signed, 2 declined |
| 3 | object | CID | when 1 | The published issue-map object version, with `author` = `member` and `origin` equal to the quoted message's ID |

An author who wants the object unsigned on the map MUST NOT send a confirm. Their phone publishes the object with `author` = `anonymous` and no `origin`, as `issue-map.md` requires, and the channel sees only the map change. Sending a confirm would tell the channel who wrote it. Section 6 has the full flow.

### 5.5 `merge-proposal`

Proposes that one issue-map object be merged into another. The duplicate's author or an organizer acts on it as `issue-map.md`, "Merging", defines; the message itself changes nothing.

| Key | Field | Type | Req | Meaning |
| --- | --- | --- | --- | --- |
| 0 | v | uint | yes | 1 |
| 1 | duplicate | CID | yes | Lineage of the object proposed to be merged away |
| 2 | survivor | CID | yes | Lineage of the object it would merge into |
| 3 | note | tstr | no | Up to 500 bytes |

### 5.6 `deck-dealt` and `release-digest`

`deck-dealt` announces a deck in a channel. The phone resolves the deck manifest through `manifest.md` verification before rendering anything but a placeholder, and renders title, card count and closing time from the manifest, never from this body. Fields 3 to 6 exist so a phone can show a notification before it has fetched the manifest.

| Key | Field | Type | Req | Meaning |
| --- | --- | --- | --- | --- |
| 0 | v | uint | yes | 1 |
| 1 | deck | CID | yes | Deck manifest version |
| 2 | context | CID | yes | The context version the deck pins; MUST be a version of the context lineage the group belongs to |
| 3 | title | tstr | no | Hint, up to 200 bytes |
| 4 | cards | uint | no | Hint |
| 5 | from_here | array of CID | no | Positions in this deck that came from this channel's issue, at most 64 |
| 6 | closes | uint | no | Hint, seconds since the epoch |

Phones deduplicate by (`deck` lineage, group). "Play your 7 left" is computed on the phone from its own hand, and the hand never appears in any message.

`release-digest` announces a release. It is sent once per release, for the version `release.md` marks final, and phones deduplicate by (release lineage, group). The phone MUST hold a verified release (inclusion proof against a witnessed checkpoint, per `manifest.md`) before showing any number. The digest body carries no numbers for that reason.

| Key | Field | Type | Req | Meaning |
| --- | --- | --- | --- | --- |
| 0 | v | uint | yes | 1 |
| 1 | release | CID | yes | Release manifest version |
| 2 | deck | CID | yes | The deck it reports on; must match the release's `refs` |
| 3 | headline | tstr | no | Up to 200 bytes of text, shown as a quote attributed to the sender, never as a statistic |

### 5.7 `file-op`, `folder-index` and `public-copy`

A folder is a channel whose messages are file operations. This spec owns the message bytes; `storage.md` §5 owns what each operation does to folder state, who may send it, and how conflicts resolve.

`file-op` is a `SinglePart` when it carries no file, and otherwise a `MultiPart` with `partSemantics` `processAll`, the op first and exactly one `ExternalPart` second.

| Key | Field | Type | Req | Meaning |
| --- | --- | --- | --- | --- |
| 0 | v | uint | yes | 1 |
| 1 | op | uint | yes | 1 add, 2 rename, 3 move, 4 new version, 5 delete, 6 pin (copy a reference from another channel), 7 unpin |
| 2 | file | bstr(16) | yes | Random file ID assigned at `add` and kept across versions |
| 3 | name | tstr | ops 1, 2, 6 | File name shown in the folder, up to 255 bytes, NFC, no `/` or NUL |
| 4 | path | array of tstr | ops 1, 3, 6 | Sub-folder path, each element up to 255 bytes, depth at most 16 |
| 5 | prev | bstr(32) | op 4 | The message ID of the version the sender saw as current |
| 6 | origin | bstr(32) | op 6 | The message ID in another channel the reference was pinned from |

Ops 1, 4 and 6 MUST carry exactly one `ExternalPart`; the others carry none. A `delete` tells phones to hide the file; the blob itself is deleted under `storage.md` §8.

`folder-index` announces a snapshot of the folder (`storage.md` §5.5). It is a `MultiPart` with `partSemantics` `processAll`: a `SinglePart` `application/vnd.hum.folder-index+cbor` with body `{0: v 1, 1: seq uint}` where `seq` is the DS sequence number of the last `file-op` the snapshot includes, then exactly one `ExternalPart` whose media type is `application/vnd.hum.folder-index+cbor` and whose bytes are the snapshot `storage.md` §5.5 defines. The device that commits an Add to a folder group MUST send one in the new epoch; that is the folder analogue of the rule in section 1.3. Any `files-delete-any` holder may send one at other times.

Two values `storage.md` leaves to this spec: `created_by` and `added_by` in the snapshot are the chat identity key (32 bytes) of the leaf that sent the operation, and `msg` is the MIMI message ID of section 5.1. The `sensitive` flag of `storage.md` §10 is key 7 of the folder's `directory` entry (section 5.9), which only `channels` holders may change.

`public-copy` frames the consent message of `storage.md` §9, which makes a public copy of a sealed file. Its payload is that spec's `{0: sealed_cid, 1: public_cid, 2: media}` and it has no version key, because `storage.md` owns the bytes. Phones MUST drop a `public-copy` whose sender's chat identity key is not that of the message or folder operation that first carried the reference to `sealed_cid` in this channel.

### 5.8 `roles`

| Key | Field | Type | Req | Meaning |
| --- | --- | --- | --- | --- |
| 0 | v | uint | yes | 1 |
| 1 | context | CID | yes | The context version these roles apply under |
| 2 | serial | uint | yes | Strictly increasing per context |
| 3 | grants | array | yes | Each element `[identity bstr(32), role uint]`; role codes 1 organizer, 2 moderator; at most 10,000 |
| 4 | overrides | map | no | Role code (1, 2, or 3 for member) to an array of capability names (tstr) replacing the default column of section 3.1; at most 16 names per role |
| 5 | channel_grants | map | no | Group ID (bstr(32)) to an array of `[identity, capability tstr]` for per-channel grants such as `files-write`; at most 1,000 groups and 256 grants per group |
| 6 | issuer_keys | map | yes | Group ID to the DS token issuer public key (bstr) for the all-members and organizers groups; redundant with the context manifest's `chat.issuerKeys`, which wins on a mismatch (section 12.4) |
| 7 | sig | bstr | yes | A COSE_Sign (RFC 9052) with detached payload `hum/chat-roles/1` ‖ SHA-256(canonical CBOR of keys 0 to 6), signed by the context's `sign` threshold |

A member not listed has the member role. Phones evaluate `sig` with the keyset in force at the context version in key 1.

### 5.9 `directory`

| Key | Field | Type | Req | Meaning |
| --- | --- | --- | --- | --- |
| 0 | v | uint | yes | 1 |
| 1 | serial | uint | yes | Strictly increasing per context |
| 2 | op | uint | yes | 1 create, 2 update, 3 archive, 4 delete, 5 snapshot |
| 3 | channel | map | ops 1 to 4 | `{0: group_id bstr(32), 1: name tstr ≤ 100 bytes, 2: kind uint, 3: issue CID (kind 2, the issue lineage), 4: parent bstr(32) (a folder attached to a channel), 5: open bool, 6: created uint, 7: sensitive bool (kind 3), 8: issuer_key bstr (the DS token issuer public key from registration), 9: default bool (greeters add every newcomer)}` |
| 4 | channels | array of map | op 5 | Every live channel, same map as key 3, at most 1,000, sent to newcomers in their first epoch |

A `snapshot` replaces the whole list. Later ops apply on top of it. An op whose `serial` is lower than the snapshot's is ignored. Two messages with the same `serial` are ordered by DS sequence number and the later one wins. The device that commits an Add to the all-members group MUST send a `snapshot` in the new epoch (section 1.3).

### 5.10 `checkpoint`

Phones exchange log checkpoint hashes inside channels, as `manifest.md` requires.

| Key | Field | Type | Req | Meaning |
| --- | --- | --- | --- | --- |
| 0 | v | uint | yes | 1 |
| 1 | log | CID | yes | The log authority |
| 2 | size | uint | yes | Tree size |
| 3 | root | bstr(32) | yes | Root hash |

A phone that holds a different root for the same size MUST mark the log as equivocating and stop acting on its proofs until a consistency proof resolves it. Sent at most once a day per device.

### 5.11 `join-request`

| Key | Field | Type | Req | Meaning |
| --- | --- | --- | --- | --- |
| 0 | v | uint | yes | 1 |
| 1 | group_id | bstr(32) | yes | The channel to join |
| 2 | handles | array | yes | One KeyPackage handle (section 2.4) per device of the requester, at most 8 |

Any device with `join-open` for an open channel, or `members` for any channel, may answer by committing the Adds. Several answers may race; phones apply the first valid commit in sequence order and the other committers see the newcomer in the tree and drop their pending request. A requester already in the group is ignored. Handles carry no delete secret, so seeing one lets a member add the requester and nothing else.

### 5.12 `agent-membership`

Sent by the committer right after a commit that adds or removes a kind 2 leaf, in the new epoch. Phones also derive the event from the commit itself, so a missing message hides nothing; `agent-sponsor.md` says the leaf credential is the source of truth. The message exists so the timeline carries where the agent runs and who sponsors it in words.

| Key | Field | Type | Req | Meaning |
| --- | --- | --- | --- | --- |
| 0 | v | uint | yes | 1 |
| 1 | event | uint | yes | 1 joined, 2 left |
| 2 | sponsor | CID | yes | The `agent-sponsor` manifest version from the leaf credential |
| 3 | runtime | uint | yes | 1 `member-hardware`, 2 `enclave`, matching the manifest's `runtime` codes. A personal agent is never a leaf, so there is no phone code. |
| 4 | leaf | uint | yes | Leaf index in the new epoch |
| 5 | host | bstr(32) | runtime 1 | The chat identity key of the member whose hardware runs the agent: the committer's |

A phone MUST label every message from a kind 2 leaf as agent content, using the credential, not this message. A phone MUST treat a kind 2 leaf with runtime 1 as removed once its `host` is no longer in the all-members group, and an `agents` holder removes the leaf at the next opportunity; the host is known from this message or, failing that, from the committer of the Add.

### 5.13 `history-offer`

| Key | Field | Type | Req | Meaning |
| --- | --- | --- | --- | --- |
| 0 | v | uint | yes | 1 |
| 1 | archive | bstr | yes | The sealed reference, direct form, to the archive blob |
| 2 | from | uint | yes | First DS sequence number covered |
| 3 | to | uint | yes | Last DS sequence number covered |
| 4 | prev | CID | no | The archive before this one, for walking back |

### 5.14 `report` and `moderate`

Defined in section 11.

### 5.15 `token-key`

Phones in a context post the Privacy Pass issuer key ID they are currently given by each store and by the DS, so a service that hands one member a unique key is caught (`storage.md` §6.1). Sent in the all-members group at most once a day per device and whenever the key ID changes.

| Key | Field | Type | Req | Meaning |
| --- | --- | --- | --- | --- |
| 0 | v | uint | yes | 1 |
| 1 | service | CID | yes | The service or blob-store authority |
| 2 | token_key_id | bstr | yes | The key ID from the issuer directory, as RFC 9578 defines it |
| 3 | seen | uint | yes | Seconds since the Unix epoch when the phone last fetched it |

A phone that holds a different `token_key_id` for the same service from the same day, from more than one other member, MUST stop using that service and show a warning. For the DS the key in question is the context-token issuer key of section 12.3. Per-channel issuer keys are checked differently: against the `directory` entry or the `roles` message (section 12.5).

### 5.16 `greeting-key`

Sent in the organizers group by a `roles` holder whenever the organizers group gains a member, and when the key rotates.

| Key | Field | Type | Req | Meaning |
| --- | --- | --- | --- | --- |
| 0 | v | uint | yes | 1 |
| 1 | context | CID | yes | The context version whose `chat.greeting` this is the private half of |
| 2 | key | bstr(32) | yes | The X25519 private key |

A phone MUST ignore a `greeting-key` whose public half does not equal `chat.greeting` of the named context version. Rotating the key is a context manifest change followed by a new `greeting-key`; tickets sealed to the old key are still opened for 14 days.

### 5.17 `join-record`

Sent in the organizers group by the greeter that is about to admit a joiner, before its Add commit (section 2.5 step 4), so every greeter can enforce one chat identity per card per context.

| Key | Field | Type | Req | Meaning |
| --- | --- | --- | --- | --- |
| 0 | v | uint | yes | 1 |
| 1 | nullifiers | array of bstr(32), 1 to 8 | yes | Every join-scope nullifier the ticket's proof yields, one per card, sorted bytewise |
| 2 | identity | bstr(32) | yes | The chat identity key admitted under them |
| 3 | context | CID | yes | The context lineage |
| 5 | day | uint | yes | The UTC day the record was written, as days since the Unix epoch |

Greeters keep the set while it can matter. A greeter deletes a record when its `identity` leaves the all-members group, and may drop a record whose `day` is more than 396 days old. A newcomer to the organizers group receives the live set as a `join-record` snapshot (`{0: v 1, 4: records [[nullifiers, identity, day], …]}`, at most 50,000 entries) from the device that added it, in its first epoch. The set is never archived and never leaves the organizers group. A context whose entry policy is `[0]` yields no nullifier; its tickets produce no `join-record` and the one-identity rule does not apply there.

## 6. Promote to map

The flow, with who sends what. The map side is `issue-map.md`, "Promotion from chat".

1. **Propose.** Anyone with `propose` long-presses a message and picks position, pro, con or sub-question. Their phone sends `promote-proposal` quoting it. The quoted message's author sees "Add to the issue map?" with the proposed text, editable.
2. **Confirm, signed.** The author's phone creates the issue-map manifest with `author` = `member` and `origin` set to the quoted message's ID, signs it with the chat identity key under `hum/author/1`, logs it, then sends `promote-confirm` with outcome 1 and the object CID. Every phone in the channel verifies the object resolves, that its signer equals the confirmer's chat identity key, and that `origin` equals the message ID it computed for the quoted message, then badges the message.
3. **Confirm, unsigned.** The author's phone publishes with `author` = `anonymous`, no `origin`, and sends nothing. The proposer's card stays open until it expires after 7 days or the author declines.
4. **Decline.** `promote-confirm` with outcome 2. The card closes for everyone.
5. **Self-promotion.** The author may skip the proposal and publish directly from their own message; their phone then sends a `promote-confirm` whose `proposal` is the message's own ID.

A `promote-confirm` from any other chat identity key is dropped (section 3.3), so nobody can put words on the map under someone else's name. Agents may propose and never confirm, because a confirm needs the author's key.

## 7. Decks and releases posted back

A deck is dealt by the context authority publishing a deck manifest (`deck.md`). A device with `digest` (an organizer or moderator, or a shared agent whose sponsor grants `post`) then sends `deck-dealt` into each channel whose issue contributed cards, and into the channel the organizer chooses for context-wide decks. Phones trust the manifest, not the sender, so a forged announcement for a real deck changes nothing and one for a nonexistent deck renders as nothing.

When the final release version lands on the ledger, the same device sends `release-digest` into the same channels. The results deck itself (`Swipe-Reveal.png`) is built on the phone from the verified release and the person's own hand. The hand never leaves the phone; this spec has no message that could carry it, and section 16 lists the conformance check.

## 8. Attachments and folders

An attachment is uploaded as a sealed blob under `storage.md`, then sent as an `ExternalPart`. Pinning a message's file to a folder sends a `file-op` `pin` carrying the same `ExternalPart`, which re-sends the key, never the file.

Citing a file on the issue map depends on the context: in a context whose issue-map text is sealed, the author nests the direct-form reference inside the object's sealed text as `issue-map.md` allows; in a context whose text is public, the author first makes a public copy (`public-copy`, section 5.7, with their consent as `storage.md` §9 requires) and cites the public CID. A direct-form reference MUST NOT appear in public text, because it carries the file key.

A folder channel is created like any channel with kind 3 and, optionally, a `parent` channel. Membership of a folder attached to a channel is kept equal to that channel's membership by the same committer rule as section 1.3. Phones snapshot a folder into an encrypted index under `storage.md` §5.5, so a newcomer reads one blob instead of replaying operations; operations after the snapshot replay from the join epoch as usual.

## 9. Agents

Shared agents are MLS members with kind 2 credentials. Everything a phone needs to label and limit them is in the credential and the sponsor manifest:

- **Visibility.** The Add commit and the `agent-membership` message both show the agent, its sponsor and where it runs. An agent in an enclave on the operator's infrastructure is visible as such, with its measurement; an agent on ordinary operator servers cannot be added at all, because `agent-sponsor.md` allows shared agents only on member hardware or in an attested enclave.
- **Capabilities.** Section 3.1 maps the sponsor's `post`, `greeter`, `history`, `author-map` and `take` onto chat capabilities. None lets an agent confirm a promotion, publish roles, moderate, or add another agent. A greeter agent admits people to the context only while it is in the organizers group, which is where the greeting key lives.
- **Rate limits.** Phones enforce the sponsor manifest's `messages` limit per window as section 3.3 defines (proposals count as messages), so a flooding agent is silenced on every honest phone without a server.
- **Sponsor versions.** The version named in the leaf credential applies. Renewals that only narrow or extend expiry arrive as the agent's own Update; anything that widens needs a Remove and a fresh Add (section 3.3).
- **Voting.** An agent has no voting credential by construction (`credentials.md`), and nothing in chat touches votes.

Personal agents run on the phone and are not MLS members. Public agents never see chat.

## 10. History

A newcomer decrypts from its join epoch onward. Earlier messages reach it only as a history archive, and only when the context's history policy allows. The policy is `storage.history` in the context manifest: 0 none, 1 shared by an organizer, 2 full channel history. Which keyring epochs a newcomer receives is a separate setting, `storage.keyringHistory`, which governs `keyring-share` (`storage.md` §4.2), not archives.

### 10.1 Archive format

An archive is a sealed blob, media type `application/vnd.hum.history+cbor-seq`, holding a CBOR sequence of records in sequence order:

| Key | Field | Type | Meaning |
| --- | --- | --- | --- |
| 0 | seq | uint | DS sequence number |
| 1 | epoch | uint | MLS epoch |
| 2 | received | uint | Stamp time, milliseconds since the Unix epoch |
| 3 | framed | bstr | The TLS-serialized `AuthenticatedContent` (RFC 9420 §6.1): the decrypted `FramedContent` with its signature. For a `PrivateMessage` there is no membership tag; that field belongs to `PublicMessage`. |
| 4 | stamp | bstr(64) | The DS stamp (section 12.6) |
| 5 | key_id | bstr | The DS stamp key's ID (section 12.6) |
| 6 | credential | bstr | The sender's credential bytes at that epoch |
| 7 | leaf_key | bstr(32) | The sender's leaf signature public key at that epoch |
| 8 | group_context | bstr | The TLS-serialized `GroupContext` of that epoch. Present on the first record of each epoch in the archive; readers carry it forward. |

Keeping `AuthenticatedContent` and the `GroupContext` rather than bare plaintext means every archived message is still attributable and still reportable (section 11). Records for messages the writer's phone had hidden by moderation or dropped under section 3.3 are omitted. `keyring-share`, `folder-index`, `token-key`, `greeting-key`, `join-record` and `history-offer` messages never enter an archive: the first and the `greeting-key` carry secrets, and the rest are superseded by the time a newcomer reads the archive. The all-members group and the organizers group are never archived; a newcomer gets their state from the `keyring-share`, `directory` snapshot and `roles` message sent in its first epoch.

### 10.2 Writing and offering

A device with `history` writes an archive covering a sequence range, uploads it, and from then on a `history-offer` goes to each newcomer in the newcomer's first epoch (the committer of the Add sends it if it holds `history`; otherwise the next `history` device to come online does). Archives chain through `prev`, so a newcomer walks back as far as the policy window allows and no further; the writer MUST NOT include records before the window. Under policy 1 the window is whatever the organizer chose when writing. Archives are written at most daily and at least when the queue would otherwise expire, so a channel's history survives the DS's 30-day retention. Their retention at the store is the context's `storage.retention` for kind 2.

Archives are deleted with the channel and when a message in them is deleted by a context order; in that case the writer re-writes the archive without the record.

## 11. Moderation and franking

### 11.1 Franking

Every application message commits to its own plaintext in a way the DS can countersign without reading it, following the message-franking construction used by Facebook Messenger.

1. The sender draws `frank_key`, 32 random bytes, and places it in the MIMI `extensions` map under the text key `"hum.frank"` as a `bstr(32)`.
2. The sender serializes the `MimiContent` (which now includes the key) to `mimi_bytes`.
3. `frank_tag = HMAC-SHA256(frank_key, "hum/frank/1" ‖ group_id ‖ epoch as uint64 big-endian ‖ mimi_bytes)`.
4. `authenticated_data = 0x01 ‖ frank_tag`.

Recipients recompute the tag after decryption and MUST drop a mismatch. The tag is also inside the sender's MLS signature over `FramedContent`, because `authenticated_data` is part of it. HMAC under a random key hides the plaintext from the DS and binds the tag to one plaintext. The tag is never written anywhere public: `issue-map.md`'s `origin` is the message ID, not the tag, precisely so that a logged signed object cannot be joined to the DS's record of tags.

Attachments are covered because the `ExternalPart` with the blob's CID, key and content hash is part of `mimi_bytes`. Opening a report therefore lets a moderator fetch and decrypt exactly the file that was sent.

### 11.2 The stamp

On accepting a message the DS signs it (section 12.6) with a `sign` key of its keyset and names that key's ID in the response; `services.md` defines no separate stamp field. The stamp proves the DS delivered a message with that tag to that channel at that time. It does not prove who sent it; the MLS signature does.

### 11.3 Reports

A report is sent into the organizers group, so only organizers and moderators see it, and only for messages someone chose to report. A moderator need not be in the reported channel, so the report carries everything needed to rebuild the signed bytes. That includes the channel's `GroupContext`, which reveals the channel's tree hash and transcript hash to the organizers group; that is accepted.

`report` body:

| Key | Field | Type | Req | Meaning |
| --- | --- | --- | --- | --- |
| 0 | v | uint | yes | 1 |
| 1 | group_id | bstr(32) | yes | The channel |
| 2 | seq | uint | yes | The DS sequence number |
| 3 | received | uint | yes | The stamp time, milliseconds |
| 4 | framed | bstr | yes | The `AuthenticatedContent` of the reported message |
| 5 | group_context | bstr | yes | The TLS-serialized `GroupContext` of the message's epoch |
| 6 | credential | bstr | yes | The sender's leaf credential at that epoch |
| 7 | leaf_key | bstr(32) | yes | The sender's leaf signature public key at that epoch |
| 8 | stamp | bstr(64) | yes | The DS stamp |
| 9 | key_id | bstr | yes | The stamp key's ID |
| 10 | keyset | CID | yes | The DS authority's `keyset` manifest version that lists `key_id` |
| 11 | reason | tstr | no | Up to 1,000 bytes |

A moderator's phone verifies, in order, and shows the result:

1. The credential's `binding` verifies, so `leaf_key` belongs to the chat identity key in the credential.
2. `FramedContentTBS` (RFC 9420 §6.1) is rebuilt from `framed` and `group_context`, and its signature verifies under `leaf_key`.
3. `frank_tag` recomputed from the content equals the tag in `framed`'s `authenticated_data`.
4. `keyset` resolves to a logged `keyset` version of the authority the context names as `chat.delivery`, it lists a `sign` key with ID `key_id` that is not revoked at the verifier's latest witnessed checkpoint, and the stamp verifies under that key over `hum/stamp/1` ‖ `group_id` ‖ `seq` ‖ `received` ‖ `authenticated_data`. A stamp is never logged, so log order cannot select the keyset; the report names it instead.

A report that fails any step is shown as unverified and cannot be acted on with `moderate`. Draft 0.1 does not prove the leaf was in the group's tree at that epoch; the chat identity binding is the attribution. A tree proof is an open question.

### 11.4 Actions

`moderate` body, sent in the affected channel:

| Key | Field | Type | Req | Meaning |
| --- | --- | --- | --- | --- |
| 0 | v | uint | yes | 1 |
| 1 | action | uint | yes | 1 hide, 2 unhide, 3 pin, 4 unpin, 5 mute, 6 unmute |
| 2 | message | bstr(32) | actions 1 to 4 | Message ID |
| 3 | identity | bstr(32) | actions 5, 6 | Chat identity key |
| 4 | until | uint | action 5 | Seconds since the Unix epoch |
| 5 | note | tstr | no | Shown as the reason, up to 500 bytes |

Hiding tells every phone to stop showing a message; it cannot unsend ciphertext. Removing a member is an MLS Remove by a device with `members`. Deleting an attachment is a context deletion order under `storage.md` §8, and a phone that sees the matching `moderate` hide deletes its cached copy as `storage.md` §8 asks. Hiding an issue-map object is the context authority's `hidden` version in `issue-map.md`. Each is a separate act and the UI offers them together.

## 12. The delivery service

### 12.1 Role and limits

The DS is a short-term queue that validates nothing it carries. It sequences ciphertext per channel and holds it for 30 days, holds a per-context join inbox, issues anonymous tokens, and stamps messages. It keeps no member list, no per-device state and no account. It never decides which commit is the real one; phones do (section 12.6). Long-term memory is the blob store (section 10).

Every request goes through an OHTTP relay ([RFC 9458](https://www.rfc-editor.org/rfc/rfc9458.html)) run by a party other than the DS operator (`services.md`, ADR 0073). Request bodies are deterministic CBOR with content type `application/vnd.hum.ds+cbor`; errors are the deterministic CBOR error map of `services.md`, "Errors" (`application/vnd.hum.error+cbor`). The DS publishes a `service` manifest with `kind` = `delivery`: its `endpoints`, `tokenIssuers`, the kind-specific `issuer` map (body key 16, the same shape as a blob store's), `limits` and `retention`. It stamps with any `sign` key of its keyset. A context names its DS by authority in `chat.delivery`, and phones use a DS only if the context names its key. A channel lives on one DS; moving a context to another DS means new channels, which is the federation cost the design doc accepts.

The common rules of `services.md` apply: error rules E-1 to E-3, token rules T-1 to T-4, and relay rules O-1 to O-5. In particular a token issuance request and a request that spends a token never share a relay connection.

Rules for a `service` manifest of `kind` = `delivery`, run at step 10 after `services.md` S-1 to S-8:

| Rule | Check |
| --- | --- |
| DL-1 | The key 16 `issuer` map is present with `type` = 1 (VOPRF, section 12.5), a non-empty `name` and a `rotation` of at most 2,592,000 seconds |
| DL-2 | `limits` is present and holds exactly the six names below, each a uint ≥ 1 |
| DL-3 | `retention` is present and declares `content` at most 2,592,000 seconds (the 30-day queue) and `errors` at most 86,400 |
| DL-4 | No key from 6, 7, 10, 11 or 17 and above is present |
| DL-5 | Between versions, `issuer.name` is unchanged |

Vectors `service-delivery-valid` and one failing per rule. The `limits` map of the DS manifest names: `channelsPerContext` (default 1,000), `bytesPerChannel` (default 256 MiB), `commitsPerHour` per channel (default 600), `sendsPerMinute` per channel (default 600), `tokensPerIssuance` (default 64), `ticketsPerContextDay` (default 10,000).

### 12.2 Endpoints

| Method and path | Credential | Purpose |
| --- | --- | --- |
| `POST /v1/tokens` | Context membership proof, scope `hum/delivery-tokens/1 ‖ token_key_id ‖ day`, with the context CID in the body | Issue context tokens, the `token` class of `services.md` |
| `POST /v1/channels` | Context token | Register a new channel group |
| `POST /v1/channel-tokens` | Delivery secret MAC | Issue channel tokens for one group |
| `POST /v1/channels/{group_id}/send` | Channel token | Submit an application message, proposal or commit |
| `POST /v1/channels/{group_id}/fetch` | Channel token | Fetch messages after a sequence number; long-poll |
| `POST /v1/channels/{group_id}/reset` | `organizer` signature (`services.md`) | Replace the channel's accepted delivery secrets |
| `POST /v1/join/{context}` | Context token | Post a join ticket |
| `POST /v1/join/{context}/fetch` | Context token | Fetch join tickets |
| `POST /v1/welcome/{handle}` | None | Fetch a Welcome by handle |

`{group_id}` is lowercase hex. Per `services.md` rule E-2, a request without a valid token answers `401` with no body, and a valid channel token cannot exist for a group that was never registered, so a non-member cannot learn whether a group exists.

### 12.3 Context tokens

Context tokens follow the token rules of `services.md` (T-1 to T-4) and the issuance shape of `storage.md` §6.2: `POST /v1/tokens` with the context CID in the body and up to 64 `TokenRequest`s, against a membership proof scoped `hum/delivery-tokens/1 ‖ token_key_id ‖ day` whose bound message is SHA-256 of the canonical CBOR of the `requests` array (`credentials.md`, "The uses"). The type is 0x0001 (VOPRF), one issuer key per context, rotated at most every 30 days, with the key ID gossiped in `token-key` messages. Each service's token type is normative in its own spec; the blob store uses 0x0002. Context tokens authorize channel registration, join tickets and inbox fetches, and nothing else. One token per request. Issuance is rate-limited per membership-proof nullifier per day; a context whose entry policy is open yields no nullifier (`credentials.md`), and for it the DS falls back to the per-context limits of its manifest.

### 12.4 Register a channel and the join inbox

Register: `{0: v 1, 1: group_id bstr(32), 2: context CID, 3: secret bstr(32), 4: epoch uint}`. `secret` is the delivery secret of the group's current epoch. Response: `{0: issuer_key bstr}`, the per-channel token issuer public key. For an ordinary channel the creator MUST place it in the channel's `directory` entry (key 8). For the all-members and organizers groups, which are registered once when the context is created, the creator MUST place both keys in the context manifest's `chat.issuerKeys` (`context.md` chat key 4, `{0: allMembers bstr, 1: organizers bstr}`, required by rule C11), so a newcomer holds them before its first token request; the `roles` message repeats them in `issuer_keys` and a phone that sees the two disagree warns and trusts the manifest. The DS counts the channel against the context's `channelsPerContext`.

Join ticket: `{0: v 1, 1: ciphertext bstr}` where `ciphertext` is the HPKE output of section 2.5, always `TICKET_BYTES` plus the AEAD tag and encapsulated key. The DS stores it for 14 days under a per-context ticket sequence number. Fetch: `{0: v 1, 1: after uint, 2: limit uint ≤ 100}` returns `{0: tickets [{0: seq uint, 1: ciphertext bstr, 2: received uint}]}` in sequence order. The DS cannot tell greeters from other members; any member with a context token can fetch ciphertext it cannot open.

### 12.5 Channel tokens

Tokens are Privacy Pass tokens ([RFC 9576](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9578](https://www.rfc-editor.org/rfc/rfc9578.html)) of type 0x0001 (VOPRF over P-384, privately verifiable), the type this spec fixes for the DS. They differ from context tokens in one way: the issuer key is per channel, not per context, so a token proves channel membership and the DS never needs a list to decide who may fetch a channel. Deriving a blind-RSA key per channel would be impractical, which is why the DS does not use type 0x0002 as the blob store does.

The issuer key for a group is derived, so the DS stores none: `seed = HKDF-Expand(PRK = DS master secret, info = "hum/pp-issuer/1" ‖ group_id, L = 32)`, then `(skS, pkS) = DeriveKeyPair(seed, info = group_id)` per RFC 9497 §3.2 for the P-384 suite RFC 9578 names.

Every phone verifies the VOPRF proof in each `TokenResponse` against the issuer key in the channel's `directory` entry, or for the all-members and organizers groups against `chat.issuerKeys` in the context manifest, never against a key the DS returns at issuance time. A newcomer therefore verifies its very first token for the all-members group, which matters because the DS has just served that device's Welcome and could otherwise single it out with a unique key. A phone that receives a response that fails under that key MUST stop using the channel and show a warning. This is what stops a DS from giving each device its own key and linking its tokens.

Issuance request: `{0: v 1, 1: group_id, 2: epoch uint, 3: requests array of TokenRequest, 4: mac bstr(32)}` with at most `tokensPerIssuance` requests and `mac = HMAC-SHA256(secret, "hum/token-request/1" ‖ canonical CBOR of keys 0 to 3)`, where `secret` is any delivery secret of the channel the DS holds (section 12.6); `epoch` is the sender's label for it and lets the DS try that entry first, but the DS accepts a MAC under any held secret and marks it used. Response: the array of `TokenResponse`.

A token is spent on exactly one `send`, or on one `fetch` session. A fetch session begins with a fetch that spends a token; the response carries a 16-byte random session cookie, which later fetches present instead of a token for at most 15 minutes from the first fetch, after which the DS forgets it and the next fetch spends a new token. The cookie is the only place a token spans more than one request, and an open session is what section 12.10 counts as a device online. The DS keeps spent token nonces for 48 hours and rejects a reuse (`services.md` T-1). Tokens carry nothing but type, key ID and nonce (T-2). A token issued under a secret that has since expired stays valid for its 48 hours, which bounds what a removed device can still do: fetch ciphertext it cannot decrypt, and send ciphertext honest members discard because its MLS authentication fails.

### 12.6 Send, sequencing and the stamp

Request: `{0: v 1, 1: kind uint, 2: message bstr, 3: welcomes array, 4: handles array, 5: mac bstr(32), 6: next_secret bstr(32)}`.

- `kind` is 1 application, 2 proposal, 3 commit. It MUST match the `PrivateMessage` content type.
- `message` is the serialized `MLSMessage`, padded per section 4.3.
- For commits only: `mac = HMAC-SHA256(secret, "hum/commit/1" ‖ message)` where `secret` is any delivery secret of this channel the DS currently holds (the DS tries each held secret); `next_secret` is the delivery secret of the epoch the commit creates; `welcomes` holds at most one padded `Welcome` (RFC 9420 allows one Welcome for every joiner of a commit) and `handles` the list of at most 1,000 `SHA-256("hum/welcome/1" ‖ KeyPackageRef)` values it is stored under. Application messages and proposals MUST omit keys 3 to 6.

The DS checks: the token; the padding bucket; `kind` against the header; for commits, that `mac` verifies under some secret it holds for the channel, and it marks that secret used. It does not check epochs at all. On success it assigns the next `seq` for the channel, records `received` in milliseconds, computes the stamp, stores the message, and for commits records `(h + 1, next_secret, received)` as a held secret and stores the Welcome under each handle for 14 days.

Held secrets: the DS keeps, per channel, at most 64 `(epoch, secret, registered, last_used)` entries registered by commits or a reset. The epoch is an informational label used only for the `top_epoch` hint; it never selects, ranks or evicts a secret. A secret is usable for commits and token issuance for 48 hours after it was registered or last used for a successful commit or token issuance, whichever is later; after that it is deleted. When a 65th secret is registered, the entry with the most recent `registered` time is dropped, never an older one. A flood of registrations therefore churns only its own newest entries and cannot reach a secret registered before it.

The commit MAC may be computed under any held secret of the channel, not only one whose epoch label equals the commit's header epoch. The MAC exists to show the sender holds a secret the DS holds for this channel; honest members hold every delivery secret since they joined, so they can always MAC under the oldest honest secret still held, even while newer honest registrations are being evicted by a flood.

Why this cannot brick a channel: the DS never refuses a commit for being the second one in an epoch, so an invalid commit (bad credential, missing capability, or garbage from a device that still holds a token) is just a message honest phones skip. Phones apply, per epoch, the first commit in sequence order that passes MLS validation and section 3.3, and ignore every later commit for the same epoch. A device that can register a secret must hold a secret the DS already has, so a removed member can act only under secrets from before their removal, and a current member who floods invalid commits is visible in the tree and removable with one valid commit that always gets sequenced. Because eviction drops the newest registration and honest use keeps an old honest secret alive under the 48-hour sliding rule, no flood can evict it or stop honest token issuance and commits.

What a removed member can still do, plainly: by issuing a token or MACing a junk commit under an old secret every 47 hours they keep that secret alive indefinitely, and each junk commit registers another secret they control. They can post junk commits and junk application messages that honest phones skip, bounded by `commitsPerHour` and `sendsPerMinute`, and they can fetch ciphertext they cannot decrypt. They cannot evict honest secrets, cannot stop honest issuance, and cannot be mistaken for a member by any phone. This lasts until an organizer resets the channel or the attacker stops for 48 hours. One degradation during a sustained flood: a member who joined after the epoch of the oldest surviving honest secret holds only newer secrets, which the flood keeps evicting, so that member cannot issue tokens or commit until the flood stops or an organizer resets; older members are unaffected. The DS master secret from which issuer keys derive is 32 uniform random bytes, which is what makes `HKDF-Expand` on it directly sound.

Reset: `{0: v 1, 1: epoch uint, 2: secret bstr(32)}` under an `organizer` signature (`services.md`: one `sign` key of the context keyset, domain `hum/service-request/1`). The DS deletes every held secret and records this one. The reset is sequenced like a message so phones see that it happened. It tells the DS that an organizer of the channel's context acted; section 12.10 lists it.

Stamp: `Ed25519-Sign(stamp_key, "hum/stamp/1" ‖ group_id ‖ seq as uint64 BE ‖ received as uint64 BE ‖ authenticated_data)`.

Response: `{0: seq uint, 1: received uint, 2: stamp bstr(64), 3: key_id bstr}` where `key_id` identifies the `sign` key of the DS keyset that made the stamp.

### 12.7 Fetch

Request: `{0: v 1, 1: after uint, 2: limit uint, 3: wait uint, 4: session bstr(16)}`, with `session` present on every fetch after the first in a session (section 12.5) and the token absent then. `limit` is at most 200; `wait` is at most 25 seconds of long-poll. Response: `{0: messages array of {0: seq, 1: kind, 2: message bstr, 3: received, 4: stamp, 5: key_id, 6: reset bool}, 1: top_epoch uint, 2: session bstr(16)}`. `top_epoch` is the highest header epoch the DS has sequenced, a hint for a returning device. Messages older than 30 days are gone; a device that has been away longer sees that it cannot decrypt and asks a member to re-add it. Phones keep the cursor; the DS keeps no cursor and no notion of which device fetched. There is no acknowledge call, because an acknowledgement would be per-device state.

### 12.8 Errors

Errors use the format and code table of `services.md`, "Errors": a deterministic CBOR map `{0: code, 1: detail, 2: step, 3: rule, 4: retryAfter}` with media type `application/vnd.hum.error+cbor`. The DS uses these codes; `detail` values are fixed per row. The DS never answers `epoch_conflict`, because it does not gate on epochs (section 12.6).

| Code | HTTP | `detail` | When |
| --- | --- | --- | --- |
| `unauthorized` | 401 | none | Bad or missing token; unknown group; unknown Welcome handle; bad issuance or commit MAC; bad `organizer` signature |
| `token_spent` | 401 | none | The token was already redeemed |
| `malformed` | 400 | `encoding` | Body does not decode, re-encode or validate |
| `malformed` | 400 | `kind` | `kind` does not match the header content type, or keys 3 to 6 present on a non-commit |
| `not_padded` | 400 | none | Message length is not a bucket of section 4.3 |
| `too_large` | 413 | `message` or `quota` | Over 1 MiB, or over `bytesPerChannel` |
| `rate_limited` | 429 | `token`, `channel` or `context` | Per-token, per-channel or per-context limit exceeded; `retryAfter` set |

### 12.9 What the DS stores

| Data | Retention | Why |
| --- | --- | --- |
| Per channel: group ID, context CID, held secrets with their epochs, byte count, `top_epoch` | While the channel exists; secrets per section 12.6 | Authorization and ordering |
| Per message: seq, kind, ciphertext, `authenticated_data`, received time, stamp | 30 days, or until `bytesPerChannel` pushes it out | The queue |
| Welcome by handle | 14 days | New members and devices |
| Join tickets by context | 14 days | Admission |
| Spent token nonces | 48 hours | Double-spend prevention |
| Error logs | 24 hours, with no request bodies and no client addresses (OHTTP removes them), timestamps rounded to the minute (`services.md` L-1) | Operations |

No member lists, no device identifiers, no fetch cursors, no KeyPackages, no push handles. Push notifications are an open question because every known design gives the DS a per-device list.

### 12.10 What the DS sees

This table is the normative version of the design doc's row for the chat delivery service. It is wider than that row ("ciphertext, timing, which channel"), and wider than `docs/threat-model.md`'s row, which omits the context: the DS also learns which context each channel belongs to, the message class, the epoch rate, Welcome and ticket counts, and token issuance counts. Per `CLAUDE.md` the spec wins; the owner should update both rows rather than this table being narrowed.

| The DS sees | Because | The DS never sees | Because |
| --- | --- | --- | --- |
| That a message arrived for a channel, and when | It queues it | Message content | MLS encryption |
| The size bucket | It enforces padding | Attachments, their names or IDs | References travel inside messages |
| Whether it is an application message, a proposal or a commit | `PrivateMessage` header | Who sent it | `PrivateMessage` encrypts sender data; OHTTP hides addresses; tokens are blind and single-use |
| The header epoch number, and so the rate of commits | Header | The member list or its size, beyond what commit sizes and Welcome counts suggest | No tree at the DS; handshake messages encrypted; credentials never in the clear |
| How many Welcome handles a commit carried, and the `KeyPackageRef`s in the Welcome's `secrets` list | It stores them by handle; the list is plaintext per RFC 9420 | Who joined | Handles and refs are hashes of KeyPackages it never sees |
| How many devices hold a fetch session open at once in a channel | One token per 15-minute session | Which devices they are | Tokens are blind |
| Which context a channel belongs to | Registration | Chat names or safety codes | Credentials never reach it |
| That some member of a context posted a join ticket, and when | The inbox | Who asked to join, or their KeyPackages | Sealed to the greeting key |
| That an organizer of a context reset a channel | The `organizer` signature | Which organizer | One key of a public keyset |
| A random 32-byte franking tag per message | `authenticated_data` | Anything about votes, hands or shields | Nothing in chat carries them |
| Token issuance counts per channel, so rough activity | Issuance | Which token belongs to which member | Blinding, and issuer keys every member checks |

Remaining leaks, stated plainly: commit size buckets grow with the log of the group size and the number of Adds; the commit rate reveals churn, though not whether a commit added or removed; open fetch sessions reveal how many devices are online; a ticket is a fixed `TICKET_BYTES` before sealing, so it does not reveal a joiner's device count, but the number of Welcome handles on the following commit does; timing correlation across channels would be possible for a DS that also ran the OHTTP relay, which is why `services.md` requires an independent relay operator.

## 13. Scale

RFC 9750 §7 covers groups of hundreds of thousands. For Hum's channels in the thousands:

- **Commits.** An Add or Remove commit with a path is O(log n) ciphertexts: under 8 KiB at 5,000 leaves. Full-group Update commits do not exist; devices send Update proposals and the next committer folds in at most 100 per commit.
- **Welcome.** `ratchet_tree` is omitted from GroupInfo whenever the group has more than 100 leaves. The committer uploads the tree as a sealed blob (TLS-serialized `ratchet_tree` as in RFC 9420 §12.4.3.3, media type `application/vnd.hum.mls-ratchet-tree`) and places its sealed reference in the `hum_tree_ref` GroupInfo extension. The newcomer fetches it with a storage token, checks it against `tree_hash`, and proceeds. At 5,000 leaves the snapshot is about 3 MiB before padding, so greeter devices should be on good links; a greeter agent on a sponsor's hardware is the expected arrangement for large contexts.
- **Joins in batches.** A greeter waits up to a minute and commits all pending tickets or join requests at once, which turns a thousand-person join into tens of commits instead of a thousand.
- **Fan-out.** The DS stores one copy per message and every device fetches it, so a 5,000-member channel costs the DS 5,000 fetches per message, not 5,000 stores. Fetch responses batch up to 200 messages.
- **History.** Archives are per channel, daily, and chained, so a newcomer to a busy channel reads days of history from the blob store, not the DS.
- **Why no external commits.** An external commit is a `PublicMessage` and carries the joiner's credential in the clear, which would give the DS the member list over time. Draft 0.1 pays for that with the ticket and join-request round trips and a greeter online to commit. If a later draft adds per-context pseudonymous leaf credentials with names delivered inside the group, external commits become possible; this is an open question.
- **All-members group size.** The all-members group is the largest group, with every device of every member. Its only traffic is control messages, so a 50,000-device group is a handful of commits a day plus roles, directory, token-key and checkpoint messages.

## 14. Search

Search runs on the phone over its local message store and attachment names. The index is stored under the device's data protection keys, never synced, and never backed up except inside an encrypted device backup. No query, index fragment, or embedding leaves the phone, and no server endpoint exists for search. A personal agent that answers "catch me up" reads the same local store under the same rule.

## 15. Security considerations

| Threat | Mitigation |
| --- | --- |
| The DS reads messages | MLS; the DS holds only ciphertext and a random tag |
| The DS learns the member list | No tree, no credentials, no KeyPackages and no external commits at the DS; blind per-channel tokens whose issuer key every member checks; OHTTP |
| The DS turns tokens into device identifiers by issuing per-device keys | Issuer keys are published in the directory and roles message and every phone verifies against them; one token per send |
| The DS forks a group by showing different commits to different members | The DS sequences everything and phones pick the first valid commit per epoch, so a fork needs the DS to show different sequences; members whose messages stop decrypting see the channel as out of sync; comparison of epoch authenticators is an open question |
| A member or a removed member bricks a channel with an invalid commit | The DS never rejects a commit for epoch reasons, phones skip invalid commits, commits need a MAC under a held secret, dead secrets expire, and an organizer can reset (section 12.6) |
| The DS drops or delays messages | MLS generation counters and epochs expose gaps; a context can name a second DS in a new version |
| A removed member keeps reading | Keys rotate on the Remove commit; their secrets expire 48 hours after their last use, or at a reset; archives written after removal are under new keys |
| A removed member keeps sending | Honest members discard messages that fail MLS authentication; per-channel send and commit limits bound the junk. Residual: a removed member who keeps using pre-removal secrets can waste a channel's rate budget, and block token issuance for members who joined after the oldest surviving honest secret, until an organizer resets (section 12.6) |
| A member forges a report | MLS signature over the rebuilt `FramedContentTBS`, credential binding, franking tag and DS stamp; a forged report fails a step of section 11.3 |
| A member reports a message the sender never sent | Same chain; the stamp proves delivery of that exact tag |
| A verifier links a resident card to a chat identity through admission | Join tickets are sealed to the greeting key and go through the DS, never through a verifier; KeyPackages are sealed blobs |
| Someone confirms a promotion of another person's words | `promote-confirm` is accepted only from the quoted message's chat identity key, and the object's `origin` must equal the message ID |
| A logged issue-map object is joined to DS records | `origin` is the salted message ID, not the franking tag the DS holds |
| An agent floods a channel | Rate limits from the sponsor manifest enforced on every phone with a shared window boundary; agent content labeled from the credential |
| An operator-hosted agent silently reads a channel | Shared agents run only on member hardware or in an attested enclave; the leaf credential and membership event show which |
| A chat message carries a vote, hand or shield | No Hum type has a field for one; the conformance suite scans every vector and the simulator's traffic for ballot structures |
| The chat identity is linked to a voting pseudonym or resident card | The credential holds only the chat identity key, a device ID and a name; roles and reports name chat identity keys only; the DS and storage tokens use the context membership proof, which `credentials.md` keeps unlinkable from the voting pseudonym |
| A message points a phone at a hostname | `ExternalPart.url` MUST be `hum:blob:` plus a CID text form |
| A store or the DS gives one member a unique token key | `token-key` gossip in the all-members group |
| A message is replayed into another channel | `frank_tag` binds group ID and epoch; MLS binds both too |
| A removed member stays in a channel no organizer is in | Every channel keeps at least one organizer or moderator device (section 1.3) |

Two properties to state plainly. First, non-repudiation: MLS signatures make every message attributable to its sender's leaf key inside the group, and Hum uses that for reports rather than adding deniability; the privacy screen says "What you say, signed." Second, one chat identity across contexts: the chat identity key, device ID and safety code are the same in every context a person joins, so two contexts that share a member can be joined by anyone who is in both. The design doc chose one chat name; open question 4 is the path to per-context names if that choice is revisited.

## 16. Vectors

W0-08 generates these from `reference/`. Each has at least one passing and, where a rule rejects, one failing case. Vectors that need live MLS group state (`chat/exporter`, the `chat/roles` commit matrix, `chat/frank` with a real `AuthenticatedContent`, `chat/ds-api` commit sequences) need an MLS implementation driven from the reference; which one is an open question for W0-08 and the decision log.

| Vector set | Covers | Failing cases |
| --- | --- | --- |
| `chat/credential` | Section 2.1 identity bytes and binding, both kinds; an agent renewal Update (expiry extended, capabilities narrowed) accepted | Bad binding; name over 256 bytes; identity map over 512 bytes; agent without sponsor; agent leaf key not equal to `agentKey`; sponsor `tier` public; expired sponsor; attestation not bound under `hum/attest/1`; an agent Update naming a version that widens capabilities or changes `runtime`; extra key; non-canonical bytes |
| `chat/safety-code` | Section 2.2 | — |
| `chat/exporter` | Section 1.2 derivations from a given exporter secret (like `storage/keyring-derive`) | — |
| `chat/message-id` | Section 5.1 derivation with Hum URIs | — |
| `chat/content/*` | One set per Hum type owned by this spec: canonical bytes and decoded fields | Unknown version; missing required key; array over maximum; non-canonical; wrong `ExternalPart` count for `file-op` and `folder-index`; `deck-dealt` with a context from another lineage; `release-digest` whose deck does not match the release |
| `storage/external-part` (owned by `storage.md`) | The sealed reference to `ExternalPart` mapping and its reject rule, `storage.md` §3.2 | `external-part-bad-*` there |
| `chat/padding` | Section 4.3 bucket function measured on the `MLSMessage` bytes, and a padded Welcome | A length that is not a bucket; `authenticated_data` of the wrong length |
| `chat/frank` | Tag computation, `authenticated_data` layout, the report round trip of section 11.3 | Wrong key; altered content; tag from another group; wrong `group_context`; stamp over different data; bad binding; `keyset` not in the context's delivery lineage |
| `chat/stamp` | Section 12.6 signature | Wrong key; altered seq |
| `chat/tokens` | Issuance MAC, the RFC 9497 `DeriveKeyPair` issuer key derivation, token response verification against the directory key and, for the all-members group, against `chat.issuerKeys`; a fetch session with its cookie | Expired secret; token response under a key that differs from the directory entry or the manifest; cookie after 15 minutes |
| `chat/join` | A fixed-size ticket's HPKE sealing and opening with its membership proof, the Welcome handle derivation | Ticket sealed to another context's key; over 8 handles; plaintext not `TICKET_BYTES`; no proof; proof whose scope names another context or whose bound message is not these handles; context version older than the one before current; any of the proof's nullifiers already in a `join-record` for a live identity (a two-card entry policy where only the second nullifier is recorded); two tickets from one card opened by two greeters at once, where the greeter with the later `join-record` does not commit; a greeter that sends its record and fails before the commit, after which another greeter admits the same identity under the existing record; an Add of a new identity with no `join-record`, with the organizers group fetched 600 seconds past the Add (the leaf is removed); the same Add seen before the organizers group is fetched that far (kept); the same in a context with `entry` = `[0]` (kept); an agent leaf and a second device of a member, each with no record (kept); a pre-commit check against an earlier record for a different identity that is live (stop), pending for 30 minutes (stop), and not a member and two hours old (commit) |
| `chat/roles` | A signed `roles` message and the commit acceptance matrix of section 3.3 | Each rejected row; bad signature; lower serial; same-serial tie resolved by sequence |
| `chat/ignore` | The application-message drop list of section 3.3 | Muted sender; `replaces` by another key; `moderate` from a sender without the capability; frank mismatch |
| `chat/promote` | Section 6 flow as a message sequence, with `origin` | Confirm from a non-author; confirm with unresolved object; `origin` not equal to the message ID |
| `chat/directory` | A sequence of `directory` ops and the resulting list, including a snapshot | Lower serial; op below the snapshot's serial; same-serial tie; op from a sender without `channels` |
| `chat/agent-limits` | Section 3.3 rate-limit rule with the shared window boundary | Message past the limit dropped; message exactly at a window boundary |
| `chat/history` | Archive records round trip with `group_context` carried forward | Record outside the policy window |
| `chat/ds-api` | Every request and response body in section 12 and each error row; an invalid commit followed by a valid one; a 1,000-commit dead branch during which an old honest secret still issues tokens and MACs a commit; a flood that fills the 64-entry table and evicts only its own newest entries; a reset; inbox fetch in sequence order | Each error row of section 12.8; commit MAC under an unheld secret; a secret unused and unrefreshed for 48 hours |
| `chat/no-votes` | A scan of every chat vector for ballot, hand and shield structures (defined in `ballot.md` and `shield.md`) | A planted ballot in a message body is detected |

## 17. Open questions and assumptions

Decisions proposed by this spec, filed as `docs/decisions/0050-w0-05-mls-profile.md`, `0051-w0-05-delivery-authorization.md` and `0052-w0-05-franking.md`:

- The MLS profile: ciphersuite 0x0001, `basic` credentials with the identity map of section 2.1, all handshake as `PrivateMessage`, no external commits, MIMI content pinned at draft 09.
- Delivery authorization by per-epoch delivery secrets, a non-validating DS that sequences everything, commit MACs under held secrets, per-channel Privacy Pass tokens with issuer keys published in the directory, and an organizer reset.
- Franking by a keyed commitment in `authenticated_data`, a DS stamp, and the MLS signature as attribution; `origin` on the map is the message ID.

Open:

1. **Push notifications.** Every design that wakes a device for a channel gives the DS a per-device list. Options: polling only; a per-context "poll now" ping that reveals device-to-context membership; or a separate wake service that learns only that some device should poll. Recommendation: the third, specified in `services.md`.
2. **Voice channels.** `Chat-Server.png` shows one. Out of draft 0.1; likely MLS-keyed SFrame, as Discord's DAVE does.
3. **Display name uniqueness.** Self-asserted names with collision marking, or a per-context handle registry in the roles table.
4. **Member list visibility and per-context names.** MLS members always see their group's leaves, so the context setting "who sees the member list" can hide the roster screen but not the tree, and one chat identity key is visible across contexts. Either accept and say so in the UX, or move to pseudonymous per-context leaf credentials with names delivered through the roles message.
5. **External commits at scale.** Blocked on the previous item.
6. **Tree membership proof in reports.** Whether a report should include a proof that the leaf was in the tree at that epoch, and what the moderator checks it against.
7. **Device-to-device history.** Whether a person's own new device gets their history outside the context policy, and how.
8. **DS retention.** 30 days of ciphertext, 14 days of Welcome and tickets, 48 hours of dead secrets are placeholders.
9. **MLS extension registration.** 0xF001 is private use; whether to register `hum_tree_ref`.
10. **Fork detection.** Whether phones should exchange epoch authenticators in `checkpoint` messages to catch a DS that partitions a group.
11. **Thread support.** MIMI `topicId` is reserved for it.
12. **MLS implementation for vectors.** The reference is Python; the vectors that need group state need a pinned MLS implementation. Proposed in ADR 0050, as the owner's choice: OpenMLS 0.9.0 with `PURE_CIPHERTEXT_WIRE_FORMAT_POLICY` for the Rust core, and `mls-rs` driven from the reference through `mls-rs-uniffi` for the vectors, so the vectors come from an implementation independent of the code under test (`docs/research/seam-libraries.md`).
13. **The design doc's and threat model's DS rows** are narrower than section 12.10. The owner should update them.
14. **Per-context signing keys.** A signed map object in a sealed context carries the author's chat identity key in its bundle, so anyone holding the bundle learns that this key is a member. `issue-map.md` raises deriving a per-context signing key from the chat identity key. Not taken in draft 0.1: it is the same question as open question 4 (per-context names) and should be decided with it.
15. **Per-instance agent leaf keys.** `agent-sponsor.md` raises letting an agent's leaf key differ from `agentKey`, bound by a signature as human devices are. Not taken in draft 0.1: leaf key = `agentKey` keeps the attestation binding and the credential check one step, and nothing yet needs several instances of one agent.
16. **One chat identity per card per context.** Section 2.5 scopes the join nullifier per person per context, so a resident card admits one chat identity to a context, and greeters keep the nullifier set. Because cards are re-issued with a new nym secret every issuer epoch, the rule bounds a person to one new chat identity per issuer epoch per context, not one ever. The alternative, a per-ticket scope with any number of chat identities per card, needs no `join-record` but lets one person hold many chat names at once, each with its own issue-map rate limits. Owner's call; the spec takes the first and accepts the per-epoch limit.

Assumptions about sibling specs:

- `credentials.md` (read, reconciled): the membership proof scopes `hum/delivery-tokens/1 ‖ token_key_id ‖ day` and `hum/join/1 ‖ context lineage CID` are adopted there, the join presentation's bound message being `SHA-256(canonical CBOR of handles)`, so the nullifier is per person; that spec's identifier table records that the organizers group holds join nullifiers beside chat identities in `join-record` messages, the one card-derived value that sits beside a chat identity by design, which is why section 5.17 keeps them inside that MLS group and out of every archive; every scope's nullifier is unlinkable to every other and to the ballot scope; presentations are about 0.6 KiB per card, which sizes `TICKET_BYTES`; the chat identity key is a software key that reaches chat-only devices by the chat-only export and replacement phones by the full backup (ADR 0023); voting is single-device with no device-to-device transfer of hand, shield or receipts; agents hold no voting credential; an open entry policy yields no nullifier.
- `context.md` (read, reconciled): `chat.allMembers`, `chat.organizers`, `chat.delivery`, `chat.greeting` (key 11.3, rule C11), `agents.addRole` (key 17), `storage.history`, `storage.keyringHistory` and `storage.retention` and `chat.issuerKeys` (chat key 4, rule C11) are used as that spec defines them.
- `storage.md` (read and reconciled): sealed reference §3 and its ExternalPart reject rule, keyring §4 (including `keyring-share`), folder state rules §5.3 to §5.5, deletion §8 and public copies §9 are used as written; the `file-op` bytes, the `folder-index` framing, the `hum:blob:` url form and the `token-key` gossip are this spec's. Its assumptions A1, A2, A4 and A5 are answered in sections 4.4, 5.1 and 5.7, 1.2, and 3.1 respectively; no `keyring-rotate` event exists in draft 0.1.
- `services.md` (read): the `service` manifest with `kind` = `delivery` (`tokenIssuers`, the key 16 `issuer` map, no stamp field), the CBOR error map and code table, token rules T-1 to T-4, the `organizer` credential class and relay rules O-1 to O-5 apply. Its summary row for the DS lists KeyPackage publish and fetch and an acknowledge call; this spec has neither, and it says the sibling spec wins.
- `issue-map.md` (read): `origin` is the message ID; the promote request and merge proposal are sections 5.3 and 5.5; the unsigned path sends nothing in chat; the chat signing key is the chat identity key of section 2.1.
- `agent-sponsor.md` (read, reconciled): capabilities `post`, `greeter`, `history`, `author-map`, `take` (codes 0 to 4); rate limits `window`, `mapObjects`, `messages`, `takes`; runtimes `member-hardware` (1) and `enclave` (2) for shared agents; the leaf key equals `agentKey`; the credential carries the sponsor lineage and version CIDs; the attestation binding `hum/attest/1`; the commit rules in "The membership event" and the sponsor-version rules of section 3.3 are shared; `label` is capped at 64 bytes there (rule AS-7), inside the credential's 256-byte `name` cap, so a published shared agent can always be added.
- `deck.md` and `release.md` (read) are pointed at by CID; `release-digest` is sent for the version `release.md` marks final. `ballot.md` and `shield.md` define the structures the `no-votes` scan looks for.
