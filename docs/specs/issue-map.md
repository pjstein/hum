# Hum Issue Map Spec — Draft 0.1

Oct 6, 2026 · W0-04 draft, revised after review; not yet approved

## Scope

This spec defines the three manifest types that make up an issue map: `issue`, `position` and `argument`. A sub-question is an `issue` with a parent issue. These are the deliberation objects that feed decks: a deck pins position versions as its cards, and arguments appear on the back of the card.

It builds on `manifest.md` for the envelope, CIDs, logs, blobs and keyrings. It defines:

- the shared body schema and the `refs` each type uses;
- authorship: who may publish an object, and how a log or a phone checks it without learning anything about how the author votes;
- promotion from chat, revision, withdrawal, merging and moderation, all as versions of the same lineage;
- how a released deck annotates the map;
- the rules a conformance vector tests.

Out of scope: the chat content types that carry proposals (`chat.md`), the ballot that records re-votes and argument ratings (`ballot.md`, `deck.md`), the credential primitives (`credentials.md`), and the sealed blob format (`storage.md`). Where this spec depends on one of those, the dependency is named in "Assumptions about sibling specs".

Conventions follow `context.md`: body keys are small uints, enumerations are uints with the names given in the tables, text is UTF-8 NFC with no control characters and a byte limit, and a CID in a signed payload or a scope is its 33-byte form (algorithm byte plus digest).

## At a glance

An issue map is a tree of small manifests. Each node is a manifest whose text lives in a blob, so the log holds structure and commitments and never a person's words.

```
issue "Ignored repair requests: what do we do?"
├─ position "File group complaints with code enforcement first."
│  ├─ argument (pro)  "…"
│  └─ argument (con)  "…"
├─ position "If repairs are ignored for 60 days, organize a rent strike."
│  ├─ argument (pro)  "Escrowing rent keeps it legal…"
│  └─ argument (con)  "Strikers risk eviction filings…"
└─ issue (sub-question) "Which buildings would actually join a strike?"
   └─ position "…"
```

Every object is one of three manifest types. All three share one body schema, differ only in what their `parent` may be, and are authored the same way.

| Type | `kind` | `parent` must be | Becomes |
| --- | --- | --- | --- |
| `issue` | 0 | absent (top-level issue) or an `issue` (sub-question) | An issue channel's subject; a group of cards |
| `position` | 1 | an `issue` | A card in a deck |
| `argument` | 2 pro · 3 con | a `position` | The back of its position's card |

`kind` numbering matches `chat.md`'s `promote-proposal` (1 position, 2 pro, 3 con), with 0 for issues; a sub-question is `kind` 0 with a parent.

## Authority and authorship

The manifest spec's type registry says these types are signed by "the author's chat key, or an anonymous membership proof; authority is the context". This section makes that precise.

- **`authority` is the context's keyset lineage.** Every object in a context's map names the same authority, so a phone can list a whole map by asking a log for entries with that authority and these three types. The log entry carries type and authority, never content.
- **The context's sign threshold is one way to author, not the only one.** Verification step 6 in `manifest.md` (a threshold of the authority's `sign` keys) is replaced for these types by the authorship check below.
- **Authorship travels beside the envelope,** in the bundle, exactly where signatures travel. It is never hashed into the CID, so a deleted author identity leaves no trace in the log.

### The four forms

| Form | Body `author` | Proof in the bundle | Who can check it |
| --- | --- | --- | --- |
| Context | 0 `authority` | The context's `sign` threshold under `hum/manifest/1` in the bundle's `signatures`, no `authorship` | Anyone |
| Member, signed | 1 `member` | A signature by the author's chat identity key under the domain string `hum/author/1`, plus that public key, plus a membership proof with a per-object scope | Anyone checks the signature and the membership proof. Members also match the key to a credential in the context group's tree and show the chat name |
| Member, unsigned | 2 `anonymous` | A membership proof with a rate-limit scope | Anyone |
| Agent | 3 `agent` | A signature by the agent key under `hum/author/1`; `refs.sponsor` names the agent-sponsor manifest version | Anyone, by resolving the sponsor manifest and the pinned context's `agents` policy |

`author` names the lineage's author and is frozen. The bundle of every version matches it, with one exception: a **moderation version** is a version greater than 1 whose bundle carries the context's `sign` threshold in `signatures` and no `authorship`, and whose body sets `moderation`. The context may publish a moderation version of any object whatever its `author`. Because `author` is inside the signed bytes, a label such as `agent` can't be stripped without invalidating the object.

### Signatures under `hum/author/1`

The signed payload is the ASCII string `hum/author/1` followed by the object's CID (33 bytes). Ed25519 only in draft 0.1. The chat identity key is the per-person Ed25519 key that `chat.md` section 2.1 puts in every leaf credential (`identity`), not a per-device leaf key, so one person signs the same way from every device. The agent key is the `agentKey` in the sponsor manifest (see `agent-sponsor.md`), which is also the `identity` of the agent's kind 2 credential.

The chat identity key is one key per person across every context, so a signed object in a sealed context publishes, in a public bundle, that this key's holder is a member there. A signed object's bundle also carries its membership proof, and a proof shows its public card fields in the clear: the issuer authority, the issuer epoch, the key id and message count, and an empty `branches` (`credentials.md`, identifier table, "Public card fields" and "Public card fields beside the chat identity"). Every valid card from one issuer presents identical public fields, and `context.md` rule C16 gives every leaf of `entry` exactly one verifier and no `any` node. So every member's proof shows the same public fields, which the public policy already names: a signed object publishes the chat identity beside "a member of this context" and nothing finer. The author screen says one thing before a signed post: "your chat name is visible to anyone who can see this map". The unsigned form exists for people who don't want that. One residual: in the first hour after the issuer's epoch turns, a proof may carry either of two epoch values (`credentials.md`, "Validity").

The same fields bound what unsigned objects reveal: unsigned objects in a context all show the same public fields, so the fields link no two of them and link none to a signed object, and nothing in them names a person or a pseudonym. A per-context signing key derived from the chat identity key would remove the leak; that is a `chat.md` change and is raised there.

### Membership proofs

A membership proof shows the prover holds a credential admitted to the context, without revealing which one. `credentials.md` defines the primitive; this spec fixes two inputs to it:

- a **scope**, a public input the verifier reads in the clear; the nullifier is a deterministic function of the identity secret and the scope, so different scopes give unlinkable nullifiers;
- a **bound message**, also a public input, which the proof commits to the way a Semaphore proof commits to its signal. A proof is valid only for the bound message it was made with.

For both forms below the bound message is `hum/author/1` ‖ object CID (33 bytes). Without it a valid proof could be copied out of one object's public bundle and attached to another, which would let a non-member publish as "some member" or burn an honest author's slot.

The policy a membership proof proves is the pinned context's `entry` policy (`context.md`), because `entry` is what admits a member to chat, map and files. An `entry` policy with no credential leaf yields no nullifier, so in such a context the unsigned form is unavailable and the author screen offers the signed form only. `credentials.md` decides the exact statement proved; see assumptions.

| Use | Scope bytes | Nullifier rule |
| --- | --- | --- |
| Signed object, any version | `hum/author-once/1` ‖ object CID | Each nullifier appears at most once. It links nothing, because the scope is unique to this object |
| Unsigned object, any version | `hum/author-slot/1` ‖ context lineage CID ‖ window (uint64, big-endian) ‖ slot (uint16, big-endian) | Each nullifier appears at most once in the log of record. `window` is `issued ÷ AUTHOR_WINDOW` (integer division; see Limits). `slot` is less than the effective unsigned limit |

Why the signed form carries a membership proof at all: a log must check membership before appending, and a log is not a member, so it can't check a chat identity key against the MLS tree. The proof costs the author nothing and reveals only "some member".

Why unsigned objects use slots instead of one scope per window: with one scope per window, all of a person's unsigned posts in a week would share a nullifier, and one slip (a signed object with the same nullifier) would unmask all of them. With slots, the verifier sees `(window, slot)` in the clear, checks the slot is in range, and rejects a reused nullifier. Nothing links slot 3 to slot 4, and nothing links either to a signed object, a chat name or a vote. The cost is that unsigned posting is capped per window.

**Limits.** `context.md` key 16 (`map`) carries `unsignedPerWindow`, `signedPerWindow` and `agentObjects`. The protocol constants below bound them: the effective limit is the smaller of the context's value and the ceiling. A context can tighten and never loosen. The window length is not a context setting: it is the protocol constant `AUTHOR_WINDOW` (86,400 seconds, `context.md`), because the log computes slot scopes with it and a per-context window would change every slot scope when it moved.

| Name | Value | Meaning |
| --- | --- | --- |
| `AUTHOR_WINDOW` | 86,400 s | The rate-limit window for every author form, defined in `context.md`; `window` in a slot scope is `issued ÷ AUTHOR_WINDOW` |
| `UNSIGNED_PER_WINDOW_MAX` | 20 | Ceiling on `ctx.map.unsignedPerWindow` |
| `SIGNED_PER_WINDOW_MAX` | 60 | Ceiling on `ctx.map.signedPerWindow` |
| `AGENT_OBJECTS_MAX` | 20 | Ceiling on `ctx.map.agentObjects` |
| `MAX_POSITIONS_ACTIVE` | 200 | Active positions under one issue before new ones land `proposed` |
| `MAX_ARGUMENTS_ACTIVE` | 40 | Active arguments under one position before new ones land `proposed` |
| `AGENT_PROPOSAL_TTL` | 2,592,000 s | Longest `expires` − `issued` for an agent-authored object |

**Windows and clocks.** `window` derives from `issued`, which `manifest.md` says is never trusted for ordering. So the clock check runs only at the log, on submission: the log accepts a window equal to its own current window or the one before it (clock skew and slow uploads), and nothing else. A phone syncing later does not check `window` against any clock; it checks only slot range and nullifier uniqueness. The consequence is that a person can spend the previous window's unused slots in the first moments of a new one, so the instantaneous burst is twice the per-window limit. Accepted in draft 0.1.

**Several logs.** A context names up to 8 logs, and the first is its log of record. An object is valid only if it is in the log of record. Nullifier uniqueness (IM-7) and rate limits (IM-15) are counted there and nowhere else, by the log at submission and by phones when they sync; positions in two different logs are never compared. The issuer key is read at the object's position in the log of record, and other listed logs accept the object on proof of inclusion in it (`credentials.md`, "Verification rules"). If the log of record was unreachable for more than an hour, the object's `issued` is stale and the author's phone rebuilds the object with a fresh `issued`, which gives a new CID, a new edit key and a new proof. Before rebuilding, the phone asks the log of record whether the old CID is there. If a rebuilt unsigned object is refused under IM-7, the first one was logged after all: the phone treats the old object as published and uses the next slot for anything new.

Authoring proves the `entry` set; ballots prove `vote` under different scopes, and the scopes above never collide with any ballot scope, because every ballot scope starts with a different prefix (`ballot.md`). This is the one place this spec touches the voting pseudonym machinery, and it does so only through scope separation and the bound message. See "Seam".

### The `authorship` bundle field

`services.md` carries the proof in the bundle's `authorship` field as one byte string. It is deterministic CBOR:

| Key | Name | Type | Present for | Meaning |
| --- | --- | --- | --- | --- |
| 0 | form | uint | all | 1 member, 2 anonymous, 3 agent. Form 0 (authority) has no `authorship`; its signatures go in the bundle's `signatures` field |
| 1 | key | bytes(32) | 1 | The chat identity public key |
| 2 | sig | bytes(64) | 1, 3 | Ed25519 signature over `hum/author/1` ‖ CID |
| 3 | slot | uint | 2 | The slot index; the verifier recomputes the scope from the context lineage, `issued` and this slot |
| 4 | (unused) | — | — | Was `nullifier`. Removed (ADR 0104): a proof yields one nullifier per card and the verifier derives all of them from `proof`, so a carried copy added nothing. The key is not reused, and a field with key 4 makes the `authorship` map invalid |
| 5 | proof | bytes | 1, 2 | The membership proof, encoded as `credentials.md` defines, over the recomputed scope and the bound message `hum/author/1` ‖ CID |
| 6 | editSig | bytes(64) | version > 1 | Ed25519 signature over `hum/edit/1` ‖ CID by the object's `editKey` |

The scope is never carried; a verifier recomputes it. Vectors fix the bytes of each form (`im-authorship-*`).

### Edit keys

Every object's first version carries an `editKey`, a fresh Ed25519 public key generated for this object alone. Versions after the first carry, in the bundle, a signature by the edit key over `hum/edit/1` ‖ new version CID, in addition to the authorship proof for that version. Moderation versions carry neither.

The edit key is how an unsigned author proves they wrote the first version without linking it to anything. Signed and agent authors use it too, so revision works the same way for everyone. The edit secret is derived, not stored: `HKDF-SHA256(IKM = the person's edit root, salt = "hum/edit-key/1", info = SHA-256 of the canonical envelope bytes of version 1 with body key 2 removed)`, where the edit root is a 32-byte secret in the same per-person backup that carries the chat identity key (`credentials.md`). The `info` cannot be the version 1 CID, because that CID hashes `editKey` itself; stripping key 2 and re-encoding deterministically gives bytes that are fixed before the key is chosen and that any device can recompute from the logged version 1. A restored phone therefore loses nothing. The output is a PRF of a secret root, so two edit keys reveal nothing about sharing one. For an object the context authority writes at version 1, the committing organizer's phone holds the edit root; later versions by the context are moderation versions and need no edit key.

## Body

All three types share this body.

| Key | Name | Type | Required | Frozen | Meaning |
| --- | --- | --- | --- | --- | --- |
| 0 | kind | uint | yes | yes | 0 issue · 1 position · 2 pro · 3 con. Must agree with the envelope type |
| 1 | author | uint | yes | yes | 0 authority · 1 member · 2 anonymous · 3 agent. Must match the authorship form in the bundle, except in a moderation version |
| 2 | editKey | bytes(32) | yes | yes | Ed25519 public key, fresh for this object |
| 3 | state | uint | yes | no | 0 proposed · 1 active · 2 withdrawn · 3 merged · 4 hidden (see "States and moderation") |
| 4 | sealed | bool | yes | yes | True when the text blob is sealed under the context keyring |
| 5 | epoch | uint | iff sealed | after dealt | Keyring epoch that decrypts `refs.text` |
| 6 | lang | text ≤ 16 bytes | no | no | BCP 47 tag of the text, pattern `^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$`, used by duplicate detection |
| 7 | origin | bytes(32) | no | yes | MIMI message ID (as `chat.md` defines it) of the chat message this object was promoted from. Allowed only with `author` = 1 |
| 8 | assisted | bool | no | no | The author used a personal agent to draft the text. Self-declared |
| 9 | moderation | uint | moderation versions only | no | 0 activate · 1 hide · 2 merge · 3 withdraw · 4 reparent |

"Frozen" means the field may not change between versions. "After dealt" means it may change until the object is dealt (defined below), then not.

Text limits are in bytes of UTF-8, measured on the plaintext: issue 400, position 560, argument 2,000. `chat.md`'s `promote-proposal` allows 2,000 bytes; the author edits before posting, so a longer message is cut by hand, not by the protocol. A conformance check reads the plaintext and counts.

Nothing in the body is a person's words or identity. The text is a blob. The author's chat identity key travels in the bundle, outside the CID, and only when the author chose to sign; the chat name is never in the bundle at all, members look it up in their tree.

The Global context is a context like any other; its lineage CID is a protocol constant clients ship with, so a deck can check a Global card belongs to it (`deck.md` rule D6). Where that constant is published is for `context.md` and `DECISIONS.md`.

### refs

| Name | Required | Points to |
| --- | --- | --- |
| `context` | yes | The latest version of the context lineage logged before this object (see IM-3) |
| `parent` | per type table | The parent object's version 1 CID (its lineage), so re-versioning a parent doesn't orphan its children |
| `text` | yes | The text blob: a public blob of media type `text/plain; charset=utf-8`, or a keyring-form sealed blob |
| `sponsor` | iff `author` = 3 | The agent-sponsor manifest version whose `agentKey` signed |
| `replaces` | no | Version 1 CID of an object this one supersedes (withdraw-and-replace, or a member adopting an agent's proposal) |
| `mergedInto` | iff `state` = 3 | Version 1 CID of the surviving object |
| `take` | no | A take version that backs an argument ("Back it up with a Studio take") |
| `evidence/<n>` | no | Public blobs cited by the text, `n` from 0, at most 8. In sealed contexts evidence is cited inside the sealed text instead, as sealed references |

`parent`, `replaces` and `mergedInto` name lineages by their version 1 CID, because the relationship is to the object, not to one wording of it; a verifier checks the named manifest has no `prev` (IM-2, IM-11). Every other ref names a version, as `manifest.md` requires. A client resolves a lineage to its current version through the log.

### Sealed text

In a context whose manifest has `sealed` = true (`context.md`, body key 1), the object's `sealed` is true and `refs.text` is the CID of a keyring-form sealed blob: `storage.md` format 2, whose header carries a fresh 16-byte salt and whose key is HKDF(epoch secret, salt). The manifest carries only the CID and `epoch`; a client builds the keyring-form reference from those two fields (`storage.md` section 3). Non-members see a manifest with a CID and an epoch and nothing more. Media type is `text/plain; charset=utf-8` either way.

When a member is removed, the keyring advances. New objects use the new epoch. Existing text stays under its old epoch; newcomers get older epochs only if the context's history policy allows (`storage.md` section 4.2 and its open question 1). An object's `epoch` may be bumped in a new version (re-encrypting the text under a newer epoch) until it is dealt.

## Lifecycle

### Posting

1. The author writes the text on the phone (`IBIS-Author`). The phone runs duplicate detection (below) and shows a near match, if any, with "Merge into it" and "It's different".
2. The author picks a form: their chat name, or unsigned. The screen states what signing publishes (the chat name). The phone derives the edit key.
3. The phone uploads the text blob (public or sealed), builds the manifest, computes the CID, produces the authorship proof, and submits the bundle to the context's log of record (the first entry of `logs`), then to each other listed log with the log of record's inclusion proof in the bundle. If no response comes back, the phone asks the log of record for the CID (`GET /v1/log/entry/{cid}`) before doing anything else, because it cannot tell an unreachable log from a lost response.
4. The object exists for other phones once it has an inclusion proof against a witnessed checkpoint, like any manifest.

### Promotion from chat

Any message in an issue channel can become a position, pro, con or sub-question. The words belong to the message's author, so the author confirms before anything is published. `chat.md` section 6 defines the message flow (`promote-proposal`, `promote-confirm`); this spec defines what lands on the map.

- Anyone with the chat `post` capability, including a shared agent, sends a `promote-proposal` quoting the message with a proposed kind and parent. The author may also start from their own message with no proposal.
- The author's phone opens the author screen pre-filled, and the author picks signed or unsigned.
- Signed: the phone publishes the object with `author` = 1 and `origin` = the quoted message's MIMI message ID, then sends `promote-confirm` naming the object CID. Phones in the channel check the object's `authorship.key` equals the confirmer's chat identity key before badging the message. The message ID is computed from the plaintext and a salt the delivery service never sees, so `origin` tells the delivery service nothing; the franking tag would, which is why it is not used.
- Unsigned: the phone publishes the object with `author` = 2 and no `origin`, and sends no confirm. The channel sees the map change and nothing else. A conformance vector checks that an unsigned object never carries `origin` (IM-8).
- Declining sends a `promote-confirm` with the decline outcome and publishes nothing.
- Agents may propose and never confirm, because a confirm needs the author's key.

### Revision

A version 2 or later of an object changes its text, parent, state or epoch within the frozen-field rules. It is authored by the same author (edit key signature plus a fresh authorship proof of the same form) or, as a moderation version, by the context authority.

An object version is **dealt in a log** when a deck manifest version whose `card/<i>`, `card/<i>/pro` or `card/<i>/con` ref names it has a lower leaf index in that log (`deck.md`). An object is **dealt** when any of the context's logs says so. A log builds this index from the envelopes it keeps (`services.md`); a phone builds it from the decks it has synced. From then on `text`, `epoch` and `parent` are frozen, and the only changes left are state changes. The decision and its reasons are in `docs/decisions/0042-w0-04-revise-until-dealt.md`. In short: votes refer to exact words, and a release annotates the words that were voted on, so wording stops moving the moment an organizer puts it in a deck. Before that, authors can fix their own text freely, and a deck draft that pins the object is the first thing to freeze it.

After it is dealt, an author who wants different words withdraws the object and posts a new one with `refs.replaces` naming the old lineage. The map shows the chain. Any open deck keeps the card it dealt. A release reports the dealt version's CID, and annotations attach to that CID.

### Withdrawal and deletion

- **Withdraw:** a new version with `state` = 2. The lineage ends there; no later version is accepted. Clients list withdrawn objects collapsed, and decks may not pin them (`deck.md` D7).
- **Delete the text:** the author presents the blob's delete secret to the store (`storage.md`). The CID stays in the log; clients show the object as "removed by its author". A release carries no statement text (`release.md`), so a withdrawn-and-deleted position that was dealt appears in the release's tables by CID and renders as removed.
- Withdrawing never retracts a vote already cast. The deck is frozen and the release is a sum; a withdrawn card is reported like any other.

### Merging

Duplicate detection runs on the phone at authoring time. The reference client normalizes both texts (NFKC, case fold, strip punctuation, split on whitespace) and flags a token-set ratio of 0.8 or more against the parent's existing children in the same `lang`. Clients may do better; the `im-dup-detect` vectors are informative, not conformance. The author decides at that moment. Picking "Merge into it" posts nothing.

After posting, three parties can merge:

| Who | How | What changes |
| --- | --- | --- |
| The duplicate's author | A version with `state` = 3 and `refs.mergedInto` naming the survivor's lineage, signed by the edit key | The duplicate collapses under the survivor |
| The context authority | A moderation version with `moderation` = 2 and the same fields | Same |
| A member or shared agent | A merge proposal in chat (`chat.md`), which the author or an organizer acts on | Nothing, until one of the above happens |

Arguments under a merged position move with it: an argument's author or the context authority may publish a version whose new `parent` is the lineage the old parent was merged into (transitively). No other reparenting is allowed, and a dealt argument cannot move at all (IM-12 wins over IM-11); it stays attached to the merged position and is shown under the survivor as "from a merged position".

A dealt position may be merged. The card stays in its deck; the map shows it merged and points at the survivor.

### States and moderation

| State | Meaning | Who sets it |
| --- | --- | --- |
| 0 proposed | Visible, labeled as a proposal, not dealable | The author at version 1, when the context's `perms.cards` requires review, the author is an agent, or the parent is full |
| 1 active | Normal | The author at version 1 when allowed; otherwise a moderation version (`moderation` = 0) |
| 2 withdrawn | Ended by its author or the context | Author or moderation version |
| 3 merged | Ended; its meaning lives on in `mergedInto` | Author or moderation version |
| 4 hidden | Ended by moderation; shown as "removed by a moderator", text may remain for appeals inside the context | Moderation version only |

The initial state follows the context's `perms.cards` setting (`context.md`, body key 5):

| `perms.cards` | `member` and `anonymous` | `agent` | `authority` |
| --- | --- | --- | --- |
| 0 organizers | proposed | proposed | active |
| 1 members, reviewed | proposed | proposed | active |
| 2 any member | active | proposed | active |

Two overrides: a position whose issue already has `MAX_POSITIONS_ACTIVE` active positions, or an argument whose position already has `MAX_ARGUMENTS_ACTIVE` active arguments, counted at the object's log position in the submitting log, lands proposed whatever the policy. Issues (including sub-questions) follow the same table as positions.

Agents never start an active object. A shared agent's drafted position or argument sits in the map as a labeled proposal until an organizer activates it, a member adopts it (posts their own object with `refs.replaces` naming the agent's), or it expires. Agent-authored objects carry `expires` at most `AGENT_PROPOSAL_TTL` after `issued`. This is the rule that keeps a flood of agent text from ever becoming a flood of cards.

Transitions: 0 → 1 by a moderation version only; 1 → 2, 3 or 4; 0 → 2, 3 or 4. Nothing leaves 2, 3 or 4. A moderation version may change `state`, `moderation`, `refs.mergedInto` and (for `moderation` = 4) `refs.parent`, and nothing else. A conformance vector exists for every forbidden transition.

Moderation reports travel in chat with message franking (`chat.md`). The map's part is only the hidden state. A hidden object's text blob can be deleted by a context order, as `storage.md` defines.

### Rate limits

Agents are the easiest way to flood a map; people with scripts are the second. Limits are enforced where the proofs are visible: at the log on submission, and on every phone when it syncs.

| Author form | Counted by | Effective limit per `AUTHOR_WINDOW` |
| --- | --- | --- |
| anonymous | Slots per window, in the proof scope | min(`ctx.map.unsignedPerWindow`, `UNSIGNED_PER_WINDOW_MAX`) per person |
| member | Chat identity key in `authorship` | min(`ctx.map.signedPerWindow`, `SIGNED_PER_WINDOW_MAX`) per key |
| agent | Sponsor authority, and all agents together | Both hold: the sponsor manifest's `rateLimits.mapObjects` per its own `window`, summed over the sponsor's agents in this context; and min(`ctx.map.agentObjects`, `AGENT_OBJECTS_MAX`) over every agent in the context |
| authority | — | None |

Each version counts as one object. A log that receives an over-limit object refuses it with a retry-after. To count the member form the log keeps `(chat identity key, count)` for the current and previous window and nothing longer; `services.md`'s logging table names that retention. A phone that sees over-limit objects (because a log was lax) ignores the excess, in log order.

Size limits: text limits above, at most 8 evidence refs, and the active caps in "States and moderation".

## After a release

A release never changes a map object. Phones compute annotations from the release's tables and show them next to the dealt version. Nothing is written back to the log.

Join keys, from the tables in `release.md`:

| Annotation on | From table | Key | Shows |
| --- | --- | --- | --- |
| Position | `tallies` | `statement` = the dealt position version CID | Agree share with a 90% interval; `Common ground`, `Divides` or `Leans yes` labels |
| Position | `group_tallies` | (`group`, `statement`) | Agree share per opinion group |
| Argument | `moved` | `argument` = the dealt argument version CID | How many re-votes named it as what moved them |
| Argument | `ratings`, `group_ratings` | (`group`, `argument`) | "Does this move you?" share per group ("fair to A 66% · B 58%" on `IBIS-Map`) |

Labels are post-processing with the noise math in `take.md`, "Noise math", at z = 1.645 (90%), in binary64, with `take.md`'s order of operations (gap test on raw `N`, then `p` and σ_p, then clamp for display). Let `p` and σ_p be the overall agree share from `tallies`, and `p_g`, σ_g the per-group shares from `group_tallies` when the release has them.

- `Divides`: the release has groups, and there exist two groups `a`, `b` with `|p_a − p_b| ≥ 1.645 · √(σ_a² + σ_b²)` and `p_a > 0.5 > p_b` after clamping.
- `Common ground`: not `Divides`, `p − 1.645 σ_p ≥ 0.6`, and, when the release has groups, every group has `p_g − 1.645 σ_g ≥ 0.6`.
- `Leans yes`: not `Divides`, not `Common ground`, and `p − 1.645 σ_p > 0.5`. `Leans no`: `p + 1.645 σ_p < 0.5`.
- Otherwise no label. A cell that fails the gap test takes no part in the label and the position shows no label.

A position replaced after being dealt shows the annotation on the old lineage, with the new wording linked. A sub-question gathers positions for the next deck; its parent issue's card shows "voted in <deck>" once any of its positions was dealt.

## Validation rules

Verification for these three types replaces `manifest.md` step 6 with the authorship check (IM-6, IM-7 and IM-15) and adds the rest as step 10.

- **A log** runs the authorship check at submission, because it is its step 6, with its own clock: for forms 1 and 2 the proof's disclosed epoch is the current one, or the previous period's during the first 3,600 seconds of a period, and the envelope `issued` is within 3,600 seconds of the log's clock, bounds included (`credentials.md`, "Validity"). The log that makes this check is the context's log of record, the first entry of `logs` in the pinned context version. It runs IM-1, IM-2, IM-3, IM-4a, IM-5 and IM-8 to IM-14 as step 10. It does not resolve blobs (`services.md`), so IM-4b is not run there.
- **A phone** runs every rule when it syncs. It verifies each membership proof with the logged-presentation rule of `credentials.md` ("Validity", third row; ADR 0101): the disclosed epoch is checked against the object's `issued` and the issuer key against the verifier version in force at the object's log position, with no clock, so an object written in an earlier issuer epoch stays valid. An aggregator or phone verifying a deck's pinned objects (`manifest.md` step 9) does the same. A logged version that fails a rule is invalid; the lineage continues from the last valid version, and a later version whose `prev` is the invalid one is itself invalid.

| Rule | Check | Rejects |
| --- | --- | --- |
| IM-1 | Envelope `type` is `issue`, `position` or `argument`, and body `kind` matches it (`issue` ↔ 0, `position` ↔ 1, `argument` ↔ 2 or 3) | type/kind mismatch |
| IM-2 | `parent` present and of the right type per the type table, and resolves to a manifest with no `prev`; absent only for a top-level `issue` | position without parent; argument whose parent is an issue; parent named by a version 2 CID |
| IM-3 | `refs.context` resolves to a context version whose authority equals the envelope `authority`, and no later version of that context lineage has a lower leaf index than this object in the submitting log | wrong authority; stale context version |
| IM-4a | `refs.text` present; `sealed` ⇔ `epoch` present | missing text; sealed without epoch |
| IM-4b | Phones only: when `sealed`, the blob's first byte is `0x02` (keyring form, `storage.md` §4.3); when not sealed, media type is `text/plain; charset=utf-8`; the plaintext is within the byte limit for `kind` | wrong format; over-length |
| IM-5 | `sealed` equals the pinned context version's `sealed` | plain text in a sealed context; sealed text in a public one |
| IM-6 | Either the version is a moderation version (version > 1, `signatures` carries the context's `sign` threshold under `hum/manifest/1`, no `authorship`, `moderation` set), or `authorship.form` equals `author` and verifies: form 1, `sig` by `key` over `hum/author/1` ‖ CID and a valid membership proof (valid under `credentials.md` P1–P8 with the logged-presentation epoch rule: the log's clock and `issued` within one hour at submission, the object's `issued` and log position afterwards) with scope `hum/author-once/1` ‖ CID and bound message `hum/author/1` ‖ CID; form 2, a valid membership proof with the recomputed slot scope, `slot` below the effective unsigned limit, and the same bound message; form 3, `sig` by the `agentKey` of the manifest `refs.sponsor` names over `hum/author/1` ‖ CID, that manifest valid, unexpired and unretired at this log position, its `tier` shared, its `capabilities` including `author-map`, and its envelope `authority` admitted by the pinned context's `agents` (`anySponsor`, or listed in `sponsors`); form 0 at version 1, `signatures` carries the context's `sign` threshold | every mismatch and every bad proof; agent not admitted |
| IM-7 | Every nullifier the presentation yields, one per card (`credentials.md`, "Every nullifier counts"), is new under `hum/author-once/1` or `hum/author-slot/1` for a different CID in the log of record. All of them are derived from `proof`; the `authorship` field carries no nullifier. Under `context.md` C16 every member presents the same set of authorities, so the count of nullifiers is the same for everyone. The log's seen-set holds all of them | reused slot or proof, by any card |
| IM-8 | `origin` absent unless `author` = 1 | origin on an unsigned or agent object |
| IM-9 | `sponsor` present iff `author` = 3; `moderation` present iff the version is a moderation version | label stripped or misplaced; authority signature with no `moderation` |
| IM-10 | Version 1 `state` matches the pinned context's `perms.cards` and the author form per the initial-state table, with the active-cap override counted at this log position | agent object born active; 201st active position born active |
| IM-11 | Version > 1: frozen fields unchanged; unless a moderation version, `editSig` under `hum/edit/1` present and valid and the authorship form equals version 1's; the state transition is allowed; `mergedInto` present iff `state` = 3 and names a manifest with no `prev`; `parent` changed only to the lineage the old parent is merged into; a moderation version changes nothing but `state`, `moderation`, `mergedInto` and (for `moderation` = 4) `parent` | every forbidden change |
| IM-12 | Version > 1 of a dealt object changes none of `text`, `epoch`, `parent` | edit after dealt |
| IM-13 | Agent-authored: `expires` present and at most `AGENT_PROPOSAL_TTL` after `issued` | missing or long expiry |
| IM-14 | At most 8 `evidence/<n>` refs, `n` contiguous from 0; `lang`, if present, within its length and pattern | too many or gapped; bad lang |
| IM-15 | Rate limits: the object does not exceed its author form's effective limit for its window (both agent limits), counted over this log at the log and over the context's logs on a phone; form 2 at the log: `window` is the log's current or previous window | over limit; stale window |

## Example

The readable JSON view of a con argument, unsigned, in a sealed context:

```json
{
  "spec": 1,
  "type": "argument",
  "authority": "c6a0te…p3e",
  "version": 1,
  "issued": 1791356400,
  "refs": {
    "context": "c6a0te…9kx",
    "parent": "c3p0si…ti0",
    "text": "c8s3al…edb"
  },
  "body": {
    "kind": 3,
    "author": 2,
    "editKey": "7f1c…a9",
    "state": 1,
    "sealed": true,
    "epoch": 4,
    "lang": "en"
  }
}
```

Beside it in the bundle: `authorship` = `{0: 2, 3: 2, 5: <proof>}`, where the proof's scope is `hum/author-slot/1 ‖ c6a0te…p3e ‖ 20733 ‖ 2` and its bound message is `hum/author/1 ‖ <this CID>`, plus a log inclusion proof. No signature, no chat key, no origin.

Version 2 of the same object after a merge by its author adds `"state": 3`, `"refs": {"mergedInto": "c1m9wz…x8r", …}`, and the bundle carries an `editSig` plus a fresh slot proof. A moderation version hiding it instead carries `"state": 4, "moderation": 1` and the context's signatures.

## Vectors

W0-08 generates these under `vectors/issue-map/`. Keys, blobs, clocks and leaf indexes are fixed; IM-12 cases ship the pinning deck and its leaf index as inputs.

Valid:

- `im-ok-issue`: top-level issue, form 1, public text.
- `im-ok-subquestion`: issue with an issue parent.
- `im-ok-position-anon-sealed`: the example above, with the sealed blob and epoch.
- `im-ok-argument-pro-member-origin`: signed pro argument promoted from chat, with `origin` equal to the `chat/promote` vector's message ID.
- `im-ok-agent-proposed`: agent-authored argument, `state` 0, `expires` 30 days out, sponsor admitted by the context.
- `im-ok-authority-activate`: version 2 of a member-authored object as a moderation version, `moderation` 0.
- `im-ok-authority-v1`: an organizer-written position, `author` 0.
- `im-ok-revise-text`: version 2 by the author before dealt, new text CID.
- `im-ok-withdraw`, `im-ok-merge`, `im-ok-reparent-after-merge`.
- `im-ok-dealt-state-only`: version 2 of a dealt position changing only `state`.
- `im-ok-slots`: three unsigned objects by one identity in one window, slots 0, 1, 2.
- `im-ok-two-logs`: the same object in the log of record and, with that log's inclusion proof, in a second log; one nullifier, counted in the log of record.
- `im-ok-lost-response-retry`: a phone whose submission was appended but whose response was lost finds the CID at the log of record and does not rebuild; `im-bad-rebuilt-after-logged`: it rebuilds anyway and the log refuses the reused slot nullifier (IM-7).
- `im-ok-verified-next-epoch`: a signed position verified by a phone after its author's issuer epoch ended, and pinned by a deck dealt in the next epoch; `im-ok-kid-removed-after`: the issuer key removed at a higher log index than the object.

Invalid, one per rule: `im-bad-kind-type` (IM-1); `im-bad-parent-type`, `im-bad-parent-not-v1` (IM-2); `im-bad-authority`, `im-bad-stale-context-version` (IM-3); `im-bad-text-missing`, `im-bad-sealed-no-epoch` (IM-4a); `im-bad-sealed-format`, `im-bad-text-long` (IM-4b); `im-bad-plain-in-private` (IM-5); `im-bad-sig`, `im-bad-form-mismatch`, `im-bad-slot-range`, `im-bad-proof-unbound` (a valid slot proof lifted from another object's bundle), `im-bad-proof-epoch-mismatch` (disclosed epoch is not that of `issued`), `im-bad-issued-skew` (at the log: `issued` two hours from the log's clock), `im-bad-kid-removed-before` (issuer key removed at a lower log index), `im-bad-agent-capability`, `im-bad-agent-not-admitted`, `im-bad-sponsor-missing` (an agent-signed bundle whose body has no `sponsor` ref fails the authorship check before anything else) (IM-6); `im-bad-slot-reused`, `im-bad-slot-reused-other-log`, `im-bad-secondary-nullifier-reused` (the designated card's nullifier new, another card's already seen) (IM-7); `im-bad-origin-anon` (IM-8); `im-bad-sponsor-on-member`, `im-bad-authority-no-moderation` (an authority-signed version > 1 with `moderation` absent; this is the only way a moderation-version mismatch can present) (IM-9); `im-bad-agent-active`, `im-bad-cap-active` (IM-10); `im-bad-frozen-editkey`, `im-bad-no-editsig`, `im-bad-transition-from-withdrawn`, `im-bad-reparent-unrelated`, `im-bad-moderation-changes-text` (IM-11); `im-bad-edit-after-dealt` (IM-12); `im-bad-agent-no-expiry` (IM-13); `im-bad-evidence-count`, `im-bad-lang` (IM-14); `im-bad-rate-limit`, `im-bad-rate-limit-context` (over `ctx.map` but under the ceiling), `im-bad-window-stale` (IM-15).

Bundle encoding: `im-authorship-member`, `im-authorship-anon`, `im-authorship-agent`, `im-authorship-v2` (with `editSig`), and failing `im-authorship-extra-key`, `im-authorship-key-4` (a carried nullifier), `im-authorship-non-canonical`, `im-authorship-scope-carried`.

Derived checks, not manifests: `im-annotate` (a small release table set and the expected labels per position, binary64); `im-dup-detect` (informative pairs at threshold 0.8); `im-edit-key-derive` (edit root, the version 1 envelope, the stripped canonical bytes with body key 2 removed and their SHA-256, expected public key).

## Batching

Recommendation: log every object version individually. The reasoning and the alternative are in `docs/decisions/0041-w0-04-log-every-authored-object.md`. The short version: individual entries let the log prove inclusion, order and non-equivocation per object, let any phone list a map straight from the log with no index server, and let authors submit without trusting a batcher that could drop them. The cost is one log entry per object and a public activity rate per context. Tessera's tile-based sequencing already batches writes internally, so throughput is not the deciding factor.

## Security considerations

| Threat | Mitigation |
| --- | --- |
| Linking an unsigned object to its author's votes or chat name | Scope-separated membership proofs; per-slot scopes; no `origin` on unsigned objects; the edit key is per object |
| Linking two unsigned objects by the same author | Different slots give different nullifiers. The only residual signal is timing and style |
| A proof lifted from a public bundle onto another object | The bound message is `hum/author/1` ‖ CID, so a proof is valid for one object only |
| A signed object reveals membership of a sealed context | True: the chat identity key is cross-context. The author screen says so and offers the unsigned form; a per-context signing key is raised with `chat.md` |
| A signed object's public card fields narrow who the author is, or link it to a ballot | `context.md` C16: one verifier per `entry` leaf and no `any` node, so every member's proof shows the same issuer, epoch, kid and count and an empty `branches`. Residual: two epoch values in the first hour after an epoch boundary |
| A log learns who authors | It sees proofs, not identities; chat identity keys are pseudonymous and visible only when the author signed |
| An agent passes as a person | `author` is in the signed bytes and must match the proof form; an agent key is never a member key |
| An agent floods the map | Per-sponsor and per-context limits at the log, admission by `ctx.agents`, proposals never dealable without a human, 30-day expiry |
| An organizer rewrites someone's words | A moderation version may change state, never text |
| An author changes a card after people voted | Frozen after dealt; replacement is a new lineage |
| Text in a sealed map leaks through the log | Only CIDs and epochs are logged; text is sealed |
| A removed member keeps reading new text | New objects use the next keyring epoch |

## Open questions

- **Who can activate proposals:** draft 0.1 says a moderation version by the context authority, which inherits the threshold-signing chore the manifest spec already flags.
- **Per-context chat signing key:** would remove the membership leak of signed objects. Declined for draft 0.1 in `chat.md` open question 14; it travels with the per-context-names decision there (open question 4).
- **Should `assisted` be required** when a personal agent drafted the text, or is a human's confirmation enough to make it human content? Draft 0.1: optional.
- **Activity-rate leakage:** per-object logging publishes how active a sealed context is. Is that acceptable, or should contexts be allowed to opt into batch roots later?
- **Reparenting by anyone:** only an argument's author or the context can move it after a merge. Should the survivor's author be allowed to?
- **Default limits:** the ceilings in "Membership proofs" and `context.md`'s defaults are guesses to be tuned by the simulator.

## Assumptions about sibling specs

Checked against the drafts on disk on 2026-10-06. Each remaining assumption is a request to its owner.

- `credentials.md` (W0-02, exists): aligned. The proof primitive takes (context version, scope, bound message), both carried in the BBS presentation header; `hum/author-once/1`, `hum/author-slot/1` and the bound message `hum/author/1` ‖ CID are in its scope table; the only ballot scope is `hum/ballot/1` ‖ deck lineage CID. Authoring proves `entry`. Every card in the presentation yields a nullifier under the scope; the `authorship` field carries none of them (ADR 0104), a verifier derives all of them from `proof`, and it treats the presentation as seen if any of its nullifiers was seen. The context's designated `nullifier` leaf (`context.md` key 19) names the primary one, which matters to `ballot.md` and not to this spec. When `entry` has no credential leaf there is no nullifier and the unsigned form is unavailable. Nullifiers are 32 bytes. The edit root lives in the per-person sealed backup beside the chat identity key (`credentials.md`, "The sealed backup"; ADR 0023).
- `chat.md` (W0-05, exists): the chat identity key is credential field `identity`; message IDs are 32 bytes and `origin` is the MIMI message ID, as sections 5.4 and 6 say; `promote-proposal` and `promote-confirm` as section 6 describes; merge proposals are `merge-proposal` messages (section 5.5).
- `context.md` (W0-01, exists): `sealed`, `perms.cards`, `map` (key 16) and `agents` (key 17) are used as written.
- `deck.md` (W0-01, exists): `card/<i>` pins position versions, `card/<i>/pro|con` argument versions, and D7 checks `active`.
- `release.md` (W0-01, exists): tables carry the dealt CID in `statement` or `argument`; releases carry no statement text.
- `storage.md` (W0-06, exists): keyring-form references, format 2, salt in the header.
- `services.md` (W0-07, exists): carries `authorship` as defined here; the bundle table should say `signatures` is used by the authority form of these types. Requested: run the log-side step-10 rules listed above at submission, keep the member-form window counters for two windows only, and count IM-15 in the log of record.

## Seam

`seam: credential presentation, pseudonyms and nullifiers.` The membership proof scopes and bound message in "Membership proofs", the edit-key derivation, and the domain strings `hum/author/1`, `hum/edit/1` and `hum/edit-key/1` need owner review. Nothing else in this spec decides what leaves the phone.
