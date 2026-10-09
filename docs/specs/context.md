# Hum Context Spec — Draft 0.1

Oct 6, 2026 · W0-01

## Scope

A `context` manifest is the rulebook of one group space. It says who may join and vote, what organizers may configure, which privacy floors apply, and which logs, aggregators and blob stores the context accepts. Decks pin a context version, so every release can be traced to the exact rules it ran under.

This spec defines the `context` body. The envelope, signatures, logs and verification steps 1–9 and 11 are in [`manifest.md`](manifest.md). This spec supplies the step-10 rules for contexts.

Related specs: [`deck.md`](deck.md), [`release.md`](release.md), [`credentials.md`](credentials.md) (entry and vote proofs), [`verifier.md`](verifier.md) and [`trust-list.md`](trust-list.md) (issuers), [`chat.md`](chat.md) (groups and keyrings), [`storage.md`](storage.md) (blob stores), [`issue-map.md`](issue-map.md) and [`agent-sponsor.md`](agent-sponsor.md) (which read limits from this manifest), [`services.md`](services.md). What this spec assumes about each is listed under Open questions.

## Conventions

These apply to every body spec written by W0-01 (context, deck, release).

- **Body keys** are small unsigned integers. The JSON view uses the names in the tables and is never signed.
- **`rat`** is a non-negative rational: a CBOR array `[num, den]` of two uints, `den ≥ 1`, `gcd(num, den) = 1`, both below 2⁶⁴. The JSON view writes it as `"num/den"`. An integer is written `"n/1"`. A `rat` that is not in lowest terms fails the schema check (step 4 of verification); step 2 cannot catch it, because `[2, 4]` re-encodes to the same bytes.
- **`cid`** is a CID as in the manifest spec. **`auth`** is an authority: the CID of a keyset lineage's version 1.
- **`time`** is seconds since the Unix epoch, uint.
- **`bytes32`** is a CBOR byte string of exactly 32 bytes.
- **Enumerations** are uints. The tables give each value a name.
- **Frozen** means the field must equal the previous version's value once the condition in the Frozen column holds. Step 10 checks it.
- Text fields are UTF-8, NFC, with no control characters, and have a byte limit.

## Protocol constants (draft 0.1)

These are built into every conforming client, aggregator and ledger. Contexts and decks can only be stricter.

| Name | Value | Meaning |
| --- | --- | --- |
| `RHO_MAX` | 127/500 (0.254) | Most ρ one release may spend. ε 4.0 at δ 10⁻⁶ |
| `DELTA_MAX` | 1/1000000 | Largest δ |
| `MIN_VOTERS` | 100 | Smallest noised voter count that may publish |
| `RELEASES_PER_DECK` | 1 | One release lineage per deck |
| `SHIELD_YEAR` | ε 20 | Yearly budget per person; tracked on the phone (`shield.md`) |
| `MIN_WITNESSES` | 2 | Witness cosignatures a checkpoint needs |
| `COUNT_RHO_MAX` | 1/50 | Most ρ a context may let the daily count part spend |
| `AUTHOR_WINDOW` | 86400 | Rate-limit window for authored objects, seconds (`issue-map.md`) |
| `GATE_TALLIES` | 100 | Noised voters to publish statement tallies |
| `GATE_COMMON` | 300 | Noised voters to publish common ground, movement and ratings |
| `GATE_MAP` | 800 | Noised voters to publish the opinion map and groups |
| `GATE_CELL` | 300 | Noised voters per cell to publish a breakdown cell |
| `GATE_CHECKS` | 5000 | Noised voters for studio checks against real data |
| `MAX_CARDS` | 256 | Cards in one deck |
| `MAX_TOPICS` | 32 | Topics in one deck |
| `MAX_POLICY_LEAVES` | 32 | Attribute leaves in one policy |
| `MAX_POLICY_DEPTH` | 4 | Nesting depth of a policy |
| `PUBLISH_WINDOW` | 2592000 | Seconds after `closes` within which release version 1 must be issued (`release.md` R13); also the slack in the upper bound on a deck's `expires` (`deck.md` D13) |

The ρ for ε 4 is 0.25398…; `RHO_MAX` rounds it to three decimals as the design doc does. A release at exactly `RHO_MAX` is ε 4.00054 at δ 10⁻⁶ (exactly, ε = ρ + 2√(ρ ln(1/δ)) in binary64), which the owner has accepted as "ε 4". Displayed ε is that value rounded half to even to two decimals, so `RHO_MAX` shows as ε 4.00; conformance vectors carry the binary64 value, not the display. See [`0010-w0-01-body-conventions.md`](../decisions/0010-w0-01-body-conventions.md).

## Body fields

| Key | Name | Type | Required | Meaning | Frozen |
| --- | --- | --- | --- | --- | --- |
| 0 | `name` | text ≤ 120 bytes | yes | Display name of the context | no |
| 1 | `sealed` | bool | yes | `true`: issue-map text and statement blobs are sealed under the context keyring. `false`: they are public blobs | from version 1 |
| 2 | `entry` | policy | yes | Who may become a member (chat, map, files) | no |
| 3 | `vote` | policy | no | Who may vote. Defaults to `entry`. Must be at least as strict in practice; the protocol only requires that it names a credential (rule C6) | no |
| 4 | `issuers` | array of `auth` ≤ 64 | no | Single verifier authorities the policies may name, beside the trust lists in `refs` | no |
| 5 | `perms` | map | yes | Organizer settings that are not floors (table below) | no |
| 6 | `floors` | map | yes | The context's privacy floors (table below) | no, but may only tighten (rule C10) |
| 7 | `logs` | array of log entries, 1..8 | yes | Transparency logs this context accepts. The first entry is the ledger of record | the first entry's `log` from version 1; its `witnesses` and the other entries may change |
| 8 | `aggregators` | array `[leader, helper]` of `auth` | yes | The two aggregator authorities every deck of this context uses | no |
| 9 | `stores` | array of `auth`, 1..8 | yes | Blob store authorities members may use | no |
| 10 | `storage` | map | yes | Storage policy (table below) | no |
| 11 | `chat` | map | yes | Chat group identifiers (table below) | `allMembers` from version 1 |
| 12 | `mixGlobal` | bool | yes | Decks of this context may include Global statements | no |
| 13 | `resultsKey` | bytes32 | if `perms.results` = 1 | X25519 public key that seals members-only release tables; derived from the keyring (below) | no |
| 14 | `resultsEpoch` | uint | with `resultsKey` | Keyring epoch `resultsKey` was derived from | no |
| 15 | `count` | map | no | Limits on the organizer's noised daily count (table below) | no |
| 16 | `map` | map | no | Issue-map authoring limits (table below); absent means every default | no |
| 17 | `agents` | map | no | Which agent sponsors are admitted and what they may do (table below); absent means every default | no |
| 18 | `aboutEpoch` | uint | iff `sealed` and `refs["about"]` present | Keyring epoch that decrypts the `about` blob | no |
| 19 | `nullifier` | array `[source, name]` | yes | The credential the voting pseudonym and nullifier are bound to (see Entry policy) | no |
| 20 | `resolvers` | array of `auth`, 1..8 | no | Resolver authorities members try first when fetching bytes by CID (`services.md`, "Resolver and mirrors"). Absent means the app's shipped defaults | no |
| 21 | `relays` | array of `auth`, 1..4 | no | OHTTP relay authorities members may use for this context's requests, beside the app's shipped relays (`services.md`, "OHTTP relay"). Absent means the shipped relays only. A relay named here must pass `services.md` rule O-5; C7 checks the part of it that needs no lookup. A relay named here carries only this context's requests, in rotation with the shipped relays, and never a request to an aggregator, a submission to a log or the blob puts of an authored object (`services.md` rule O-6). A relay that only this context names learns that each client address it sees belongs to a member, and the services screen says so | no |

`refs` names:

| Name | Points to | Required |
| --- | --- | --- |
| `parent` | A `context` manifest version: the parent context | no |
| `tl/<i>` for i = 0.. | A `trust-list` manifest version | one per trust list the policies use; indices contiguous from 0 |
| `about` | A public UTF-8 text blob ≤ 8 KiB, or a sealed blob when `sealed` is true | no |

Nothing in the body or refs names a person. The member list, moderators and invitees live in the chat layer and in verifiers, never in the manifest. The envelope's `expires` is optional on a context; if present it gates only new decks pinning this version.

### `perms` (key 5)

| Key | Name | Type | Values | Design-doc setting |
| --- | --- | --- | --- | --- |
| 0 | `cards` | uint | 0 organizers · 1 members, reviewed by organizers · 2 any member | Who writes cards |
| 1 | `results` | uint | 0 everyone (public ledger) · 1 members · 2 organizers (reserved; rejected in draft 0.1, rule C12) | Who sees results |
| 2 | `memberList` | uint | 0 no one · 1 organizers · 2 members | Who sees the member list |

`cards` and `memberList` are enforced in the issue-map and chat layers. `memberList` can hide a screen, not the MLS tree: every member's device sees its groups' leaves (`chat.md`). `results` is enforced by the release spec: with 1, release tables are sealed to `resultsKey` (see [`release.md`](release.md), "Members-only results"). Organizers-only results need a keyring the organizers group does not have in draft 0.1, so 2 is reserved.

### The results key

`resultsKey` is derived from the context keyring, so every phone that holds keyring epoch `k` can derive the private key, including newcomers who receive `k` through `keyring-share` (`storage.md` §4.2). No new MLS export is needed.

```
seed       = HKDF-Expand(HKDF-Extract(salt = "", IKM = secret_k), info = "hum/results-key/1", L = 32)
private    = clamp(seed)            (RFC 7748 X25519 clamping)
resultsKey = X25519(private, 9)     (the public key)
```

`secret_k` is the keyring epoch secret as `storage.md` §4.1 defines it; `k` = `resultsEpoch`. Organizers publish a context version with a new `resultsKey` whenever they want releases sealed to a newer epoch. Members removed before epoch `k` cannot derive the key; members removed after it keep it, as with files.

Only members can check the derivation, so they do: a member phone that holds epoch `resultsEpoch` MUST recompute `resultsKey` from `secret_k` and, on mismatch, refuse to treat the context version as valid and warn the member. This stops an organizer quorum from publishing a key whose private half lives outside the keyring. When `storage.keyringHistory` is 1, newcomers receive only the current epoch, so organizers should republish `resultsKey` at the current epoch after each removal.

### `floors` (key 6)

| Key | Name | Type | Required | Must be | Design-doc setting |
| --- | --- | --- | --- | --- | --- |
| 0 | `rho` | rat | yes | ≤ `RHO_MAX`, > 0 | Privacy spend per release |
| 1 | `delta` | rat | yes | ≤ `DELTA_MAX`, > 0 | — |
| 2 | `minVoters` | uint | yes | ≥ `MIN_VOTERS` | Minimum voters to publish |
| 3 | `releasesPerDeck` | uint | yes | = 1 | Releases per deck |
| 4 | `rhoYear` | rat | no | ≥ `rho` if present | Total ρ the context's releases may spend in any 365-day window |
| 5 | `minWitnesses` | uint | yes | ≥ `MIN_WITNESSES` | — |

The yearly shield is a per-person floor kept on the phone and is not a context field.

### Log entries (key 7)

Each entry is a map:

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | `log` | auth | The log's authority |
| 1 | `witnesses` | array of bytes32, 2..16 | Ed25519 public keys of witnesses whose cosignatures count for this log |

A checkpoint of this log counts for the context when at least `floors.minWitnesses` of the listed witnesses cosigned it. A manifest the context's members act on must be proven in at least one listed log. The first entry is the context's **log of record**, and its ledger of record for decks and releases (`release.md` R10, R14; `deck.md` D16): an authored issue-map object must be in it, its authorship proof is checked there, and nullifier and rate-limit counts are taken there (`credentials.md`, "Verification rules"; `issue-map.md`). The order of `logs` therefore carries meaning, and the first entry's `log` is frozen from version 1 (C11).

### `storage` (key 10)

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | `retention` | map of kind → uint seconds | Longest a blob of each kind may live; 0 = keep until deleted. Kinds: 0 attachment · 1 folder file · 2 history archive · 3 issue-map text and evidence · 4 release table |
| 1 | `maxBlob` | uint | Largest blob a member may upload, in bytes |
| 2 | `history` | uint | 0 none · 1 shared by an organizer · 2 full channel history |
| 3 | `quota` | uint | Context quota in bytes the stores enforce |
| 4 | `keyringHistory` | uint | 0 newcomers receive every keyring epoch · 1 only the current epoch. Default 0 (`storage.md` §4.2) |
| 5 | `sensitiveMax` | uint | Size cap in bytes for a folder marked sensitive, which is re-keyed eagerly on removal. Default 268435456 |

All five kinds must be present in `retention`. Stores read the policy from the context version a token was issued against (`storage.md` §6.1). `history` is the message-history policy; `keyringHistory` is separate because the keyring also unlocks issue-map text.

### `chat` (key 11)

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | `allMembers` | bytes32 | MLS group ID of the all-members group, which exports the context keyring |
| 1 | `organizers` | bytes32 | MLS group ID of the organizers group |
| 2 | `delivery` | auth | Delivery service authority |
| 3 | `greeting` | bytes32 | X25519 public key a joiner HPKE-seals their KeyPackage handles to (`chat.md` §2.5); the private half lives in the organizers group |
| 4 | `issuerKeys` | map `{0: bytes, 1: bytes}` | The delivery service's P-384 VOPRF token issuer public keys for the all-members group (0) and the organizers group (1), as returned when the groups were registered (`chat.md` §12.4). A newcomer verifies its first token responses against the manifest, not the service; the `roles` message carries a copy and the manifest wins on mismatch |

Group IDs are random and carry nothing about members. `greeting` is in the manifest because a joiner is in no MLS group yet and the handle must not pass through a verifier that saw their evidence; rotating it is a new context version.

### `count` (key 15)

| Key | Name | Type | Default | Meaning |
| --- | --- | --- | --- | --- |
| 0 | `rhoMax` | rat ≤ `COUNT_RHO_MAX` | 1/200 | Most ρ a deck's release plan may give the daily count part |

See "The noised daily count" below.

### `map` (key 16)

Rate limits `issue-map.md` enforces on authored objects.

| Key | Name | Type | Default | Meaning |
| --- | --- | --- | --- | --- |
| 1 | `unsignedPerWindow` | uint, 1..20 | 20 | Unsigned objects one member may author per `AUTHOR_WINDOW` (slots in the membership-proof scope) |
| 2 | `signedPerWindow` | uint, 1..60 | 60 | Signed objects one member may author per window |
| 3 | `agentObjects` | uint ≥ 1 | 20 | Objects all agents together may author per window in this context; `issue-map.md` rule IM-15 enforces it with the sponsor's own limit |

The window is the protocol constant `AUTHOR_WINDOW`; a context may lower the counts, never raise them, and cannot change the window because the log computes slot scopes with the constant.

### `agents` (key 17)

| Key | Name | Type | Default | Meaning |
| --- | --- | --- | --- | --- |
| 0 | `anySponsor` | bool | false | Any logged agent sponsor may be added |
| 1 | `sponsors` | array of `auth` ≤ 64 | `[]` | Admitted sponsor authorities when `anySponsor` is false |
| 2 | `addRole` | uint | 0 | Who may add a shared agent to a channel: 0 organizers · 1 moderators too · 2 any member |

Agents never vote. No policy in this manifest may name the `agent-sponsor` attribute (rule C15), so no agent credential can satisfy `entry` or `vote`.

## Entry policy

A policy is a tree of conditions over issuer and attribute. It is published so that anyone can read who may join, and it is what a phone proves in zero knowledge when it joins or votes (`credentials.md`).

Encoding: a node is a CBOR array whose first element is the kind.

| Node | Encoding | Satisfied when |
| --- | --- | --- |
| true | `[0]` | always |
| all | `[1, [node, …]]` | every child is satisfied; at least one child |
| any | `[2, [node, …]]` | at least one child is satisfied; at least one child |
| attr | `[3, source, name, pred]` | the phone holds a credential from `source` carrying attribute `name` that satisfies `pred` |

- `source` is `[0, i]` for the trust list at `refs["tl/<i>"]`, or `[1, i]` for `issuers[i]`. From a trust list, any verifier authority the list accepts for `name` counts; in draft 0.1 that must be exactly one authority (rule C16).
- `name` is text ≤ 32 bytes, the attribute name as the verifier manifest spells it.
- `pred` is `[0]` (present), `[1, [value, …]]` (the credential's value is one of 1..64 distinct uints), or `[2, lo, hi]` (uint in the inclusive range, `lo ≤ hi`); see the draft 0.1 restriction below. Every attribute value in a credential is a uint (`verifier.md`: bool 1, enum value `v`, band 0-based index, uint itself), so predicates carry uints only. A bool attribute is present only when true, so `[0]` on `invite` or `approved` means true.
- Children of `all` may be satisfied by different credentials held by the same prover; `any` needs one child satisfied by one credential. A `true` node is not a leaf for the leaf count but counts toward depth.
- **Draft 0.1 proves selective disclosure only** (`credentials.md`, ADR 0022): a presentation reveals an attribute's value or its presence, never a hidden predicate over it. So a conforming policy uses `[1, [v]]` with exactly one value (equality), `[2, lo, hi]` only with `lo = hi`, and `[0]` only on a `bool` attribute. Sets of two or more values, real ranges and presence on an enum, band or uint are validation errors (C5) until a later draft adds range proofs; the encodings are kept so that draft does not change bytes.
- **One cell per context (draft 0.1, rule C16, ADR 0100).** A presentation shows, in the clear, which verifier issued each card and which child of each `any` node was taken (`credentials.md`). If members of one context could differ in those values, the difference would sit beside their votes on every ballot and beside their chat name on every signed issue-map object, and a member who was alone in a combination could be picked out. So in draft 0.1 neither `entry` nor `vote` may contain an `any` node, and every `attr` leaf's source must resolve to exactly one verifier authority: a `[1, i]` source always does; a `[0, i]` source does when exactly one entry of the pinned trust list version accepts the leaf's attribute name (the entry lists the name, or its `attributes` is empty). The rule covers the whole context, `entry` as well as `vote`, because join tickets, token requests and authorship proofs prove `entry`. Every member's presentation for a given use then has the same issuers in the same order and an empty `branches`, and the number of cards is the number of distinct authorities the policy names. The `any` encoding is kept so a later draft that hides the issuer and the branch does not change bytes.
- **Effective voting policy.** A ballot proves `[1, [entry, vote]]`: both must hold, so `vote` can only narrow membership, never widen it. When `vote` is absent the effective policy is `entry`.
- **Nullifier leaf.** `nullifier` = `[source, name]` names the credential the per-deck voting pseudonym and primary nullifier are bound to. The effective voting policy must contain an `attr` leaf with that source and name that is reachable from the root through `all` nodes only (no `any` on the path), so every satisfying presentation includes that credential. Every credential used in a presentation yields a nullifier, and every one must be new for the deck, which stops two people pooling cards under an `all`; the designated leaf's is the *primary* nullifier, which keys ballot replacement, the later rounds and the daily count (`ballot.md`). The design doc's sybil caveat applies: uniqueness is as good as the nullifier credential's issuer.

The design doc's four "who can join" options map to policies:

| Option | Policy |
| --- | --- |
| Anyone | `entry` = `[0]`; `vote` names a uniqueness or resident-card source, which is also the `nullifier` |
| Invite link | `attr` on the organizer's invite verifier, attribute `invite`, present |
| People you approve | `attr` on the organizer's approved-list verifier, attribute `approved`, present |
| Verified residents | `attr` on a trust list that accepts `area` from one verifier, or on that verifier directly, attribute `area` equal to one value. To admit several wards, coarsen at issuance (an `area` attribute), or use a verifier that issues the predicate as a `bool`. An `any` of equality leaves is not available: C16 rejects every `any` node in draft 0.1 |
| Either of two ways in ("approved, or a resident") | Not expressible in one context in draft 0.1 (C16). Run two contexts, or one verifier that issues the disjunction as a `bool` |

Attribute names and values are spelled as the verifier manifest spells them (`verifier.md`: `invite`, `approved`, `ward`, `area`, `age-band`, `unique`). Invite and approved-list verifiers are the profiles `verifier.md` defines; organizers run each one under an authority of its own, a separate keyset created for that verifier, and name it in `issuers`. It is never the context's authority: an authority can hold one `verifier` lineage, ever (`verifier.md` rule 31), a context may need both profiles, and a verifier whose frozen fields were set wrong can only be replaced by a new authority, which must not mean a new context. What "accepted from a trust list" means, row by row, is the resolution algorithm in `trust-list.md`.

## Roles and signing

| Role | Holds | Can |
| --- | --- | --- |
| Admin | A `rotate` key in the context authority's keyset | Publish the next keyset, and everything an organizer can |
| Organizer | A `sign` key in the context authority's keyset | Publish context versions, decks and delete orders; read the daily count; everything in `perms` marked organizers |
| Moderator | A chat credential the organizers group marks as moderator (`chat.md`, `roles` message) | Act on franked reports; review member cards when `perms.cards = 1`; add agents when `agents.addRole ≥ 1` |
| Member | A membership proof satisfying `entry` | Chat, author issue-map objects, use files, and vote if they also satisfy `vote` |

Who holds a role is not in this manifest. Admins and organizers are whoever holds the keys, so the set of organizer keys is public in the logged keyset, though keys name nobody; moderators are named in the organizers group's signed `roles` message (`chat.md`), which the manifest never lists.

Every manifest the context authority publishes (a context version, including one that changes `resultsKey`; a deck; a delete order) needs the keyset's `sign` threshold; publishing a new keyset needs its `rotate` threshold. There are no per-action quorums in draft 0.1: a context that wants three organizers on a deck but two on a delete order runs two contexts or waits for a later draft. Rotation and recovery are in the manifest spec.

Organizers never hold a view of votes. What they see is in the design doc's who-sees-what table: who accepted an invite (through their own verifier), the noised daily count, and releases.

## Floors

Floors come in layers that can only get stricter: protocol constants, the parent context's floors, this context's floors, and each person's shield. A deck's release plan must satisfy the floors of the context version it pins ([`deck.md`](deck.md), rule D10).

- `rho` and `delta` cap one release. `minVoters` is the smallest noised voter count at which a release may publish anything.
- `rhoYear` caps the sum of ρ over all releases of this context whose first version was logged in any 365-day window. The ledger checks it when it logs a release (`release.md`, rule R14). A context with four decks a year at ε 4 spends about ρ 1.02, which is about ε 8.5 by zCDP composition.
- A context version may tighten floors at any time. Open decks keep the version they pinned.
- The parent relation (rule C13) is checked once, against the parent version pinned in `refs`. If the parent later tightens its own floors, the child is not retroactively invalid; it picks up the new parent version when it next republishes.

## The noised daily count

Organizers see how many people have played an open deck so far, once a day, with noise. Nobody can watch one person vote.

- **What it measures.** Bucket `d` = ⌊(t_received − `opens`) / 86400⌋ for each ballot, counting at most the first ballot of each voting pseudonym; the series is the number of ballots in each bucket. The bucket that contains `closes` is noised at `closes`; a `closes` extension continues the series. The organizer's view is the noised increments and their running sum.
- **Why increments.** A person appears in exactly one day's increment, so the whole series of any length is one sum with L2 sensitivity 1. A series of running totals would charge √(days).
- **Budget.** The deck's release plan gives the `count` part a ρ, at most `count.rhoMax` (default 1/200, never above `COUNT_RHO_MAX`). Noise is the discrete Gaussian of `release.md` with σ = 1/√(2ρ) (rounded up to σ_r as that spec defines), so the default σ is 10 ballots per day. The running sum over a 20-day deck has σ about 45. The part is inside the plan's total, so it is inside `floors.rho` and the shield charges it with everything else.
- **Accounting.** The aggregator adds noise to each day's increment once, at the end of that day, and publishes nothing else about intake. The series goes to organizers through the aggregator API (`services.md`) and is included in the release as the `count` table so the spend is auditable.
- **The one exception to the voter minimum.** The daily count is served while the deck is open, before anyone knows whether the deck will reach `minVoters`, so it has no voter minimum. It is the only output that has none (ADR 0103). It is noised, capped at `COUNT_RHO_MAX`, inside the plan's ρ, and seen by organizers only until release. A below-minimum release publishes nothing else: no table, no `nHat`, no receipt tree.
- **Phase 2.** The increment is a one-hot over day buckets; DAP time-interval batches produce the same sums.

A deck whose plan omits the `count` part gives organizers no count at all. A plan may not give it more than `count.rhoMax`.

Known gap: a deck abandoned before any release version is logged has spent its `count` ρ on the live series, and the yearly floor (`release.md`, R14) never sees it. Shields are unaffected, since they charge at the first ballot. Aggregators SHOULD publish a final release version for an abandoned deck so the spend is logged; whether to require it is open.

## Validation rules (verification step 10 for `context`)

Each rule is phrased so one vector can test it. A failing rule rejects the manifest; the ledger refuses to log it and clients never act on it.

| Rule | Check |
| --- | --- |
| C1 | Required fields 0, 1, 2, 5, 6, 7, 8, 9, 10, 11, 12, 19 are present, with the types and limits in the tables; no unknown keys; every `rat` is in lowest terms |
| C2 | `name` is 1..120 bytes of valid UTF-8 |
| C3 | `floors.rho` ≤ `RHO_MAX`, `floors.delta` ≤ `DELTA_MAX`, `floors.minVoters` ≥ `MIN_VOTERS`, `floors.releasesPerDeck` = 1, `floors.minWitnesses` ≥ `MIN_WITNESSES`; `rho` and `delta` > 0 |
| C4 | If `rhoYear` is present, `rhoYear` ≥ `rho` |
| C5 | Every policy node is well-formed: known kinds; `all` and `any` have 1..32 children; depth ≤ `MAX_POLICY_DEPTH`; `attr` leaves ≤ `MAX_POLICY_LEAVES`; every `[0, i]` source has `refs["tl/<i>"]`; every `[1, i]` source has `issuers[i]`; `name` matches `^[a-z][a-z0-9-]{0,31}$`; in draft 0.1 `[1, …]` has exactly one uint, `[2, lo, hi]` has `lo = hi`, and `[0]` is on an attribute the verifier declares as `bool` (checked after step 9 resolves the source); no `any` node has two leaf children on the same (source, name) |
| C6 | `nullifier` names a source that exists, and the effective voting policy `[1, [entry, vote]]` (or `entry` alone) has an `attr` leaf with that source and name reachable from the root through `all` nodes only (no `any` on the path) |
| C7 | `refs` trust lists are named `tl/0`, `tl/1`, … with no gaps; no trust list is unused by both policies; `aggregators[0] ≠ aggregators[1]`; no duplicate in `stores`, `logs`, `issuers`, `resolvers` or `relays`; `resolvers` has 1..8 and `relays` 1..4 entries when present; no entry of `relays` equals any authority this context names in `logs`, `aggregators`, `stores`, `resolvers`, `issuers` or `chat.delivery` (the part of `services.md` rule O-5 that needs no lookup) |
| C8 | Each log entry has 2..16 distinct witness keys, and `floors.minWitnesses` ≤ the number of witnesses of every log entry |
| C9 | `storage.retention` has all five kinds; `maxBlob` ≥ 65536; `history` ∈ {0,1,2}; `keyringHistory` ∈ {0,1}; `sensitiveMax` ≥ 1048576 |
| C10 | Version > 1: `floors.rho` ≤ prev, `floors.delta` ≤ prev, `floors.minVoters` ≥ prev, `floors.minWitnesses` ≥ prev; if prev had `rhoYear`, this version has `rhoYear` ≤ prev's |
| C11 | Version > 1: `sealed`, `chat.allMembers` and `logs[0].log` equal prev (the ledger of record never changes within a context lineage, so the counts of `release.md` R10 and R14 cannot be restarted; a context that must move ledgers starts a new lineage, in the open); `chat.greeting` is a 32-byte string and `chat.issuerKeys` has both entries in every version |
| C12 | `perms.results` ∈ {0, 1}; if 1, `resultsKey` and `resultsEpoch` are present; if 0, both are absent; `aboutEpoch` present iff `sealed` and `refs["about"]` present |
| C13 | If `refs["parent"]` is present, it resolves to a `context` manifest whose `floors` are no stricter than this one's on `rho`, `delta`, `minVoters` and `minWitnesses`, and whose lineage is not this one's |
| C14 | If `count` is present, `count.rhoMax` ≤ `COUNT_RHO_MAX` |
| C15 | No `attr` leaf in `entry` or `vote` names the attribute `agent-sponsor`; `map.unsignedPerWindow` in 1..20, `map.signedPerWindow` in 1..60, `map.agentObjects` ≥ 1 when present; `agents.sponsors` is empty when `anySponsor` is true and has no duplicates otherwise; `agents.addRole` ∈ {0,1,2} |
| C16 | Draft 0.1, checked after step 9 resolves the trust lists: no `any` node (`[2, …]`) appears anywhere in `entry` or `vote`; and for every `attr` leaf with a `[0, i]` source, exactly one entry of the trust list version at `refs["tl/<i>"]` has the leaf's `name` in its `attributes` or has empty `attributes`. A `[1, i]` source needs no check |

Where these plug in: the ledger and every phone run C1–C16 at step 10. Aggregators run them on the context version a deck pins before accepting the first ballot. Rules C13 and C16 need references resolved (step 9), which is why they come after.

## Example (JSON view)

```json
{
  "spec": 1,
  "type": "context",
  "authority": "c4f7q2…k2a",
  "version": 1,
  "issued": 1790000000,
  "refs": {
    "tl/0": "c8m2vp…r4t",
    "about": "c0q9dd…z1n"
  },
  "body": {
    "name": "Millbrook Tenants Union",
    "sealed": true,
    "aboutEpoch": 3,
    "entry": [3, [0, 0], "area", [1, [1]]],
    "vote": [1, [
      [3, [0, 0], "area", [1, [1]]],
      [3, [0, 0], "unique", [0]]
    ]],
    "nullifier": [[0, 0], "unique"],
    "perms": { "cards": 1, "results": 1, "memberList": 1 },
    "floors": {
      "rho": "127/500", "delta": "1/1000000", "minVoters": 100,
      "releasesPerDeck": 1, "rhoYear": "51/50", "minWitnesses": 2
    },
    "logs": [{ "log": "c2lg…", "witnesses": ["a1…", "b2…", "c3…"] }],
    "aggregators": ["c7k3na…m1d", "c9hp2x…q0s"],
    "stores": ["c3st…"],
    "storage": {
      "retention": { "0": 7776000, "1": 0, "2": 31536000, "3": 0, "4": 0 },
      "maxBlob": 268435456, "history": 1, "quota": 53687091200,
      "keyringHistory": 0, "sensitiveMax": 268435456
    },
    "chat": { "allMembers": "7f…", "organizers": "e2…", "delivery": "c6dl…", "greeting": "4a…",
              "issuerKeys": { "0": "03b1…", "1": "02e7…" } },
    "mixGlobal": true,
    "resultsKey": "9c…", "resultsEpoch": 3,
    "map": { "unsignedPerWindow": 20, "signedPerWindow": 60, "agentObjects": 20 },
    "agents": { "anySponsor": false, "sponsors": ["c1sp…"], "addRole": 0 }
  }
}
```

The policy reads: join if the trust list's district verifier says your area is Millbrook (`area` = 1). Vote only with that area credential and a uniqueness credential from the trust list; the primary nullifier is bound to the uniqueness credential. The pinned trust list accepts `area` from one verifier and `unique` from one verifier, so the context has one cell (C16): every member's join ticket and authorship proof shows the district verifier, and every ballot shows the district and uniqueness verifiers, in that order. An earlier draft of this example let members in through an approved list or the area credential; C16 rejects that `any` in draft 0.1.

## Vectors (for W0-08)

Directory `vectors/context/`. Each case carries the canonical CBOR bytes, the CID, the JSON view and the expected result.

Valid:

- `context-valid-open`: `entry` = `[0]`, `vote` names a trust-list uniqueness attribute, `results` = 0, no parent.
- `context-valid-sealed-parent`: the example above, plus `refs["parent"]` to a public parent with looser floors.
- `context-valid-v2-tighten`: version 2 of the example that lowers `rho` to 1/5 and raises `minVoters` to 300.
- `context-valid-count`: a version with `count.rhoMax` = 1/400.

Invalid, one per sub-condition, named `context-invalid-<rule>-<case>`:

- C1: missing `logs`; unknown key; `rat` not in lowest terms (`[2, 4]`).
- C2: empty name; 121 bytes.
- C3: `rho` 3/10; `delta` 1/100000; `minVoters` 50; `releasesPerDeck` 2; `minWitnesses` 1.
- C4: `rhoYear` < `rho`.
- C5: unknown node kind; `all` with no children; depth 5; 33 leaves; `[0, 2]` with only `tl/0`; `[1, 3]` with one issuer; text value in a predicate; a two-value set; `lo < hi`; `lo > hi`; `[0]` on an enum attribute; an `any` with two leaves on the same (source, name); bad attribute name.
- C6: `nullifier` source missing; nullifier leaf absent from the policy; nullifier leaf only under an `any`.
- C7: gapped `tl/`; unused trust list; equal aggregators; duplicate store; duplicate relay; five relays; an empty `resolvers` array; a relay equal to the context's Leader authority.
- C8: `minWitnesses` 3 with two witnesses; duplicate witness key.
- C9: retention missing kind 4; `maxBlob` 1000; `history` 3; `keyringHistory` 2; `sensitiveMax` too small.
- C10: version 2 raises `rho`; raises `delta`; lowers `minVoters`; lowers `minWitnesses`; drops `rhoYear`; raises `rhoYear`.
- C11: version 2 changes `allMembers`; changes `sealed`; changes `logs[0].log`; swaps the first two `logs` entries; valid: version 2 changes `logs[0].witnesses` and adds a second log; `greeting` missing; `issuerKeys` with one entry.
- C12: `results` 2; `results` 1 without `resultsKey`; `results` 0 with `resultsKey`; sealed `about` without `aboutEpoch`.
- C13: parent with stricter `minVoters`; parent in the same lineage.
- C14: `count.rhoMax` 1/20.
- C16: an `entry` with an `any` node; a `vote` with an `any` node nested under an `all`; a leaf whose trust list accepts the attribute from two verifiers by name; a leaf whose trust list has one named entry and one entry with empty `attributes` (two authorities); valid: two leaves on different attributes that the list accepts from the same single verifier.
- C15: a `vote` leaf naming `agent-sponsor`; `unsignedPerWindow` 21; `sponsors` non-empty with `anySponsor`; `addRole` 3.

Policy evaluation vectors `context-policy-eval-*`: a tree plus a set of `(authority, attribute, value)` triples the prover holds, and the expected result, covering `all` across two credentials, `any`, a range, a set, and a nullifier leaf. These test the evaluator on trees; a context manifest holding the `any`, range or set trees is itself rejected by C5 or C16 in draft 0.1. Daily count vectors `context-count-*`: ballot receipt times and `opens`/`closes` in, bucket increments out, with noise supplied as input; one case with `closes` mid-bucket and one with an extension. Results key vectors `context-results-key-*`: `secret_k` in, `resultsKey` out, and `context-results-key-mismatch`, a version a member phone must refuse.

## Security considerations

- The policy tree is public, so anyone can see what a context asks for. The proofs that satisfy it are `credentials.md`'s business. They show which verifier issued each card, which C16 makes the same for every member of the context, and otherwise reveal only that the policy holds.
- `resultsKey` is derived from the keyring epoch secret. It lets aggregators seal tables for members without ever holding a keyring. A removed member who held the epoch's key can read releases sealed to it until organizers publish a context version with a new key. This matches the storage model, where removal cannot recall files already received.
- Both group IDs in `chat` are public in the log. They are random and name nobody, but a log mirror can tell which delivery-service group is the organizers' if it can also observe the delivery service.
- `logs[].witnesses` and `floors.minWitnesses` let a context demand more than the protocol's two cosignatures.
- The daily count's ρ is inside the release budget, so no amount of organizer curiosity can spend more than the plan declared.

## Open questions

Filed in `docs/decisions/`:

- **Results key derivation** ([`0011-w0-01-members-only-results.md`](../decisions/0011-w0-01-members-only-results.md)): HKDF from the keyring epoch secret with info `hum/results-key/1`; no new MLS export, so `chat.md` needs no label and `storage.md`'s reservation of the label as an exporter label can go. Organizers-only results (`results` = 2) are deferred until the organizers group has a keyring. Seam: key derivation.
- **Policy proof requirements for `credentials.md`:** a ballot proves the conjunction `[1, [entry, vote]]`; children of `all` may come from different credentials; the nullifier is bound to the `nullifier` leaf's credential. These are requirements, not assumptions.
- **Daily count budget** ([`0012-w0-01-daily-count.md`](../decisions/0012-w0-01-daily-count.md)): default `count.rhoMax` 1/200, and whether the series should simply be public (`services.md` asks the same).
- **Per-action quorums:** draft 0.1 has one sign threshold for every organizer action. Whether some actions need more signers is deferred.
- **Retired and successor markers:** the manifest spec describes retiring a lineage and naming a successor but assigns no envelope keys. This spec defines none in the body; the manifest spec should assign them.
- **Admission flow:** owned by `chat.md` §2.5; this spec carries only `chat.greeting`.

Where this spec and its siblings differ in names:

- `chat.md` has three chat roles, `organizer`, `moderator`, `member`; `admin` here is a keyset role (a `rotate` key) with no chat meaning. `chat.md` §3.1 reads `agents.addRole` from the pinned context version; `agent-sponsor.md` reads the same field.
- `issue-map.md` uses `unsignedPerWindow`, `signedPerWindow` and an agent object cap: `map` (key 16), with the window fixed at `AUTHOR_WINDOW` because the log computes slot scopes with it. Admitted sponsors: `agents` (key 17). Map visibility: `sealed`. Write policy: `perms.cards`.
- `agent-sponsor.md` asks for admitted sponsors, agent caps, the role that may add agents, and the `agent-sponsor` rule: `agents` and C15.
- `storage.md` A3 asks for a keyring-history switch and a sensitive-folder cap: `storage.keyringHistory` and `storage.sensitiveMax`.

Assumptions about sibling specs:

- `credentials.md` (W0-02, now written): presentations prove `[1, [entry, vote]]`, children of `all` may use different credentials, every presented credential yields a nullifier and the `nullifier` leaf's is the primary one, per deck lineage (ADR 0021); only selective disclosure is proven in 0.1 (ADR 0022).
