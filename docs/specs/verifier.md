# Hum Verifier Spec — Draft 0.1

Oct 6, 2026 · W0-03 · revised after review

## Scope

A verifier is a party that checks evidence and issues resident cards. This spec defines the `verifier` manifest body: what a verifier declares before anyone sends it anything. Issuance and presentation cryptography live in `credentials.md`. The code a verifier runs, and where it runs, live in `verifier-runtime.md`. Which verifiers a context accepts lives in `trust-list.md` and `context.md`.

Three facts shape this spec:

1. **Verifiers are a protocol, not a plugin store.** Anyone with an authority can publish a verifier. The platform's district, age-band and uniqueness verifiers use the same manifest and earn trust the same way.
2. **Custom code can't break unlinkability.** That comes from the credential cryptography, whatever the verifier runs.
3. **Custom code can over-collect evidence.** The defense is transparency. The phone builds a disclosure summary from the manifest alone, shows it before anyone submits evidence, and sends only what the manifest declares.

Envelope fields (`spec`, `type`, `authority`, `lineage`, `version`, `prev`, `issued`, `expires`, `refs`) come from `manifest.md`. The verifier manifest is signed by the verifier's authority and is in the type registry as `verifier`.

Conventions, shared with `context.md`: text fields are UTF-8, NFC, with no control characters, and every limit is in bytes. CBOR keys are small unsigned integers; the JSON view uses the names.

## Terms

| Term | Meaning |
| --- | --- |
| Verifier | The party and its manifest lineage. Named by its authority CID. |
| Issuer key | The credential-signing key in the manifest body. Separate from the authority's manifest-signing keys. |
| Host | The server that runs the verifier's module, holds the issuer key, and talks to phones. See `verifier-runtime.md`. |
| Module | The code that decides whether evidence earns a credential. Pinned by hash. |
| Attribute | A fact a credential can carry, such as `ward` or `age-band`. |
| Evidence | What a person submits to get a credential. Never in a manifest. |
| Dataset | Reference data the module reads, fixed by a Merkle root. Rosters, code lists and voter files are datasets. |
| Disclosure summary | The structure the phone derives from the manifest before evidence is submitted. |
| Profile | A named shape for a verifier: invite, approved list, district, age band, uniqueness, or custom. |

## Body fields

"Frozen" means the field can't change between versions of one lineage; verification step 10 checks it.

| Key | Name | Type | Required | Frozen | Meaning |
| --- | --- | --- | --- | --- | --- |
| 0 | name | text ≤ 64 | yes | no | Display name, such as "Millbrook district verifier" |
| 1 | operator | text ≤ 64 | yes | no | The organization or role that runs it. Not a person's name. |
| 2 | lang | text ≤ 16 | yes | no | BCP 47 tag, `^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$`, for every label in this body |
| 3 | profile | text | yes | yes | One of `invite`, `approved-list`, `district`, `age-band`, `uniqueness`, `custom` |
| 4 | class | text | yes | yes | `person` or `agent`. A `vote` policy is never satisfied by an `agent` credential. |
| 5 | issuerKeys | array ≤ 8 of issuer key | yes | no | Keys that sign credentials, each from a given epoch on |
| 6 | retiredKids | array ≤ 64 of bytes | no | no | Every issuer `kid` ever listed in this lineage and no longer in `issuerKeys` |
| 7 | hostKeys | array ≤ 8 of host key | yes | no | Keys session payloads are sealed to |
| 8 | attributes | array ≤ 32 of attribute | yes | partly | Attributes this verifier issues. Names, types and value numbers are frozen; new ones may be added. |
| 9 | evidence | array ≤ 16 of evidence item | yes | no | Everything a person is asked for, and how long each item is kept |
| 10 | datasets | array ≤ 16 of dataset | no | no | Reference data the module reads |
| 11 | dedup | array ≤ 4 of dedup item | yes | no | How the verifier stops one person getting two cards. Empty means no check. |
| 12 | revocation | revocation | yes | no | How a credential stops being valid |
| 13 | validity | uint seconds | yes | yes | Nominal credential lifetime. A multiple of 86,400, at least 2,419,200 (28 days), at most 31,622,400 (366 days). Frozen, because it fixes the epoch grid; see "Lifetime". |
| 14 | assurance | uint 0–3 | yes | no | Declared assurance level |
| 15 | code | code | yes | no | The module and how to rebuild it |
| 16 | sessionCap | uint | no | no | Most issuance sessions one phone may open per day. Default 5. How the host counts is in `services.md`; see the open question in `verifier-runtime.md`. |

### Issuer key

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | kid | bytes 4–32 | Key ID. Unique within the lineage, never reused. |
| 1 | alg | text | Credential signature suite. Draft 0.1: `bbs-bls12381-sha256` only; `key` is 96 bytes (G2, compressed). |
| 2 | key | bytes | Public key in the suite's encoding |
| 3 | fromEpoch | uint | The first epoch this key signs. Set once, carried unchanged. |
| 4 | since | uint | The manifest version that introduced this key. Set once, carried unchanged. |

**Which key signs an epoch.** The key of epoch `E` is the listed key with the largest `fromEpoch ≤ E`, read from the manifest version in force at the start of `E`'s handover. (`E`'s message layout does not depend on that version: it is the attributes with `fromEpoch ≤ E`, computable from any version that lists them.) If that key has since been removed from `issuerKeys`, the key of `E` is the one the current version selects. A key leaves `issuerKeys` in one of two ways. **Ordinary retirement:** a key none of whose epochs can still be presented moves to `retiredKids`, and that is no sooner than `KEY_TAIL` = 44,928,000 seconds (520 days) after its last epoch ends. The tail is fixed because a card of epoch `E` must keep verifying for every replacement and later round of any deck whose version-1 `closes` fell in `E` (`ballot.md`, `shield.md`): `closes` can move up to a year after `opens`, `expires` up to 150 days after that, and 5 days are margin (ADR 0104). **Emergency removal:** a key is removed earlier only to revoke it, and that has the cost set out under "Lifetime". `KEY_TAIL` is a commitment, not a checkable rule: the log can't tell an early retirement from an emergency removal, and the emergency path must stay open, so no validation rule enforces the tail and its vector is informative (an accepting case only). A trust list that sees a key removed early without a stated compromise can treat that as conduct.

A presentation carries the issuer `kid` and the card's epoch (see "Lifetime"). Both are the same for every valid card of an issuer at any moment, so they identify the issuer, not a cohort within it. Late joiners to an epoch get that epoch's key even after a newer key is listed; a first session in handover gets two cards under their two epochs' keys, each response naming its `kid`. Fixing a flaw in how a verifier decided (a dedup bug, a bad dataset) requires a new `kid`; trust lists compare `minVersion` to the key's `since`, read from the verifier version in force, so old credentials under the old key can be refused while the lineage continues and nobody walks the lineage. `issuerKeys` holds at most 8 keys and a replaced key stays listed for `KEY_TAIL`, so a verifier can change keys about seven times in any 520 days. An eighth change in that time forces an early removal, which is the emergency path and ends the later rounds of open decks for holders of the removed key. A verifier that fixes flaws under new keys that often should move to a new authority instead. When `retiredKids` is full, the lineage retires and names a successor (`manifest.md`, "Moving to a new authority").

The suite is set by `credentials.md`. If W0-02 recommends a group-proof scheme instead of BBS, `alg` names that scheme and `key` holds the group commitment. The rest of this spec does not change.

### Host key

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | kid | bytes 4–32 | Key ID |
| 1 | alg | text | `hpke-x25519-sha256-chacha20poly1305` in draft 0.1 |
| 2 | key | bytes 32 | Public key |

Session payloads, meaning every evidence body and the blind issuance request, are HPKE-sealed by the phone to a listed host key. An evidence body uses base mode with `info` = `hum/evidence/1` ‖ this verifier's authority CID (33 bytes) ‖ the evidence item's `name`, and `aad` = the 16-byte session ID ‖ SHA-256(the issuance request plaintext, canonical CBOR), 48 bytes. The phone builds the issuance request before it seals any evidence. The binding to the request is what matters: the session ID is returned by the host through whatever edge sits in front of it, and it is the only credential for the issue call, so an edge could hand the phone its own session's ID, or let the evidence through and send an issuance request of its own in the same session. With the request hash in the `aad`, evidence opens only beside the exact request the person's phone made, so a sealed item cannot be replayed to another verifier, as another item, into another session, or under another issuance request. The host therefore holds evidence items sealed until the issue call arrives, opens the request, recomputes the hash, opens each item under it, and refuses the session (`rejected`, rule `V-4`) if any item fails to open. An edge can still deny service. A `credential` evidence item binds to the same hash as its bound message. An item that is a bearer secret by nature, such as a one-time code, still depends on the host not misusing it. The issuance request uses `hum/issue/1` (`credentials.md`). TLS is transport only. A load balancer or edge in front of the host sees ciphertext, and the manifest's key is what binds the session to this verifier. Hosts are named by key; where to reach one travels as an unsigned location hint beside the bundle, never in the body.

### Attribute

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | name | text ≤ 32 | `^[a-z][a-z0-9-]{0,31}$`. Unique within the manifest. Frozen. |
| 1 | label | text ≤ 40 | Display label, such as "Ward". May be edited between versions. |
| 2 | type | text | `bool`, `enum`, `band` or `uint`. Frozen. |
| 3 | values | array ≤ 1024 | For `enum`: items `{v: uint, label: text ≤ 40}` with unique `v`. For `band`: items `{lo: uint, hi: uint, label}`, ascending and non-overlapping. Absent for `bool` and `uint`. |
| 4 | max | uint | For `uint` only: the largest value, below 2⁶⁴ − 1 (the absent sentinel in `credentials.md`). Absent otherwise. |
| 5 | exposure | text | `gate` or `breakdown`. See the next section. |
| 6 | status | text | `active` or `deprecated`. A deprecated attribute is no longer issued, stays valid in existing credentials, and never returns to `active`. |
| 7 | fromEpoch | uint | The first epoch whose cards carry this attribute's message. Set once, when the attribute first appears, and carried unchanged. Non-decreasing in array order. |

The value a credential carries is a non-negative integer in every case:

- `bool`: the attribute is present in a credential only when true, with value 1. A policy predicate "present" means true.
- `enum`: the declared `v`.
- `band`: the 0-based index into `values`. Order is therefore frozen.
- `uint`: the number itself, at most `max`.

Values of `enum` and `band` may be added at the end in a later version. Existing `v` numbers and band positions keep their meaning and may not be removed; labels may be reworded. An appended attribute becomes issuable from its `fromEpoch`. **The message layout of epoch `E` is the attributes with `fromEpoch ≤ E`, in array order**, so a card of epoch `E` has `2 + (number of attributes with fromEpoch ≤ E)` messages. Anyone can compute that from any version of the manifest that lists the attribute, with no clock and no log position, which is what a verifier of a logged proof needs (`credentials.md`, "Message layout"; ADR 0101). An attribute must not join an epoch whose cards may already exist, so a new attribute's `fromEpoch` is at least the epoch after the latest one whose handover has begun: `E_now + 1` outside handover, `E_now + 2` during it. The log checks that with its own clock when the version is submitted (rule 30).

### Evidence item

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | name | text ≤ 32 | Field name the phone, host and module use. Unique within the manifest. |
| 1 | kind | text | One of the kinds in the table below |
| 2 | schema | text | How the phone collects it: `none`, `text`, `number`, `date`, `image`, `credential`, `device` |
| 3 | purpose | text ≤ 140 | Why it is asked for, shown verbatim |
| 4 | kept | uint seconds | How long the host keeps it after the session. 0 means discarded when the session ends. At most `validity` plus 30 days. |
| 5 | storedAs | text | `none`, `hash` (a keyed hash only) or `raw` |
| 6 | required | bool | Whether the session can proceed without it |
| 7 | accepts | array ≤ 8 of `{authority: CID, attributes: array ≤ 8 of text}` | For `kind` `credential` only: the alternatives. The phone presents exactly one card, from the lowest-index entry whose authority it holds a valid card from, and discloses that entry's attributes. It never presents one card per entry. The asking host learns which entry was used, so which verifier issued the person's card; that is accepted here and only here, because the host already sees the person's evidence. Required and non-empty then; absent otherwise. |

Evidence kinds and what the phone says for each:

| Kind | Phone shows | Typical schema |
| --- | --- | --- |
| `code` | "A one-time code from an organizer" | `text` |
| `link` | "The invite link you opened" | `none` |
| `roster` | "A roster entry an organizer added for you" | `text` or `none` |
| `voter-file` | "Your name and address, matched against the voter file" | `text` |
| `address` | "Your street address" | `text` |
| `date-of-birth` | "Your date of birth" | `date` |
| `document` | "A photo of an identity document" | `image` |
| `selfie` | "A photo of your face, matched to your document" | `image` |
| `phone` | "Your phone number" | `text` |
| `email` | "Your email address" | `text` |
| `device` | "A one-time attestation from this phone" | `device` |
| `credential` | "A resident card from another verifier" | `credential` |
| `other` | The `purpose` text, prefixed with "Something else:" | any |

A `credential` item is how a verifier requires a card from another verifier at issuance, such as a core uniqueness card. The phone presents the card under the **issuance scope** `hum/issuance/1 ‖ verifier authority CID` (the ASCII label followed by the raw CID bytes, algorithm byte included), which is distinct from every context scope, so the nullifier the host sees can't be joined to any context's nullifier for the same card. The presentation's bound message is SHA-256 of the session's issuance request plaintext (`credentials.md`, "The uses"), so the proof cannot be moved to another session. `credentials.md` adopts this scope string. The host verifies the presentation and gives the module only the disclosed `(authority, attribute, value)` triples.

### Dataset

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | name | text ≤ 32 | Name the module uses |
| 1 | kind | text | `public` (the record blob is pinned in `refs`) or `private` (the records stay on the host) |
| 2 | commitment | bytes 32 | Merkle root over the records, computed as `verifier-runtime.md` defines, for both kinds |
| 3 | records | uint | Record count |
| 4 | describe | text ≤ 140 | What it is, such as "County voter file, 2026-09 extract" |

Both kinds use the same record format and the same tree, so a module looks up a public and a private dataset the same way. For a `public` dataset the blob at `refs["dataset.<name>"]` holds the records, and `commitment` equals the root recomputed from that blob.

Datasets are how a profile is configured without changing its code. An invite verifier's list of one-time codes, an approved-list verifier's roster and a district verifier's voter file are all datasets. Secret ones are `private`; what the public sees is the root and the record count.

### Dedup item

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | method | text | `evidence`, `credential` or `device` |
| 1 | field | text | The evidence item the key comes from |
| 2 | scope | text ≤ 64 | What one key covers, such as "one card per voter-file record" |

The key for each method:

- `evidence`: the module derives it from the named item, for example a voter-file record ID.
- `credential`: the issuance-scope nullifier of the presented card. The host supplies it; the module never sees it.
- `device`: the per-verifier keyed hash of the device attestation key. The host supplies it.

The host stores, under a keyed hash of each key, a row holding `lastEpoch` (the epoch of the newest card issued under it), the `kid` that signed it, and the hash of that card's issuance request, and keeps the row until 30 days after `lastEpoch` ends. One key yields at most one card per epoch. When a session matches several rows, the largest `lastEpoch` governs and is written back to every row; a row whose `kid` is no longer in `issuerKeys` counts as no row, so an emergency key removal lets everyone re-enrol. `verifier-runtime.md` step 4 gives the host rule. A `credential` item is never the only dedup item: the presented card's nullifier changes with that card's epoch, and another issuer's epoch grid can turn inside this one's. Dedup links two issuance attempts at one verifier. It never touches a context presentation, a pseudonym or a context nullifier.

### Revocation

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | method | text | `reissue` or `accumulator` |
| 1 | accumulator | text | For `accumulator`: the scheme name. Reserved; no scheme is defined in draft 0.1. |

Draft 0.1 verifiers use `reissue` (decision 0032): a card lives one epoch, and renewal is an ordinary evidence session during the epoch's handover that issues the next epoch's card post-dated. There is no evidence-free renewal in draft 0.1 (`credentials.md` ADR 0026). A renewal session presents the same evidence as before (the same code, roster entry, document or device), which maps to the same dedup row, so nobody needs a new one-time code each epoch.

### Lifetime

`credentials.md` measures time in 28-day periods aligned to the Unix epoch, and groups them into **epochs** of `V = floor(validity / 2,419,200)` periods, `epoch(p) = floor(p / V)`. A card carries its epoch, disclosed at every presentation, and is valid in that epoch only. A card issued mid-epoch is shorter-lived; one issued in an epoch's last period lives at most 28 days, which verifiers with `validity` under 56 days should weigh. **Handover** is the last two periods of an epoch: a session then issues the next epoch's card (and, for a first-time holder, the current one too). The district example's `validity` of 180 days gives `V = 6` and 168-day epochs. There is no per-card lifetime; a verifier that wants shorter cards sets `validity` for everyone. Removing an issuer key from `issuerKeys` before its `KEY_TAIL` has run revokes every credential under it at once; this is the emergency path. Its effect on open decks is stated here so nobody is surprised (ADR 0104): voters under that key keep the round-0 ballot they already sent (`release.md` R12), and can neither replace it nor answer rounds 1 to 3, because their phone is pinned to the dead card (`shield.md` S11) and the aggregator now rejects it. Their dedup rows count as no row, so they re-enrol in the same epoch and get a card with a new nym secret. An honest phone does not vote again in a deck it already has an entry for. A modified client can, because the new card's nullifier is new for the deck, so one such person can be counted twice in that deck. An organizer whose deck has not closed should retire it and deal a new one. When a verifier lineage retires, its credentials stop verifying at the next presentation.

### Code

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | format | text | `wasm-component/1` |
| 1 | abi | text | The module world, such as `hum:verifier/module@0.1` |
| 2 | source | bytes 20 or 32 | Source commit hash |
| 3 | toolchain | text ≤ 120 | Compiler and target, such as `rustc 1.99.0, target wasm32-wasip2`. That target emits a component directly; no separate component tool is used. |

The module bytes are pinned in `refs` as `code`; the build recipe is pinned as `build`. A module takes no build-time parameters. Everything that varies between two verifiers using the same module comes from the manifest body (value sets, bands, evidence names) or from datasets. `verifier-runtime.md` says how a rebuild is checked.

## Refs

| Name | Points to | Required |
| --- | --- | --- |
| `code` | Public blob: the module, at most 16 MiB | yes |
| `build` | Public blob: the build recipe (`verifier-runtime.md`) | yes |
| `profile` | Public blob: the reference operator's binary for this profile | for the five named profiles |
| `dataset.<name>` | Public blob: the record array for each `public` dataset | one per public dataset |

For a named profile, `code` and `profile` are the same CID: the one fixed binary the reference operator publishes for that profile. A trust list that attests that CID attests every verifier built on it. A verifier manifest pins no other manifest.

## Gate and breakdown attributes

An attribute's `exposure` says what it can be used for.

- **`gate`** attributes are only ever proven in zero knowledge against a context's entry policy. The phone never discloses a gate attribute's value to anyone.
- **`breakdown`** attributes may also be disclosed, at the person's choice, so a release can split tallies by them. The aggregator publishes a breakdown cell only once its noised count reaches `GATE_CELL` (300); that gate is in `deck.md` and `release.md`.

Rules:

1. A `uint` attribute is always `gate`. Numbers such as a unit or a roster row identify people.
2. An `enum` or `band` attribute may be `breakdown` only if it has at most 64 values.
3. A `bool` attribute may be either.
4. Exposure can move from `breakdown` to `gate` in a later version, never the other way.
5. A phone discloses a breakdown attribute only if all three hold: the verifier version marks it `breakdown`, the deck's release plan names it (as a policy leaf: source, name, values), and the person approved it for that context. Each context asks again. The plan's source resolves to exactly one verifier (`deck.md` rule D9, by the test of `context.md` rule C16), so every breakdown ballot of a deck carries a card from the same verifier.

A unit number can gate entry to a building's context and never appear in a breakdown. A ward can do both.

Policies in draft 0.1 can prove only simple predicates on a gate attribute: a `bool` present, a single `enum` or `band` value, or a `uint` range with `lo = hi` (`credentials.md`, "What is proven"). A verifier that expects policies like "wards 1–3" should coarsen at issuance instead: the district profile's `area` attribute exists for that.

## Disclosure summary

Before a phone opens an issuance session, it derives a summary from the manifest and nothing else. The host can't change it: `services.md`'s session call returns no list of asks, so the only list the person ever sees is the one the phone derived. Conformance vectors give the manifest and the expected summary as JSON. The summary is structured; the app turns it into sentences in the person's language, and that prose is not part of conformance.

| Field | Source |
| --- | --- |
| `who.name`, `who.operator`, `who.lang` | `name`, `operator`, `lang` |
| `who.assurance` | `assurance`, as the number 0–3 |
| `who.class` | `class` |
| `who.authority` | The authority CID in text form |
| `proves[]` | One entry per `active` attribute, in manifest order: `name`, `label`, `type`, `values[]` (labels, in order), `max` when `uint`, `canBreakdown` |
| `asks[]` | One entry per evidence item, in manifest order: `name`, `kind`, `schema`, `purpose`, `required`, `keptSeconds`, `storedAs`, and `accepts` when present |
| `links[]` | One entry per dedup item: `method`, `scope`. Empty when no dedup. |
| `expires` | `{validitySeconds, epochPeriods: V, renewal: "reissue" or "accumulator"}` |
| `code` | `{cid, source (hex), toolchain, profile (the ref's CID text, or null)}` |
| `datasets[]` | `{name, kind, records, describe}` |

The app adds, outside the summary, the "who learns what" rows (the verifier learns the evidence listed and that you got a card; contexts learn only the facts you approve; no one can link you across contexts), and may add which of the context's pinned trust lists attest `code.cid`. Neither is in the vectors because both need context the manifest doesn't carry.

Assurance labels the app uses:

| Level | Label | Meaning |
| --- | --- | --- |
| 0 | Open | Anyone with the link or code |
| 1 | Vouched | An organizer or a roster says you belong |
| 2 | Record-matched | Matched against an independent record, such as a voter file, with no identity document |
| 3 | Identity-checked | A government document with a liveness check, or in person |

Assurance is declared by the verifier and judged by everyone else. Releases list the accepted verifiers and their declared assurance; trust lists say which levels a community accepts.

## Profiles

A profile fixes what a verifier of that kind must declare. Each of the five named profiles is one fixed binary, built and attested by the reference operator, so an organizer configures a manifest and datasets rather than writing code. A `custom` verifier is bound only by the general rules.

| Profile | Attributes it must declare | Evidence allowed | Datasets | Dedup | Assurance |
| --- | --- | --- | --- | --- | --- |
| `invite` | `invite` (bool, gate); optional `cohort` (enum, breakdown) | `link` or `code`; optional `device` | `codes` (private: salted hashes of one-time codes) when `code` is used | none for a multi-use link; `evidence` on `code` for one-time codes; optional `device` | 0 |
| `approved-list` | `approved` (bool, gate); optional `role` (enum, gate) | `roster` plus one of `email`, `phone`, `code`; optional `device` | `roster` (private) | `evidence` on `roster`; optional `device` | 1 |
| `district` | `ward` (enum, breakdown) and `area` (enum, breakdown) | `voter-file` or `address`; optional `credential` for a uniqueness card | `voters` (private), `wards` (public) | `evidence` on the matched record; `credential` when required | 2 |
| `age-band` | `age-band` (band, breakdown) with bands 18–24, 25–34, 35–49, 50–64, 65+ | `date-of-birth` with `document`, or `voter-file` | `voters` (private) when `voter-file` is used | `evidence` on the matched record or document number | 2 or 3 |
| `uniqueness` | `unique` (bool, gate) | `device` plus `document` and `selfie`, or `device` plus `phone` | none | two items: `evidence` on `document` or `phone`, and `device` | 2 or 3 |

Profile rules a conformance vector checks (rule 20 below, one vector per sub-rule):

- 20a. Every attribute in the profile's row is declared with the listed type and exposure.
- 20b. Every evidence item's `kind` is in the profile's allowed set.
- 20c. Every dedup item the profile's row requires is present. (A method outside the profile's set is unreachable here: rule 14 ties each method to an evidence kind, and 20b already rejects kinds the profile doesn't allow.)
- 20d. `assurance` is within the profile's range.
- 20e. The `profile` ref is present and `refs["code"]` equals it.

Notes on the profiles:

- **Invite** and **approved list** verifiers' authorities are usually the context's own authority. The platform host runs their binary for organizers who don't run servers. Codes and rosters are private datasets, so the public sees their size and root, never their contents. Renewal in handover presents the same code or roster entry, which maps to the same dedup row.
- **District** keeps no address. The module matches the submitted fields against the private dataset, outputs `ward` and `area`, and returns a dedup key built from the record ID. The host stores the keyed hash, not the record. The address item's `kept` is 0 and `storedAs` is `none`.
- **Age band** issues bands, never a birth date. Bands drift as people age; `validity` of at most one year handles it. A document image's `kept` is 0.
- **Uniqueness** is per verifier. Its two dedup keys mean one card per document (or phone number) and one card per device. A policy leaf names exactly one verifier in draft 0.1 (`context.md` rule C16), so a context cannot accept two uniqueness verifiers as alternatives; if a later draft allows that, one person may hold a card from each.

## Validation rules

Each rule is phrased so a conformance vector can test it. Rules 1–20 run in verification step 4 (schema); 21–29 run in step 10 (type rules) and compare to `prev` only; 30 and 31 are run by the log at submission, because they need its clock or its history.

1. `profile` is one of the six values, `class` is `person` or `agent`, and `lang` matches its pattern.
2. Every text field is valid UTF-8, NFC, free of control characters, and within its byte limit. Every array is within its size limit.
3. Every issuer key's `alg` is a known suite, every `key` has the suite's length, every `since` is at least 1 and at most the manifest's `version`, and `fromEpoch` values are unique across `issuerKeys`.
4. Issuer key IDs are unique within `issuerKeys` and absent from `retiredKids`.
5. `hostKeys` has at least one key and every `alg` is known with the right key length.
6. Attribute names are unique and match the pattern.
7. 7a. Every `enum` and `band` attribute has at least two values. 7b. `v` values and labels are unique within an attribute. 7c. Bands are ascending and don't overlap.
8. A `uint` attribute has `max` below 2⁶⁴ − 1 and `exposure` `gate`; no other type has `max`.
9. An `enum` or `band` attribute with more than 64 values has `exposure` `gate`.
10. Evidence names are unique; every `kind` and `schema` is known; `other` has a non-empty `purpose`.
11. Every evidence item's `kept` is at most `validity` plus 2,592,000 (30 days).
12. An evidence item with `storedAs` `none` has `kept` 0.
13. A `credential` item has a non-empty `accepts`; every other item has none. Each `accepts` entry has a valid CID and non-empty attribute names.
14. Every dedup item's `field` names an evidence item whose kind fits the method: any kind for `evidence`, `credential` for `credential`, `device` for `device`. Fields are unique across dedup items. A non-empty `dedup` contains at least one item whose method is not `credential`.
15. `revocation.method` is `reissue`, or `accumulator` with a known scheme (none in draft 0.1).
16. `validity` is a multiple of 86,400, at least 2,419,200 and at most 31,622,400.
17. `assurance` is 0 to 3.
18. `code.format` is `wasm-component/1` and `code.abi` is a known world.
19. `refs` contains `code` and `build`, and a `dataset.<name>` entry for every `public` dataset; every dataset has a 32-byte `commitment`.
20. The profile rules 20a–20e hold.
21. `profile`, `class` and `validity` equal the previous version's.
22. Every attribute in the previous version is present with the same `name`, `type`, `max` and, for `enum` and `band`, the same `v` numbers and band ranges in the same positions. New values appear only at the end.
23. No attribute moved from `gate` to `breakdown`, and no `deprecated` attribute became `active`.
24. `retiredKids` contains every `kid` that was in the previous version's `issuerKeys` or `retiredKids` and is not in this version's `issuerKeys`, and no `kid` in `issuerKeys` was in the previous version's `retiredKids`.
25. Every `kid` present in both versions has the same `key`.
26. Every `kid` present in both versions has the same `fromEpoch`, and every `kid` not in the previous version has a `fromEpoch` greater than every other listed key's.
27. Every `kid` present in both versions has the same `since`.
28. Every `kid` not in the previous version has `since` equal to this manifest's `version`. In version 1, every key has `since` 1.
29. Every attribute has a `fromEpoch`. Values are non-decreasing in array order. Every attribute present in the previous version has the same `fromEpoch`.
30. At the log, with `E_now` computed by the log's clock from this lineage's `validity`. For a version greater than 1: every attribute not in the previous version has `E_now + 1 ≤ fromEpoch ≤ E_now + 2`, and during the last two periods of `E_now` exactly `E_now + 2`. For version 1: every attribute has `fromEpoch ≤ E_now + 2`. The ceiling exists because `fromEpoch` is frozen and non-decreasing, so a mistyped far-future value could never be corrected. A later verifier does not re-check this rule. A log that skips the lower bound lets an attribute join an epoch whose cards already exist; those holders then present a `len` every verifier rejects, and dedup keeps them from re-enrolling until handover.
31. One `verifier` lineage per authority. The log refuses version 1 of a `verifier` manifest when its own history already holds a `verifier` lineage under the same authority, retired or not. A verifier that needs a new lineage (a different `validity`, a full `retiredKids`) uses a new authority and the successor mechanism of `manifest.md`. A phone or aggregator that nevertheless finds two under one authority uses the one with the lower index in the log it is reading (the context's log of record, for a context policy) and ignores the other.

Rules 24–28 make "a key ID is never reused", "`since` is honest" and "newer keys sign later epochs" checkable against `prev` alone, because every retired ID stays listed forever and `since` and `fromEpoch` can only be set when a key first appears.

A phone or aggregator that accepts a credential checks, beyond these, that the issuer `kid` is in `issuerKeys` of the verifier version in force, that the lineage is not retired, and that the attribute is declared there. "In force" is defined once, in `credentials.md` under "Verification rules": for a ballot, a join ticket, a token request or issuance evidence, which have no log position, it is the latest version the verifying party holds a witnessed proof for; for a proof stored in a logged object it is the version at that object's position in the log of record. The key's `since` in that version is the version it first appeared in; `trust-list.md` compares `minVersion` to it without walking the lineage.

## Example

The readable view of a district verifier's second version:

```json
{
  "spec": 1,
  "type": "verifier",
  "authority": "c5r2hq…9ta",
  "lineage": "c8ne1y…k0d",
  "version": 2,
  "prev": "c8ne1y…k0d",
  "issued": 1791259200,
  "refs": {
    "code": "c3a9vd…x1p",
    "build": "c0m7lk…e4s",
    "profile": "c3a9vd…x1p",
    "dataset.wards": "c6tq0w…r8n"
  },
  "body": {
    "name": "Millbrook district verifier",
    "operator": "Hum reference operator",
    "lang": "en",
    "profile": "district",
    "class": "person",
    "issuerKeys": [
      { "kid": "6d62310a", "alg": "bbs-bls12381-sha256", "key": "a3f1…", "fromEpoch": 4, "since": 2 },
      { "kid": "6d623009", "alg": "bbs-bls12381-sha256", "key": "91c0…", "fromEpoch": 0, "since": 1 }
    ],
    "retiredKids": [],
    "hostKeys": [ { "kid": "68307301", "alg": "hpke-x25519-sha256-chacha20poly1305", "key": "7e2b…" } ],
    "attributes": [
      { "name": "ward", "label": "Ward", "type": "enum", "exposure": "breakdown", "status": "active", "fromEpoch": 0,
        "values": [ { "v": 1, "label": "Ward 1" }, { "v": 2, "label": "Ward 2" }, { "v": 3, "label": "Ward 3" } ] },
      { "name": "area", "label": "Area", "type": "enum", "exposure": "breakdown", "status": "active", "fromEpoch": 0,
        "values": [ { "v": 1, "label": "Millbrook" }, { "v": 2, "label": "Outside Millbrook" } ] }
    ],
    "evidence": [
      { "name": "match", "kind": "voter-file", "schema": "text", "required": true,
        "purpose": "To find your ward in the county voter file", "kept": 0, "storedAs": "none" }
    ],
    "datasets": [
      { "name": "voters", "kind": "private", "commitment": "4c9e…", "records": 48210, "describe": "County voter file, 2026-09 extract" },
      { "name": "wards", "kind": "public", "commitment": "d02a…", "records": 3, "describe": "Ward boundaries, 2024 redistricting" }
    ],
    "dedup": [ { "method": "evidence", "field": "match", "scope": "One card per voter-file record" } ],
    "revocation": { "method": "reissue" },
    "validity": 15552000,
    "assurance": 2,
    "code": { "format": "wasm-component/1", "abi": "hum:verifier/module@0.1",
              "source": "9f4e…", "toolchain": "rustc 1.99.0, target wasm32-wasip2" }
  }
}
```

Its disclosure summary:

```json
{
  "who": { "name": "Millbrook district verifier", "operator": "Hum reference operator", "lang": "en",
           "assurance": 2, "class": "person", "authority": "c5r2hq…9ta" },
  "proves": [
    { "name": "ward", "label": "Ward", "type": "enum", "values": ["Ward 1", "Ward 2", "Ward 3"], "canBreakdown": true },
    { "name": "area", "label": "Area", "type": "enum", "values": ["Millbrook", "Outside Millbrook"], "canBreakdown": true }
  ],
  "asks": [
    { "name": "match", "kind": "voter-file", "schema": "text", "purpose": "To find your ward in the county voter file",
      "required": true, "keptSeconds": 0, "storedAs": "none" }
  ],
  "links": [ { "method": "evidence", "scope": "One card per voter-file record" } ],
  "expires": { "validitySeconds": 15552000, "epochPeriods": 6, "renewal": "reissue" },
  "code": { "cid": "c3a9vd…x1p", "source": "9f4e…", "toolchain": "rustc 1.99.0, target wasm32-wasip2", "profile": "c3a9vd…x1p" },
  "datasets": [ { "name": "voters", "kind": "private", "records": 48210, "describe": "County voter file, 2026-09 extract" },
                { "name": "wards", "kind": "public", "records": 3, "describe": "Ward boundaries, 2024 redistricting" } ]
}
```

## Security considerations

| Threat | Mitigation |
| --- | --- |
| A verifier asks for more than it needs | Evidence is declared per item with purpose and retention. The phone sends only declared items and shows them first. Every change is a new logged version. |
| A person gets two valid cards from one dedup key | The dedup row records the newest epoch and outlives every card under it; handover issues only the next epoch; the largest `lastEpoch` across matched rows governs (`verifier-runtime.md` step 4). |
| A card-only dedup key turns with the other issuer's epoch | Rule 14: a `credential` item is never the only dedup item. |
| `validity` changes and renumbers every epoch | Frozen (rule 21). A verifier that needs a different lifetime retires and names a successor. |
| An emergency key removal locks every holder out until handover | Rows whose `kid` is unlisted count as no row; the current version's key selection takes over for the epoch. |
| An emergency key removal during an open deck | Round-0 ballots stand; affected voters lose replacements and later rounds; a modified client can vote a second time with its re-issued card, an honest phone cannot ("Lifetime"). Organizers are advised to re-deal a deck that has not closed. |
| A key is retired while a pinned card of one of its epochs can still be presented | Ordinary retirement waits `KEY_TAIL` (520 days) after the key's last epoch. |
| A verifier's host keeps evidence it said it would discard | Not preventable by protocol. Declared retention is a public commitment; trust lists and track records are how it is judged. |
| A TLS terminator in front of the host reads evidence | Session payloads are HPKE-sealed to a manifest-listed host key; TLS is transport only. |
| A fine-grained attribute leaks through breakdowns | `uint` attributes and large enums are gate-only; breakdown cells need 300 noised voters. |
| The issuer `kid` or epoch in a presentation narrows the holder within an issuer | Every valid card of an issuer shares its `kid`, epoch and message count: one key per epoch chosen by `fromEpoch` from the version in force at handover start, layouts fixed per epoch by each attribute's `fromEpoch`. What a presentation reveals is the issuer, which the policy reveals anyway. |
| A disclosed credential expiry fingerprints a person | The card's epoch is disclosed, and every valid card of this issuer shares it. There is no per-card lifetime, so nothing finer exists to disclose. |
| An issuer key is stolen | Remove it from `issuerKeys` in a new version; every credential under it stops verifying. The authority's own keys follow `manifest.md`. |
| A verifier issues credentials to agents that a voting policy accepts | `class` is frozen; `trust-list.md` resolution yields no `vote` rows from an `agent` verifier; `context.md` rule C15 forbids the sponsor attribute in policies. |
| Dedup links a person's issuance to their votes | Dedup keys are keyed hashes of evidence, an issuance-scope nullifier or a device hash, held by the host, and never leave issuance. Context presentations carry none of them. |
| The issuing host joins a required card to a context | The card is presented under the issuance scope, which is distinct from every context scope, so the nullifiers differ. |
| A small private dataset is confirmed by guessing against its root | Leaves are salted with a per-dataset secret (`verifier-runtime.md`). |
| A verifier silently swaps its code | The module is pinned by CID; a new module is a new logged version the phone shows again. |
| Two versions of a verifier are shown to different people | Equivocation rules in `manifest.md`. |

## Vectors

W0-08 generates these from `reference/`.

Valid:

- One manifest per profile: `invite` (multi-use link), `invite` (one-time codes with a `codes` dataset), `approved-list`, `district`, `age-band`, `uniqueness` (two dedup items), one `custom`, and one `class: agent` verifier.
- A three-version district lineage: version 2 adds a ward value and adds an issuer key with a later `fromEpoch`; version 3 removes the old key into `retiredKids`, logged more than `KEY_TAIL` after that key's last epoch ended (informative: the tail is not a validation rule).
- The disclosure summary for each valid manifest.

Invalid, one per rule 1–28 and per lettered sub-rule (7a–7c, 20a–20e), each naming the failing rule, plus:

- A `custom` verifier whose `code` ref is missing (rule 19).
- A `breakdown` attribute with 65 enum values (rule 9).
- Two issuer keys with the same `fromEpoch` (rule 3).
- `validity` of 27 days (rule 16).
- A `custom` verifier whose only dedup item is `credential` (rule 14).
- Version 2 changes `validity` (rule 21), changes a key's `fromEpoch`, or adds a key with a `fromEpoch` below an existing key's (rule 26).
- A `credential` evidence item without `accepts` (rule 13).
- A dedup item of method `device` whose `field` is a `text` item (rule 14).
- Version 2 removes an attribute (rule 22), inserts an enum value in the middle (rule 22), changes `profile` (rule 21), moves `ward` from `gate` to `breakdown` (rule 23), or reactivates a deprecated attribute (rule 23).
- Version 3 reuses a `kid` from version 1 that version 2 retired (rule 24).
- Version 2 changes an existing key's `since` (rule 27), or introduces a key with `since` 1 (rule 28).
- A `district` manifest missing `area` (rule 20a).
- Evidence sealing: an item sealed for one session and submitted in another (rejected: the AEAD fails under the other session ID); an item sealed under another item's name (rejected); an issuance request that differs from the one the evidence was sealed for, sent in the same session (rejected); a session ID replaced in transit, so the phone seals for the edge's session and the edge sends its own request there (rejected: the items open only beside the phone's request); a handover session whose one request carries two commitments, with every item sealed under that one request's hash (valid); a lost-response retry in a new session with the identical request plaintext and evidence re-sealed under the new session ID (valid, identical response).
- A `uniqueness` manifest with only the document dedup item and no `device` item (rule 20c).
- An attribute without `fromEpoch`; `fromEpoch` values decreasing in array order; version 2 changes an existing attribute's `fromEpoch` (rule 29).
- At the log: version 2 appends an attribute with `fromEpoch = E_now` (rule 30); the same during handover with `fromEpoch = E_now + 1` (rule 30); `E_now + 2` during handover (valid). A new attribute with `fromEpoch = E_now + 3` (rule 30, ceiling); version 1 with `fromEpoch` 500 (rule 30).
- At the log: a second `verifier` lineage's version 1 under an authority that already has one (rule 31).
- Layout: a lineage whose version 3 appends an attribute with `fromEpoch` 5; the message count for epochs 4 and 5, computed from version 3 alone.

## Open questions

Filed in `docs/decisions/` where they are decisions; listed here for the cross-spec pass.

- **Resolved with W0-01 (2026-10-06): attribute spelling and value types.** `context.md` and `deck.md` spell the attribute `ward`, and policy predicates and breakdown value sets carry uints with this spec's encoding (bool 1, enum `v`, band index, uint itself).
- **Cross-spec, assurance mix in releases (W0-01).** `release.md` R12 lists accepted verifier authorities with declared assurance from manifests, not per-voter counts. That is the safe choice: a per-verifier voter count is an unnoised sum and would need its own ρ. This spec's text now matches R12. If counts are ever wanted, they are a noised release part.
- **Resolved with W0-07 (2026-10-06): evidence item key.** `services.md` now keys submitted evidence by the item's unique `name`, and every evidence body and the blind request are HPKE-sealed to a `hostKeys` entry named by `kid`.
- **Cross-spec, retired lineages (manifest).** `manifest.md` assigns no envelope key for "retired" or "successor". This spec and `context.md` both need it.
- **Accumulator revocation** is reserved but undefined (decision 0032).
- **Localization.** One `lang` per manifest. Deferred.
- **Private dataset provenance.** A commitment fixes the data but doesn't prove it is the real voter file. Dataset attestation is an open question in `trust-list.md`.
- **Resolved by `release.md` R12: emergency distrust mid-deck.** Issuer status is not re-checked at close; ballots cast under the deck's context version stand. Issuer-key removal takes effect at the next presentation. This spec accepts that answer.
- **Attribute cardinality for breakdowns.** 64 values is a planning bound; the cell gate does the privacy work.

Assumptions about sibling specs:

- `credentials.md` (W0-02, confirmed 2026-10-06, after its re-review): issuer keys are `bbs-bls12381-sha256` with 96-byte G2 keys, issued blind; a presentation carries the verifier authority CID, the issuer `kid`, the message count and the card's epoch, all shared by every valid card of the issuer; attribute values are uints, gate attributes are proven in zero knowledge, breakdown attributes are disclosed only with per-context consent when the plan names them; its rule P3 rejects `agent`-class credentials in any policy presentation; the issuance scope `hum/issuance/1 ‖ authority` is adopted; cards live one epoch of `V` periods (see "Lifetime"), renewal is an evidence session in handover, and there is no evidence-free renewal or renewal nullifier; the issuance response is sealed back inside the request's HPKE context (RFC 9180 §9.8), and the phone checks the `kid` is the epoch's key by the `fromEpoch` rule, the epoch is current or next-in-handover, every value is declared, and no unapproved attribute is present; a retried identical request gets the identical response; bool attributes are present only when true. Predicates provable in 0.1 are bool present, a single value, and `lo = hi`.
- `context.md` (W0-01): policy leaves name sources `[0, i]` (trust list at `refs["tl/<i>"]`) or `[1, i]` (`issuers[i]`), an attribute name and a predicate. Rule C15 keeps the sponsor attribute out of policies.
- `deck.md` and `release.md` (W0-01, confirmed 2026-10-06): a breakdown is a policy leaf with 2–64 uint values, pooled across the source's verifiers; `GATE_CELL` is 300 per cell in post-processing; releases list accepted verifiers with declared assurance and no counts (R12); issuer status is not re-checked at close.
- `services.md` (W0-07): host API `/v1/verifier/sessions`, `.../evidence`, `.../issue`, `/v1/verifier/revocation` (`/v1/verifier/reissue` withdrawn by `credentials.md`); evidence submitted as `{name, kid, ciphertext}` and the issue call as `{kid, ciphertext}`, HPKE-sealed to a host key, over TLS as transport; the session call returns no asks; duplicate codes are masked as this spec's runtime says; its logging table lists `verifier-runtime.md`'s exact fields. Confirmed on disk.
