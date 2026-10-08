# Hum Trust List Spec — Draft 0.1

Oct 6, 2026 · W0-03 · revised after review

## Scope

A trust list is a signed, versioned, logged list of verifiers a publisher vouches for, with the attributes and assurance it accepts from each. Anyone with an authority can publish one. Contexts point at trust lists, or at single verifiers, in their entry policy. This spec defines the `trust-list` manifest body and how a context resolves the verifiers it accepts.

A trust list never issues anything and never sees a credential. It is a statement of opinion that the log makes public and permanent.

Conventions, shared with `context.md`: text fields are UTF-8, NFC, with no control characters, and every limit is in bytes. No text field holds a person's name; `note` fields are opaque to every resolver.

## Who publishes one

Any authority. At launch the reference operator publishes two:

| List | Scope | Holds |
| --- | --- | --- |
| Core | `core` | The platform's district, age-band and uniqueness verifiers, with rebuilt-code attestations for the five profile binaries |
| Federation | `federation` | Verifiers run by federation members, once federation exists. Empty at launch. |

A civic group, a union, a county or an auditor can publish its own. Nothing distinguishes the operator's lists from anyone else's except who signed them and who pins them. A context that pins only its own `approved-list` verifier needs no trust list at all.

## Body fields

"Frozen" fields can't change within a lineage; verification step 10 checks it.

| Key | Name | Type | Required | Frozen | Meaning |
| --- | --- | --- | --- | --- | --- |
| 0 | name | text ≤ 64 | yes | no | Display name, such as "Hum core verifiers" |
| 1 | publisher | text ≤ 64 | yes | no | The organization that maintains it. Not a person's name. |
| 2 | lang | text ≤ 16 | yes | no | BCP 47 tag, `^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$` |
| 3 | scope | scope | yes | partly | What kinds of verifiers the list covers. `kind` is frozen. |
| 4 | entries | array ≤ 256 of entry | yes | no | Accepted verifiers. May be empty. |
| 5 | removed | array ≤ 256 of removal | no | no | Verifiers in the previous version's `entries` and not in this one's, with a reason. Only those. |
| 6 | minAssurance | uint 0–3 | yes | no | Floor for every entry. An entry may be stricter. |
| 7 | reviewPeriod | uint seconds | no | no | How often the publisher says it re-reviews entries. Informational. |

The envelope's `expires`, if present, is informational for a trust list. A context pins a list version, and that pin stays valid for the context version regardless of the list's own expiry.

### Scope

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | kind | text | `core`, `federation` or `community` |
| 1 | area | text ≤ 64 | Optional. Where the verifiers operate, such as "Millbrook" |
| 2 | classes | array of text | Credential classes covered: `person`, `agent` or both. Default `["person"]`. |

### Entry

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | authority | CID | The verifier's authority (its keyset lineage CID). The list names the authority, and the log decides the current verifier version. |
| 1 | attributes | array ≤ 32 of text | Attribute names accepted from this verifier. An empty array means every attribute the verifier declares at presentation time. |
| 2 | minAssurance | uint 0–3 | Optional. Overrides the list floor upward only. |
| 3 | minVersion | uint | Optional. A credential counts only if its issuer `kid` first appeared in a verifier version numbered at least this. Used after a verifier fixes a flaw under a new key. |
| 4 | attested | array ≤ 8 of CID | Code CIDs this publisher rebuilt and matched to a verifier's `code` ref. See `verifier-runtime.md`. |
| 5 | note | text ≤ 140 | Why it is listed, such as "County voter file, reviewed 2026-09" |

### Removal

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | authority | CID | The verifier removed |
| 1 | reason | text | `retired`, `scope`, `assurance`, `conduct` or `compromise` |
| 2 | note | text ≤ 140 | Optional |

`compromise` means the publisher believes credentials from this verifier should stop being accepted now. Contexts that pin the list learn this on their next version; see "Taking effect" below.

## Refs

A trust list pins nothing. It names verifier authorities, and each authority's current verifier version is found through the log. An authority has exactly one `verifier` lineage (`verifier.md` rule 31), so naming the authority names one verifier. Pinning a verifier version would freeze the list on every verifier update, and a list is an opinion about a party, not about one version (decision 0034).

## How a context uses trust lists

`context.md` owns the entry policy format: a policy leaf names a source, `[0, i]` for the trust list pinned at `refs["tl/<i>"]` or `[1, i]` for the authority at `issuers[i]`, plus an attribute name and a predicate. This section fixes what "accepted from a source" means, so phones and aggregators compute the same set.

A source resolves to **rows**. A row is `[authority, filter, minAssurance, minVersion, classes]` where `filter` is an attribute name or `"*"`.

1. A single authority in `issuers[i]` yields one row `[authority, "*", 0, 1, ["person", "agent"]]`. Assurance is not floored for direct issuers; that is intended for organizer-run invite and approved-list verifiers. A context that names a core verifier directly bypasses the core list's floor, and organizer tooling should say so.
2. A trust list entry yields one row per name in `attributes`, or one `"*"` row if `attributes` is empty. `minAssurance` is the larger of the list floor and the entry's own; `minVersion` is the entry's or 1; `classes` is the list's `scope.classes`.
3. The rows of a context version are fixed once it is logged, because every trust list version is pinned. What a `"*"` filter expands to is evaluated against the verifier version in force, as is everything in step 4. "In force" is `credentials.md`'s definition ("Verification rules"): the latest version the verifying party holds for a ballot, a join ticket or a token request; the version at the object's position in the log of record for a proof stored in a logged object.
4. A credential satisfies a policy leaf over attribute `a` if some row of the leaf's source matches all of:
   - the row's authority is the credential's verifier authority;
   - the filter is `a` or `"*"`, and the verifier version in force (step 3) declares `a`;
   - that version's `assurance` is at least the row's minimum;
   - the issuer key's `since`, read from that same version in force, is at least the row's `minVersion`;
   - the verifier's `class` is in the row's `classes`;
   - the attribute's `exposure` allows the use: any for gating, `breakdown` for disclosure.
5. A row whose verifier `class` is `agent` never satisfies a leaf of the `vote` policy, whatever the source. This is where "agents never vote" is enforced structurally, beside `context.md` rule C15.
6. A retired verifier lineage matches no row.
7. **Draft 0.1, one verifier per leaf.** `context.md` rule C16 rejects a context in which a policy leaf's trust-list source has more than one entry that accepts the leaf's attribute (by name, or by empty `attributes`). A list may still hold several verifiers for one attribute; it then cannot back a policy leaf on that attribute, and a context names one of the verifiers in `issuers` or pins a narrower list. The reason is that a presentation shows which verifier issued each card (`credentials.md`), and members of one context must not differ in it (ADR 0100). Organizer tooling should say so when a list is pinned.

Rows are listed in vectors sorted bytewise on their canonical CBOR encoding, so two resolvers can be diffed.

## Taking effect

Trust list changes take effect when a context publishes a new version pinning the new list version, and then only for decks dealt under that context version. An open deck keeps the context version it was dealt with, so a list change can't change who counted in a deck mid-way. This follows the pinning rule in `manifest.md`.

Two fast paths exist outside trust lists:

- A verifier can remove an issuer key from its own manifest, which revokes every credential under it immediately for new presentations.
- A context can publish a new version that drops the source. The next deck uses it.

A `compromise` removal is a signal to context administrators, not a mechanism. Whether aggregators should re-check issuer status at deck close is an open question in `verifier.md`.

## Validation rules

Each rule is phrased for a conformance vector. Rules 1–10 run in verification step 4; 11–13 in step 10 against `prev`.

1. `scope.kind` is `core`, `federation` or `community`; `scope.classes` is non-empty and contains only `person` and `agent`; `lang` matches its pattern.
2. Every text field is valid UTF-8, NFC, free of control characters and within its byte limit; every array is within its size limit.
3. `minAssurance` is 0 to 3, and every entry's `minAssurance`, when present, is at least the list floor.
4. Entry authorities are unique within `entries`.
5. Every `authority` in `entries` and `removed` is a CID with algorithm byte `0x01`.
6. Entry attribute names match `^[a-z][a-z0-9-]{0,31}$` and are unique within the entry.
7. `removed` authorities are unique, not also in `entries`, and every `reason` is a known value.
8. Every `attested` CID is distinct within the entry.
9. `minVersion`, when present, is at least 1.
10. The envelope is within 64 KiB (the real bound on entries; 256 is a parser bound).
11. `scope.kind` equals the previous version's.
12. Every authority in the previous version's `entries` and not in this version's is in `removed`.
13. Every authority in `removed` was in the previous version's `entries`.

Rules a resolver checks against live state, not in the vector set: an entry's attribute names exist in the verifier's version in force, and an attested CID equals some logged verifier version's `code` ref. A mismatch makes the row inert, not the list invalid. A context whose leaf then matches no row is unsatisfiable; `context.md` rule C5 doesn't catch that, and organizer tooling should warn.

## Example

The readable view of the core list's third version:

```json
{
  "spec": 1,
  "type": "trust-list",
  "authority": "c2w9pm…4ux",
  "lineage": "c7h3za…m2r",
  "version": 3,
  "prev": "c1kd6f…j8e",
  "issued": 1791259200,
  "refs": {},
  "body": {
    "name": "Hum core verifiers",
    "publisher": "Hum reference operator",
    "lang": "en",
    "scope": { "kind": "core", "classes": ["person"] },
    "minAssurance": 2,
    "reviewPeriod": 7776000,
    "entries": [
      { "authority": "c5r2hq…9ta", "attributes": ["ward", "area"], "attested": ["c3a9vd…x1p"],
        "note": "District verifier. County voter file, reviewed 2026-09." },
      { "authority": "c9u1bn…0lq", "attributes": ["age-band"], "minAssurance": 2, "attested": ["cb7e2s…q5w"],
        "note": "Age band from voter file or document." },
      { "authority": "c4yx8d…t3k", "attributes": ["unique"], "minAssurance": 3, "minVersion": 2, "attested": ["c0pr5v…h9a"],
        "note": "Uniqueness. Version 1 had a dedup flaw; version 2 fixed it under a new issuer key." }
    ],
    "removed": [
      { "authority": "c6ee3q…n7b", "reason": "retired", "note": "Pilot district verifier, superseded." }
    ]
  }
}
```

The uniqueness entry's `minVersion: 2` refuses every card signed by the key that version 1 introduced, because that key first appeared in version 1. Cards under the key version 2 introduced pass. If version 2 had kept signing with the old key, `minVersion` would have had no effect, which is why `verifier.md` requires a new `kid` when a flaw is fixed.

A context that accepts "area is Millbrook from the core list, and approved on its own roster" pins this list as `tl/0` and writes two leaves: `[0, 0]` over `area` with the single value `[1]`, and `[1, 0]` over `approved`, present. Draft 0.1 policies carry one value per leaf (`context.md` rule C5).

## Security considerations

| Threat | Mitigation |
| --- | --- |
| A publisher lists a verifier it never reviewed | The list is an opinion. Contexts choose whose opinion to pin, and the log keeps the record. |
| A list quietly drops a verifier to hide a past mistake | Rules 12 and 13: every drop appears in `removed` with a reason, once, in the log. |
| A publisher's key is stolen and a bad verifier is added | Authority keys follow `manifest.md`. Contexts pin versions, so the bad version only reaches contexts that adopt it. |
| A list claims an attestation it never made | Attestation is a claim checkable by anyone who rebuilds the code. A false claim is on the record under the publisher's key. |
| A verifier keeps a flawed key active after a fix | `minVersion` binds to the key's first version, so the list can refuse the old key's cards; the verifier must introduce a new key for the fix to count. |
| A list names an attribute the verifier later changes | Attribute names and types are frozen in `verifier.md`. A deprecated attribute stays valid. |
| A `class: agent` verifier reaches a vote policy through a list or a direct issuer | Resolution rule 5. |
| A list is used to track which contexts trust whom | Lists and context manifests are public by design; this reveals nothing new. |

## Vectors

W0-08 generates these from `reference/`. The resolution vectors reuse `verifier.md`'s valid district, uniqueness (three-version lineage) and agent manifests and `context.md`'s `context-valid-open` and the ward example.

Valid:

- The core list, versions 1 to 3, including a removal.
- A community list with `scope.area`, an empty `attributes` on one entry, and no attestations.
- An `agent` scope list with one entry.
- Resolution: a context with one list source and one direct issuer, the expected rows sorted bytewise; a `kid` introduced in version 1 against `minVersion` 2, expected not accepted; the same `kid` introduced in version 2, accepted; an `agent` list yielding rows that satisfy no `vote` leaf.

Invalid, one per rule 1–13, plus:

- Version 2 drops an entry without a `removed` row (rule 12).
- Version 2 lists a removal that was never an entry (rule 13).
- Version 2 changes `scope.kind` from `community` to `core` (rule 11).
- An entry whose `minAssurance` is below the list floor (rule 3).

## Open questions

- **Assurance review.** Who reviews declared assurance levels for the core list, and on what schedule. `reviewPeriod` records a promise; nothing enforces it.
- **Dataset attestations.** Whether an entry should also attest a verifier's dataset commitment (for example, "this is the county's 2026-09 extract"), alongside code attestations.
- **List-of-lists.** Whether a trust list may include another list by authority. Not in draft 0.1; a context can pin several lists instead.
- **Discovery.** How an organizer finds trust lists to pin. A service question for `services.md`.

Assumptions about sibling specs:

- `context.md` (W0-01): sources `[0, i]` and `[1, i]`, `refs["tl/<i>"]`, `issuers[i]`, rule C5 for well-formedness and C15 for the sponsor attribute. Confirmed on disk.
- `credentials.md` (W0-02, confirmed 2026-10-06): a presentation carries the verifier authority CID and issuer `kid`, so step 4 can read the key's `since` from the version in force; the phone's policy proof and the aggregator's intake check both compute rows with the algorithm above.
