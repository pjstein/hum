# Hum Agent Sponsor Spec — Draft 0.1

Oct 6, 2026 · W0-04 draft, revised after review; not yet approved

## Scope

Agents are first-class participants whose privileges come from where they run. This spec defines the `agent-sponsor` manifest, which is how an agent gets an identity in the protocol: a key, a tier, a declared runtime with its attestation, a capability list, rate limits, and an accountable sponsor behind it. It also fixes:

- the three tiers and exactly what each can see and do;
- how agent content is labeled in every object an agent can author, and why the label can't be removed;
- why an agent can never hold a voting credential;
- the visible membership event when a shared agent joins a channel, and which sponsor version applies to an agent already in one.

Out of scope: the agent's own software, how a personal agent reads a phone's local data, the chat content types (`chat.md`), and the verifier that issues sponsor credentials (`verifier.md`, `credentials.md`).

Conventions follow `context.md`: body keys are small uints, enumerations are uints with the names given in the tables, text is UTF-8 NFC with no control characters and a byte limit.

## Tiers

| Tier | Runs | Sees | May do | Needs a sponsor manifest |
| --- | --- | --- | --- | --- |
| Personal | On the member's own phone, inside the app's process | Everything that phone shows its owner, including the owner's own hand and shield. Nothing leaves the device | Summarize, draft, prepare. Anything it drafts is posted by the person, as the person, after confirmation | No. It has no protocol identity |
| Shared (0) | As a visible member of a channel, on a member's own hardware or in an attested enclave | What the channel sees: messages, attachments and the map objects of the contexts it is in. A `greeter` agent also sits in the organizers group (`chat.md` 3.2) and so reads every moderation report that lands there. Never a hand, a shield, a ballot or the context's admitted credential set | Read; and, as its capabilities allow, post in channels it is in, propose promotions and merges, author labeled map proposals, post deck and release cards, greet joiners, write history archives, write takes | Yes |
| Public (1) | Anywhere | Releases, public takes, public maps. Nothing sealed | Write takes | Yes |

What no tier can do, ever: present a membership proof, send a ballot, read another member's hand or shield, hold a keyring epoch for a context it is not a visible member of, or publish a context, deck or release manifest.

### Personal agents

A personal agent is a feature of the app, not a participant. It runs where the keys are and is bound by the same rules as the app: it cannot write to a blob store what the app would not, and the conformance check that nothing but ballots carries a vote applies to it. When a person posts text a personal agent drafted, the object's `author` is the person's form (member or anonymous), and the body may set `assisted` = true. Whether that flag should be required is an open question in `issue-map.md`.

### Shared agents

A shared agent is a member of specific channels. Its leaf in each MLS group is visible to every other member, its credential (kind 2 in `chat.md` section 2.1) names its sponsor manifest, and the context sees where it runs before it is added. It has no voting identity and no chat name of its own beyond the label its sponsor manifest gives it.

Two runtimes are allowed:

- **A member's own hardware** (`runtime` 1). The member who adds the agent runs it (a laptop, a home server). There is no cryptographic attestation; the accountability is that a named member added it, and the membership event records who. When that member leaves the context, the agent is treated as removed (see "The membership event").
- **An attested enclave** (`runtime` 2). The agent runs in a hardware-isolated environment whose measurement is published in the manifest and whose attestation report, bound to the agent's key, is a public blob. This is the only way an agent may run on infrastructure the channel's members do not control, including the operator's. An agent on ordinary operator servers would quietly undo end-to-end encryption for its channels; the attestation is what makes that trade visible and checkable.

### Public agents

A public agent reads only what the public reads. Its takes are labeled and ranked like everyone else's. It has no channel membership and no capabilities beyond `take`. `chat.md` section 9 says the same from its side: public agents never see chat.

## Why agents never vote

The protocol closes this from four directions, so no single bug opens it.

1. **No credential.** A voting credential (resident card) is issued to a person by a verifier of class `person` after evidence and deduplication (`verifier.md`, `credentials.md`). A sponsor credential comes from a verifier of class `agent`, a frozen field of the verifier manifest, and no entry or vote policy may name an agent-class verifier (`context.md` rule C15, `trust-list.md` rule 5). An agent key is a bare Ed25519 key, not a credential of any kind.
2. **No membership.** Ballots require a membership proof over the context's admitted set (`ballot.md`). Agents are never in that set; a shared agent's channel membership is an MLS leaf, which is a different structure with no proof of this kind.
3. **No path.** Aggregators accept shares only under a valid membership proof and a deck the phone verified. Nothing in the agent's reach produces either.
4. **No sight.** A hand and a shield never leave the phone; a shared agent sees only channel content; a personal agent can read its owner's hand but has no outbound path for it other than the ballot code, which does not take input from it.

An agent can help a person sort a deck; the person casts every card. A ballot has no slot for an agent signature, so the conformance vector for this (`ballot.md`) is a ballot with no valid membership proof, which the aggregator rejects.

## Body

| Key | Name | Type | Required | Frozen | Meaning |
| --- | --- | --- | --- | --- | --- |
| 0 | agentKey | bytes(32) | yes | yes | Ed25519 public key. Signs the agent's objects under `hum/author/1` and is the `identity` of the agent's kind 2 chat credential |
| 1 | tier | uint | yes | yes | 0 shared · 1 public |
| 2 | runtime | uint | yes | no | 1 member-hardware · 2 enclave · 3 anywhere. Codes 1 and 2 match `chat.md` section 5.12 |
| 3 | attestation | map | iff runtime = 2 | no | See below |
| 4 | codeHash | bytes(32) | iff runtime = 2 | no | SHA-256 of `attestation.measurement`; the value the membership event shows |
| 5 | capabilities | array of uint | yes | no | Subset of the tier's allowed set, below; may be empty (a read-only agent) |
| 6 | rateLimits | map | yes | no | See below |
| 7 | label | text, 1 to 64 bytes | yes | no | How the agent is named in channels and bylines. Not a person's name. Clients always render it with an agent mark. It is copied into the agent's credential `name`, which `chat.md` 2.1 caps at 256 bytes, so a label always fits |
| 8 | description | text ≤ 560 bytes | yes | no | What the agent does. Not a person's name or contact |
| 9 | sponsorKind | uint | yes | yes | 0 person · 1 organization |
| 10 | sponsorProof | bytes | no | no | A presentation of a credential from a verifier of class `agent`, as `credentials.md` defines: scope `hum/sponsor/1` ‖ this manifest's authority CID, proof of possession only, no attribute disclosed. Contexts may require it |
| 11 | retired | bool | no | — | Final version; the agent's key is dead from this log position |

The envelope's `authority` is the sponsor's keyset lineage, and `expires` is required: at most 7,776,000 seconds (90 days) after `issued`. `label` and `description` are undeletable prose in a public manifest; the sponsor is told so before publishing.

### refs

| Name | Required | Points to |
| --- | --- | --- |
| `verifier` | iff `sponsorProof` present | The verifier manifest version that issued the sponsor credential; its `class` is `agent` |
| `report` | iff runtime = 2 | The attestation report, a public blob |

### Capabilities

| Code | Capability | Tier | Meaning |
| --- | --- | --- | --- |
| 0 | `post` | shared | Send application messages in channels it is in: text, `promote-proposal`, merge proposals, `deck-dealt`, `release-digest` (`chat.md` sections 5 and 9). Without it the agent only reads |
| 1 | `greeter` | shared | Answer `join-request`s in open channels and send Welcomes (`chat.md` maps it to `join-open`, and to `members` for Adds that answer a request) |
| 2 | `history` | shared | Write history archives for newcomers (`chat.md`) |
| 3 | `author-map` | shared | Publish `issue`, `position` and `argument` manifests with `author` = agent, which land as proposals (`issue-map.md`) |
| 4 | `take` | shared, public | Publish `take` manifests with `author` = agent |

Reading is membership, not a capability: an agent that is a leaf of a channel decrypts it. A public agent's capabilities are exactly `[4]`. A shared agent's are any subset of the five, including none. The chat roles table (`chat.md` section 3.1) intersects these with what the role grants; an agent is never `admin`, never confirms a promotion, and never adds another agent.

### Rate limits

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | window | uint | Seconds, 3,600 to 604,800 |
| 1 | mapObjects | uint | Map manifest versions per window, per context |
| 2 | messages | uint | Application messages per window, per channel, of any content type. Proposals count here; there is no separate proposal limit |
| 3 | takes | uint | Take versions per window, total |

These are the sponsor's own declared ceilings, summed across every agent manifest under the same sponsor authority. The context caps agents too: `ctx.map.agentObjects` bounds map objects from all agents together per window (`context.md` key 16), and both limits hold. Logs enforce `mapObjects` and `takes` by counting entries per sponsor authority (`issue-map.md` IM-15, `take.md`); phones enforce `messages` by ignoring the excess in channel order (`chat.md` section 3.3).

### Attestation

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | platform | uint | 0 SEV-SNP · 1 TDX · 2 Nitro · 3 Apple PCC. New codes are registered in `docs/DECISIONS.md` until a registry exists |
| 1 | measurement | bytes | The platform's launch measurement of the agent image, at the platform's length (SEV-SNP 48 bytes, for instance) |
| 2 | issuedAt | uint | Seconds since the epoch when the report was produced |
| 3 | policy | text ≤ 256 bytes | Optional platform policy string the report was produced under |

The report blob in `refs.report` is the raw platform report. Two things bind it to this manifest:

- **Measurement.** `codeHash` = SHA-256(`measurement`), and `measurement` is what the report attests (SEV-SNP `MEASUREMENT`, TDX `MRTD`, Nitro PCR0, PCC's release manifest hash).
- **Key binding.** The report's caller-supplied data (SEV-SNP `REPORT_DATA`, TDX `REPORTDATA`, Nitro `user_data`, PCC's equivalent) equals `SHA-256("hum/attest/1" ‖ agentKey ‖ sponsor authority CID)`. Without this, a genuine report from a genuine enclave could be attached to a manifest whose key lives on a laptop or on the operator's servers; with it, the report says that this key was presented from inside that image.

These two bindings are AS-2b. They decide whether a phone accepts the Add commit and what the membership event says, never whether the manifest is valid, because a log never parses reports and two phones may hold different parsers. A phone that cannot parse the format shows "attestation not verified" on the membership event and lets the committer decide; a phone that parses it and finds a mismatch rejects the commit. Verifying the report's certificate chain to the platform vendor is an open question below. The reference implementation ships a synthetic report format for vectors.

## Labeling

Every object an agent can produce carries an agent label inside the bytes that are signed or encrypted, so stripping it breaks verification.

| Object | Label | Where it lives | Checked by |
| --- | --- | --- | --- |
| Chat message | The sender's leaf credential has `kind` 2 and names the sponsor manifest | The leaf credential in the ratchet tree (`chat.md` section 2.1) | Every member's phone, on every message, through the sender's leaf |
| Map object (`issue`, `position`, `argument`) | `author` = 3, `refs.sponsor` | The manifest body and refs, inside the CID | Anyone (IM-6, IM-9) |
| Take | `author` = 3, `refs.sponsor`, and the sponsor's authority equals the take's | The manifest body, refs and envelope | Anyone (TK-5, TK-6) |
| Promote request, merge proposal, release digest | The message label above | The MLS message | Every member's phone |
| Rating, ballot, membership proof | None, because none exist | — | Aggregators reject anything not under a membership proof |

Clients render the label as the manifest's `label` with an agent mark and the sponsor's short authority CID, never as a bare name. A map card authored by an agent shows "Position · from an agent" where `IBIS-Card` shows "Position · from a member".

## The membership event

Adding a shared agent to a channel is a visible membership event. The MLS add is the event: the agent's leaf credential, which every member's phone receives in the commit, has `kind` 2, `identity` = `agentKey` and `sponsor` = a version CID of this manifest's lineage (`chat.md` section 2.1). The committer then sends an `agent-membership` message (`chat.md` section 5.12) so the timeline says it in words; phones derive the event from the commit even if that message never arrives. There is no way to add the agent without every member's phone learning what it is and where it runs.

Before a member with the `agents` capability confirms adding an agent, their phone shows:

| Shown | From |
| --- | --- |
| Label, description, sponsor kind | Manifest body |
| Tier and runtime | Manifest body |
| For runtime 1: which member will run it | The adding member's own chat name; they are the host |
| For runtime 2: platform, `codeHash`, and whether the report's measurement and key binding verified (AS-2b) | `attestation`, `refs.report` |
| Capabilities and effective rate limits | Manifest and context manifest |
| For capability `greeter`: "this agent will be in the organizers group and will see reports" | Manifest and `chat.md` 3.2 |
| Whether the sponsor presented a credential, and from which verifier | `sponsorProof`, `refs.verifier` |

After the commit, every member's phone renders the event in the channel timeline: "<label> (agent) joined. Runs on <host member>'s hardware" or "Runs in a <platform> enclave, code <short hash>". The `agent-membership` message's `runtime` field (1 member-hardware, 2 enclave, as `chat.md` 5.12 numbers them) must match this manifest's; a mismatch is shown as a warning and the manifest wins. The message also names the host for runtime 1 (`host`, the committer's chat identity key; requested from W0-05).

Phones apply these rules to the commit (`chat.md` section 3.3 carries them as MLS validation; they are listed here so the sponsor manifest's fields have a consumer):

- An agent leaf's sponsor manifest resolves, verifies, is not expired or retired, its `tier` is 0, and its `agentKey` equals the credential's `identity`.
- The sponsor's authority is admitted by the context: `ctx.agents.anySponsor`, or listed in `ctx.agents.sponsors` (`context.md` key 17).
- The committer holds the chat `agents` capability, which `ctx.agents.addRole` assigns (0 organizers, 1 moderators too, 2 any member; `context.md` key 17) and `chat.md` section 3.1 reads from the pinned context version. Nothing here hard-codes a role.
- Runtime 1: the committer is the host, and the event names them. A runtime 1 agent whose host's chat identity key is no longer in the all-members group is treated as removed by every phone, before any commit lands.
- Runtime 2: AS-2a holds (it does for any valid manifest) and, where the phone parses the format, AS-2b holds against `refs.report`.
- The sponsor lineage's latest logged version is not `retired`, in addition to the credential's named version being unexpired (`chat.md` 2.1 step 3, repeated whenever a phone learns of a new version).
- A commit that fails these is rejected by the phone, the way a commit from a member without the right role is rejected.

### Which sponsor version applies

The version named in the agent's leaf credential is the one that applies to that agent in that group, for capabilities, runtime, limits and expiry. Sponsors publish new versions; the rule for adopting one is:

| New version, relative to the one in the credential | How the agent adopts it |
| --- | --- |
| Only `expires` later, `capabilities` equal or narrower, `rateLimits` equal or lower, `description` changed | The agent commits or proposes an MLS Update carrying a new credential that names the new version. Phones validate it with the section 2.1 rules and accept it. This is how renewals keep an agent in place |
| `capabilities` wider, `runtime`, `attestation`, `codeHash` or `label` changed, `rateLimits` higher | Remove and Add by an `agents` holder. It is a membership event again, with the screen above. Phones reject an Update whose new credential names such a version |
| `retired` on the lineage's latest logged version, or that version expired | Phones treat the agent as removed at the next commit and show why. This is a check on the lineage's latest version, not only on the version the credential names, otherwise a sponsor retiring at version 3 would leave a leaf naming version 2 valid |

Nothing in the manifest is frozen to make this work; the rule lives at the commit, and `chat.md` section 3.3 carries it (requested from W0-05). Removing the agent is an ordinary MLS remove, visible the same way. The keyring advances as it does for any removal.

## Validation rules

Steps 1 to 9 of `manifest.md` run as written; the sponsor's keyset signs under `hum/manifest/1`. These run as step 10.

| Rule | Check | Rejects |
| --- | --- | --- |
| AS-1 | `tier` ∈ {0, 1}; `runtime` allowed for the tier: shared → 1 or 2; public → 3 | public agent claiming an enclave; shared agent anywhere |
| AS-2a | `attestation`, `codeHash` and `refs.report` are all present iff `runtime` = 2; `codeHash` = SHA-256(`attestation.measurement`); `platform` is a registered code. Decides manifest validity; every verifier including the log runs it | enclave without report; `codeHash` mismatch; unknown platform |
| AS-2b | Phones that parse the platform's format, at the Add commit: the report's measurement equals `attestation.measurement` and its report data equals `SHA-256("hum/attest/1" ‖ agentKey ‖ authority CID)`. Decides the commit and the display, never manifest validity | report for another image; report bound to another key |
| AS-3 | `capabilities` is a subset of the tier's allowed set, with no duplicates; public = exactly `[4]` | public agent with `post`; unknown capability |
| AS-4 | `rateLimits.window` in [3,600, 604,800]; all four fields present | window of one second |
| AS-5 | `agentKey` is not any key in the sponsor's current keyset | sponsor key reused as agent key |
| AS-6 | `expires` present and at most 7,776,000 seconds after `issued` | missing or year-long expiry |
| AS-7 | `label` 1 to 64 bytes and `description` ≤ 560 bytes, NFC, no control characters | over-length |
| AS-8 | `sponsorProof` present iff `refs.verifier` present; when present, the verifier manifest's `class` is `agent`, the presentation verifies under `credentials.md` P1–P8 against its issuer key under scope `hum/sponsor/1` ‖ this authority CID with bound message `agentKey`, and discloses no attribute. It is a logged presentation (`credentials.md`, "Validity", third row). Its log of record is the log whose inclusion proof the bundle carries, whichever context later uses the manifest, so this rule gives one answer everywhere; a context accepts the manifest when that log is one of its `logs`. The log checks at submission that its disclosed epoch is current and that this version's `issued` is within 3,600 seconds of the log's clock; a phone checks later against `issued` and the verifier version in force at this manifest's log position, with no clock, so a sponsor manifest stays valid to its `expires` across the agent verifier's epoch boundary. Each new version carries a proof made for that version | proof without verifier; `person`-class verifier; wrong scope; disclosed attribute |
| AS-9 | Version > 1: `agentKey`, `tier` and `sponsorKind` unchanged; no version follows `retired` = true | key swap under a live lineage |

Rules consumed elsewhere, with their vectors in the owning spec: an object signed by an `agentKey` whose body `author` is not 3 (IM-6, TK-5); a take whose `authority` is not the sponsor's (TK-5); a ballot without a membership proof (`ballot.md`); a commit adding an agent leaf whose manifest fails the rules above, and an Update to a widened version (`chat.md`).

## Example

```json
{
  "spec": 1,
  "type": "agent-sponsor",
  "authority": "c9sp0n…s0r",
  "version": 2,
  "lineage": "c9sp0n…v01",
  "prev": "c9sp0n…v01",
  "issued": 1791183600,
  "expires": 1798959600,
  "refs": {
    "report": "c4rep…0rt",
    "verifier": "c3ver…ify"
  },
  "body": {
    "agentKey": "a3d1…77",
    "tier": 0,
    "runtime": 2,
    "attestation": { "platform": 0, "measurement": "9c0e…b2…(48 bytes)", "issuedAt": 1791183000 },
    "codeHash": "5e71…c4",
    "capabilities": [0, 3],
    "rateLimits": { "window": 86400, "mapObjects": 10, "messages": 50, "takes": 2 },
    "label": "millbrook-facilitator",
    "description": "Proposes issues from long threads and drafts the strongest pro and con for each position. Posts nothing without a member's confirmation except release digests.",
    "sponsorKind": 1,
    "sponsorProof": "…"
  }
}
```

## Vectors

Under `vectors/agent-sponsor/`:

Valid: `as-ok-shared-hardware`, `as-ok-shared-enclave` (the example, with a synthetic report whose report data is computed as AS-2b specifies), `as-ok-public`, `as-ok-with-proof`, `as-ok-renew` (version 2 with a new `expires`), `as-ok-empty-capabilities`, `as-ok-retire`.

Invalid manifests, one per rule: `as-bad-tier`, `as-bad-public-enclave`, `as-bad-shared-anywhere` (AS-1); `as-bad-enclave-no-report`, `as-bad-codehash`, `as-bad-platform` (AS-2a); `as-bad-public-post`, `as-bad-capability-unknown` (code 9), `as-bad-capability-dup` (AS-3); `as-bad-window` (AS-4); `as-bad-key-reuse` (AS-5); `as-bad-no-expiry`, `as-bad-long-expiry` (AS-6); `as-bad-label-long` (AS-7); `as-bad-proof-no-verifier`, `as-bad-proof-class`, `as-bad-proof-scope`, `as-bad-proof-epoch-mismatch` (disclosed epoch is not that of `issued`), `as-ok-proof-after-epoch` (valid, verified in the verifier's next epoch) (AS-8); `as-bad-key-swap`, `as-bad-after-retire` (AS-9).

Commit rejections against the synthetic report, not manifest rejections (AS-2b): `as-commit-bad-measurement` (report for another image), `as-commit-bad-report-key-binding` (report data bound to another key), and the valid `as-commit-ok-enclave`.

Cross-spec: `as-x-unlabeled-object` (an `argument` signed by an `agentKey` with `author` = 1; rejected by IM-6), `as-x-sponsor-not-admitted` (rejected by IM-6), `as-x-take-authority` (rejected by TK-5), and in `chat.md`'s credential set: an Update to a renewal accepted, an Update to a widened version rejected.

## Security considerations

| Threat | Mitigation |
| --- | --- |
| An agent on the operator's servers reads channels | Only runtimes 1 and 2 may join; runtime 2 means a published measurement and a report bound to `agentKey` that every member's phone can check |
| A genuine enclave report attached to a key outside the enclave | The report data commits to `agentKey` and the sponsor authority (`hum/attest/1`) |
| An agent votes | No credential, no membership, no path, no sight (see "Why agents never vote") |
| Agent text passes as human | Label inside signed bytes; agent key never a member key; map objects land as proposals |
| An agent publishes under someone else's authority | TK-5 requires the sponsor's authority to equal the take's |
| A sponsor floods maps or channels | Declared ceilings per sponsor and the context's cap, counted at the log and on every phone; map proposals expire in 30 days |
| A stale or abandoned agent lingers | 90-day expiry; phones drop it at the next commit |
| A sponsor widens an agent's powers after members accepted it | Widening needs Remove and Add, a visible membership event; renewals go through an Update phones validate |
| A sponsor swaps the agent behind a trusted label | `agentKey` frozen; a new agent is a new manifest and a new membership event |
| A compromised agent key | Retire the lineage; the key is dead from that log position; channels remove it at the next commit |
| The host of a member-hardware agent leaves | Phones treat the agent as removed when the host's key leaves the all-members group |
| A shared agent learns the member list | It sees the MLS tree of channels it is in, like any member. It never sees the context's admitted credential set |
| A personal agent exfiltrates a hand | It runs inside the app; the only outbound vote path is the ballot code, and the conformance suite checks nothing else writes a vote |

## Open questions

- **Attestation verification:** which platforms to support at launch, which report fields each client parses, and whether phones verify report chains themselves or accept a witness-style co-signature from an independent attestation verifier. Draft 0.1 requires the measurement and key bindings and leaves chain verification to the client.
- **One key per agent:** `chat.md` 2.1 makes the agent's MLS leaf key equal `agentKey` in every group, so one key signs messages, map objects and takes everywhere. Humans get an identity key plus per-device leaf keys bound by signature; agents could get the same. Declined for draft 0.1 in `chat.md` open question 15, because one key keeps the attestation binding and the credential check to one step; revisit with per-instance agents.
- **Personal agents on a hosted model API:** a personal agent that calls a hosted model sends channel text off the device. Is that allowed with a warning, only with an on-device model, or only through an enclave?
- **Sponsor credentials:** required for all shared agents, or only when a context asks? Draft 0.1: optional in the manifest, a context may require it.
- **Default rate limits:** 10 map objects, 50 messages and 2 takes per day are guesses to be tuned by the simulator.

## Assumptions about sibling specs

Checked against the drafts on disk on 2026-10-06.

- `chat.md` (W0-05, exists): aligned. Kind 2 credentials with `identity` = `agentKey` and `sponsor` = a version CID of this lineage; capability codes 0 to 4 in section 3.1; proposals counted under `messages` (3.3, 9); `agent-membership` carries `runtime` (1, 2) and `host` (5.12) with the host-left rule; the sponsor-version rule of "Which sponsor version applies" in 3.3 with its two credential vectors; `addRole` read from the pinned context version; the `hum/attest/1` binding checked in 2.1 step 3; `origin` is the MIMI message ID. W0-08 should generate `chat/promote` and `im-ok-argument-pro-member-origin` from the same message.
- `verifier.md` and `trust-list.md` (W0-03, exist): matches. Verifier `class` is `person` or `agent`; policies cannot name agent-class verifiers; trust lists carry `classes`.
- `credentials.md` and `ballot.md` (W0-02, exist): aligned. `sponsorProof` is a possession-only presentation under scope `hum/sponsor/1` ‖ authority CID with no attribute disclosed; rule P3 there rejects agent-class credentials in any policy presentation; the "agents never vote" vector is `ballot.md`'s B3 no-credential case.
- `context.md` (W0-01, exists): `map.agentObjects` and `agents` (`anySponsor`, `sponsors`, `addRole`) are used as written.
- `services.md` (W0-07, exists): sponsor manifests are submitted with an `authority` signature; logs count map objects and takes per sponsor authority per window.

## Seam

`seam: credential presentation` for `sponsorProof` and its scope `hum/sponsor/1`. `seam: signing and domain-separation strings` for `hum/attest/1`. `seam: anything that decides what leaves the phone` for the personal-agent rules. The domain string `hum/author/1` is defined in `issue-map.md` and reused here.
