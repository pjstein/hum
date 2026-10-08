# Review: `docs/specs/agent-sponsor.md` (Draft 0.1, W0-04)

Reviewed 2026-10-06 against `CLAUDE.md`, `docs/design.md`, `docs/specs/manifest.md`, `docs/specs/context.md`, `docs/specs/chat.md`, `docs/specs/verifier.md`, `docs/specs/trust-list.md`, `docs/specs/services.md`, `docs/specs/issue-map.md`, `docs/specs/take.md`, and decisions 0041 to 0043.

Not on disk: `credentials.md`, `ballot.md` (W0-02). Findings that depend on them are marked.

## Verdict

**Approve with fixes.** The three tiers, the "no credential, no membership, no path, no sight" argument, and the label-inside-signed-bytes rule are sound, and `context.md` C15 plus `trust-list.md` rule 5 close the voting path structurally. Three blockers: the attestation does not bind the agent's key, so an enclave report proves nothing about who holds `agentKey`; the capability and field names disagree with `chat.md`; and nothing says which sponsor version applies to an agent already in a channel, so renewals drop agents and capability widenings go unseen.

Answers to the questions the lead asked:

- Can an agent hold a voting credential or confirm a promotion? No. A voting policy cannot name an `agent`-class verifier (`context.md` C15, `trust-list.md` rule 5), the sponsor key is a bare Ed25519 key, and `chat.md` 3.3 ignores a `promote-confirm` from any key but the quoted message's sender. The dependence on `credentials.md` is only that an `agent`-class credential has no path into a membership proof.
- Is agent content labeled in every authorable object? Yes: map objects and takes carry `author` = `agent` plus `refs.sponsor` inside the CID, chat messages carry it in the leaf credential. The attribution gap is in `take.md` B1 (an agent can publish under another authority), not in the label.
- Could a field carry personal data or a sealed key? No sealed key anywhere. `label` and `description` are undeletable prose; see N1. `sponsorProof` is a credential presentation in a public manifest; see S2.

## Findings

### Invariants

**B1 (blocker) — "Attestation", AS-2, and "The membership event".** Clients check `attestation.measurement` = `codeHash` and that the report's embedded measurement matches. Nothing requires the report to commit to `agentKey`. Every attestation platform listed (SEV-SNP, TDX, Nitro, Apple PCC) carries caller-supplied report data for exactly this purpose. Without it, anyone can take a genuine report from a genuine enclave running the published image and attach it to a manifest whose `agentKey` they hold on a laptop, or on the operator's servers. The membership event then says "runs in a SEV-SNP enclave" and the key is nowhere near one. Fix: require the report's user data (SEV-SNP `REPORT_DATA`, TDX `REPORTDATA`, Nitro `public_key` or `user_data`, PCC's equivalent) to equal `SHA-256("hum/attest/1" ‖ agentKey ‖ sponsor authority CID)`, and add the check to AS-2 and to the phone's commit rules. Add vector `as-bad-report-key-binding`. The domain string is new and should go in the Seam line.

**B2 (blocker) — "Capabilities", "Rate limits" and "The membership event", against `chat.md` 3.1, 3.3, 5.12 and 9.** The two specs name different things:

- This spec: `post`, `greeter`, `history`, `author-map`, `take`, with `post` covering `promote-proposal`, `deck-dealt` and `release-digest`. `chat.md` 3.1: agent column `post`, `propose`, `digest`; `join-open`, `members`, `history` are "no" for agents; section 9 lists `read`, `post`, `propose`, `digest`, `author-map`, `take`; section 17 says this spec "has no `greet` or `archive` capability". Both are wrong about each other. A sponsor declaring `greeter` passes AS-3 and grants nothing; a sponsor declaring `propose` fails AS-3.
- Rate limits: this spec has `window`, `mapObjects`, `messages`, `takes`. `chat.md` 3.3 enforces "`messages` or `proposals`". `proposals` does not exist here.
- The membership message: this spec says `agent-membership` has `runs` with 1 phone, 2 member hardware, 3 enclave. `chat.md` 5.12 has `runtime` with 1 `member-hardware`, 2 `enclave`.

Fix, in this spec: adopt `chat.md`'s split (`post`, `propose`, `digest`, `author-map`, `take`), drop `greeter` and `history` until `chat.md` defines what they grant (its section 13 and open question 5 say that needs a design), add `proposals` to `rateLimits` or ask W0-05 to count proposals under `messages`, and cite the field as `runtime` with `chat.md`'s codes. Then correct the "Assumptions" paragraph, which currently claims `chat.md` matches.

**B3 (blocker) — "Body" (`runtime`, `capabilities`, `codeHash` not frozen), "The membership event" and `chat.md` 2.1 step 3.** The leaf credential names one sponsor version (`sponsor`) and the lineage. `chat.md` validates that named version as unexpired. Two failures follow:

- Renewal: a sponsor publishes version 2 with a new `expires`. The leaf still names version 1, which expires, and every phone drops the agent even though the lineage is live.
- Widening: version 2 adds `post` and `author-map` to an agent added read-only, or changes `runtime` from `enclave` to `member-hardware`, or changes `codeHash`. Nothing marks that as a membership event. Members confirmed one thing and are now running another.

Fix: say which version applies and how a new one is adopted. Recommendation: the version in the leaf credential is the one that applies. A version that only extends `expires` or narrows `capabilities` may be adopted by the agent's own MLS Update carrying a new credential, which phones validate with the section 2.1 rules. A version that widens `capabilities`, changes `runtime`, `attestation`, `codeHash` or `label` requires Remove and Add by an `agents` holder, so it is a visible membership event again. Phones reject an Update whose new credential names such a version. Freeze nothing in the manifest; the rule lives at the commit. Put it in AS-9's neighborhood and ask W0-05 to carry it in `chat.md` 3.3.

**S1 (should fix) — `agentKey` as leaf key, credential identity and manifest signing key.** `chat.md` 2.1 step 3 requires a kind 2 leaf's `signature_key` to equal `identity` = `agentKey`. One key then signs MLS messages in every group, the self-binding, map objects and takes. Compromise of any instance is compromise of all, and an enclave agent must hold the manifest-signing key inside the enclave for every channel. Humans get an identity key plus per-device leaf keys bound by signature; agents should get the same: per-instance leaf keys with `binding` by `agentKey`. That changes `chat.md` step 3 and this spec's key 0 text. Raise with W0-05.

**S2 (should fix) — `sponsorProof`, AS-8.** "A presentation ... bound to this manifest's authority CID" names no scope string and no disclosure rule. A presentation carries a nullifier and the issuer `kid`; it sits in a public manifest forever. Say: scope `hum/sponsor/1 ‖ sponsor authority CID`, no attribute disclosed, proof of possession only, and that the agent-class verifier's `attributes` are therefore never read here. This parallels `verifier.md`'s `hum/issuance/1` and keeps the sponsor's nullifier unlinkable to any other presentation. Marked as depending on `credentials.md`.

**S3 (should fix) — "Shared agents", member hardware: "Removing that member removes the agent."** No rule implements it. `chat.md` 3.3 checks the committer is the host at Add time; nothing records the host afterward, and `agent-membership` has no host field. Add a `host` field (chat identity key) to the request for `chat.md` 5.12, and a phone rule: a kind 2 leaf with `runtime` = `member-hardware` whose host is no longer in the all-members group is treated as removed.

**N1 (note) — `label` and `description`.** Undeletable prose in a manifest. `verifier.md` says of `operator`: "Not a person's name." Say the same here for `label` and `description`, and apply the shared text conventions (UTF-8, NFC, no control characters).

**N2 (note) — "Why agents never vote", point 4, and the `as-x-agent-ballot` vector.** A ballot has no slot for an agent signature, so "an agent-signed ballot is submitted and rejected" can only mean a ballot with no valid membership proof. Phrase the vector that way so `ballot.md` can define it.

### Floors

This spec spends no budget and touches no floor. `AGENT_PROPOSAL_TTL` and the 90-day expiry are the only time bounds and AS-6 and IM-13 check them. OK.

### Sums

Nothing here feeds a release. OK.

### Federation

Sponsors are keyset lineages, verifiers are named by authority, the report is a blob by CID. `platform` "others by registration" names no registry; say where (suggest `docs/DECISIONS.md` until a registry exists). OK otherwise.

### Consistency

**S4 (should fix) — "Rate limits" and "Assumptions", against `context.md` keys 16 and 17.** This spec says "`context.md` has no per-context cap in draft 0.1" and asks for an agent policy. `context.md` on disk has `map.agentObjects` (all agents per context per window, default 20) and `agents` (`anySponsor`, `sponsors`, `addRole`). Update the text: both caps hold (the sponsor's and the context's), `ctx.agents` decides which sponsors a context admits, and `addRole` decides who holds the chat `agents` capability. The last point also changes `chat.md` 3.1, which hard-codes organizers; tell W0-05.

**S5 (should fix) — Enum encoding.** `tier`, `runtime`, `sponsorKind`, `platform` and the capability names are text; `chat.md` uses uints for `runtime` and `context.md` for everything. One decision for the cross-spec pass (see `reviews/issue-map.md` S9).

**N3 (note) — Tiers table, shared row: "greet joiners and write history archives when granted".** Depends on B2; drop until the capabilities exist.

**N4 (note) — "Labeling" table, chat row.** `chat.md` 5.12 says phones label from the credential, not from the `agent-membership` message. Matches. OK.

### Implementability

**S6 (should fix) — AS-2 "the report's embedded measurement matches".** Which bytes of which report format hold the measurement is per platform. Either name the field per platform in a table (SEV-SNP `MEASUREMENT`, TDX `MRTD` plus `RTMR`s, Nitro PCR0, PCC's release manifest hash) or say draft 0.1 clients compare only `attestation.measurement` to `codeHash` and treat report parsing as the open question it already lists. Two implementers will otherwise parse differently or not at all.

**N5 (note) — AS-3 empty capabilities.** "Any subset of the five" includes the empty set (read-only agent). Say it is allowed.

**N6 (note) — `attestation.measurement` and `codeHash` lengths.** `codeHash` is bytes(32); `measurement` is unbounded bytes. SEV-SNP measurements are 48 bytes. Either define `codeHash` as the SHA-256 of the measurement or let both be the platform's length.

### Testability

One failing vector per rule is present. Gaps:

- B1: `as-bad-report-key-binding`, and a valid vector with a fixed synthetic report whose user data is computed as specified.
- B2: after renaming, `as-bad-capability-unknown` should use `greeter` to pin the change.
- B3: `as-ok-renew` exists; add the commit-side cases to `chat.md`'s `chat/roles` or `chat/credential` set: Update to a renewal accepted, Update to a widened version rejected.
- S2: `as-bad-proof-scope` (presentation under another scope).
- S4: `as-x-sponsor-not-admitted` (sponsor not in `ctx.agents`), owned by `issue-map.md` IM-6.

## Summary for the author

B1 is the one that matters most: without key binding, the enclave runtime is a label, not a guarantee. B2 and B3 are alignment with `chat.md` and need W0-05 in the room; the recommended rule for B3 (credential version applies, widening needs Remove and Add) also fixes renewals. S4 is reading `context.md` as it exists.

## Re-review (2026-10-06, revised draft, 271 lines)

Re-read the revised spec in full and `chat.md` (881 lines) sections 2.1, 3.1, 3.3, 5.12 and 9 as they are now.

**Status of the first-round findings.** B1 fixed: the report data must equal `SHA-256("hum/attest/1" ‖ agentKey ‖ sponsor authority CID)`, `codeHash` is the SHA-256 of the platform-length measurement, the per-platform fields are named, and `chat.md` 2.1 step 3 repeats the binding. B2 fixed from both sides: `chat.md` 3.1 now takes the sponsor names `post`, `greeter`, `history`, `author-map`, `take` and maps them onto its own rows, 3.3 counts proposals under `messages`, and 5.12 carries `runtime` with codes 1 and 2 plus a `host` field. B3 fixed from both sides: "Which sponsor version applies" and `chat.md` 3.3's last paragraph state the same rule (credential version applies; renewals and narrowings by Update; widenings, runtime, attestation, `codeHash` or `label` changes need Remove and Add). S2 to S6 and N1 to N6 are addressed: `hum/sponsor/1` scope with no disclosure, host-left rule, `ctx.map.agentObjects` and `ctx.agents` read as written, uints, empty capabilities allowed. S1 (one key per agent everywhere) is now an open question raised with W0-05, which is the right place.

**New findings on the new text.**

**S7 (should fix) — AS-2, "where the client parses the report".** AS-2 is a step-10 rule, so it decides whether the manifest is valid. Its last clause runs only where a client can parse the platform report. A log, which never parses reports, accepts a manifest that a phone with a SEV-SNP parser rejects, and two phones with different parsers disagree. Split it as `issue-map.md` did for IM-4: AS-2a (field checks: presence, `codeHash` = SHA-256(`measurement`), registered `platform`) is the manifest rule every verifier runs; AS-2b (report measurement and key binding) is run by phones that can parse the format and decides the Add commit and the membership-event display, never the manifest's validity. Then the `as-bad-report-key-binding` vector is a commit-rejection vector against the synthetic report, not a manifest-rejection vector.

**S8 (should fix) — AS-7 against `chat.md` 2.1.** `label` may be 80 bytes, but the credential `name` is "1 to 64 bytes" and must equal the sponsor's `label` (`chat.md` 2.1 step 3). A shared agent with a 65-byte label can be published and never added. Set `label` ≤ 64 bytes.

**S9 (should fix) — "Capabilities", `greeter`, and what the agent reads.** `chat.md` 3.1 gives a `greeter` agent `members` only while it sits in the organizers group, and 3.2 adds greeter agents to that group. The organizers group is where every moderation report lands (`chat.md` 1.4 and 11.3). A greeter agent therefore reads every report, which the tiers table ("What the channel sees") and the pre-add screen do not say. State it in the tiers row and show it on the membership screen for any sponsor whose capabilities include `greeter`: "this agent will be in the organizers group and will see reports".

**N7 (note) — "Which sponsor version applies", retirement.** The table says a retired lineage removes the agent, but `chat.md` 2.1 step 3 checks only that the version named in the credential is unretired. A sponsor that retires with version 3 leaves a leaf naming version 2 valid. Ask W0-05 to check the lineage's latest logged version for `retired` as well.

**N8 (note) — `chat.md` section 9.** Still says phones enforce "`messages` and `proposals` limits"; 3.3 of the same spec says proposals count under `messages`. Stale sentence for W0-05.

**Testability.** After S7, the vector list should say which vectors are manifest rejections (AS-2a) and which are commit rejections (AS-2b). Otherwise complete.

**Updated verdict: approve with fixes.** No blockers remain. Three should-fix items: make AS-2 deterministic by splitting it, cap `label` at 64 bytes to match the credential, and disclose that a greeter agent reads reports.
