# Review: `docs/threat-model.md` (Draft 0.1, W0-07)

Reviewed 2026-10-06 against `CLAUDE.md`, `docs/design.md`, `prompts/wave-0/07-services-and-threat-model.md`, every spec in `docs/specs/`, and ADRs 0071 to 0073. The review of `docs/specs/services.md` is in `reviews/services.md`; findings that depend on it are marked.

Not on disk: `credentials.md`, `ballot.md`, `shield.md`, `simulator.md`. The document names them as assumptions, which is the right way to handle it.

## Verdict (first review)

**Approve with fixes.** The document covers every adversary and asset the prompt lists, maps all seven CLAUDE.md seams to spec sections, states its assumptions and what breaks, and is honest about what is out of scope. One blocker: the who-sees table is wrong about the log, and that row is the one a reviewer would use to check issue-map submissions. The rest is stale cross-references and a few missing parties.

See the [Re-review](#re-review-2026-10-06-after-rework) at the end for the current verdict.

## Coverage against the prompt

| Prompt asks for | Present |
| --- | --- |
| Adversaries: operator, breach or subpoena, organizers, members who know you, the public, malicious verifier, malicious or compromised agent, compromised phone, colluding servers | All nine, plus network attacker and modified client |
| Assets: votes, hands, shields, the identity link, membership, chat content, files, metadata | All eight, plus participation, evidence and releases |
| Per party: sees, must never see, mechanism with spec section | Yes, fifteen rows |
| Assumptions and what breaks | Nine rows |
| Out of scope | Eleven items |
| Seam list mapped to specs | All seven seams |

## Blocker

**B1 (blocker) — "What each party sees", row "Log and witnesses".** The row says the log must never see "which member submitted an authored object" and that the mechanism is "authored objects are submitted with an anonymous token". Neither is true under `services.md`. `POST /v1/log/add` takes no token; the credential is the bundle's `authorship` proof (`issue-map.md`, "The authorship bundle field"). For the `member` form that proof carries the author's chat identity public key by design, and the log must read it to count `SIGNED_PER_WINDOW` (IM-15). For the `anonymous` form the log sees a `(window, slot)` nullifier. The log also sees the submitter's IP unless the submission goes through the relay, which `services.md`'s routing table does not currently require (see `reviews/services.md` B4). Fix the row: sees "manifest CIDs with type and authority in order; for signed authored objects, the author's chat identity key; for unsigned ones, a per-slot nullifier that links to nothing"; never sees "a chat key joined to a vote or a resident card, a slot nullifier joined to anything, which phone submitted or looked up what"; mechanism "scope-separated membership proofs (issue-map.md), per-log nullifier set only, every phone request through the relay (services.md routing table)".

## Should fix

**S1 — "Parties and adversaries" and the who-sees table: missing parties.**

- **The Helper in phase 1.** It sees `nHat`, the receipt roots, every table and the Leader's `propose` requests; it never sees a ballot or a raw sum (`release.md`, "Who signs"). It is a distinct party with its own key and, at launch, possibly the same operator. Add a row.
- **Moderators.** A report delivers the decrypted message, its attachment reference and the sender's chat identity to the organizers group (`chat.md` §11.3). That is more than the organizer row's "who signed what in chat". Add it to the organizer row or add a moderator row, with "never sees: anything about votes; messages nobody reported".
- **A separate token issuer.** `storage.md` §6.1 allows the issuer to be a party other than the store. It sees a membership proof per issuance and the count per pseudonym per day under the `blob-tokens` scope, and nothing about which blob. The colluding-servers table has a row for it, but the who-sees table does not.
- **Organizer-run verifiers.** `verifier-runtime.md` ("Transparency") says organizers see session outcomes for the invite and approved-list verifiers they run. The organizer row's "who accepted an invite" covers it loosely; name the mechanism.

**S2 — "The operator", first paragraph, and "Assumptions".** "Does not control the relay, the Helper, the witnesses, or the phones." `release.md` ("Who signs") says "when the Leader and Helper are run by one operator, as at launch", and the Helper operator is an open decision in `DECISIONS.md`. Say what is true at launch: the operator may run both aggregators, phase 1 does not depend on the Helper's independence (its signature is a separately keyed parameter check), and phase 2 does. Move "the Helper is independent" to the assumptions table with "if it fails: phase 2 collapses to phase 1".

**S3 — "Colluding servers", row "Token issuer and the service spending the token".** Cites rule T-4, which does not exist in `services.md` (its connection rule is T-3; `storage.md` also cites T-4). Fix the reference once `reviews/services.md` B1 settles the numbering.

**S4 — "Assumptions about sibling specs", second list.** `release.md`, `chat.md` and `agent-sponsor.md` are on disk and the first list already says `agent-sponsor.md` landed. Move all three to the landed list, check them, and record what they settle: `release.md` defines the rounds, the Helper's phase 1 attestation and R14; `chat.md` uses per-channel tokens derived from a per-epoch delivery secret (not a per-member credential), defines `agent-membership` and `public-copy`; `agent-sponsor.md` defines `rateLimits.mapObjects` and `capabilities`. One claim needs correcting when you do: `chat.md` §12.9 says the delivery service sees "the epoch number, and so the rate of joins and leaves" and "how many Welcomes a commit carried", which is a membership-size signal the "Chat delivery service" row should list under sees.

**S5 — "Seams mapped to specs", row 1.** The domain-string list is incomplete: `chat.md` adds `device/1`, `safety/1`, `frank/1`, `stamp/1`, `chat-roles/1`, `welcome/1`, `token-request/1`, `pp-issuer/1`, and exporter labels `keyring/1` and `delivery/1`; `verifier.md` adds the `hum/issuance/1` scope; `storage.md` adds the `keyring/1/blob` HKDF info; `context.md` proposes `hum/results-key/1`. A reviewer using this table to check "is this label unique" would miss half of them. Either list them all or point at one registry (requested from `services.md` in `reviews/services.md` S16) and say the registry is the seam.

**S6 — "What each party sees", row "Other members", mechanism.** "The three identities are separate keys with no shared derivation" is not what the specs say. The voting pseudonym nullifier, the `hum/author-once/1` and `hum/author-slot/1` nullifiers and the token-issuance scopes are all derived from one credential secret under different scopes (`issue-map.md`, "Membership proofs"; `storage.md` A6). What keeps them apart is scope separation inside the proof system, not separate keys. The chat identity key alone is independent. Say that, because it is the property `credentials.md` has to deliver and the cross-spec identifier trace has to check.

**S7 — "What each party sees", row "Credential issuer and verifier", never-sees column.** "Any value that appears in a later presentation" is too strong. A `credential` evidence item gives the host the disclosed attribute values of another card (`verifier.md`, evidence kinds), and a ward value is exactly what a breakdown later discloses. The property is unlinkability, not value secrecy: the host never sees an identifier, nullifier or pseudonym that a later presentation produces. Reword.

## Notes

**N1 — "Aggregator, phase 1", sees column.** "Timing to the minute" describes the logs (`services.md` L-1). The aggregator sees exact arrival times while a deck is open and keeps ballots keyed by receipt leaf until release. Say "exact timing in memory until release; logs to the minute", so the breach row's "pseudonymous votes for that deck" is read correctly.

**N2 — "The operator", stopped-by list, "the identity link".** "No service receives two of the three identities in one request" is the right test. Add the one place the specs come close: a phase 1 breakdown ballot carries a disclosed attribute value beside the pseudonym (`deck.md` open question), which the last paragraph of the assumptions section already carries as a residual. Cross-reference it from here.

**N3 — "Invariants and how they are tested".** Rows 1, 2, 4, 6 and 7 cite `simulator.md`, which does not exist; W0-09 owns `sim/` and `prompts/wave-0/09-simulator.md` is the only description. Point at the prompt until the spec lands, or at `sim/README.md`.

**N4 — "Colluding servers", missing rows worth a line each.** Delivery service and log: a `promote-confirm` in a channel at time t and a signed object logged at t is a timing join between a chat event and a map object, but the signed object already names the chat key, so nothing new; for unsigned objects the join reaches the channel, not the person. Gateway and any operator service: nothing beyond the gateway alone, since the service sees the same decrypted request. Writing them down stops the next reviewer re-deriving them.

**N5 — "Out of scope", coercion.** Good and honest. Add one sentence that the receipt page design (`services.md`, "Receipts") means a coercer who holds the phone can check the leaf, but a coercer who does not cannot ask the aggregator for it, since no per-leaf query exists.

**N6 — "The public", stopped-by.** "No breakdown cell under 300, no map or groups under 800" matches `context.md`'s gates. Add `GATE_COMMON` 300 for common ground, movement and ratings, since those are the parts most likely to be read as "what the group thinks".

## Invariants, floors, sums, federation (summary)

- **Invariants.** The document is the right shape for checking them. B1 is the one row that would send a reviewer to the wrong conclusion. S6 and S7 are precision fixes that matter because `credentials.md` will be written against this text.
- **Floors.** The organizer section's five bullets on floors are correct and match `context.md` C3, C10 and `deck.md` D10 to D12. The "closing a deck early" bullet is a good catch.
- **Sums.** Invariant 5's test row ("reference computes each part from vectors both ways") is the right test. It should also name the DAP mapping in `services.md` ("Phase 2") as the thing the twin implementation checks.
- **Federation.** The last assumptions row ("the context's named services are what members intended") is the honest statement. Add relay discovery to it once `services.md` defines it (`reviews/services.md` S5), since a context that names a relay run by its gateway's operator has silently removed the OHTTP guarantee.

## Summary for the author (first review)

Fix B1 now; it is one table row and it is wrong in a way that matters. Then update the sibling-spec lists (S4), add the Helper, moderators and the separate issuer as parties (S1), and correct the launch picture for the Helper (S2). S5 and S6 are the two places a later reviewer will rely on the exact wording, so get them right before the cross-spec pass.

---

## Re-review (2026-10-06, after rework)

Re-read the reworked `threat-model.md` (294 lines) in full against the reworked `services.md` and the current `release.md`, `chat.md`, `storage.md` and `verifier-runtime.md`.

### Verdict

**Approve with fixes.** The blocker is fixed and every should-fix and note from the first review has landed. Two fixes remain, both about claiming slightly more than a mechanism delivers; neither changes the document's shape.

### Status of the first review's findings

| Finding | Status | Evidence |
| --- | --- | --- |
| B1 log row | Fixed | The row now states the chat key for signed objects, the slot nullifier for unsigned ones, the sponsor for agents, and the relay on submissions; mechanism cites issue-map.md and the routing table. Matches `services.md` "Submitting a manifest". |
| S1 missing parties | Fixed | Rows for Moderator, Helper (phase 1) and separate token issuer; organizer row names organizer-run verifier sessions with the verifier-runtime.md section. |
| S2 Helper at launch | Fixed | Operator paragraph says it may run the Helper at launch and why phase 1 does not depend on it; assumptions table has the phase 2 independence row. |
| S3 T-4 | Fixed | T-4 now exists in `services.md`. |
| S4 sibling list | Fixed | release.md, chat.md and agent-sponsor.md are in the landed list with what they settle; the delivery row lists epoch rate and Welcome counts. |
| S5 seam row 1 | Fixed, with a caveat | Points at the registry in `services.md` and calls it the seam. The registry itself is stale (see `reviews/services.md` F1), so the caveat is there, not here. |
| S6 shared derivation | Fixed | Row states one credential secret under scope-separated proofs and an independent chat key. |
| S7 issuer value secrecy | Fixed | Reworded to unlinkability of identifiers. |
| N1 to N6 | Fixed | Exact timing in memory; breakdown cross-reference; simulator prompt pointer; two collusion rows; coercer sentence; `GATE_COMMON`. |

### Remaining fixes

**R1 (should fix) — "Assumptions and what breaks", last row; also the federation note.** The row says a context naming a relay run by its gateway's operator "silently removes the OHTTP guarantee, which is why services.md rule O-5 makes phones refuse it". O-5 cannot do that against the adversary this document is written for. Authorities are free to create, so an operator who runs the relay signs its relay manifest with a fresh keyset and O-5 passes; O-5 also refers to "the gateway's authority", which no longer exists because the gateway has no manifest (`reviews/services.md` F2). O-5 catches honest misconfiguration and openly shared authorities. The separation rests on who runs the relay (ADR 0073), the app-shipped relay constants, and the services screen making a context's relay choice visible. Rewrite the row to say so, and move "the relay operator is independent" into the assumptions table as its own row, next to "the relay does not collude with the gateway", with "if it fails: every anonymous request becomes attributable to an IP" (the same consequence as the collusion row, because it is the same failure).

**R2 (should fix) — "Seams mapped to specs", row 1.** Declaring the registry in `services.md` the seam is right, but add that the owning spec's text wins over the registry when they disagree, and that a disagreement is itself a finding. Without that sentence a stale registry entry (there are eleven today) reads as the normative string.

### Notes

**R3 (note) — "Other members" row, sees column.** "The epoch rate of joins and leaves" belongs to the delivery service row (where it also appears). Members see joins and leaves directly in the MLS tree, which is more than a rate; say that instead.

**R4 (note) — Bootstrap constants.** The document does not yet mention that the app ships the reference log's authority, origin and launch witness keys and the reference relays' authorities as constants (`services.md`, "Checkpoints", Bootstrap; "Who runs it"). That is a trust anchor and belongs in the operator section ("controls: the published app build, which carries the bootstrap constants") and in the assumptions table ("the constants in the audited build name the intended log, witnesses and relays; if they fail, the build is malicious, see Out of scope"). It is already covered in substance by the malicious-build bullet, but a reviewer looking for "where are the roots of trust" should find them named. The refinement in `reviews/services.md` F3 (constants bootstrap only the first checkpoint, then Global's logged witness list applies) would shrink what the constants have to be trusted for; mention it once it lands.

**R5 (note) — Moderator row.** "The reporter's ... chat identity" is implied by the report's MLS sender, not by a field in the report body (`chat.md` §11.3). Fine as written, but cite the sender rather than the body so nobody looks for a field.

### Coverage after rework

Parties: eighteen rows, now including the Helper, moderators and a separate token issuer. Assets: unchanged and complete against the prompt. Seams: all seven mapped, row 1 via the registry. Assumptions: ten rows; R1 asks for one more. Out of scope: unchanged. The document does what the prompt asks.
