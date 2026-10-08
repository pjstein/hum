# 0051 · How the delivery service authorizes sends and fetches without a member list

**Status:** proposed (W0-05, 2026-10-06; revised after spec review) · `seam:` key derivation, what leaves the phone

## Context

The design doc requires that the chat delivery service (DS) authorize access to a channel with anonymous credentials and never be able to list its members. The DS must still stop non-members from reading or flooding a channel's queue, and must know which context a channel belongs to for quotas. The first draft let the DS keep an authoritative epoch counter and accept one commit per epoch; the spec review showed that one invalid commit from any member, or from a removed member with a leftover token, would then brick the channel for good, and that handing the per-channel token issuer key to one device let the DS link each device's tokens.

## Decision

Recorded in `docs/specs/chat.md` section 12:

- **The DS validates nothing and decides nothing.** It assigns a sequence number to every message it accepts and never rejects a commit for being the second one in an epoch. Phones apply, per epoch, the first commit in sequence order that passes MLS validation and the role rules, and skip the rest. This is the non-validating Delivery Service pattern of RFC 9750.
- **A per-epoch delivery secret** is exported from each MLS group with label `hum/delivery/1`. Only current members can derive it. A commit must carry an HMAC under any secret the DS already holds for the channel, and registers the next epoch's secret. The DS holds at most 64 secrets per channel; a secret lives 48 hours past its registration or last successful use, and when the table is full the newest registration is dropped, so a flood evicts only itself and an old honest secret kept alive by honest use is never reached. A removed member cannot derive the secret of the epoch that removed them; by refreshing older secrets they can keep posting rate-limited junk that honest phones skip until an organizer resets, but they cannot evict honest secrets or stop honest issuance.
- **An organizer reset** replaces every held secret with the honest current one, under the `organizer` credential class of `services.md`. It is the backstop against a flooding current member (who is removed first) and the way to cut a removed member off at once.
- **Per-channel Privacy Pass tokens** (RFC 9576, RFC 9578 type 0x0001). A device proves channel membership to the issuer with an HMAC under a held delivery secret over its blinded token requests. The issuer key per channel is derived from a master secret and the group ID with RFC 9497 `DeriveKeyPair`, so the DS stores nothing per channel. The channel's creator publishes the issuer public key in the channel's directory entry (or the roles message for the two context groups), and every phone verifies token responses against that key only. One token per send; one token per 15-minute fetch session.
- **Context tokens**, issued against the context membership proof from `credentials.md`, authorize registering a channel and posting or fetching join tickets. They follow `services.md` and `storage.md` §6.1 exactly.
- **Everything goes through an OHTTP relay** run by a party other than the DS operator.

## Alternatives considered

- An authoritative DS epoch with one commit per epoch (the first draft). Rejected: unrecoverable bricking by any member.
- An authoritative DS epoch with a secret-authenticated reset by any member. Rejected: a malicious current member races the reset forever.
- A static per-channel shared secret. Rejected: it does not rotate on removal.
- Public-metadata tokens with the group ID as metadata. Equivalent in outcome, but the draft is less mature than RFC 9578.
- Proving context membership on every send. Rejected: too expensive on a phone, and it would not prove channel membership.

## Consequences

- A removed device can keep spending tokens it already holds for up to 48 hours, and can register dead-branch secrets until its last known secret expires. It can fetch ciphertext it cannot decrypt and send junk honest members discard, bounded by per-channel send limits. The spec says so.
- The DS learns how many devices hold fetch sessions open and that an organizer acted when a reset happens. Both are in the spec's metadata table.
- `services.md` must list `stamp` in the delivery service's manifest (it does, body key 11), `context.md` must carry the greeting key for admission (requested), and `credentials.md` must define the context membership proof as unlinkable to the voting pseudonym.
