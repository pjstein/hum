# W0-04 · Issue map, takes and agent sponsors

**Owns:** `docs/specs/issue-map.md`, `docs/specs/take.md`, `docs/specs/agent-sponsor.md`

Specify the deliberation objects that feed decks, the studio takes built on releases, and how agents participate.

## Read first

- `docs/design.md`: "Deliberation layer (IBIS)", "Agents as first-class participants", "Open data platform"
- `docs/specs/manifest.md`: the `issue`, `position`, `argument`, `take` and `agent-sponsor` rows; "Blobs and storage" (sealed text and keyring epochs); the open questions on batching and editing authored objects
- `docs/ux/screens/IBIS-Map.png`, `IBIS-Card.png`, `IBIS-Author.png`, `Chat-Channel.png`, `S-Gallery.png`, `S-Studio.png`, `S-Take.png`

## Issue map (`issue-map.md`)

- Objects: issue, position, argument (pro or con) and sub-question; parent links; text as a blob, sealed under the context keyring in members-only contexts.
- Authorship: signed with the author's chat key, or unsigned with an anonymous membership proof ("hidden from everyone, organizers included"). Either way, never linked to how the author votes.
- Promote-to-map from chat: the message format, and author confirmation before it lands, since it's their words.
- Near-duplicate detection and merging, and who decides.
- Revising versus withdrawing a position (the manifest spec's open question), and what happens to a position already dealt into a deck.
- Batching: log every object, or a per-context batch root on a schedule. Recommend one and say what each choice lets the log prove.
- After a release: how positions are annotated with support by group and arguments with whom they persuaded.
- Moderation and abuse limits, since agents are the easiest way to flood a map.

## Takes (`take.md`)

- A query and chart spec over release tables, plus a text blob, pinned to the release versions it uses so it's reproducible and forkable.
- Error bars from the published noise come automatically; differences within the noise are flagged.
- Gallery ranking by whether every opinion group rates a take a fair reading. Ratings are votes too: specify how they're collected and released with DP, and their budget.

## Agent sponsors (`agent-sponsor.md`)

- Body fields: the agent's public key, where it runs (on a member's phone, on a member's hardware, or in an attested enclave) and its attestation, capabilities, and per-sponsor rate limits.
- The three tiers (personal, shared, public) and exactly what each can see and do.
- How agent content is labeled in every object it can author, and why agents can never hold a voting credential.
- The visible membership event when a shared agent joins a channel.

## Done when

Three specs exist with field tables, validation rules and vector lists; batching and editing have recommendations filed in `docs/decisions/`; and the `spec-reviewer` subagent has no blockers left.
