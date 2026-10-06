# W1-12 · Agents

**Owns:** `core/crates/hum-agent`, agent screens (with W1-09 and W1-10), `docs/ux/agents.md`
**Implements:** `docs/specs/agent-sponsor.md` and "Agents as first-class participants" in `docs/design.md`

Agents make each step of the ratchet cheaper. They are visible members whose privileges come from where they run, and they never vote.

## Build

- **The three tiers:**
  - *Personal* agents run on the phone and see what you see, including your own votes; nothing leaves the device. Use the platform's on-device model APIs where available (check what Apple and Google currently offer on-device), behind an interface so the model can change. Jobs: "catch me up on #repairs", "what changed since I voted", "prep me for this deck".
  - *Shared* agents are channel members running on a member's hardware or in an attested enclave. Jobs: proposing issues from threads, drafting clean positions, merging duplicates, writing the strongest pro and con, posting release digests.
  - *Public* agents work only from releases: studio takes and analysis, labeled and ranked like everyone's.
- **The tool surface** each tier gets, as an explicit allowlist. There is no voting tool at any tier, and casting a card requires a human gesture the agent API can't produce. Test that.
- **Sponsorship:** sponsor credentials, per-sponsor rate limits, labeling on everything an agent authors, and the visible membership event when a shared agent joins a channel, including where it runs.
- **Agent screens:** catch-up, a facilitator agent in a channel, and the membership event aren't designed yet. Design them in the Direction B language, write them up in `docs/ux/agents.md`, and hand them to the app workstreams.

## Tests

A simulator scenario with a shared facilitator agent proposing positions and a flood attempt that hits rate limits; the leak check confirms a personal agent sent nothing off the device; no code path lets an agent submit a ballot.

## Seams

The tool allowlists, the no-vote guarantee, and anything a personal agent could send off the phone.

## Done when

All three tiers run in the simulator within their limits, and the agent screens are designed and handed off.
