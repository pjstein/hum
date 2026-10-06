# W1-07 · Deliberation: the issue map

**Owns:** `core/crates/hum-ibis`
**Implements:** `docs/specs/issue-map.md`, and the IBIS parts of `deck.md` and `ballot.md`

## Build

- Issue, position, argument and sub-question objects as manifests, with text in public or sealed blobs as the context requires; authorship signed by the chat key or unsigned with a membership proof.
- **Promote-to-map:** turning a chat message into a proposal, the author's confirmation, and landing it on the map (with `hum-chat`'s content types).
- **Near-duplicate detection,** on the phone or by a shared agent, never on a server that could read members-only text. Start with something simple and testable (normalized lexical similarity); leave a seam for an on-device embedding model.
- **The map view model** the apps render: issues, positions, arguments ranked by how fair every opinion group found them (once releases exist), sub-questions, counts.
- **Flip-card data:** capturing the vote, the flip, and the re-vote or "did either case change your mind", passed to `hum-ballot` so movement is released only as noised totals.
- **Argument ratings** ("does this move you?") on the top few arguments per position, or a sample per person, passed to `hum-ballot`.
- **Dealing positions into a deck:** a position becomes a card the organizer can deal.
- **After a release:** annotations on positions (support by group) and arguments (whom they persuaded).
- The batching and editing rules wave 0 decided.

## Tests

Issue-map vectors; a simulator scenario where chat messages become positions with pro and con arguments, are dealt, voted, flipped and re-voted, and come back annotated after the release; members-only text never appears unsealed outside members' phones.

## Done when

The ratchet's map stage runs in the simulator from promotion through annotation.
