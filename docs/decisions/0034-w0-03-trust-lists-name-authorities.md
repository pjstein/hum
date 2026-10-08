# 0034 · Trust lists name verifier authorities, not versions, and record removals

**Status:** proposed (W0-03, 2026-10-06)

## Context

`manifest.md` says references are pinned to versions, and that naming an authority instead of a version is allowed only for keysets. A trust list is an opinion about a party. If it pinned verifier versions, every verifier code or key update would require every list that includes it, and then every context that pins the list, to publish new versions.

## Decision

A trust list entry names a verifier **authority** (its keyset lineage CID) in the body, with optional `minVersion`, and pins nothing in `refs`. The verifier version that applies is the one logged before the presentation, per the manifest spec's keyset rule. Contexts pin trust-list **versions** in `refs`, so a context version's accepted set is fixed once logged. A version that drops an entry must list it under `removed` with a reason, or it fails validation (rule 11).

This extends the manifest spec's authority-naming exception from keysets to trust-list entries. It is a body-level name, not a `refs` entry, so the envelope rule is unchanged; the manifest spec's registry row already says trust lists name authorities.

## Consequences

- Verifier updates don't ripple through lists and contexts.
- A list can't quietly drop a verifier; the log holds the reason.
- A compromised verifier is cut off fastest by its own issuer-key removal, not by a list change. List changes reach contexts at their next version and decks at their next deal.
- `context.md` already pins lists as `refs["tl/<i>"]` and names single verifier authorities in its `issuers` array; its policy leaves resolve with the algorithm in `trust-list.md`.
