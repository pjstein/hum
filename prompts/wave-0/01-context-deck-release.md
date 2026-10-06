# W0-01 · Context, deck and release specs

**Owns:** `docs/specs/context.md`, `docs/specs/deck.md`, `docs/specs/release.md`

Write the body specs for the three manifest types at the heart of Hum. They define what organizers can configure, what people vote on, and the only thing that ever leaves aggregation.

## Read first

- `docs/specs/manifest.md`: the envelope, refs, frozen fields, verification step 10, the type registry and privacy floors
- `docs/design.md`: "Core concepts", "Differential privacy design", "Evidence from real conversations", "Contexts, permissions and platform rules", "Deliberation layer (IBIS)"
- `docs/research/dp-polis/README.md` and `polis_dp.py` (`dp_pipeline`, `DEFAULT_SPLIT`, `repness`, `consensus`)
- `docs/ux/screens/O-Create.png`, `O-Compose.png`, `O-Plan.png`, `P-Ledger.png`, `Swipe-Reveal.png`, `B-Release.png`

## Each spec includes

- A body field table: CBOR key, name, type, required or optional, meaning, and whether the field is frozen once the manifest is in use.
- The `refs` names it uses and what each must point to.
- Validation rules, each phrased so a conformance vector can test it, and how they plug into verification step 10.
- A readable JSON example.
- The vectors W0-08 must generate: valid cases, and one invalid case per rule.
- Open questions you couldn't settle, also filed in `docs/decisions/`.

## Context

- Entry policy: conditions over issuer and attribute (see "Verifiers" in the design doc), trust lists, invite links and approved lists.
- Every organizer setting in the design doc's settings table, including history for newcomers and file retention, and which ones are protocol floors.
- Context floors, which can only be stricter than the protocol's.
- Accepted logs, aggregator authorities (Leader and Helper; one operator in phase 1), blob-store authorities and storage policy, the all-members chat group ID, parent context, and mixing in Global statements.
- Roles and how they map to signing thresholds.
- The noised daily count organizers see: what it measures, its budget, and how that budget is accounted. It must not let anyone watch one person vote.

## Deck

- Title, open and close times, statements (refs to positions or statement blobs, including Global ones), and a topic per card for the topic meters.
- The release plan: parts by tier, the ρ split across parts (default tallies 0.15, covariance 0.35, map 0.15, groups 0.35), contribution cap K (default 60; recommend K at or above deck size), M = 60 statements for covariance, a 24 × 24 map grid, the blur, and the size gates (tallies 100, common ground 300, map and groups 800, breakdown cells 300).
- IBIS release parts: re-vote movement per argument after the card flips, and argument ratings ("does this move you?"). A re-vote reveals more, so it costs more budget; say how much and why.
- Frozen fields: statements and release plan freeze at open; only `closes` may move, and only later.
- Whether each phone sees cards in its own random order.

## Release

- Mechanism, ρ and δ spent, noised participant count, the tiers unlocked, the receipt root, and the verifier and assurance mix.
- **Rounds.** The map and groups need phones to act after close: phones project themselves onto the published axes and report one map cell, then assign themselves to a group from the published centroids and report group tallies. Specify the rounds, what's published between them, how dropouts between rounds affect the numbers, and how all of it stays one release with one budget.
- Table blobs as Parquet: a schema for each part (tallies, covariance or axes, map histogram, centroids, group tallies), plus derived tables (noise-aware representative statements and common ground, computed as post-processing and including the noise level).
- Who signs: two aggregator authorities. Say what the second signer attests in phase 1, when one operator does the adding.
- Members-only results: the context setting allows results visible only to members, but the ledger is public. Resolve this, for example with the manifest logged and its tables sealed under the keyring.

## Done when

The three specs exist and are internally consistent with the manifest spec, the `spec-reviewer` subagent has no blockers left, and the open questions are filed.
