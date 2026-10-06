# W0-10 · Cross-spec review

**Owns:** `docs/specs/reviews/cross-spec.md`, and fixes the owner approves

Every spec has had its own review. This pass reads them together, because the dangerous bugs live between specs: an identifier one spec treats as harmless and another treats as linking, a budget charged in one place and spent in two, a domain string reused.

## Read

`CLAUDE.md`, `docs/design.md`, `docs/threat-model.md`, every file in `docs/specs/`, and the per-spec reviews in `docs/specs/reviews/`.

## Check

1. **Identifier trace.** List every identifier, key, nullifier, token, CID and timestamp across all specs: where it's created, where it travels, who sees it. Flag any pair of observations that could link a vote to a person or join two of the three identities.
2. **Budget trace.** Every release part, the daily count, IBIS movement and ratings, gallery ratings: each has a ρ, each is charged to the shield, and the totals compose correctly under zCDP.
3. **Floors.** Every place a floor is checked, and every path where one could be skipped.
4. **Labels and namespaces.** One registry of every domain-separation string, exporter label, CBOR key range, type name and media type, with no collisions. Propose namespacing under `hum/` if it isn't already.
5. **Seams between specs.** Formats that cross specs agree byte for byte (sealed references in chat and storage, ballots in ballot and release, credentials in credentials and verifier).
6. **Coverage.** Every rule has vectors in `conformance.md`'s table; list the gaps.
7. **Federation.** Nothing names a service by hostname or trusts the reference network.

## Output

`cross-spec.md` with findings by severity, each with a proposed fix. Apply fixes that are clearly editorial. List the rest for the owner, grouped by the decision they need, and add each to `docs/decisions/`.
