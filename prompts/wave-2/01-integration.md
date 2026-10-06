# W2-01 · Integration: the whole ratchet

**Owns:** the full-ratchet scenarios in `sim/`, `docs/reports/integration.md`

Make the simulator run Hum end to end with no fakes left, and keep it running on every change.

## Do

1. Remove every remaining fake from the simulator, or list each one with the workstream that owes the real component.
2. Build the full-ratchet scenario: a context created with real manifests and floors; members verified through real credentials; chat across channels with files; messages promoted to the map; positions and arguments; a deck dealt; votes, flips and re-votes; the release rounds with realistic dropouts; the release logged and witnessed; the digest posted back to chat; takes built and rated in the studio; then the next issue raised from the release.
3. Run it at 100, 300, 800, 1,600 and 5,000 members with Polis replay voting, at ε 2, 4 and 8, with several seeds. Check the metrics against the research ranges, the tiers unlocked against the size gates, and every invariant through the leak check.
4. Add churn (joins, removals, device changes, a member losing their phone and restoring) and failures (a service restarting mid-round, a witness offline, a slow relay).
5. Make the fast variant part of `just sim-fast` and the full sweep part of `just sim-full`.

## Done when

The full ratchet passes with no fakes at every size, `docs/reports/integration.md` has the metrics table and every failure found with its fix, and the scenario gates every merge.
