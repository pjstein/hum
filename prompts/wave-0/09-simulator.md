# W0-09 · Simulator design and skeleton

**Owns:** `sim/`, `docs/specs/simulator.md`

The simulator is the project's main test: a headless world of simulated phones running the whole ratchet through the real code. In wave 0, design it and build the skeleton; wave 1 workstreams plug their real components into it, and wave 2 runs everything through it.

## Read first

- `docs/design.md` (the ratchet and the privacy model)
- `docs/research/dp-polis/` (metrics, baselines and Polis replay)
- `docs/specs/services.md` and the other specs as they land
- `CLAUDE.md` (the simulator gates every merge)

## Design (`simulator.md`)

- **Architecture:** a Rust binary that runs core crates and services in-process behind the same interfaces as production (`services.md`), with fakes allowed only until the real component lands. Simulated phones each hold their own keys, credentials, hand and shield.
- **Scenarios:**
  - Polis replay: real conversations from the Polis open data (CC BY 4.0) mapped onto contexts, decks and ballots, at sizes 100, 300, 800, 1,600 and 5,000.
  - The full ratchet: chat messages promoted to the map, positions dealt into a deck, votes, a release, the digest posted back.
  - Churn: members joining, leaving and switching devices mid-deck; dropouts between release rounds.
  - Adversarial hooks wave 2 will fill: a lying log, a modified client, an over-collecting verifier, a malicious agent.
- **Oracles:** the non-private baseline from the research code; metrics carried over from `polis_dp.py` (tally error, ARI between groups, top-5 representative statements found in the top 15, common ground overlap) with thresholds per size and ε; protocol checks (every manifest verifies, every release respects floors, no shield overspends, no forbidden data in any service's logs).
- **Two modes:** `sim-fast` (under 60 seconds, every commit) and `sim-full` (nightly, all sizes and seeds), each writing a report with the metrics and any invariant violations.
- **Leak checks:** the simulator records everything every service sees, then searches it for anything it must never see (votes, cross-identity joins, sealed keys). This is how invariant 1 gets tested continuously.

## Build now

The skeleton: scenario loading, simulated phones as data structures, a fake aggregator that calls a port of the research pipeline, the metrics and report writer, and the Polis loader. Wire `just sim-fast` and `just sim-full` to it.

## Done when

`just sim-fast` runs a Polis replay at 300 and 800 voters through the fake aggregator and reports metrics within the research results' range, and `simulator.md` says exactly how each wave 1 workstream plugs in.
