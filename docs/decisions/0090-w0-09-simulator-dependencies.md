# 0090 · Simulator dependencies and what its fakes may do

**Status:** proposed (W0-09, 2026-10-06)

## Context

`sim/` needs seeded randomness, Gaussian noise for the fake aggregator, JSON
reports, and a CSV parser for the Polis open data (whose comment bodies contain
commas, quotes and newlines). `CLAUDE.md` forbids hand-rolled cryptography and
floating-point noise sampling in product code and requires approval for new
dependencies in a seam. The simulator is not a seam and not product code, but
it links into the same workspace and lockfile.

## Decision

`sim/Cargo.toml` adds, for `hum-sim` only:

| Crate | Version | Use |
| --- | --- | --- |
| `rand`, `rand_chacha` | 0.9 | Seeded scenarios (ChaCha8 per world and per noise draw) |
| `rand_distr` | 0.5 | `Normal` for the fake aggregator's noise, as in the research code |
| `serde`, `serde_json` | 1 | Reports, the tape payloads, sim-side manifest bodies |
| `csv` | 1 | Polis loader and the fixture writer |
| `anyhow` | 1 | Error plumbing in the CLI and loaders |

No workspace-level dependency table entries were added; no other crate's
manifest changed. The root `Cargo.lock` gained the transitive closure.

Two things the simulator's fakes do that product code never may:

1. **Floating-point Gaussian noise** in `sim/src/pipeline/dp.rs` and
   `sim/src/fakes/aggregator.rs`. It is the research oracle, ported one to
   one. `release.md` requires a discrete Gaussian from a vetted sampler in
   `hum-release`; the simulator compares that sampler's releases against this
   oracle and never ships it.
2. **A non-cryptographic hash** (FNV-1a, `fake_hash` in `sim/src/ports.rs`)
   for fake CIDs, identity tokens and the fake ledger's chain. It makes
   references pinnable and chains checkable in structure. It proves nothing
   and is replaced by `hum-manifest` CIDs in wave 1.

Both are marked in their doc comments. A grep for `fake_hash` or
`rand_distr` outside `sim/` is a review finding.

## Consequences

- `cargo clippy --workspace`, `cargo test --workspace` and `just sim-fast`
  all pass with these crates (run 2026-10-06).
- `rand` 0.9 rather than 0.10 because `rand_distr` 0.5 is the version that
  matches it; W1-13 may bump both together.
- When W1-03 lands `hum-release`, the fake aggregator keeps calling the
  oracle so the comparison stays available; the `rand_distr` dependency then
  belongs to the oracle only.
