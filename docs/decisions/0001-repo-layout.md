# 0001 · Repo layout and one Cargo workspace

**Status:** proposed (bootstrap, 2026-10-06)

## Context

`CLAUDE.md` fixes the top-level layout: `docs/`, `prompts/`, `reference/`,
`vectors/`, `core/`, `services/`, `apps/`, `sim/`, `tools/`. The bootstrap
prompt asks for the Rust services to go either in the same Cargo workspace as
`core/` or in a second one, and to record the choice.

## Decision

**One Cargo workspace, rooted at `/Cargo.toml`,** with members
`core/crates/*`, the seven Rust services under `services/`, and `sim/`.

- Core crates are `core/crates/hum-<name>`. Service packages are
  `hum-<name>` with a short binary name (`services/aggregator` builds
  `aggregator`). The simulator package is `hum-sim`, binary `sim`.
- Workspace lints: `unsafe_code = "forbid"`, clippy `all` denied, clippy
  `pedantic` as warnings. `hum-ffi` keeps its own lint table with
  `unsafe_code = "allow"` and is the only crate that may use `unsafe`.
- Toolchain pinned in `rust-toolchain.toml` (1.99.0, edition 2024).
- The ledger is a separate Go module, `services/ledger`
  (`github.com/pjstein/hum/services/ledger`).
- The reference implementation is a `uv` project in `reference/` and is
  the only writer of `vectors/`. `just conformance` regenerates into a temp
  directory and diffs against the committed tree.
- CI is one workflow (`.github/workflows/ci.yml`): `just check` and
  `just sim-fast` on push and PR, `just sim-full` nightly.

## Why one workspace

- The simulator links core crates and services in-process behind the same
  interfaces as production (W0-09). One workspace gives it plain path
  dependencies and one `Cargo.lock`.
- One lockfile is one surface for the dependency policy W1-13 adds
  (`cargo-deny`, `cargo-vet`, the seam allowlist).
- One `target/` and one cache in CI; `just check` is a single
  `cargo clippy --workspace` and `cargo test --workspace`.
- The lint table applies uniformly, so the `unsafe` exception for `hum-ffi`
  is the only exception anywhere.

The cost is that a dependency bump in a service invalidates the shared lock
for everyone. If that becomes a problem, split `services/` into its own
workspace with path dependencies on `core/crates/*`; nothing else needs to
change.

## Consequences

- Wave 1 workstreams add dependencies in their own crate's `Cargo.toml` and,
  for shared versions, in `[workspace.dependencies]`.
- Licenses are still open, so no `license` field is set in any manifest and
  `LICENSE-TBD.md` says so.
- The Go module path is a guess at the eventual GitHub location; change it
  before the first external import.
