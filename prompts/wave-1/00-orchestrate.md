# W1-00 · Orchestrate wave 1 (build everything)

Wave 1 builds every layer at once against the approved wave-0 specs. Each workstream owns its directories, implements its specs, passes the conformance vectors, and plugs into the simulator.

## Before starting

Confirm with the owner that wave 0 is approved: every spec merged, `just vectors` clean, `just sim-fast` running. If a spec a workstream needs is still unapproved, hold that workstream and say so.

## Plan

1. Start `01-manifests-and-logs` first; everything signs and verifies manifests. The others can start in parallel against its spec and vectors, using the reference implementation through a thin adapter until the Rust crate lands.
2. Run `02` to `13` in parallel, each in its own git worktree and branch (`w1/<name>`). Dependencies to watch:
   - `08-core-ffi` defines the API the apps use; `09-ios` and `10-android` build against its interface from day one, with fakes behind it.
   - `03-aggregation` needs `02-identity` for pseudonyms; use the spec's vectors until it lands.
   - `04-publication-and-open-data` needs `01` and `03`; `11-studio-and-gallery` needs `04`'s tables.
3. For every change marked `seam:`, run the `seam-reviewer` subagent before asking the owner to merge.
4. Merge order follows dependencies. After each merge, every other branch rebases and re-runs `just check` and `just sim-fast`.

## Report, as often as the owner asks

A table of workstreams: status, which spec rules are implemented and passing vectors, simulator status, seams waiting on review, and blockers (especially spec questions, which go back to `docs/decisions/` rather than being guessed in code).
