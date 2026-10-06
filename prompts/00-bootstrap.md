# 00 · Bootstrap the Hum repo

You're setting up the Hum monorepo from the seed: docs, prompts and agent definitions are already here. Build the skeleton every later workstream will fill in. Don't implement protocol features.

## Read first

- `CLAUDE.md` (the repo layout and gates you're creating)
- `prompts/README.md`, and skim `prompts/wave-0/` and `prompts/wave-1/` so the skeleton fits them
- `docs/DECISIONS.md` (the stack is proposed, not final; keep the skeleton easy to change)

## Do

1. `git init` if needed. Add `.gitignore` files for Rust, Go, Python, Xcode and Gradle, and `.editorconfig`.
2. Install the reviewer subagents: copy `prompts/agents/spec-reviewer.md` and `prompts/agents/seam-reviewer.md` into `.claude/agents/`, unchanged. Check that Claude Code lists them.
3. Create the layout from `CLAUDE.md`. Give every top-level directory a short `README.md` saying what lives there and which workstream owns it (take ownership from the `Owns` lines in `prompts/wave-1/`).
4. **`core/`:** a Cargo workspace with empty library crates `hum-manifest`, `hum-log`, `hum-cred`, `hum-ballot`, `hum-release`, `hum-chat`, `hum-store`, `hum-ibis`, `hum-take`, `hum-agent` and `hum-ffi`, on the current stable toolchain pinned in `rust-toolchain.toml`. Workspace-level lints: `unsafe_code = "forbid"` except in `hum-ffi`, and clippy pedantic as warnings.
5. **`services/`:** empty Rust binary crates `aggregator`, `issuer`, `verifier-host`, `delivery`, `blob-store`, `opendata` and `gallery` (in the same workspace or a second one; pick one and record why), plus a Go module `services/ledger` with a `main.go` that exits 0.
6. **`reference/`:** a Python project (`pyproject.toml`, managed with `uv`) with `pytest`, `ruff`, and a `hum-vectors` CLI stub that writes `vectors/README.md` and exits 0.
7. **`sim/`:** a Rust binary that prints "no scenarios yet" and exits 0.
8. **`apps/ios` and `apps/android`:** a `README.md` each. W1-09 and W1-10 create the projects.
9. **`justfile`** with `fmt`, `check` (format check, lints and tests for Rust, Go and Python, then conformance), `vectors`, `sim-fast` and `sim-full`. `check` must pass on the empty skeleton.
10. **CI** (GitHub Actions): one workflow running `just check` and `just sim-fast` on every push and PR, with Rust, Go and Python toolchains cached. Add a nightly job for `just sim-full`.
11. **`.github/pull_request_template.md`** with a checklist: which spec sections this implements, whether vectors were regenerated, whether the simulator passes, and a `seam:` line listing any security seam touched.
12. `docs/decisions/0001-repo-layout.md` recording the layout and the one-workspace-or-two choice.

## Don't

- Choose licenses (it's an open decision). Add `LICENSE-TBD.md` saying so.
- Add dependencies in any seam crate.
- Change anything under `docs/` except adding the decision record.

## Done when

`just check` and `just sim-fast` pass locally, CI config is valid (run `actionlint` if it's available), and your summary lists the tree you created and anything you had to guess.
