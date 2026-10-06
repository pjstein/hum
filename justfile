# Hum task runner. `just --list` shows the recipes.

set shell := ["bash", "-euo", "pipefail", "-c"]

ledger := "services/ledger"
reference := "reference"

default:
    @just --list

# Install Python dev dependencies for the reference implementation.
setup:
    uv sync --project {{reference}}

# Format every language in place.
fmt:
    cargo fmt --all
    gofmt -w {{ledger}}
    uv run --project {{reference}} ruff format {{reference}}
    uv run --project {{reference}} ruff check --fix {{reference}}

# Fail if anything is not formatted.
fmt-check:
    cargo fmt --all --check
    test -z "$(gofmt -l {{ledger}})" || { gofmt -l {{ledger}}; echo "gofmt: files need formatting"; exit 1; }
    uv run --project {{reference}} ruff format --check {{reference}}

# Lints for Rust, Go and Python.
lint:
    cargo clippy --workspace --all-targets --locked
    cd {{ledger}} && go vet ./...
    uv run --project {{reference}} ruff check {{reference}}

# Unit tests for Rust, Go and Python.
test:
    cargo test --workspace --locked
    cd {{ledger}} && go test ./...
    uv run --project {{reference}} pytest -q {{reference}}

# Regenerate vectors/ from the reference implementation. Never hand-edit vectors/.
vectors:
    uv run --project {{reference}} hum-vectors --out vectors

# Fail if the committed vectors/ differ from a fresh run of the reference.
conformance:
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT; \
    uv run --project {{reference}} hum-vectors --out "$tmp/vectors"; \
    diff -r "$tmp/vectors" vectors

# The merge gate: format check, lints, tests, then conformance.
check: fmt-check lint test conformance

# The simulator in its under-a-minute mode. Runs on every commit.
sim-fast:
    cargo run --locked -p hum-sim -- fast

# The simulator in its nightly mode: all sizes and seeds.
sim-full:
    cargo run --locked -p hum-sim -- full
