# W1-01 · Manifests and logs

**Owns:** `core/crates/hum-manifest`, `core/crates/hum-log`, `services/ledger` (Go)
**Implements:** `docs/specs/manifest.md`, the ledger and witness parts of `docs/specs/services.md`, and their vectors

Everything else in Hum signs, verifies, logs and pins manifests, so this lands first.

## Build

- **`hum-manifest` (Rust):** a strict deterministic-CBOR encoder and decoder that rejects any non-canonical input; CIDs and their text form; COSE_Sign with a detached payload under the `manifest/1` domain string (coset plus an audited Ed25519 crate); keysets with sign and rotate thresholds, pre-rotation and revocation; all 11 verification steps, with results cached by CID; per-type body validation through a registry other crates extend.
- **`hum-log` (Rust):** a client for the ledger's tiles; inclusion and consistency proofs (RFC 9162); checkpoints and witness cosignatures; the phone's checkpoint store, which checks consistency on every update; lineage lookup that verifies the chain from version 1. Expose the checkpoint hash phones exchange in their channels (chat defines the message; you define the value).
- **`services/ledger` (Go, on Tessera):** the submission API, which runs verification steps 1–6 and 8 (plus 10 for releases) before appending, reimplemented in Go from the spec, not translated from the Rust. This is Hum's second, independent implementation of manifest verification. Serve tiles and checkpoints, integrate witnesses using the C2SP witness protocol, and run two witnesses in dev.

## Tests

- Both implementations pass every manifest and log vector, including each failing vector by the right step.
- Interop: Rust-produced bundles verify in Go, and Go-accepted entries verify in Rust, in CI.
- Fuzz targets for the CBOR decoder, the bundle parser and the proof verifiers.
- Plug into the simulator: real manifests and a real ledger replace the fakes, and the simulator's lying-log hook can make the ledger equivocate so phones' consistency checks are exercised.

## Seams

All of it. Run the `seam-reviewer` subagent on each PR.

## Done when

Vectors pass in Rust and Go, interop runs in CI, fuzzers have run for a meaningful time with findings fixed, and `just sim-fast` runs on real manifests and a real ledger.
