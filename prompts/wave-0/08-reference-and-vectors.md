# W0-08 · Reference implementation and test vectors

**Owns:** `reference/`, `vectors/`, `docs/specs/conformance.md`

Build a small, readable Python implementation of every spec rule that has bytes or numbers in it, and use it to generate the test vectors every Rust, Go and Swift or Kotlin implementation must pass. It exists to be independent of the production code: it's the second opinion, so write it from the specs, not from any other code.

## Read first

- `docs/specs/manifest.md` (start here; it's final enough to begin today)
- Every other `docs/specs/*.md` as it lands
- `docs/research/dp-polis/` (the DP math you port)

## Build, in this order

1. **Manifests:** deterministic CBOR (RFC 8949 §4.2.1), CIDs and their text form, COSE_Sign with a detached payload and Ed25519 under `manifest/1`, keysets with thresholds, pre-rotation and revocation, and all 11 verification steps.
2. **Logs:** RFC 9162 Merkle trees, inclusion and consistency proofs, checkpoints and witness cosignatures.
3. **Storage:** Padmé, the chunked AES-GCM sealed format, sealed references, keyring derivation given an exporter secret as input.
4. **Release math:** ε↔ρ conversion, σ per part from sensitivity and the ρ split, contribution capping, size gates, noise-aware representative statements and common ground (ported from `polis_dp.py`). Noise itself can't be a fixed vector; test the deterministic parts with fixed noise inputs, and provide a statistical test harness for samplers (mean, variance and tail checks over many draws).
5. **Context, deck, release, issue map, take, agent sponsor, verifier and trust-list bodies,** as their specs define them.
6. **Credentials and ballots:** use the BBS and pseudonym drafts' own test vectors where they exist, and generate ballot-encoding vectors from `ballot.md`.

## Vectors

- One directory per spec in `vectors/`, JSON with hex-encoded bytes, each case with an ID, a description, the spec section it tests, inputs, and either expected outputs or the expected rejection (the failing step and reason).
- **Every rejection rule gets at least one failing vector.** For manifests, that means one per verification step.
- A corpus of whole bundles: valid ones a client must accept, and invalid ones it must reject exactly.
- Deterministic: fixed keys and seeds, so regenerating produces identical files. `just vectors` regenerates; CI fails if the result differs from what's committed.

## Conformance (`conformance.md`)

How an implementation runs the vectors, what "conformant" means for clients, aggregators, ledgers and stores, and the interop milestone (an independent implementation verifies a deck and release produced by another).

## Done when

`just vectors` regenerates every file identically, each spec rule maps to vectors in a coverage table in `conformance.md`, and the reference passes its own tests. Mark the manifest, storage and release-math parts `seam:`.
