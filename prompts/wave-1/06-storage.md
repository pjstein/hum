# W1-06 · Storage

**Owns:** `core/crates/hum-store`, `services/blob-store`, the OHTTP relay setup
**Implements:** `docs/specs/storage.md`, the blob-store and relay parts of `services.md`

## Build

- **`hum-store`:** Padmé padding and the chunked AES-GCM sealed format (RustCrypto crates, not your own primitives); sealed references; keyrings from the exporter `hum-chat` provides; folders as replayed file operations with encrypted index snapshots; uploads and downloads with streaming and ranges; the author's delete secret; promotion of a file to a public copy with consent.
- **`services/blob-store`:** put (recompute the CID, reject mismatches), get, range get and delete; Privacy Pass token issuance against a context membership proof; per-context quotas and per-token rate limits; context-signed deletion orders; retention expiry; nothing in logs that names a member or a channel.
- **OHTTP:** the client in core (the `ohttp` crate is the likely choice) and a relay for development; record who runs the production relay as an open question.

## Tests

Storage vectors, including truncation, chunk swapping and wrong-CID cases; fuzzing for the sealed-format parser; a simulator scenario where a file goes from chat to a folder to map evidence to a public copy without a second upload; the leak check finds no keys, file names or member identifiers on the store; removed members can't read files added after removal.

## Seams

The sealed format, keyrings, delete secrets, tokens.

## Done when

The simulator's files scenario passes end to end with the store seeing only what the threat model allows.
