# 0081 · Libraries and encoding choices in the Python reference

**Status:** proposed (W0-08, 2026-10-06) · `seam:` signing, canonical encoding, sealed format, key derivation

## Context

`reference/` is the second opinion on every spec rule with bytes in it and the only writer of `vectors/`. `CLAUDE.md` says: never hand-roll cryptography or noise sampling, use recorded libraries, and record library choices. The reference needs deterministic CBOR, Ed25519, AES-128-GCM, HKDF and SHA-256, and it must stay independent of the Rust code.

## Decision

| Need | Choice | Why |
| --- | --- | --- |
| Ed25519, AES-128-GCM | `cryptography` (pyca), 50.x | Vetted bindings to OpenSSL; no primitive is written in the reference |
| HKDF-SHA256 (MLS exporter arithmetic, keyring blob keys) | `hmac` and `hashlib` from the standard library | HKDF is two HMAC calls; writing them out keeps every intermediate value visible in the vectors (`prk`, `derived_secret`) |
| Deterministic CBOR | Hand-written encoder and strict decoder, `reference/src/hum_reference/cbor.py` (about 200 lines) | The canonical-form rule is itself under test (verification step 2) and the failing vectors need the exact violation named. `cbor2`'s canonical mode sorts map keys length-first (RFC 7049), not bytewise as RFC 8949 section 4.2.1 requires |
| COSE_Sign | Hand-written structure, `cose.py` | The structure is four CBOR arrays; `pycose` would add a dependency in a seam for no checking it does not already get from the vectors |
| Merkle trees, proofs, checkpoints | Hand-written to RFC 9162 and the C2SP note formats, `merkle.py`, `log.py` | Tested against the certificate-transparency-go known-answer roots |
| Oracle check for rankings | `numpy`, dev dependency only | `tests/test_release.py` imports `docs/research/dp-polis/polis_dp.py` with its heavy imports stubbed and compares `repness` and `consensus` on random inputs |

Encoding is the one thing `CLAUDE.md` allows the reference to write itself ("beyond encoding"), and that is the line this follows.

## Consequences

- `reference/pyproject.toml` depends on `cryptography`; dev adds `pytest`, `ruff`, `numpy`.
- Adding anything else in a seam needs the owner's approval, as `CLAUDE.md` says.
- Noise is never drawn in the reference. The sampler harness checks draws an implementation hands it.
