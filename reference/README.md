# reference

The Python reference implementation of Hum's specs, and the only source of
`vectors/`.

**Owner:** W0-08 (reference and vectors).

It is written from `docs/specs/`, never from the Rust, Go or app code, so it
can act as an independent second opinion. Managed with `uv`:

```bash
uv sync                      # from this directory
uv run pytest                # about five minutes: the test worlds verify every manifest
uv run ruff check . && uv run ruff format --check .
uv run hum-vectors --out ../vectors
```

From the repo root, `just vectors` regenerates `vectors/` and `just check`
fails if the committed vectors differ from a fresh run.

## Modules (`src/hum_reference/`)

| Module | Spec | What it holds |
| --- | --- | --- |
| `cbor.py`, `cid.py`, `keys.py`, `cose.py` | manifest.md | Deterministic CBOR, CIDs, Ed25519, COSE_Sign under `hum/manifest/1` |
| `merkle.py`, `log.py` | RFC 9162, services.md | Trees and proofs, leaves, C2SP checkpoints, witness cosignatures |
| `manifest.py` | manifest.md, services.md | Envelope, keysets, bundles, the eleven steps, per-type hooks, the wire bundle, the test `World` |
| `bodies/*.py` | one per type spec | `context`, `deck`, `release`, `issue_map`, `take`, `agent_sponsor`, `verifier`, `trust_list`, `verifier_runtime`, `service` |
| `storage.py`, `storage_folders.py` | storage.md | Sealed format, references, keyring keys, folders, delete orders, store API decisions |
| `services.py` | services.md | Errors, signed requests, task ids, receipts and pages, witness protocol, relay rules |
| `chat.py` | chat.md | Content types, message ids, padding, safety code, ExternalPart |
| `release.py` | deck.md, release.md | ε↔ρ, σ per part, plans against floors, round computations, rankings, sampler harness |
| `credentials.py`, `ballot.py`, `shield.py` | credentials.md, ballot.md, shield.md | Epochs and scopes, presentation structure, ballots and frames, intake, receipts, the shield ledger |
| `fixtures.py` | — | The base deterministic world |
| `vectors/` | — | One generator per `vectors/<spec>/` directory |
| `cli.py` | — | `hum-vectors` |

Seams (owner review before merge): everything above except `cli.py` and the
generators' JSON plumbing.

The reference never draws noise and never implements a cryptographic primitive
beyond encoding. What needs a library it does not have (BBS with pseudonyms,
HPKE, Argon2id, Parquet, a wasm runtime, an MLS stack, Privacy Pass, Prio3) is
listed as a gap in `docs/specs/conformance.md`.
