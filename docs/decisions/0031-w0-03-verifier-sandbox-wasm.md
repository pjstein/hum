# 0031 · Verifier modules run as WebAssembly components with a closed host interface

**Status:** proposed (W0-03, 2026-10-06)

## Context

`docs/specs/manifest.md` lists the custom verifier runtime as an open question, with a WebAssembly sandbox as the leading option. The design doc requires that custom verifier code can't break unlinkability and that over-collection is answered by transparency. The runtime has to be auditable (the manifest pins a code hash) and has to give a module no path to anything that appears in a later presentation.

Alternatives considered:

- **No custom code in draft 0.1; only the five parameterized profiles.** Simplest and safest, but the design doc and accepted decision 11 say context administrators run their own verifiers from day one, and "verifiers are a protocol, not a plugin store" implies a general contract.
- **Containers on the host.** Too wide an interface to enumerate; network and filesystem isolation would be policy, not construction.
- **A declarative rules language.** Covers invite, approved list and district, but not document or selfie matching, and would be a second thing to specify.

## Decision

Verifier modules are WebAssembly components targeting the world `hum:verifier/module@0.1`, importing only `hum:verifier/host@0.1`. The host interface is the complete list in `docs/specs/verifier-runtime.md`: manifest body, declared evidence, declared datasets with salted Merkle proofs and the session's opening day; dedup is checked by the host after the module exits. Normalizers ship inside the module, not as an import. No network, filesystem, randomness, fine time or signing. The module exports one function, `decide`, and the host validates its output against the manifest before signing.

Each of the five reference profiles is one fixed binary with no build-time parameters; configuration comes from the manifest body and datasets. The binaries are built reproducibly and attested in the core trust list, so every verifier on a profile shares the attested CID.

## Consequences

- Determinism by construction, so dual-run audits are possible.
- Document and selfie matching must run inside the 16 MiB module or wait for a host import in a later world (open question in the runtime spec).
- Wave 1's verifier host needs a component-model runtime. `wasmtime` (49.x at the time of writing, monthly majors) is the recommendation in `docs/research/seam-libraries.md`, with `wasmtime` from PyPI in the reference pinned to the same major. The spec's CPU limit is wall clock, not fuel, so nothing in conformance depends on which wasmtime major a host runs; the host workstream pins its own major and may meter fuel as an extra stop.
- Modules are built with `rustc` for `wasm32-wasip2`, which emits a component directly. `cargo-component` is not used (experimental, last commit 2025-07).
- Conformance vectors for modules ship as `.wasm` files beside the JSON, and the Python reference needs a component-model runtime (`wasmtime` with component support) to run them.
- Changing the host interface means a new world name and a new `code.abi` value, so old modules keep working under the old world.
