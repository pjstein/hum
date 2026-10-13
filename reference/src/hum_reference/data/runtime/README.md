# Component sandbox probes

These short component-model WAT sources are compiled by approved Wasmtime 49.0.0
for the reference tests and vectors. They are authored sandbox probes, not profile
binaries. The exported `decide` uses the specified `result<decision,rejection>`
with full record shapes. The memory-growth and NaN probes return rejection code
0 when their assertion passes, and code 1 if it fails; those are probe signals,
not real evidence decisions.

The default runner links no imports and gives each invocation a fresh isolated process. It
sets a 1 MiB Wasm stack and a 64 MiB memory cap, disables threads/shared memory
and relaxed SIMD, and enables NaN canonicalization. A one-memory limit prevents
multiple memories each receiving the full per-memory allowance. This conservative
adapter does not yet support otherwise legitimate multi-memory components.

The source spec has no pinned WIT artifact. Wasmtime rejects literal `time.day`
as not kebab-case and `hum:verifier/host@0.1` as an invalid SemVer interface name.
The exact proposal in `wit/proposed-verifier.wit` uses a single host interface,
kebab-case function names and version 0.1.0. Bytecode Alliance wit-parser 0.261.0
successfully parsed and resolved that artifact. The `proposed_host=` opt-in
adapter executes all eight functions, type-checks imports before instantiation,
and returns only explicitly projected evidence/claims/dataset records. This
remains a proposed ABI, without a normative code.abi allowlist change. Five
profile algorithms/binaries and reproducible build recipes are still absent.

A process deadline also bounds native execution or future host callbacks, which
fuel and Wasm epoch interruption alone cannot interrupt while in host code.
Tests exercise an unbounded Wasm loop with fuel disabled, a blocked host callback
(the test synchronizes on actual callback entry), and a partial IPC result.

The canonical result payload begins at byte 4, because the decision's list pairs
have four-byte alignment. The rejection, memory-growth and NaN WAT probes were
corrected from byte 8. Deliberately failing controls verify that a failed probe
produces code 1 instead of silently reading a zero-initialized field.
