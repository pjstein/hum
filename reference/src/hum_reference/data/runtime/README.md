# Component sandbox probes

These short component-model WAT sources are compiled by approved Wasmtime 49.0.0
for the reference tests and vectors. They are authored sandbox probes, not profile
binaries. The exported `decide` uses the specified `result<decision,rejection>`
with full record shapes. The memory-growth and NaN probes return rejection code
0 when their assertion passes, and code 1 if it fails; those are probe signals,
not real evidence decisions.

The runner links no imports, gives each invocation a fresh isolated process,
sets a 1 MiB Wasm stack and a 64 MiB memory cap, disables threads/shared memory
and relaxed SIMD, and enables NaN canonicalization. A one-memory limit prevents
multiple memories each receiving the full per-memory allowance. This conservative
adapter does not yet support otherwise legitimate multi-memory components.

The source spec has no pinned WIT artifact. Wasmtime rejects literal `time.day`
as not kebab-case and `hum:verifier/host@0.1` as an invalid SemVer interface name.
Choosing how to map these to actual WIT requires a spec decision. Until then no
host-world adapter or five-profile execution coverage is claimed. A valid WIT
world must also pin all record/list representations at the import boundary.

A process deadline also bounds native execution or future host callbacks, which
fuel and Wasm epoch interruption alone cannot interrupt while in host code.
Current tests exercise an unbounded Wasm loop with fuel disabled; imported
callback deadline testing awaits that pinned ABI and an actual host adapter.
