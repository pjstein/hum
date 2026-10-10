# Library lanes: independent spec and seam review

2026-10-09 · Reviewer: BBS reference workstream, reviewing other workstreams only.
BBS implementation and its pinned-draft findings are excluded from this review.

Reviewed against `CLAUDE.md`, manifest/design invariants, credentials, verifier,
verifier-runtime, release, storage and chat normative bindings. Scope: the new
HPKE Python module and vectors; Parquet helper, tests and generator; Python
Privacy Pass framing/public verification and Rust RFC KAT harness; no-import
component sandbox; MLS UniFFI feasibility patch and live checks; Android report.

## Resolved finding

**Should fix — runtime complete-result deadline.** The original
`component_runtime.run` bounded `Pipe.poll`, then called blocking `recv` without a
remaining deadline. A readable partial result bypassed the promised wall-clock
bound. The review reproduced a 0.5-second budget taking 1.573 seconds and escaping
`OSError` after a deliberately incomplete IPC message. The author moved receipt
and deserialization to a supervised reader, waits only the remaining deadline,
handles EOF/I/O failure, kills the worker and bounds cleanup. A regression checks
a stalled partial transfer. The review reran the same reproduction: retryable
`module-limit` at 0.516 seconds, no credential or dedup mutation. Resolved.

## Scope findings retained as notes

**Note — R15 needs a trusted complete caller contract.**
`parquet_tables.Contract` / `validate_table` checks decoded schemas, nulls, row
counts, ordering, metadata and supplied coordinate/card bindings. The eighteen-card
fixture supplies all bindings and rejects wrong statement CIDs. This is not yet
release-world R15 enforcement: `expected_keys` and `card_cids` are optional,
argument-to-card membership must be supplied through the complete expected key
domain, and plan/body-derived metadata must come from trusted state. Keep that
qualification when updating coverage. Integrating callers must derive the complete
contract from verified release/deck/plan data, never from the table under review.
The generator already labels this limitation. Authoritative common metadata
cannot be overwritten through the extra-metadata map.

**Note — HPKE authentication is not credential authorization.**
The module uses the prescribed two suites, info labels, evidence request hash and
session AAD, response exporter labels, keybox prefix/AAD, 4096-byte ticket framing,
and Argon2id/HPKE backup key wrap. CFRG known answers test both suites and exporters.
Opaque request/ticket proof bytes in transport vectors are explicitly labeled;
these do not establish BBS P4 or ticket-policy validity. Response AEAD assumes one
response plaintext per request context; caller retry/state policy remains required.
No additional cryptographic construction or plaintext disclosure was found.

**Note — Privacy Pass primitive coverage is separate from Hum redemption policy.**
The Python module authenticates type-2 tokens against exact challenge/key hashes
and RSA-PSS; it deliberately does not authenticate type-1 tokens. The independent
RFC inputs drive the approved Rust library for all five private and five public
cases, including issuance/finalization/redemption, duplicate redemption rejection,
and invalid private-token proof rejection. Its explicit `blind-rsa-signatures`
version is the same dependency already used by the approved `privacypass` crate.
These KATs do not implement Hum context/token-key gossip, authenticated rate limits,
persistent atomic spent state or delivery issuer derivation. Preserve those gaps.

**Note — runtime probes do not implement the five profiles or host world.**
The sandbox checks code CID and size, component return shape, fuel, memory, stack,
NaNs, shared-memory refusal and an actual process deadline. Every import fails
closed. Decisions are raw module outputs: manifest attribute validation, evidence
imports, logged-session-day replay, dedup and issuance remain outside this adapter.
The pinned textual ABI still needs an agreed valid WIT spelling/version. A
`module-limit` is retryable and is not evidence about a person. No issuer secrets
or dedup writes enter these probes.

**Note — MLS remains primitive/binding feasibility.**
The patch exposes existing library exporters, authenticated data, serialized
messages and private GroupInfo extension data; it adds no primitive. The live
checks exercise ciphertext controls, join, export agreement/rotation, application
AAD authentication, replay refusal and removal. They explicitly do not establish
Hum credential policy, franking, buckets, control AAD or the remaining profile
sequences. An observed upstream behavior is recorded: a failed authenticated-data
check consumes the receive generation, so the authentic original then fails too.
Do not remove this limitation or treat the harness as full profile approval.
The synthetic GroupInfo extension is transport data, not a verified sealed tree
reference. Real crypto outputs remain local and are not published as deterministic
reference vectors.

**Note — Android cross-build is not device execution.**
The evidence/report accurately claims arm64 cross-build, exported UniFFI symbols,
Kotlin binding generation and a host binding call. It explicitly leaves Android
loader/Kotlin/JNA device execution, actual BBS-wrapper integration, timing and
outside cryptographic review unresolved. No device execution claim was found.

## Independent verification

- HPKE, Parquet and Privacy Pass Python tests: 47 passed.
- Revised component sandbox tests, including partial-result deadline: 12 passed.
- `cargo test --manifest-path tools/privacy-pass-kat/Cargo.toml --locked`: both
  fixture-loop tests passed, covering all ten RFC 9578 cases.
- Generated MLS Python bindings: 26 live checks passed; the upstream receive-key
  consumption limitation was reproduced/asserted and remained in the output.
- Source inspection of the final Parquet generator confirmed the accepted case
  supplies all eighteen card keys/CIDs and negative sums, and rejection cases
  execute the validator rather than embedding unchecked expected booleans.

## Verdict

**Approve within the documented reference/helper/feasibility scope.** The concrete
runtime deadline defect found in review is fixed and regression-tested. No open
blocking finding remains in the reviewed code. This is not approval to merge the
security seams, deploy production handling, close full R15/P4/MLS/runtime policy
gaps, or claim Android device execution. Owner seam review remains required.
