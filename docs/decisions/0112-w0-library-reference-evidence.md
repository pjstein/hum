# ADR 0112 · Approved-library reference evidence

2026-10-09 · Implementation record; no new protocol or library approval.

`seam:` credentials, sealed evidence and keyboxes, release tables, verifier sandbox,
chat MLS, and store/delivery tokens.

The owner requested all seven follow-up lanes after W0-11. This record activates
already approved reference dependencies: py_ecc 8.0.0, pyhpke 0.6.5, pyarrow 25.0.1
and wasmtime-py 49.0.0. The root production Cargo workspace is unchanged. Isolated
locked probes test approved blst 0.3.17, mls-rs 0.56.0 via UniFFI and privacypass
0.2.0-pre.3. These probes are outside the root gate and have separate run scripts
or documented commands.

The Python reference now produces base BBS, HPKE, opened-Parquet, sandbox-component
and RFC Privacy Pass files. Existing evidence seals and release keyboxes use real
HPKE. Numeric Parquet contents, schema and metadata are normative; writer bytes
are examples. Published RFC/draft fixtures are independent known answers, not
output from Hum's code under test. No hand-written pairing, AEAD, OPRF or MLS
primitive was introduced.

Scope limits remain binding:

- Full blind issuance and Hum P4 wait for a reviewed resolution of the pinned
  BBS blind/nym draft inconsistencies and complete independent generation inputs.
- Backup phrase encoding and outer envelope remain unspecified.
- R15 requires caller-supplied verified table contracts; world integration,
  suppression logic and all derived numeric tables are not complete.
- The runtime runs no-import components. Exact WIT import names/version and the
  five profile builds remain missing; one-memory enforcement is conservative.
- Android arm64 cross-build and Kotlin generation passed, but no Android device
  or Kotlin runtime execution occurred.
- MLS wrapper capabilities passed live tests, but Hum policy, deterministic
  vector generation and failure-state handling remain incomplete. The probe
  records failed authentication consuming a receive generation.
- Privacy Pass library KATs and Python public-token verification do not establish
  Hum service/context binding, delivery key derivation or durable spent-token state.

See `docs/handoff/library-lanes.md` for results and next actions, research reports
for primary evidence, and `docs/specs/reviews/library-lanes.md` for independent
review. This record does not resolve any owner decision, authorize a merge,
change protected design documents, or approve production cryptographic use.
