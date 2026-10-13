# 0114 · Seven-lane integration evidence

2026-10-13 · implementation record; owner seam review remains required

This continues the seven-lane handoff at `a4d0ba4` on
`codex/seven-lane-integration`. The user explicitly requested the handoff work.
The earlier branch was already pushed to main before the user corrected the task
interpretation. This record does not approve the new changes for merge.

## Implemented boundaries

- Release readers derive R15 contracts from verified deck and release manifests,
  check blob CIDs, open actual HPKE keyboxes and sealed references, and validate
  every table before returning any rows. Both public and sealed four-stage worlds
  contain real synthetic Parquet files. Rating group-share post-processing applies
  the 300-person noised cell floor while preserving raw signed counts. The table
  fixtures do not claim to reproduce the numerical oracle or a noise sampler.
  ADR 0115 records a pre-existing consensus transition conflict requiring owner
  clarification; the tested worlds do not cover those contradictory paths.
- The proposed verifier host links all eight semantic operations to actual
  Wasmtime components. It projects only explicitly supplied disclosed claims,
  validates dataset roots, and enforces the process deadline through host calls
  and result transfer. The exact WIT artifact remains opt-in until accepted;
  the five production profile binaries are not supplied.
- The mls-rs wrapper receives into a cloned candidate and publishes it only after
  authentication, Hum wire policy, and result conversion succeed. Failed receives
  preserve current and prior-epoch state. A captured synthetic fixture supports
  repeatable replay, persistence, private-control AAD, franking and stamp checks.
  Captured replay is not deterministic random group generation.
- The Privacy Pass adapter calls the approved Rust implementation for actual
  type-1 and type-2 issuance and finalization. Policy checks bind keys, challenges,
  contexts and channel directories, derive channel keys through RFC 9497, redeem
  through durable atomic SQLite uniqueness, and enforce separate caller-supplied
  connection identities and fifteen-minute fetch cookies. P4 membership proofs,
  real transport identity, and unspecified key-expiration semantics remain outside
  this adapter. RFC fixtures are synthetic inputs, never production key material.
- Generated Kotlin now executes the existing blst feasibility probe through JNA
  and UniFFI on an Android 15/API-35 arm64 emulator: twenty calls and 120 assertions.
  It uses the same cross-built library as ADR 0112. The tested emulator has 4 KiB
  pages; this does not claim 16 KiB-page or physical-device coverage.

## Proposed protocol choices

[ADR 0113](0113-bbs-and-backup-proposals.md) records concrete BBS E1 and backup B1
choices. Their executable proposals remain separate from normative credential
validation. No existing P4 placeholder is silently converted into an accepted
proof implementation, and no owner answer is inferred from an implementation.
The [proposed WIT](../../reference/src/hum_reference/data/runtime/wit/PROPOSAL.md)
likewise retains an explicit opt-in API.

## Review and verification

The parent independently reran the MLS, Privacy Pass and Android probes. Review
caught and fixed breakdown-domain sorting in R15, and identified raw-evidence
projection and image-container handling issues in the proposed host. The final frozen-source
`just check` passed: 483 Python tests and a clean comparison of 960 accepting /
931 rejecting cases. `just sim-fast` reported 5 passing, 0 failing and 4 pending
scenarios. The handoff records probe results and remaining coverage.

`seam:` credential issuance and presentation; key derivation and storage; sealed
backups and keyboxes; release metadata and privacy-floor post-processing; token
nonce persistence; what evidence reaches a verifier module; MLS receive state.
