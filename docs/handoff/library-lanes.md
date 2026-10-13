# Wave 0 approved-library follow-up

Continued on 2026-10-13 in [seven-lane integration](seven-lane-integration.md).
The dated record below describes the earlier implementation and its then-open gaps.

2026-10-09 · branch `wave-0/contracts` · follows commit `0ae01ca`

The owner requested all seven lanes after W0-11. Each now has executable work and
an explicit coverage boundary. This is reference and feasibility work, not the
start of production services or a claim that all protocol vectors are complete.
The pre-existing main push remains `f8f76d3`; this follow-up does not merge or push
wave 0. Protected `CLAUDE.md` and `docs/design.md` are unchanged.

## Delivered

| Lane | Result | Remaining boundary |
| --- | --- | --- |
| BBS | Independent SHA-256 base -12 sign/verify/proof generation and verification over py_ecc; published signatures/proofs/generators match; two commitments and seven N=1 pseudonym proofs verify | Full blind issuance and Hum P4 blocked by pinned blind/nym draft contradictions and incomplete private generation inputs |
| HPKE | Both RFC 9180 suites and exporters match known answers; real issuance/evidence/response/keybox/ticket seals; Argon2id and backup key wrap | Proof contents remain opaque; backup phrase encoding and outer envelope unspecified |
| Android blst | Actual API26 arm64 library/executable cross-build; Kotlin generated from Android library; generated Python host binding executed | No Android device or Kotlin runtime execution; probe uses BLS operations, not the future Hum BBS wrapper |
| Parquet | All sixteen decoded logical schemas, metadata, counts, sort/uniqueness, nulls, optional complete key/CID bindings; eighteen-card R15 positive/negative vectors | Callers must derive trusted contracts from verified deck/release data; full world integration and cell suppression remain |
| Verifier runtime | Wasmtime components return real decision/rejection; hostile sandbox probes, complete-transfer process deadline, CID/size/import limits; separate host decision validation | No host imports linked, no five profile binaries; exact WIT ABI and aggregate multi-memory support remain |
| MLS | Pinned real mls-rs UniFFI build plus wrapper-only APIs for exporter, AAD, message bytes, private controls and GroupInfo extensions; 26 live checks | Fourteen complete Hum suites and deterministic generation remain; failed authentication consumes a receive generation |
| Privacy Pass | Independent RFC framing/type-2 RSA verification in Python; all ten RFC fixtures execute issuance/finalization/redemption in approved Rust library; double spending and altered DLEQ reject | Hum context/key/channel binding, delivery derivation, persistent atomic spent state and Python type-1/issuance adapter remain |

Five new generated files add 25 accepting and 55 rejecting cases:
`credentials/bbs-base` (4+12), `credentials/hpke` (6+13),
`release/parquet` (1+11), `verifier-runtime/component-sandbox` (4+9), and
`storage/privacy-pass-rfc9578` (10+10). Existing evidence and release keybox
cases now contain real HPKE ciphertext; changed keybox CIDs propagate through
release, deck and take fixtures. No pre-existing case ID was removed.
Writer-specific Parquet bytes are transport
examples; decoded contents are the comparison target.

## Verification

The frozen Python suite passed: `364 passed in 1803.37s (0:30:03)`.
`just check` exited 0, including formatting, lints, Rust/Go checks and the
final recursive vector diff: `933 accepting and 894 rejecting cases`.
All 113 frozen reference files and 104 vector files stayed unchanged through
the gate. A final trailing-whitespace cleanup in eight WAT probes was checked
to preserve compiled bytes exactly; all 13 runtime tests were rerun and passed.
`just sim-fast` exited 0:
`hum sim · mode fast · 3.7s · pass 5 fail 0 pending 4`.
Separate probes are outside the root Cargo workspace and must be run explicitly:

- `ANDROID_NDK_HOME=... tools/android-blst/run.sh`: parent rerun passed host test,
  actual generated binding, arm64 build, ELF inspection and Kotlin generation.
  Library SHA-256 `4f9cf441705129756f333adad9b51de05849f1033a3f2cae152f3e3557d08017`.
- `HUM_MLS_SOURCE=/tmp/hum-mls-rs-056 tools/mls-reference/run.sh`: parent rerun
  passed 3 Rust unit tests, 6 generated Python scenarios, and 26 live checks.
  The known authentication-failure state consumption was independently reproduced.
- `cargo test --manifest-path tools/privacy-pass-kat/Cargo.toml --locked`:
  2 test loops passed, covering all 10 RFC 9578 fixtures. Clippy with `-D warnings`
  passed. The reviewer independently reran this probe.

The other-lane reviewer found and verified a fix for a partial IPC result that
could bypass the runtime deadline. BBS is excluded from that author's review;
the parent inspected its equations/parsing and ran the draft fixture tests.
See [review](../specs/reviews/library-lanes.md),
[ADR 0112](../decisions/0112-w0-library-reference-evidence.md), and
[coverage map](../specs/conformance.md).

## Review and next actions

1. Read [BBS findings](../research/bbs-pinned-draft-findings.md). Recommended:
   retain base -12 and N=1 fixture verification, require a versioned reviewed
   errata profile with independent complete fixtures before implementing full
   blind issuance. A corrected published upstream draft is preferable; none
   newer than the pinned blind/nym -03 was available at this check.
2. Pin an exact WIT artifact for the verifier host. Recommended: preserve the
   spec's semantic operations and explicitly map them to valid kebab-case names
   and a full semantic version such as `0.1.0`. The current literal dotted names
   and `@0.1` cannot be linked as written. This needs an explicit spec decision;
   the harness has not invented wire names.
3. Pin the recovery phrase encoding and backup outer-envelope fields. The crypto
   components are ready, but choosing serialization silently would create a new
   interoperability rule.
4. Investigate [MLS failure-state behavior](../research/mls-reference-feasibility.md)
   before production use. Recommend upstream clarification and a reviewed remedy;
   do not change primitive semantics or hide the failing original-message replay.
   Extend the now-working wrapper with deterministic state inputs and Hum policy
   checks before emitting canonical chat vectors.
5. Finish trusted R15 contract derivation and group-cell suppression, the Privacy
   Pass reference adapter and service policy, and the actual Android Kotlin test.
   These are implementation follow-ups, not reasons to select new libraries.

The existing owner decisions from [W0-11](wave-0-closeout.md) remain open. None is
accepted implicitly by this implementation record. Wave 0 remains awaiting owner
seam review and an explicit merge instruction.
