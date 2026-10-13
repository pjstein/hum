# Seven-lane integration review

2026-10-13 · review branch `codex/seven-lane-integration`

Review covered the reference adapters and isolated probes listed in
[ADR 0114](../../decisions/0114-seven-lane-integration-evidence.md). This is an
implementation review, not owner approval of BBS E1, backup B1 or the WIT proposal,
and not an outside cryptography audit.

## Findings resolved before the final gate

| Boundary | Finding | Resolution and evidence |
| --- | --- | --- |
| Parquet reproducibility | Unordered metadata changed file bytes and dependent CIDs across Python hash seeds | Sort writer metadata; subprocess regression and complete deck/take world CID comparisons under seeds 1 and 2 agree |
| R15 breakdown | Valid plans may declare values in a different order from sorted table rows | Contract derives sorted value keys; regression uses plan `[2,1]` and rows `[1,2]` |
| Host evidence | Checking only schema allowed a credential/device kind to enter the raw evidence path | Check both kind and schema; only explicit disclosed-claim projections reach imports |
| Host images | Returning at PNG IEND or JPEG SOS could ignore later EXIF or trailing data | Validate full container structure, PNG CRC/order and JPEG scan/marker boundaries; reject EXIF and trailing bytes. This is container validation, not pixel decoding |
| E1 resource boundary | A huge signer count could trigger expensive generators before invalid proof framing was rejected | Validate count, disclosure count and exact proof length before generator derivation; a test fails if malformed input reaches generators |
| E1 scalar/index types | Float or boolean disclosure indexes were not reliably rejected | Exact integer indexes checked before core operations; malformed inputs fail closed |
| E1/B1 retained state | Zero prover shares and retained blinds are scalars the pinned random procedure can produce | Accept private scalars in the specified domain; retain nonzero final nym requirement. Actual zero-share and zero-blind issuance/proof paths pass |
| Commitment wire scalars | Allowing zero random inputs does not imply zero serialized responses are valid | Reject identity commitments and zero serialized challenge/responses as blind -03 §5.4.2 requires; individual zero random inputs have positive cases |
| Fetch cookies | Expired cookies were rejected but retained in memory | Delete at the exact 900-second boundary, clean up on both request paths and expose trusted-clock idle cleanup; test no resurrection and invalid clock inputs |

The release implementation and host adapter were reviewed by an agent other than
their author. BBS was independently checked against the pinned equations and
complete upstream fixture inputs; the reviewer reran the boundary tests after
fixes (11 passed). The parent read the code and independently reran the MLS,
Privacy Pass and Android probes, plus focused reference tests.

## Remaining limits

- E1 and B1 stay proposed. Normative P4 and proof-bearing service composition are
  still unimplemented. Published fixture agreement does not substitute for the
  owner's protocol decision or outside cryptography review.
- The WIT adapter is opt-in. Its inputs assume an externally verified manifest
  and already verified credential/device evidence. It is not the complete host
  session, dedup and signing service, nor the five profile binaries.
- R15 validates transport, schemas, binding metadata, row domains and specified
  suppression. Synthetic derived columns are not claims of oracle computation.
  Independent review exposed a pre-existing consensus stage-transition conflict;
  [ADR 0115](../../decisions/0115-release-consensus-stage-transitions.md) records
  the owner question. The tested worlds do not cover those contradictory paths.
- MLS candidate-state receive and persistent replay checks cover the tested
  wrapper/backend; the fourteen complete Hum chat suites remain separate work.
- Privacy Pass connection IDs and issuer authorization come from the caller.
  These adapters do not implement real network separation or membership P4.
- Android evidence is from an arm64 emulator with 4 KiB pages and the BLS probe.

`seam:` credential issuance/presentation; key derivation/storage; sealed backup
and keybox formats; release metadata/floors; token nonce persistence; verifier
input projection; transactional MLS receive. Owner review is required before merge.
