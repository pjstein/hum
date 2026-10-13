# Seven-lane integration follow-through

2026-10-13 · `codex/seven-lane-integration` · based on `a4d0ba4`

The user meant to continue the seven-lane handoff. The previous wave-0 branch had
already been fast-forwarded and pushed to main at `a4d0ba4` before that correction.
This follow-through is a separate review branch. It does not start production
services or silently accept the outstanding protocol choices.

| Lane | Implemented now | Remaining boundary |
| --- | --- | --- |
| BBS | Explicit E1 proposal: blind commitment, issuance, finalization, pseudonym proof generation/verification. Independently reproduces all 2 commitments, 4 signatures and 7 complete proofs from pinned upstream private inputs whose outputs match the published draft | Owner adoption of the draft errata/layout; normative P4 and composite proof wiring; outside cryptography review |
| Backup / HPKE | Explicit B1 proposal: pinned/checksummed recovery phrases, complete authenticated recovery and chat-only files, strict nested allowlists, no partial return. A restored E1 card can generate a valid proof. Actual release keyboxes now open complete Parquet files | Owner adoption of phrase/envelope and E1 card layout; production atomic state installation and shield restore policy |
| Android | Generated Kotlin → JNA → UniFFI → the cross-built blst library executes on Android 15/API-35 arm64: 20 calls, 120 assertions | BLS feasibility only; future Hum BBS wrapper, physical devices and 16 KiB pages remain untested |
| Parquet / R15 | Verified-manifest contracts, complete row domains, CID/keybox/sealed-reference checks, real synthetic table transports across public and sealed four-stage worlds, rating cell-floor filtering, group-total binding | Consensus transition conflict awaits ADR 0115; numerical oracle outputs/tolerances remain separate; raw synthetic sums are not a noise sampler |
| Verifier runtime | All eight proposed WIT imports execute in real components, with disclosed-claim projection, dataset proof checks and a deadline covering host calls/result transfer. Exact WIT parses. Raw credential/device evidence and image-container bypasses were fixed during review | Owner WIT adoption; one-memory cap is conservative; five production profile binaries and complete host issuance orchestration remain |
| MLS | Transactional receive preserves state after authentication or policy failure, private-control/application AAD policy, persistent replay rejection, actual franking/stamp checks, deterministic replay of captured synthetic state | Captured replay is not deterministic setup; fourteen complete Hum chat suites and production integration remain |
| Privacy Pass | Approved-library type-1/type-2 issuance/finalization adapter, channel DeriveKeyPair, key/challenge/context/directory bindings, durable atomic nonce redemption, request MAC and fetch-cookie policy | Membership P4 proof composition, actual transport separation, and unresolved issuance-key lifetime semantics |

## Decisions to review

The unanswered choices remain proposals:

1. [BBS E1](../decisions/0113-bbs-and-backup-proposals.md): retain the prover blind,
   correct the message layout, and use the explicitly versioned transcript matching
   the published fixtures. The independent generation-fixture gate now has evidence.
2. [Backup B1](../decisions/0113-bbs-and-backup-proposals.md): exact phrase input,
   canonical outer envelope and strict restored-state format.
3. [Exact WIT](../../reference/src/hum_reference/data/runtime/wit/PROPOSAL.md):
   valid component names and version preserving the existing semantic operations.
4. [Consensus publication](../decisions/0115-release-consensus-stage-transitions.md):
   publish only in final versions, and require unlocked part 3 at stage 4. Existing
   R6–R8 and the baseline reference conflict on two transition paths.

`vectors/experimental/` contains reproducible test artifacts for these proposals.
They are explicitly excluded from normative conformance until adoption. Existing
credential P4 placeholders have not been presented as complete cryptography.

## Code review order

1. Read ADR 0113, then [proposed BBS](../../reference/src/hum_reference/proposed_bbs.py)
   and [proposed backup](../../reference/src/hum_reference/proposed_backup.py).
   Start at `proposed_bbs.py:42` (entropy), `:58` (issuance), `:108` (proofs),
   and `proposed_backup.py:95` (restored state), `:153` (seal), `:197` (open).
2. Read [release opening and contracts](../../reference/src/hum_reference/release_tables.py),
   then its [public/sealed and floor tests](../../reference/tests/test_release_tables.py).
   Start at `release_tables.py:34` (contracts), `:185` (verified opening), and
   `:227` (rating floor). Read ADR 0115 before reviewing stage-transition coverage.
3. Read the proposed WIT, [host projections](../../reference/src/hum_reference/runtime_host.py)
   and [isolated execution](../../reference/src/hum_reference/component_runtime.py).
   Start at `runtime_host.py:73` (inputs), `:165` (host), and
   `component_runtime.py:74` (worker), `:169` (deadline).
4. Read the [MLS wrapper patch](../../tools/mls-reference/uniffi-hum-profile.patch)
   and [transaction checks](../../tools/mls-reference/transaction_checks.py).
   The candidate-state transaction starts at patch line 161.
5. Read [token policy](../../reference/src/hum_reference/token_policy.py), the
   [library adapter](../../reference/src/hum_reference/privacy_pass_adapter.py), and
   [Android runtime evidence](../../tools/android-blst/evidence/kotlin-runtime.json).
   Start at `token_policy.py:36` (atomic spend), `:64` (redemption), `:146`
   (cookie lifetime), and `privacy_pass_adapter.py:73` (channel derivation).

## Review evidence

The parent reran the Android emulator test, MLS probe and Privacy Pass Rust/Python
checks. Independent review caught and fixed sorted breakdown domains, raw evidence
projection for credential/device kinds, and incomplete image-container scanning.
The [independent review](../specs/reviews/seven-lane-integration.md) also verified
the BBS scalar and malformed-input fixes. The cross-proposal backup test restores
the retained blind/nym and verifies a new
scope-bound proof, including rejection under a different scope.

Protected `CLAUDE.md` and `docs/design.md` are unchanged. Approved runtime libraries
are unchanged; Android SDK/JDK/Gradle/JNA tooling lives in the isolated probe.
See [ADR 0114](../decisions/0114-seven-lane-integration-evidence.md) and the
[current coverage map](../specs/conformance.md) for scope and limitations.

`seam:` credential issuance/presentation; key derivation/storage; sealed backups
and keyboxes; release metadata and cell floors; token replay state; evidence
projection; MLS receive state. Owner seam review is still required before merge.

## Final verification

The frozen-source Python suite passed: `483 passed in 1524.23s (0:25:24)`.
`just check` exited 0, including formatting, lints, Rust/Go checks and the final
recursive vector comparison. An independent `just conformance` also exited 0:
`960 accepting and 931 rejecting cases`, with no recursive vector diff.

- `just sim-fast` exited 0: `pass 5 fail 0 pending 4`, in 3.7 seconds.
- Android parent rerun: 20 Kotlin calls, 120 assertions; the native, APK and
  generated-Kotlin hashes match the checked-in evidence.
- MLS parent rerun: 3 Rust tests, 6 generated Python scenarios, 26 raw live checks
  and 12 transactional/policy checks, including two exact fixture replays.
- Privacy Pass parent rerun: 2 Rust test loops covering all 10 RFC fixtures,
  clippy with warnings denied, and 18 Python policy tests.
- The reference writer now sorts metadata. All 29 focused Parquet/release tests
  passed, including separate-process hash-seed regression. Complete deck/take
  bundle/blob CID sets agree under `PYTHONHASHSEED=1` and `2`.

All 199 frozen reference/probe source files and 109 vector files remained
unchanged through the gate. All existing vector case IDs are retained. Five new vector files add 64 cases;
44 of them are explicitly experimental (15 accepting, 29 rejecting), excluded
from normative conformance. The final corpus totals above include those tested
proposal artifacts. No generated vector was hand-edited.
