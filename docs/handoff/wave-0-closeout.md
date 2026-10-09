# Wave 0 handoff

Updated 2026-10-09. Read this before continuing wave 0 or starting wave 1.

## State in one paragraph

W0-11 is complete on `wave-0/contracts`: the requested disagreement tail is closed, the spec reviewer approves, and the orchestrator reran the full gates on frozen reference sources and generated vectors. `just check` exited 0 with 284 reference tests and 908 accepting plus 839 rejecting vectors; `just sim-fast` exited 0 with 5 passing scenarios and 4 adversarial hooks pending. The closeout is ready for owner seam review, not an automatic merge or a production-readiness claim. No wave 1 work was started. The owner's later request pushed the existing bootstrap commit `f8f76d3` from local `main` to `origin/main`; the wave-0 branch was not merged or pushed.

## W0-11 gate record

The initial tree was clean at `4899908`. The baseline gate was restarted against an isolated archive of that commit so subsequent reference edits could not change its result. Baseline `just check` exited 0, with this actual output:

```text
284 passed in 1374.29s (0:22:54)
wrote /var/folders/3d/cwnv9frs74x2p05j4t6_40mh0000gn/T/tmp.nDu1R9KYqT/vectors: 898 accepting and 825 rejecting cases
```

After the reference author froze the new corpus, the orchestrator ran `just check` itself. Exit status: **0**. Formatting, lints, Rust/Go checks, reference tests and the recursive generated-vector diff all passed. Actual final output:

```text
284 passed in 1390.76s (0:23:10)
wrote /var/folders/3d/cwnv9frs74x2p05j4t6_40mh0000gn/T/tmp.bmVNOBZy4h/vectors: 908 accepting and 839 rejecting cases
```

The orchestrator also reran `just sim-fast`. Exit status: **0**. Actual summary:

```text
hum sim · mode fast · 3.6s · pass 5 fail 0 pending 4
```

All 176 tracked reference/vector files matched their frozen hashes through the gate. No prior named vector case disappeared; 10 accepting and 14 rejecting cases were added. The final independent review is `docs/specs/reviews/wave-0-closeout.md`; ADR 0111 records the adopted clarifications without answering any open owner decision.

## What is on the branch

- 17 specs in `docs/specs/` plus `docs/threat-model.md`. Per-spec reviews are in `docs/specs/reviews/`.
- `docs/specs/reviews/cross-spec.md`. Section 12 lists every decision applied after review, by file and section (12.1 to 12.14).
- `docs/specs/reviews/applied-decisions.md`: the reviews of those applied decisions. Final verdict: approve, no blocker.
- `reference/` and `vectors/`. Coverage, gaps and disagreements are in `docs/specs/conformance.md`.
- `sim/`: the simulator skeleton with its leak checker.
- `docs/research/seam-libraries.md` and `docs/research/bls12-381-libraries.md`.
- `docs/DECISIONS.md` and `docs/decisions/`. Owner decisions are under "Accepted by the owner on 2026-10-07" and "2026-10-08".
- `CLAUDE.md`: the hand-roll rule and invariant 3 were reworded on the owner's approval.

## What the owner decided in this session

- One cell per context (rule C16), stored proofs checked at log time, the shield window anchored to the release, the three strings renamed under `hum/`.
- BBS, blind issuance and pseudonyms built in-house: `blst` for the Rust crate behind one wrapper holding all unsafe code, `py_ecc` for a second implementation in the Python reference, `zkryptium` only as a comparison.
- The conservative sampler rule (rational σ_r, no floating point).
- The library table in `docs/DECISIONS.md` (OpenMLS, hpke-rs, argon2, privacypass, OpenDP, wasmtime, parquet and their Python counterparts).
- Decision records 0103, 0104 and 0107 as recommended; the two-phone shield risk accepted and disclosed; a context's first log frozen; a context relay limited to chat, files and log reads.

## Disagreement tail closed by W0-11

Items 20, 26–29 and 31–33 in `docs/specs/conformance.md` are resolved. R5/R6 now give one answer for rating unlocks and counts; the rating-at-400 vector claims manifest coverage only. L-6 fixes field domains and validates encodings and required maps. V-4 fixes the failure rule without prescribing the reference's diagnostic; O-6 separates protocol behavior from deterministic fixture choices.

The chat review found two behavioral fixes, not just wording: record reuse stops before age 3,600 seconds, and pruning/snapshot omission cannot retrospectively turn an established admission into a missing-record removal. Initial Adds and retries both follow the strict age boundary. The no-record fetch threshold includes exactly 600 seconds. Reference code and generated vectors follow the reviewed text.

Unclosed work is the owner decisions and coverage gaps below; this closeout does not claim live BBS, HPKE, MLS or Parquet conformance.

## Before merging to `main`

Use `docs/handoff/wave-0-review-guide.md` for the ordered seam sections with current line numbers and every owner question with a recommendation. The owner reviews the seam diffs. Start with rule C16 in `docs/specs/context.md`, "Validity" in `docs/specs/credentials.md`, "Window" in `docs/specs/shield.md`, relay rule O-6 and evidence rule V-4 in `docs/specs/services.md`, and section 2.5 of `docs/specs/chat.md`. Two points the owner should see: the relay rule ended narrower than the option chosen (ballots, every aggregator request and every log submission use shipped relays only), and draft 0.1 lost the policies listed in `cross-spec.md` section 12.7.

## Decisions still waiting on the owner

The review guide presents these as numbered questions with recommendations. Unanswered decisions remain open; accepted decisions and the Open section in `docs/DECISIONS.md` are unchanged.

- **Privacy targets.** ε 4 per release and ε 20 per year are placeholders. The rating-deck budget depends on them.
- **Receipt clamp δ** (record 0102 items 2 and 3). Adopting it changes every reported ε.
- **Outside cryptography reviewer.** Scope so far: records 0022 and 0026, the BBS crate and its `blst` wrapper.
- **One chat identity per resident card** (`chat.md` open question 16) and **whether a context can forbid agents**.
- **`docs/design.md` edits.** The list is in `cross-spec.md` section 10. The specs win where they differ.
- **Operator, Helper, relay and witness operators, hosting, licenses, first contexts.**
- Remaining parts of record 0105 (signature convention, media types) and the retired and successor markers in `manifest.md`.
- `sessionCap` counting for verifier profiles without a device item.

## Not done, by design

- **Vectors that need a library.** BBS proofs (in-house over `py_ecc`, not started), HPKE-sealed formats (`pyhpke`; exact info and aad bytes are generated, the seals are not), Parquet tables and release rule R15 (`pyarrow`), verifier-runtime rules (`wasmtime-py`), 14 chat sets that need MLS (`mls-rs` through its uniffi bindings), Privacy Pass tokens, phase 2 reports. All libraries are approved.
- **`just sim-full`** has never completed. The simulator models no release rounds, receipts, issuer epochs, relays or daily count. Its new relay and card-field checks are exercised by unit fixtures only.
- **An Android build of `blst`** through uniffi.
- Six response bodies in `services.md` (log proof, gallery) are marked provisional.

## What this session learned the hard way

- **Verify relayed claims.** Agents reported green gates that were not green, and fixes that had not landed. Re-run the gate and read the spec text.
- **Reviews find real problems late.** The yearly shield bound was broken three separate ways after its first fix, and evidence binding twice. Send every applied decision through the spec-reviewer, then send the fix through it again.
- **Do not gate a moving tree.** Ask the reference author to freeze before running `just check`; a mid-edit run fails the conformance diff.
- **Session limits kill agents silently.** Ask for a return to green after each step.
- **The reference test suite takes about 24 minutes.** Run `just check` in the background.
- **After any spec change, tell the reference author the byte-level changes explicitly.** Each round of spec fixes produced a few new labelling disagreements; expect a short tail.
