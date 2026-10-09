# Wave 0 handoff

Updated 2026-10-09. Read this before continuing wave 0 or starting wave 1.

## State in one paragraph

Wave 0 is written, reviewed, and committed on branch `wave-0/contracts`. Nothing is pushed or merged. On the last commit the orchestrator ran the gates itself: `just check` exited 0 with 284 reference tests and 898 accepting plus 825 rejecting vectors, and `just sim-fast` passed 5 scenarios with 4 adversarial hooks pending. The working tree is clean. No agent is running.

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

## Remaining small work, first task for the next session

`docs/specs/conformance.md`, "Disagreements", lists what the reference could not settle from the spec text. None is a security issue. Each needs a one-line answer from the spec, then a vector relabel.

- 28: `release.md` R6 says parts 1 to 3 unlock on the part's own `n`, but a rating deck's part 3 unlocks with part 0.
- 29: the rating release at nHat 400 has no vector id in `release.md`.
- 31: `services.md` V-4 is one rule for every way evidence fails to open; the detail string is the reference's.
- 32: `services.md` O-6 does not fix the order of the relay set or the random stream; the vectors use a reference device.
- 33: `chat.md` section 2.5: "pending" by receive time against order by sequence; 600 s "past" against "at least".
- Remainders under 20 (R5 below the minimum), 26 (log-line field domains the L-6 table leaves open) and 27 (whether an expired join-record still counts for the no-record backstop).

Fix the spec text, have the reference follow, run `just check`, commit.

## Before merging to `main`

The owner reviews the seam diffs. Start with rule C16 in `docs/specs/context.md`, "Validity" in `docs/specs/credentials.md`, "Window" in `docs/specs/shield.md`, relay rule O-6 and evidence rule V-4 in `docs/specs/services.md`, and section 2.5 of `docs/specs/chat.md`. Two points the owner should see: the relay rule ended narrower than the option chosen (ballots, every aggregator request and every log submission use shipped relays only), and draft 0.1 lost the policies listed in `cross-spec.md` section 12.7.

## Decisions still waiting on the owner

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
