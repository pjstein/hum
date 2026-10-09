# W0-11 · Close out wave 0

Wave 0 is committed on branch `wave-0/contracts` with one more round of approved edits uncommitted in the working tree. Finish that round, verify it, and commit. Do not start wave 1.

## Read first

- `CLAUDE.md`
- `docs/handoff/wave-0-closeout.md` (the state, what was in flight, and the remaining steps)
- `docs/specs/reviews/cross-spec.md` section 12.9
- `docs/DECISIONS.md`, sections "Accepted by the owner on 2026-10-07" and "2026-10-08", and "Open"

## Do, in this order

1. **Measure.** Run `git status`, `just check` and `just sim-fast` and record the result. The reference suite takes about 22 minutes; run it in the background.
2. **Review.** If `docs/specs/reviews/applied-decisions.md` has no section "ADRs 0103, 0104, 0107", run the `spec-reviewer` subagent on the uncommitted spec diff with the checks listed in the handoff. Fix blockers and should-fix items in the specs, then re-review until no blocker is left.
3. **Simulator.** Make `sim/src/leak.rs` follow the allow table in `docs/specs/simulator.md`, with one failing fixture per new rule. Rust gates must pass.
4. **Reference and vectors.** Apply the byte-level changes and add the vectors listed in section 12.9. Update `docs/specs/conformance.md`. Any vector that disagrees with a spec is a bug in one of them: fix it or file it.
5. **Verify yourself.** `just check` exits 0 and `just sim-fast` passes. Report the actual output.
6. **Commit** on `wave-0/contracts`, one commit per concern, with `seam:` in the message where it applies. Do not push or merge.
7. **Library research.** If `docs/research/bls12-381-libraries.md` is missing, run the research described in the handoff and bring the owner a recommendation for the Rust crate and the Python reference.

## Rules

- Do not edit `CLAUDE.md` or `docs/design.md` without asking. The handoff lists the one `CLAUDE.md` sentence waiting on the owner.
- Decisions in "Open" in `docs/DECISIONS.md` are the owner's. Bring them as questions with a recommended option; do not apply them.
- Never hand-edit `vectors/`.
- Verify every relayed claim: re-run the gate and read the text.

## Report

- What was already done when you started, and what you did.
- The gate output.
- Each open owner decision, with your recommendation.
- Whether wave 0 is ready to merge, and what wave 1 should start with.
