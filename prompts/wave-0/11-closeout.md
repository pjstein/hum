# W0-11 · Finish wave 0 and prepare the merge

Wave 0 is committed on branch `wave-0/contracts` with green gates. A short tail of spec wording questions remains, then the owner reviews and merges. Do not start wave 1.

## Read first

- `CLAUDE.md`
- `docs/handoff/wave-0-closeout.md`
- `docs/specs/conformance.md`, "Disagreements" and "Gaps"
- `docs/DECISIONS.md`, the two "Accepted by the owner" sections and "Open"

## Do, in this order

1. **Measure.** Run `git status`, `just check` and `just sim-fast`. The reference suite takes about 24 minutes; run it in the background.
2. **Close the disagreement tail.** For each open item in `conformance.md` (28, 29, 31, 32, 33 and the remainders under 20, 26, 27), fix the spec text so it gives one answer, have the reference and vectors follow, and close the item. If a fix changes behaviour, bytes or a security property, send it through the `spec-reviewer` subagent first.
3. **Verify yourself.** `just check` exits 0 and `just sim-fast` passes. Report the actual output. Commit.
4. **Bring the owner the open decisions** from the handoff as questions with a recommended option. Apply only what they answer.
5. **Prepare the merge.** Write a short review guide for the owner: the seam sections to read in order, with file paths and line numbers, and what each one changed. Do not merge or push.
6. **If the owner asks to go further,** the next useful work is the vector gaps the approved libraries unblock, starting with the Python BBS implementation over `py_ecc` and the HPKE seals.

## Rules

- Do not edit `CLAUDE.md` or `docs/design.md` without showing the owner the exact wording first.
- Decisions in "Open" in `docs/DECISIONS.md` are the owner's.
- Never hand-edit `vectors/`. Ask the reference author to freeze before you gate.
- Verify every relayed claim: re-run the gate and read the text.

## Report

- The gate output.
- What you closed, and anything you could not.
- Each open owner decision with your recommendation.
- Whether wave 0 is ready to merge, and what wave 1 should start with.
