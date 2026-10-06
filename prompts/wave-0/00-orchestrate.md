# W0-00 · Orchestrate wave 0 (contracts)

You coordinate wave 0. The goal is a complete set of specs, a reference implementation that generates test vectors, and a simulator skeleton, so wave 1 can build every layer in parallel against fixed interfaces.

## Plan

1. Read `CLAUDE.md`, `docs/DECISIONS.md` and every prompt in `prompts/wave-0/`.
2. Launch one subagent per prompt `01` to `09`, in parallel. Give each its prompt file's path and tell it to follow that file and `CLAUDE.md`. Each prompt owns different files, so they can share a working tree; use worktree isolation if your tools offer it.
   - `08-reference-and-vectors` starts on the manifest spec right away and adds vectors for the other specs as they land. Re-run it after the others finish.
   - `09-simulator` can start immediately; it builds against the research code and stubs.
3. As each spec lands, run the `spec-reviewer` subagent on it.
4. When all drafts and reviews are in, run `prompts/wave-0/10-spec-review.md` for the cross-spec pass.
5. Report to the owner. Don't merge or approve anything yourself.

## Report

Return one summary with:

- each spec: its file, length, the reviewer's verdict, and its blockers;
- every question waiting on the owner, collected from `docs/decisions/` and the specs' open-question sections, grouped by the decision it blocks;
- vector coverage: which spec rules have passing and failing vectors, and which don't yet;
- the simulator's status;
- what you'd do first in wave 1, given what wave 0 found.
