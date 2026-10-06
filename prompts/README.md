# Hum prompts

Prompts for building Hum with Claude Code, one per task, in three waves. Every session in this repo also loads `CLAUDE.md`, so the prompts don't repeat the invariants, the seams or the workflow rules.

| Step | Prompts | Runs | Done when |
| --- | --- | --- | --- |
| Bootstrap | `00-bootstrap.md` | Once, alone | The skeleton builds and `just check` passes |
| Wave 0: contracts | `wave-0/01`–`09` in parallel, then `wave-0/10` | Parallel | You've approved every spec, `vectors/` is generated, `just sim-fast` runs |
| Wave 1: build | `wave-1/01`–`13` | Parallel | Each workstream passes conformance and the simulator |
| Wave 2: integrate and attack | `wave-2/01`–`06` | Mostly parallel | The whole ratchet runs in the simulator, red-team findings are fixed or accepted, the audit package is ready |

Each wave also has an `00-orchestrate.md` that fans the wave out from one session.

## Running a prompt

From the repo root:

```bash
claude "Read prompts/wave-0/01-context-deck-release.md and carry it out."
```

## Running a wave in parallel

**Option A, one session fans out.** Run the wave's `00-orchestrate.md`. It launches one subagent per prompt and collects their summaries. You can also ask Claude Code to "use a workflow" for it.

**Option B, separate sessions in git worktrees.** This is better for wave 1, where workstreams edit code for hours:

```bash
git worktree add ../hum-w1-02 -b w1/identity
cd ../hum-w1-02 && claude "Read prompts/wave-1/02-identity.md and carry it out."
```

Merge each branch when its gates pass and you've reviewed any `seam:` changes.

## Your part

- **Wave 0:** approve each spec (merge it), and answer the questions specs raise in `docs/decisions/`.
- **Every wave:** review anything marked `seam:` before it merges.
- **Before real people use it:** the open decisions in `docs/DECISIONS.md`, and the outside cryptography review.

## Reviewer subagents

`prompts/agents/` defines two subagents the prompts call on. The bootstrap installs them into `.claude/agents/`, where Claude Code finds them:

- `spec-reviewer` reads a spec adversarially against the invariants and the other specs.
- `seam-reviewer` reviews a change that touches a security seam.
