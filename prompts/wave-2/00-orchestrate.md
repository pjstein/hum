# W2-00 · Orchestrate wave 2 (integrate and attack)

Wave 2 connects everything and tries to break it before real people depend on it.

## Plan

1. Run `01-integration` first and keep it running: it owns the full-ratchet simulator scenarios everything else uses.
2. Once the full ratchet passes, run `02` to `05` in parallel. The red teams (`03`, `04`) report findings; they don't fix them. Route each finding to the owning wave-1 workstream as a task, and re-run the attack after the fix.
3. Run `06-audit-package` last, after findings are fixed or explicitly accepted by the owner.

## Report

Findings by severity with their status (open, fixed and re-tested, accepted with the owner's reason), the full-ratchet simulator's metrics across sizes, twin-implementation disagreements and how each was resolved in the spec, and the state of the audit package.
