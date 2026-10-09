# 0111 · Wave 0 closeout clarifications

**Status:** adopted in the specs under W0-11; independently reviewed, pending owner seam review before merge. This is not an owner acceptance of any open decision.

`seam:` admission/nullifiers, release validation, logging, relay selection and evidence binding.

## Context

The closeout prompt asks the specs and reference to give one answer for conformance disagreements 20, 26–29 and 31–33. Most are wording or coverage issues. Review also found an inclusive admission deadline overlapping another greeter's pending interval, and a no-record backstop that could mistake pruned historical evidence for a missing admission record.

## Decision

- Rating part 3 unlocks with part 0. It retains a required noised `n`, which does not gate the unlock. Recorded parts 0–3 require integer, non-boolean `n` when `nHat` is present. Below the minimum, no `groupsK` is compared or published. Name the rating-at-400 manifest vector without claiming Parquet-cell coverage.
- A greeter may use its admission record only before age 3,600 seconds, for an initial Add or retry. At the boundary it sends and sequences a fresh record and repeats the check. Sequence numbers order records; delivery receive times measure age. The no-record fetch boundary remains inclusive at 600 seconds.
- Expired records cannot trigger duplicate-nullifier removal and are omitted from snapshots. The no-record backstop only applies to Adds observed after acquiring current membership state and an organizers snapshot. A record naming the joining identity establishes existence for that Add even if expired; later pruning cannot revoke that observation. Historical snapshot omissions never justify retrospective removal. The broader identity policy stays the owner's question.
- L-6 fixes logging field domains and enforces the existing exact host schema and resolver count shape. Host days remain integer `time.day`; true rejection outcomes cover 0–999, as the runtime already specifies. Invalid hexadecimal encodings, invalid dates, wrong enum types and incomplete required maps reject. Structural permission does not override privacy, retention or noised-value provenance.
- Every evidence-open failure ends the session with `rejected`, rule V-4, and no issuance. A particular diagnostic detail is not required. Relay eligibility, uniform selection, retry and no direct fallback are normative; deterministic picker ordering, labels and draws are reference fixtures. Shipped relay authorities are distinct and context relay lists have passed C7; overlap between the lists counts once.

## Consequences and verification

Reference changes and generated vectors follow the spec text; no vectors are hand edited and no dependency is added. New rating rejection bundles also change the generated worlds' checkpoints and inclusion proofs. No production primitive or MLS implementation is supplied by this closeout.

Review findings and final verdict are in `docs/specs/reviews/wave-0-closeout.md`; actual full gate results are recorded in `docs/handoff/wave-0-closeout.md`. The owner questions and seam reading order are in `docs/handoff/wave-0-review-guide.md`.

The accepted decisions and the Open section in `docs/DECISIONS.md` remain unchanged. `CLAUDE.md` and `docs/design.md` remain unchanged. Wave 1 is not started.
