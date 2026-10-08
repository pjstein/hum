# 0012 · The organizer's daily count is a noised series of daily increments inside the deck's budget

**Status:** proposed (W0-01, 2026-10-06) · `seam:` DP budget accounting

## Context

Organizers need to know roughly how many people have played an open deck, and the design doc says nobody may watch one person vote. A running count re-read every day would charge once per day.

## Decision

- The aggregator buckets first ballots per voting pseudonym by UTC day since `opens` and noises each day's increment once, at the end of that day. The organizer sees the increments and their running sum. A person is in exactly one bucket, so the whole series is one sum with L2 sensitivity 1.
- The budget is a part (`count`, id 4) of the deck's release plan, at most `count.rhoMax` from the context (default 1/200, σ = 10 ballots per day). It is inside the plan's total, so inside the context floor and the shield charge.
- The series is included in the release as the `count` table so the spend is auditable, and it is what the plan's `absorb` option uses to decide the map tier before any tallies noise is drawn.

## Consequences

- A plan without part 4 gives organizers no count.
- `services.md` asks whether the series should simply be public. Under this decision it becomes public at release time; publishing it live is a one-line change if the owner wants it.
- Reading a timestamp finer than a day would need a different mechanism; the aggregator rounds request logs to the minute anyway (`services.md`).
