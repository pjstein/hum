# 0091 · Synthetic fixture, Polis data and the simulator's gates

**Status:** proposed (W0-09, 2026-10-06)

## Context

`just sim-fast` must run offline on every commit and report metrics within the
research results' range. The research ran on the Polis open data (CC BY 4.0,
about 370 MB), which is too large to vendor and which the repo should not
depend on fetching at merge time. The metrics are noisy per seed: at 800
voters and ε 4 the research's own per-run ARI ranged from 0.12 to 0.90.

## Decision

1. **Polis data is fetched, never vendored.** `sim full` and `sim replay`
   take `--polis DIR` or `HUM_POLIS_DATA`. The loader is a port of the
   research `load`. Reports name the conversation and the licence.
2. **A seeded synthetic fixture stands in for Polis in `sim fast`.** It is
   generated in memory (`sim/src/data/synthetic.rs`), so the repo carries no
   data and the run is deterministic. Its shape follows what mattered in the
   research: three uneven groups, a mix of consensus, divisive and noise
   statements, long-tailed votes per participant, and a skewed exposure curve
   so the 60 most-voted statements carry most votes. Every report labels it
   `synthetic`.
3. **Gates are per source, per tier and per ε.** Polis replays are gated
   against the research mean for the nearest size at or below `n`, with slack
   for seed spread (tally ≤ 1.5 × mean + 2 pp; common ground ≥ mean − 0.25;
   ARI ≥ mean − 0.45; representative ≥ mean − 0.35); a gate that would clamp
   to zero is skipped. The fixture has its own table, calibrated on
   2026-10-06 with the tallies blend off and recorded in
   `docs/specs/simulator.md`; its tally gate scales with σ from the ε 4 value
   and its ranking and group gates apply from ε 4 up. A gate applies only to
   a tier the design unlocks at that size. A (size, ε) pair with no gate is
   not run and is reported pending; ε 1 is out of both suites for that
   reason.
4. **Fast uses the mean over two seeds; full uses five.** The fast gates are
   set with headroom below the measured values so they are a tripwire for
   regressions in the pipeline or the world, not a measurement.

## How to recalibrate

Run `cargo run -p hum-sim -- replay --size N --eps 4 --seeds 5` on the
fixture after a deliberate change to the fixture, the pipeline's random-draw
order or the world, read the measured means, and set each synthetic gate
about 0.1 (or 2 pp) below them. Record the date and the measured values in the
spec's threshold table. Research gates are recomputed from
`docs/research/dp-polis/results/e2.csv` into `sim/src/thresholds.rs` only when
the research results change.

## Consequences

- The fixture is a little easier than real conversations on tallies and
  about the same on groups and rankings (ARI 0.52 vs 0.61 at 800 voters, ε 4,
  blend off). It is a regression tripwire; the nightly Polis replays are the
  evidence.
- Measured on 2026-10-06 at ε 4, blend off, cap on the phone: 11.8 pp and
  common ground 0.20 at 300; 9.6 pp, 0.40, ARI 0.52, representative 0.47 at
  800. The common-ground gate below 800 is 0.15, inside the research's
  0.14–0.20 at 200–400 voters. With the blend on the tallies were 8.1 and
  7.7 pp. Values at ε 2, 8 and 16 are to be recorded here after the next
  nightly.
- Gates on a two-seed mean are loose by construction; a real regression that
  moves ARI by 0.1 at 800 voters would not trip them. The pipeline's
  noiseless-agreement unit test and the Polis nightly carry that weight.
- `sim-full` without Polis data runs the fixture at every size and ε and
  passes; with it, the four research conversations are added.
