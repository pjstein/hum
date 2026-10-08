# sim

The headless simulator: a world of simulated phones running the whole ratchet
through the core crates and services, in-process. The design is
`docs/specs/simulator.md`; this file is the quick start.

**Owner:** W0-09 designed it and built the skeleton; W1-13 platform owns the
harness wiring; W2-01 owns the full-ratchet scenarios once wave 1 has plugged
its real components in behind the ports in `src/ports.rs`.

```
just sim-fast                      # per-commit suite, offline, a few seconds
just sim-full                      # nightly suite on the synthetic fixture
HUM_POLIS_DATA=/path/to/openData just sim-full     # plus the four research conversations
cargo run -p hum-sim -- replay --size 800 --eps 4 --seeds 3 \
    --polis /path/to/openData --conversation vtaiwan.uberx
cargo run -p hum-sim -- fixture --out /tmp/hum-fixture --size 1000
cargo run -p hum-sim -- help
```

Reports land in `target/sim/<mode>.json`; the same table prints to stdout.
Exit code 0 is a pass, 2 a failed gate, violation or leak, 1 an error.

Polis open data is CC BY 4.0 from <https://github.com/compdemocracy/openData>
and is not vendored: `git clone --depth 1` it anywhere and point `--polis` or
`HUM_POLIS_DATA` at it. Without it the simulator runs its seeded synthetic
fixture, which is labelled as such in every report.

Layout:

| Path | What |
| --- | --- |
| `src/world.rs` | The world: phones, contexts, decks, services, the ratchet's flows, the protocol oracles |
| `src/phone.rs` | A simulated phone: identities, per-deck nullifiers, hand, shield state machine, floors, restore from backup, phone-side group placement |
| `src/ports.rs` | The service traits wave 1 implements, the sim-side object shapes, the tape |
| `src/fakes/` | Wave 0 stand-ins behind each port |
| `src/pipeline/` | Port of `docs/research/dp-polis/polis_dp.py`: the oracle and the fake aggregator's math |
| `src/data/` | Vote matrix, Polis loader, synthetic fixture |
| `src/leak.rs` | The leak checker over the tape |
| `src/scenario.rs`, `src/thresholds.rs`, `src/report.rs`, `src/cli.rs` | Suites, gates, reports, command line |

Nothing here is product code. The fakes use floating-point noise and a
non-cryptographic hash on purpose; neither may move into `core/` or `services/`.
