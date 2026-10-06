# sim

The headless simulator: a world of simulated phones running the whole ratchet
through the real core crates and services, in-process.

**Owner:** W0-09 designs it and builds the skeleton (`docs/specs/simulator.md`);
W1-13 platform owns the harness wiring; W2-01 owns the full-ratchet scenarios.

`just sim-fast` runs the under-a-minute mode on every commit. `just sim-full`
runs every size and seed nightly. For now the binary prints `no scenarios yet`.
