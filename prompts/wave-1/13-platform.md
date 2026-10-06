# W1-13 · Platform

**Owns:** CI, `tools/`, `sim/` harness wiring (with W0-09's design), build and release infrastructure, `docs/ops/`

Keep the gates fast and trustworthy for a dozen parallel workstreams, and make Hum shippable and checkable.

## Build

- **CI:** `just check` and `just sim-fast` on every PR in under about 15 minutes, with caching; `just sim-full`, fuzzing and dependency audits nightly. Flaky tests get fixed or quarantined with an owner, never retried silently.
- **Dependency policy:** `cargo-deny` and `cargo-vet` (or equivalents) for Rust, `govulncheck` for Go, and an allowlist for dependencies in seam crates.
- **Fuzzing:** targets for every parser (CBOR, bundles, proofs, sealed blobs, MLS content, ballots) running nightly, with a corpus in the repo.
- **Logging policy as code:** a lint or test that fails if services log fields the threat model forbids (ballot contents, nullifiers next to anything identifying, keys, member identifiers), plus the simulator's leak check in CI.
- **Reproducible builds:** for the services and the Rust core first, then as far as each app store allows; publish build hashes so they can go on the ledger, as the design doc plans.
- **Release signing and key handling** for the reference network's own authorities (operator, aggregators, ledger), written up in `docs/ops/keys.md` with thresholds that match the manifest spec.
- **A local reference network:** one command that brings up the ledger, two witnesses, the aggregator, issuer, verifier host, delivery service, blob store, relay and gallery, so the apps can run end to end on a laptop.
- **Deployment plan:** hosting is an open decision. Write `docs/ops/deploy.md` with the options, the operational and privacy requirements (no IP logging behind the relay, retention limits, subpoena posture), and what each choice implies. Don't deploy anything public.

## Done when

The gates are fast and green, nightly jobs run, the local network comes up with one command, and the ops docs exist for the owner's decisions.
