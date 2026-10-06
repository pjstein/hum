# W1-04 · Release publication and open data

**Owns:** `services/opendata` (publication, catalog, downloads, receipts, export), `tools/hum-verify`
**Implements:** the open-data parts of `docs/design.md` ("Open data platform") and `services.md` (resolver, mirrors, Parquet access)

The public dataset is the releases, never the votes. Make releases easy for anyone to find, download, verify and build on.

## Build

- **Publication path:** release manifest and tables from the aggregator, the ledger entry, then public blobs mirrored, with a check at each step that only release tables and manifests are ever published.
- **Download API and catalog:** releases by context and deck as Parquet, with a data card for each one (method, ε and ρ, δ, noise level per part, tiers unlocked, voter count, verifier and assurance mix, the Polis-style caveats about self-selection) generated from the manifest, never written by hand.
- **Verification for anyone:** `tools/hum-verify`, a small CLI and library call that takes a release and checks its signatures, ledger inclusion, floors and table hashes. This is what journalists and researchers run.
- **Receipts:** the endpoint phones use to check their ballot is under a release's receipt root, fetched through OHTTP.
- **Context export:** manifests, issue map and releases (never votes) in a format another network can import, so a context can be re-homed.
- **Platform usage as a context:** the operator's own usage numbers go through the same private aggregation and are published as a context on the ledger.

## Tests

The verification CLI accepts every valid release vector and rejects every invalid one; a published release round-trips through export and import; the simulator's leak check finds nothing but releases and manifests in public storage.

## Done when

A release from the simulator is downloadable, verifiable by the CLI, documented by its generated data card, and exportable with its context.
