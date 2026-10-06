# services

The reference network's server side. Every Rust service is a binary crate in
the root Cargo workspace; the ledger is a separate Go module.

| Directory | Language | Owner |
| --- | --- | --- |
| `aggregator` | Rust | W1-03 aggregation |
| `issuer` | Rust | W1-02 identity |
| `verifier-host` | Rust | W1-02 identity |
| `delivery` | Rust | W1-05 chat |
| `blob-store` | Rust | W1-06 storage |
| `opendata` | Rust | W1-04 publication and open data |
| `gallery` | Rust | W1-11 studio and gallery (ranking); W1-04 for the rest |
| `ledger` | Go (Tessera) | W1-01 manifests and logs |

Package names carry a `hum-` prefix (`hum-aggregator`) so they cannot collide
with crates.io names; the binaries keep the short names (`aggregator`).

Services are named by key in manifests, never by hostname. Nothing in here may
log a vote, a hand, a shield, a sealed-blob key, or anything that joins two of
the three identities.
