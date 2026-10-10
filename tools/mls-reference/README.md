# Live MLS reference integration

Run `tools/mls-reference/run.sh` from any directory. It fetches mls-rs tag
`0.56.0`, verifies commit `8f1b43f447a792ff9307f1c2c7f54da63914870e`,
applies the small wrapper patch, installs the tracked upstream workspace lockfile,
builds the actual library and generated Python bindings, runs upstream tests,
and executes `profile_checks.py`. No whole upstream source tree is vendored.

Requirements: the repository's Rust toolchain, Python 3, Git and OpenSSL development
libraries. On Apple Silicon macOS, the script defaults `OPENSSL_DIR` to Homebrew's
`/opt/homebrew/opt/openssl@3`; override it for another installation. On Linux the
normal openssl-sys discovery applies. `HUM_MLS_SOURCE` overrides the isolated
checkout path (default `${TMPDIR:-/tmp}/hum-mls-rs-056`). The script refuses a
wrong source revision and an incompatible patch. Use a checkout dedicated to this
probe: its Cargo.lock is replaced with the tracked harness lockfile.

Results and bindings are generated under ignored `out/`. Reviewed result and
provenance snapshots are in `evidence/`. Random secrets and protocol bytes are
not recorded. These are live integration checks, not deterministic conformance
vectors, and they do not close the complete Hum chat profile.

The wrapper patch exposes MLS message serialization, application authenticated
data, the RFC exporter, an option to encrypt controls, and one opaque GroupInfo
extension. It uses existing mls-rs APIs; no primitive is implemented here.

The checks explicitly reproduce a known limitation: failed authentication of a
modified message consumes its receive generation, so the original message later
fails to decrypt. This observation is separate from the 26 successful primitive
checks. Do not use this harness result as production security approval.

See [findings and remaining profile work](../../docs/research/mls-reference-feasibility.md).
