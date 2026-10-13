# Live MLS reference integration

Run `tools/mls-reference/run.sh` from any directory. It fetches mls-rs tag
`0.56.0`, verifies commit `8f1b43f447a792ff9307f1c2c7f54da63914870e`,
applies the small wrapper patch, installs the tracked upstream workspace lockfile,
builds the actual library and generated Python bindings, runs upstream tests,
and executes `profile_checks.py` plus `transaction_checks.py`. No whole upstream source tree is vendored.

Requirements: the repository's Rust toolchain, Python 3, Git and OpenSSL development
libraries. On Apple Silicon macOS, the script defaults `OPENSSL_DIR` to Homebrew's
`/opt/homebrew/opt/openssl@3`; override it for another installation. On Linux the
normal openssl-sys discovery applies. `HUM_MLS_SOURCE` overrides the isolated
checkout path (default `${TMPDIR:-/tmp}/hum-mls-rs-056`). The script refuses a
wrong source revision and an incompatible patch. Use a checkout dedicated to this
probe: its Cargo.lock is replaced with the tracked harness lockfile.

Results and bindings are generated under ignored `out/`. Reviewed result and
provenance snapshots are in `evidence/`. The original live check output records no secrets; the explicitly marked
`fixtures/synthetic-replay.json` does contain public synthetic private keys and
complete test group state for exact replay. Never use it for a live group. These are live integration checks, not deterministic conformance
vectors, and they do not close the complete Hum chat profile.

The wrapper patch exposes MLS message serialization, application authenticated
data, the RFC exporter, an option to encrypt controls, and one opaque GroupInfo
extension. It uses existing mls-rs APIs; no primitive is implemented here.

The original checks explicitly reproduce a known limitation: failed authentication of a
modified message consumes its receive generation, so the original message later
fails to decrypt. This observation is separate from the 26 successful primitive
checks. A separate reviewed clone/process/publish wrapper now prevents failures from changing
accepted state. Twelve checks replay the captured fixture twice, covering current
and past-epoch storage, policy rejection, persistent replay protection, control
AAD, franking HMAC and Ed25519 stamps. The wrapper policy validates wire/AAD shape;
full roles, credentials, franking and log trust remain separate. Do not use this
harness result as production security approval.

To deliberately recapture synthetic replay input, after building run
`PYTHONPATH=tools/mls-reference/out/python python3 tools/mls-reference/transaction_checks.py --capture`.
Normal `run.sh` never recaptures it. Recapture changes random test bytes and needs
review of the new fixture and evidence. Python requires the repository-approved
`cryptography` dependency in addition to the standard library.

See [findings and remaining profile work](../../docs/research/mls-reference-feasibility.md).
