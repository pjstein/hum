# Privacy Pass library bridge and policy reference

`cargo test --manifest-path tools/privacy-pass-kat/Cargo.toml --locked` runs the
five published RFC 9578 P384 and five RSA issuance/finalization known answers.
The isolated workspace pins approved `privacypass` 0.2.0-pre.3 and its existing
lockfile. All fixture private keys and deterministic randomness are public test
material, never production keys.

`reference/.venv/bin/pytest -q reference/tests/test_token_policy.py` executes the
JSON-lines Rust bridge from Python. `privacy_pass_adapter.prepare_bridge()` is an
explicit preparation entry point; first use builds with `--locked` only if the
source/lock/fixture fingerprint differs. Subsequent processes reuse the binary.
No root Cargo dependency was added. A Rust toolchain is required on first build.

The bridge operations are `challenge`, `derive`, `private_issue`, `verify`,
`validate_request`, `public_issue`, and `public_fixture`. Bytes are hex JSON fields;
responses contain `ok` or `error`. Private issuance accepts seed/info or public RFC
secret_key, challenge, nonce, blind, pinned_public and optional response. Public
issuance accepts the RFC-shaped skI (hex PEM), pkI (hex SPKI), token_challenge,
nonce, salt and blind. These explicit randomness interfaces are reference/test
interfaces. All OPRF and blind RSA operations use the pinned library. Random DLEQ
proof bytes are omitted from generated outputs; finalized tokens remain exact.

The Python policy layer derives channel seeds through cryptography HKDF-Expand
and library RFC9497 key derivation. It binds current context/accepted authority,
full issuer key and fixed empty-context/origin challenge, pins the directory or
all-members/organizers issuerKeys before request/finalization, enforces separate
issuance/spend connection handles, and atomically records full key ID+nonce with a
SQLite unique constraint. Tests race 16 independent connections and reopen the
database. Rejected authentication/policy checks do not consume valid nonces.
Type 2 issuance is callable with synthetic inputs, followed by actual RSA-PSS
verification and the same persistent service policy. Channel request validation
uses library point decoding, accepts any currently held secret, and returns its
index so the caller records use. Fetch-only random cookies expire at 900 seconds
from first redemption, without extending on use. Request entry points purge expired
cookies, and the service must call `FetchSessions.expire(now=trusted_clock)`
periodically while idle to implement forgetting even without later fetches.
Nonfinite, nonnumeric and boolean session clocks are rejected before token spend.

Externally verified context/directory inputs and actual relay connection identity
remain caller boundaries. P4 membership proof verification is not implemented or
simulated by a boolean. Secret lifecycle tracking, key gossip, and precise
context/key rotation expiry remain external; the ledger intentionally does not
invent pruning times or claim 48-hour expiry enforcement. No network service,
production key management, or end-to-end anonymous issuance is claimed.
