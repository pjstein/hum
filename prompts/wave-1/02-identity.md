# W1-02 · Identity: credentials, pseudonyms and verifiers

**Owns:** `core/crates/hum-cred`, `services/issuer`, `services/verifier-host`
**Implements:** `docs/specs/credentials.md`, `verifier.md`, `trust-list.md`, `verifier-runtime.md`, and the issuer and verifier-host parts of `services.md`

## Build

- **`hum-cred`:** BBS credentials with blind issuance and selective disclosure; the per-context pseudonym and nullifier scheme the owner approved in wave 0; policy presentations; the chat-name credential handoff to `hum-chat`; agent sponsor credentials that no voting policy accepts. Evaluate existing BBS implementations against the draft's own test vectors before using one. If none pass, stop and report rather than writing the primitives yourself.
- **`services/issuer`:** issuance, re-issuance on a schedule, revocation (as the spec chose), and evidence handling that keeps only what the verifier manifest declares, for only as long as it declares.
- **`services/verifier-host`:** runs custom verifier code in the WebAssembly sandbox the runtime spec defines (wasmtime is the likely host), with its resource limits and host interface, and checks the running module's hash against the verifier manifest.
- **The first verifiers:** invite, approved list, district, age band and uniqueness, each with its verifier manifest. The district verifier's evidence source is an open question; build it behind an interface with test fixtures and file what it needs.

## Tests

Draft vectors for BBS and pseudonyms, Hum's own vectors, unlinkability tests (two contexts' presentations by one person can't be matched; the issuer can't match issuance to presentation), and the simulator's over-collecting verifier hook.

## Seams

All of `hum-cred`, nullifier handling, and the sandbox boundary.

## Done when

Phones in the simulator get resident cards, join contexts through policy presentations with real nullifiers, and a custom verifier module written by a "context admin" in a test runs sandboxed end to end.
