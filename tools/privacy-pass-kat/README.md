# RFC 9578 library feasibility probe

Run `cargo test --manifest-path tools/privacy-pass-kat/Cargo.toml --locked`.
The isolated workspace pins the owner-approved `privacypass` 0.2.0-pre.3;
its test-only interfaces supply RFC randomness. It is not a production service.

Two tests execute all five Appendix A (P384 VOPRF/type 1) and all five Appendix B
(RSA/type 2) fixtures from the reference's pinned RFC dataset. They compare request
and final token bytes, compare type-2 response bytes, verify the published type-1
DLEQ response, exercise fresh type-1 issuance, redeem, and reject double spending.
A corrupted type-1 DLEQ proof fails finalization. The library supplies all primitives.

These tests establish library capability and independent published known answers.
They do not implement Hum T-1 to T-4, delivery issuer-key derivation from the DS master secret/group ID, key gossip,
context binding, durable atomic nonce storage, service admission, or Python bindings.
The Python reference independently verifies type-2 RSA signatures and frames both
types; it does not implement type-1 OPRF issuance. All fixture keys are public test keys.

The root Cargo workspace and `just check` do not run this isolated probe. Its
lockfile is committed; build output remains ignored.
