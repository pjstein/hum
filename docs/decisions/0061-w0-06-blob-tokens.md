# 0061 · Blob-store tokens: publicly verifiable Privacy Pass with one issuer key per context

**Status:** proposed (W0-06, 2026-10-06)

## Context

Every blob-store request carries an anonymous token issued against a context membership proof (`docs/specs/manifest.md`, "Store protocol"). The store must know which context a request counts against, but never which member. Privacy Pass (RFC 9576–9578) tokens carry no public metadata, so the context has to be encoded some other way.

## Decision

- **Token type `0x0002`** (RFC 9578, publicly verifiable, blind RSA per RFC 9474, 2048-bit). The store verifies with the issuer's public key, so the issuer may be the store or a separate operator-run issuer, as `services.md` rule T-3 expects. A separate issuer means the store never sees a membership proof. An earlier draft of this ADR chose type `0x0001`; it was changed to match `services.md` and to allow a separate issuer.
- **One issuance key per context.** The `token_key_id` tells the store which context's quota to charge. The context is identified by the key, not by token metadata, so no draft extension is needed. Keys rotate at most every 30 days and are published in the RFC 9578 issuer directory.
- **Key consistency is checked by members.** Phones post the current `token_key_id` in the all-members channel, as they already do for log checkpoints. A phone whose key differs from its peers stops using the store and warns.
- **Fixed TokenChallenge** (empty redemption context and origin info), built by the phone from the `blob-store` manifest, so tokens are issued in advance and one token fits any request. Tokens are single-use; the store keeps redeemed nonces per key.
- **Issuance is the rate limit.** The membership proof is scoped per `token_key_id` and day so the store can cap tokens per pseudonym per day without identity. Up to 64 RFC 9578 TokenRequests travel in one issuance call, as a Hum extension, until the IETF batched-tokens work can replace it.
- **Public blob GETs need no token,** so anyone can mirror them.

See `docs/specs/storage.md` §6.1–6.2.

## Consequences

- The store learns the context of every sealed request, and nothing more. This matches the design doc's who-sees-what table.
- Depends on W0-02 providing a scoped per-context membership proof. The fallback (an all-members exporter secret presented as a MAC) proves membership but cannot limit per member.
- An issuer that gave a unique key to one member could track them; the channel check is the defense, and it needs `chat.md` to carry the gossip message.
- `services.md` rule T-2 assumes the context travels in public metadata. The cross-spec pass should pick one approach for the store and the delivery service; open question 3 in `storage.md`.
- 2048-bit blind RSA keygen per context per month is cheap for an issuer; tokens are 256 bytes larger than VOPRF tokens, which is irrelevant at one token per request.
