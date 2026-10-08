# 0072 · A `service` manifest type with a `kind` field

**Status:** proposed (W0-07, 2026-10-06; aligned with W0-06 the same day)

## Context

The manifest spec registers `blob-store` as a type and asks, in its open questions, whether delivery services and blob stores should share one type since both are named by key and see only ciphertext. `services.md` needs the same thing for logs, witnesses, aggregators, issuers, resolvers, gateways and the gallery: a signed, logged object that says where a service is and what keys it uses, so phones never take an endpoint or an OHTTP key configuration from an unsigned source.

## Decision

Add one registry type, **`service`**, with a `kind` field: `log`, `witness`, `aggregator`, `issuer`, `delivery`, `blob-store`, `resolver`, `gateway`, `gallery`.

- Common fields use keys 0 to 15: `kind`, `endpoints`, `apiVersion`, `ohttp`, `tokenIssuers`, `limits`, `witnesses` and `origin` (logs), `jurisdiction`, `retention`, `hpke` (aggregators), `stamp` (delivery). The table and rules S-1 to S-4 are in `services.md`.
- Kind-specific fields start at key 16 and are defined by the spec that owns the service. `storage.md §7` defines the blob store's: `issuer`, `blobLimits`, `blobRetention`, `formats`.
- The registry row `blob-store` becomes `service` with `kind: blob-store`. Until the manifest spec's owner updates the registry, clients accept either type name for a store.

## Why

- Every service needs the same handful of fields, and a phone verifies them the same way.
- One type means one validation path and one set of vectors for "where is this service and what key does it use."
- The OHTTP gateway key must come from a logged manifest (`services.md` rule O-2); without a `service` type there is nowhere signed to put it.
- Splitting the key space at 16 lets each owning spec evolve its fields without touching the common table.

## Consequences

- 2026-10-06: `manifest.md`'s type registry now lists `service` and retires `blob-store`, so the "accept either type name" allowance above has ended. `services.md` is current on kinds: it has `relay`, and no `gateway` kind or `stamp` field.

- The type registry in `manifest.md` gains one row and retires one. That edit belongs to the manifest spec's owner.
- `context.md` names aggregator, log and store authorities by CID as before; the `service` manifest is what a phone resolves those authorities to for endpoints.
- `storage.md`'s open question about one type for stores and delivery services is answered: the delivery service is `service` with `kind: delivery`.
- W0-10's cross-spec review checks that no kind-specific field uses a key below 16.
