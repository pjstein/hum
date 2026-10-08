# 0105 · One rule for domain strings, signature domains, enumerations and media types

**Status:** item 1 (the rename) accepted by the owner 2026-10-07, as applied. Items 2 to 5 stay open · `seam:` signing, domain-separation strings, exporter labels, canonical encoding

*2026-10-07:* The owner accepted the rename. Previous status: item 1 (the rename) Applied 2026-10-06 on the owner's go-ahead; seam, pending owner review of the diff (W0-10). Items 2 to 5 stay open.

## Context

The registry in `services.md` ("Domain strings and scopes") now matches every spec on disk: 46 strings, none equal, none a prefix of another. Four naming questions were left for the cross-spec pass.

1. **Three strings were outside `hum/`** (renamed on 2026-10-06; the old names are quoted in this ADR on purpose). `manifest/1` (COSE external AAD for every manifest signature), `keyring/1` and `delivery/1` (MLS exporter labels). Everything else is `hum/<name>/<version>`.
2. **COSE signatures place the domain string in two ways.** Manifests and signed service requests put it in `external_aad` and sign a detached payload that is a CID or a hash (ADR 0082, `services.md` A-2). The chat `roles` signature (`chat.md` §5.8) and the context delete order (`storage.md` §8.2) put the string at the front of the detached payload and do not say what `external_aad` is. `storage.md` says "exactly as manifests are signed", which reads as the first way. The reference implements the second with an empty `external_aad`.
3. **Enumerations are encoded two ways.** `context.md`, `deck.md`, `release.md`, `issue-map.md`, `take.md`, `agent-sponsor.md` and `chat.md` use uints. `verifier.md` (`profile`, `class`, `alg`, attribute `type`, `exposure`, `status`, evidence `kind`, `schema`, `storedAs`, dedup `method`, revocation `method`), `trust-list.md` (`scope.kind`, `classes`, removal `reason`) and `services.md` (`kind`) use text.
4. **Media types follow no single pattern.** Most are `application/vnd.hum.<name>`. The take text blob is `application/hum-take+cbor`. Receipt pages, the receipt root blob, a verifier's `code`, `build` and dataset blobs and an attestation report have no declared type. The reference store's default `formats.public` list (`storage.md` §7) lacks the take type, so a store with defaults refuses a take's text blob.

## Decision (proposed)

1. **Namespace the three strings now:** `hum/manifest/1`, `hum/keyring/1`, `hum/delivery/1`. Cost today: three constants in `reference/`, one `just vectors` run (every signed bundle and the keyring exporter vector change bytes), and text edits in `manifest.md` (four places), `chat.md` §1.2 and its table, `storage.md` §4.1 and §4.4, the registry in `services.md`, the "Adopted" line in `DECISIONS.md`, and ADRs 0050, 0060 and 0082. No Rust, Go or app code signs anything yet. Cost after wave 1: every implementation and every logged manifest. Benefit: one rule, "every Hum domain string starts with `hum/`", which a lint can check; and no shared prefix with another protocol that might use `manifest/1` under the same Ed25519 keys. If the owner prefers not to touch an adopted string, keep `manifest/1` and rename only the two exporter labels, which no adopted line fixes.
2. **One COSE convention:** the domain string is always the `external_aad`, and the detached payload is always a CID or a SHA-256. `roles` signs payload `SHA-256(keys 0 to 6)` with `external_aad` `hum/chat-roles/1`; a delete order signs payload `SHA-256(order)` with `external_aad` `hum/blob-delete/1`. The alternative is to keep the prefix form and state `external_aad` = empty in both specs. Either way both specs must say it.
3. **Enumerations:** leave text enumerations in `verifier`, `trust-list` and `service` bodies for draft 0.1, because the phone shows these manifests to people and the reference already encodes them, and write the rule in `context.md` "Conventions": new body fields use uints; the three listed types are the exceptions. The alternative is to convert them now at the cost of regenerating those vectors.
4. **Media types:** every Hum-defined type is `application/vnd.hum.<name>[+cbor]`. Rename the take blob to `application/vnd.hum.take+cbor`. Assign `application/vnd.hum.receipt-page` (concatenated 32-byte leaves), `application/vnd.hum.receipt-root+cbor`, `application/wasm` for `code`, `application/cbor` for `build` and dataset blobs, `application/octet-stream` for attestation reports. Add all of them to the store's default `formats.public`.
5. **Registry rules:** no string is a prefix of another; a version suffix is a single decimal digit until a draft says otherwise, so `…/1` can never be a prefix of `…/10`; the registry lists every string before it is used, with HPKE export labels and HTTP header names.

## Consequences

- Items 1, 2 and 4 change bytes that only `reference/` and `vectors/` hold today. They are cheap this week and expensive after wave 1 starts.
- `manifest.md` edits are listed in ADR 0106.
