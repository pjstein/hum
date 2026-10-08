# 0107 · Discovery fields and wire-format gaps between specs

**Status:** proposed (W0-10, 2026-10-06) · `seam:` what leaves the phone (relay and resolver discovery), canonical encoding

## Context

Gaps where one spec relies on a field or a format that no spec defines. Each needs a few lines from the named owner. None needs a design decision beyond the choices below.

**Discovery and federation**

1. `services.md` says a client "tries the resolvers its context names first" and that a context may name relays "in its manifest (requested of context.md as a `relays` field)". `context.md` has no resolver or relay field (body keys 0 to 19).
2. A phone's first request needs a relay endpoint, the reference log's endpoint and the log's OHTTP key configuration. `services.md` O-2 accepts a key configuration only from a logged `service` manifest, and the phone cannot read the log before it has one. The bootstrap constants list authority CIDs and witness keys only.

**Wire formats**

3. `services.md` writes its own request and response bodies with names (`{ leaf, signature }`, `{ taskIds, round0, … }`, `{ index, checkpoint, path }`, `{ root, k, pages }`, `{ sigma, buckets, total }`, `{ id, expires }`, `{ name, kid, ciphertext }`, `{ bundle, tables, pages }`) and says bodies are deterministic CBOR per `manifest.md`, where map keys are integers. No integer keys are assigned.
4. The receipt root blob ("lists `k` and the page CIDs") has no encoding. The receipt signature does not say which `sign` key of the aggregator's keyset made it.
5. Evidence bodies are HPKE-sealed to a host key with no stated `info`. `credentials.md` says the issuance request is sealed "exactly as evidence is" and gives `hum/issue/1 ‖ verifier authority CID`.
6. A verifier host's rejection code (0 to 999, `verifier-runtime.md`) has no field in the error map of `services.md`.
7. The `delivery` kind of the `service` manifest has no validation rules of its own. `storage.md` has BS-1 to BS-6 for stores. `chat.md` names the `limits` keys in prose only.
8. The bound message of a presentation is defined only in `credentials.md`'s uses table. `storage.md` §6.2, `chat.md` §12.3, `agent-sponsor.md` AS-8 and `verifier.md` (the `credential` evidence item) name the scope and not the bound message.

**Smaller disagreements**

9. `issue-map.md` describes a context field `unsignedWindow` and a constant `UNSIGNED_WINDOW_MIN`. `context.md` has neither and fixes the window as `AUTHOR_WINDOW`. `services.md` keeps the log's author counters for one window; `issue-map.md` says two.
10. `ballot.md` B1 answers `malformed` for a presentation over 8 KiB; `services.md` intake check 1 answers `too_large`.
11. `release.md` says the aggregator's logs round counts "as `services.md` requires". `services.md` has no such rule and lets the aggregator log exact accepted and rejected counts.
12. `simulator.md`'s allow table lets the delivery service see a device key; `chat.md` §12.9 and §12.10 say it never sees a credential or a device identifier. The registry has no kind for token-scope nullifiers, join nullifiers, issuance nullifiers or the public card fields.

## Decision (proposed)

1. `context.md` gains two optional body keys: `resolvers` (array of `auth`, up to 8) and `relays` (array of `auth`, up to 4). Absent means the app's shipped defaults.
2. The app ships, beside the constants, the signed bundles with log proofs of the reference log's and the reference relays' `service` manifests. They verify offline against the constants, so O-2 holds from the first request. Endpoints stay unsigned hints.
3. `services.md` assigns integer keys to every body it owns, in the order the fields are written, and W0-08 fixes them in vectors.
4. The receipt root blob is `{0: k, 1: [page CIDs]}`. The receipt response gains `2: kid`.
5. Evidence is sealed with `info` = `hum/evidence/1 ‖ verifier authority CID ‖ item name`. The string joins the registry.
6. The error map's `rule` carries the rejection code as `"vr-<code>"`.
7. `chat.md` gains rules for the `delivery` kind: `issuer.type` is 1; the `limits` keys and types; the retention classes it must declare.
8. Each of the four specs names its bound message next to its scope.
9. `issue-map.md` drops `unsignedWindow` and `UNSIGNED_WINDOW_MIN` and uses `AUTHOR_WINDOW`; `services.md` keeps counters for two windows.
10. `ballot.md` B1 uses `too_large` for the presentation cap.
11. `services.md` gains L-5: the aggregator's count metrics for an open deck are bucketed to the nearest 50, or `release.md` drops the sentence.
12. `simulator.md` sets delivery and device key to "no", and adds the four registry kinds with where each is allowed: a token-scope nullifier at its issuer only, a join nullifier at no service, an issuance nullifier at the issuing host only, the public card fields wherever a presentation is allowed.

## Consequences

- Items 1, 3, 4, 5 and 9 change bytes that no implementation has built yet.
- Item 12 changes the constant `ALLOWED` in `sim/src/leak.rs`, which is W0-09's.
