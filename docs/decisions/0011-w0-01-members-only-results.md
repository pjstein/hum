# 0011 · Members-only results: logged manifest, sealed tables, HPKE keybox

**Status:** proposed (W0-01, 2026-10-06; revised after spec review) · `seam:` key derivation, sealed blob format, what a manifest carries

## Context

A context may show results to members or organizers only (`perms.results`), but every release must be logged in a public log, and aggregators are not members of any MLS group, so they cannot send a sealed reference over chat as `services.md` first assumed.

## Decision

- The release manifest is logged in the clear: parameters, `nHat`, `unlocked`, receipt roots. Tables are sealed blobs (`storage.md` format 1, fresh key per table).
- The context publishes `resultsKey`, an X25519 public key, and `resultsEpoch`. The private key is derived from the keyring epoch secret: `seed = HKDF-Expand(HKDF-Extract(salt = "", IKM = secret_k), info = "hum/results-key/1", L = 32)`, clamped per RFC 7748. No new MLS export: newcomers who receive epoch `k` through `keyring-share` can derive it, and nothing has to be computed at commit time.
- Organizers-only results (`results` = 2) are deferred: the organizers group has no keyring in draft 0.1, and rule C12 rejects the value.
- The release pins a `keybox` blob: `0x01 ‖ enc ‖ ct`, HPKE (RFC 9180, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode) sealing of a CBOR array of direct-form sealed references for every table so far, with `info` = `hum/results-keybox/1` ‖ deck CID bytes and `aad` = deck CID bytes; media type `application/vnd.hum.keybox+hpke`, a public blob; one per release version.
- No key appears in any manifest, log or store request; the manifest carries only the keybox's CID.
- `nHat` stays public in sealed releases because the ledger enforces the voter floor with it. A sealed release reveals approximate size and nothing else.

## Alternatives considered

- Sending keys over MLS: aggregators are not members; it would need an organizer's phone as a relay after every release.
- Encrypting to the context's signing keys: Ed25519 signing keys are not encryption keys, and reusing them across purposes is a known hazard.
- Hiding `nHat`: the ledger could not refuse a release below 100 voters, which breaks invariant 3.

## Consequences

- `chat.md` needs no new exporter label; `storage.md` §4's reservation of `hum/results-key/1` as an exporter label can be reworded as an HKDF info string.
- Organizers refresh `resultsKey` by publishing a context version; removed members keep access to releases sealed to epochs they held, consistent with files.
- Needs owner review as a seam (key derivation).
