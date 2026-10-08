# 0083 · Reference choices made in the second vector run

**Status:** proposed (W0-08, 2026-10-06) · `seam:` signing and domain strings, credential presentation (structure), ballot construction, shield accounting, release σ and receipts

## Context

The second run of the reference added every type body, the services byte rules, chat content types, storage folders and orders, and the credentials, ballot and shield specs. Where a spec left a byte or an algorithm to the implementation, the reference chose one so that vectors exist. Each choice is listed here so the owning spec can adopt it or replace it; none is a protocol rule until a spec says so.

## Decisions

1. **Type hooks.** Each body module registers a step-4 schema, a step-10 rule set and, where the spec replaces step 6 (authored objects, two-signer releases, agent takes), a signature check. Rejections carry the spec's rule id. Step 9 treats a CID the phone holds in its fetched blobs as a resolved blob; the log's per-type ref table in `services.md` is the rule.
2. **Misbehaving-log worlds.** Invalid versions a real log would refuse are appended to the test logs so that phones reach the step under test. Every world file names them.
3. **Synthetic attestation report** for AS-2b: CBOR `{0: platform, 1: measurement, 2: report_data}` with `report_data = SHA-256("hum/attest/1" ‖ agentKey ‖ sponsor authority CID)`. Real platform parsers replace it.
4. **MIMI readings** (settled by the lead on 2026-10-07 against draft -09): message-id URI lengths are uint16, the salt is hashed twice as the draft writes it, and the ExternalPart is a flat 15-element CBOR array in -09 field order.
5. **RFC 9458 KeyConfig** is parsed as `key_id(1) ‖ kem_id(2) ‖ public key (length by KEM) ‖ suites_len(2) ‖ (kdf, aead) × n`, non-empty, no trailing bytes.
6. **Receipt root blob** is CBOR `{0: k, 1: [page CIDs]}`; pages are assigned by the first `k` bits of each leaf over the bytewise-sorted padded list.
7. **Seed expansions** for the ratings selection and the send schedule are SHA-256 streams under `hum/ratings-selection/1` and `hum/send-schedule/1` with rejection sampling: a reference device for deterministic vectors, not a protocol rule.
8. **Placeholders where a library is missing:** release tables are opaque blobs (no Parquet), the keybox is an opaque public blob (no HPKE), BBS proofs and pseudonyms are fixed opaque bytes with a per-card `proof_valid` input, backups are plaintext layouts (no Argon2id or HPKE wrap). The vectors say so in their notes.
9. **Task ids** follow the one form both specs now give (ADR 0024): `hum/dap-task/1 ‖ deck lineage CID ‖ uint8(round) ‖ uint8(part)`. Run 2 carried two forms; run 3 removed the round-only one.
10. **Rating decks** carry exactly parts 0, 3 and 8 (`deck.md` D8 now says so; run 2 had exempted them under D15); the R10 by-source count for rating releases runs on version 1 over releases whose version 1 was issued within 365 days before.
11. **Delete orders and `roles` messages** are signed as COSE_Sign with the domain string prefixed to the detached payload and empty external AAD, following those specs' "signed payload" wording.

12. **Log-side clock checks** (`deck.md` D16, `release.md` R13's `closes`-to-now half) are log-admission callables, not step-10 rules: the specs give them to the ledger and the aggregators by their own clocks, and a phone verifying from a log must accept what the log admitted. Their vectors carry `{"step": null, "check": "log-admission"}`.
13. **R2's "highest deck version logged before `closes`"** is read as the highest deck version logged before the release lineage's version 1, because a log has no clock. `release.md` R2 now says exactly that (W0-01, 2026-10-07), with D16 and R13 named as the clocks that make it the version in force at `closes`.

## Consequences

- Every item above has a vector, so a spec change shows as a regenerated file.
- The gaps that need a library are listed in `docs/specs/conformance.md` with the candidate dependency; adding any of them touches a seam and needs the owner.
- The verifier module follows the revised `verifier.md` (issuer-key `fromEpoch`).
