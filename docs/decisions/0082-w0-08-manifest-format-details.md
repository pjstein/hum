# 0082 · Format details the manifest spec leaves open

**Status:** proposed (W0-08, 2026-10-06) · `seam:` signing, domain separation, keysets, log proof verification

## Context

`docs/specs/manifest.md` fixes the envelope, the CID, COSE_Sign under `hum/manifest/1`, keysets with thresholds, pre-rotation and revocation, and the eleven verification steps, but not every byte. The reference had to choose the rest to produce vectors. Each choice below is provisional: if the manifest spec's owner picks differently, the reference changes and the vectors regenerate.

## Decisions

1. **Where `hum/manifest/1` goes in COSE.** The spec says the detached payload is the CID and the signed payload is `hum/manifest/1` followed by the CID. The reference puts the domain string in `external_aad`, so the Ed25519 signature is over `Sig_structure = ["Signature", h'', protected, "hum/manifest/1", cid]` (RFC 9052 section 4.4). Alternatives were a payload of `hum/manifest/1 || cid` (then the payload is not the CID) or a prefix outside COSE (then COSE verifiers cannot check it). A signature made without the domain string, or under `ballot/1`, does not verify (`vectors/manifest/signature.json`).
2. **Protected header.** Exactly `{1: -8, 4: kid}`: EdDSA and the key ID. The body protected header is empty; no unprotected headers.
3. **Keyset body** (no `keyset.md` exists yet): `{0: keys, 1: thresholds, 2: next?, 3: revocations?}`. A key is `{0: kid (bstr), 1: alg (-8), 2: public (bstr 32), 3: roles ([tstr])}` with roles `sign` and `rotate`. Thresholds are `{"sign": n, "rotate": n}`. `next` is the pre-rotation commitment: SHA-256 of the deterministic CBOR list `[[kid, public], ...]` sorted by kid. `revocations` is a list of `[kid, from position]`.
4. **A keyset's first version has no `authority` field.** Its CID is the authority, and the field cannot hold its own hash. Later keyset versions set `authority = lineage = CID of version 1`. Verification step 4 requires `authority` on every other type.
5. **Who signs a keyset.** Version N is signed by the `rotate` threshold of version N−1; version 1 is signed by its own `rotate` threshold. The spec says "version 1 signs itself" without naming the role; `rotate` makes the rule uniform and keeps a stolen `sign` key from minting a new authority.
6. **Revocations apply by log position across the lineage.** A revocation declared in any later keyset version invalidates manifests the key signed that were logged at or after the named position, while earlier ones stand (`deck X` in the test world).
7. **Reference depth.** The manifest under verification is depth 0 and each `refs` hop adds one; a hop to depth 17 is rejected at step 9. Keyset and `prev` lookups do not add depth. A bundle already verified in the same session is not re-verified, so caching can accept a graph a cold start would reject at the depth limit; the vectors use a cold cache per case.
8. **Checkpoints are the phone's state, not the bundle's.** A phone verifies a checkpoint once (log signature, witness cosignatures, consistency with the held checkpoint), then holds it. A consistency proof handed over with a bundle is a proof from the held checkpoint to that bundle's checkpoint and is used the first time that checkpoint is met, whichever bundle (a keyset, a `prev`, a reference) gets there first.
9. **Leaf authority for a genesis keyset.** `services.md`'s leaf is `[cid, type, authority, lineage or null, version]`; for a keyset version 1 the reference writes its own CID in the authority slot.

Items taken from other specs rather than chosen here: the leaf encoding, origin and witness names, C2SP checkpoint and cosignature formats, the bundle map and witness-key matching come from `services.md`; the sealed format, references and keyring derivation from `storage.md`; `rat`, σ rounding and `RHO_MAX` from `context.md` and ADR 0010.

## Consequences

- Items 1 to 5 belong in `manifest.md` or a `keyset.md`; this ADR is the request to the manifest spec's owner to adopt or replace them.
- Every item has at least one vector, so a change shows up as a regenerated file, never a silent drift.
