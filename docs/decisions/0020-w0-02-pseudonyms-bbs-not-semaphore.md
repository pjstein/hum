# 0020 · Voting pseudonyms: BBS with pseudonyms, not Semaphore-style group proofs

**Status:** proposed (W0-02, 2026-10-06) · `seam:` credential presentation, pseudonyms and nullifiers

## Context

The design doc describes the voting identity as "a Semaphore-style group proof with a per-context nullifier" and the resident card as a BBS credential. `docs/DECISIONS.md` lists the choice as open and asks W0-02 to recommend one. The two candidates:

- **BBS with pseudonyms:** [draft-irtf-cfrg-bbs-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/) (-12) with [draft-irtf-cfrg-bbs-blind-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-blind-signatures/) (-03) and [draft-irtf-cfrg-bbs-per-verifier-linkability](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-per-verifier-linkability/) (-03). The pseudonym is `hash_to_curve(scope)` raised to a hidden, blindly issued secret, proven inside the credential proof.
- **Semaphore-style:** a Groth16 proof (Circom, BN254) that an identity commitment is a leaf of a group Merkle tree, with a nullifier `hash(scope, identity)` and a bound signal ([Semaphore v4](https://docs.semaphore.pse.dev/)).

## Comparison

| | BBS with pseudonyms | Semaphore v4 |
| --- | --- | --- |
| Attributes and policies | Native: selective disclosure over signed messages; policies over issuer and attribute are what BBS is for | None. A ward or age-band policy needs a second credential system anyway, so Semaphore would be a second proof system beside BBS, not instead of it |
| Issuance and unlinkability to the issuer | Blind issuance of the pseudonym secret is in the draft; proofs reveal nothing about the signature | The identity commitment is published into the group tree by whoever admits the member, so the admitter holds a stable per-person identifier that is linked to the admission event |
| Group state | None. The accepted set is the issuers a context names; nothing per member is published | A Merkle tree per context that someone maintains and every phone syncs; adding a member is a public tree update |
| Revocation | Expiry and issuer-key removal in 0.1 (ADR 0032); accumulator later | Tree removal: instant and per person, the one place Semaphore is better |
| Trusted setup | None (pairing-based, no SRS) | Groth16: Powers of Tau plus a circuit-specific ceremony; a flaw forges membership silently |
| Proof size | About 0.5 to 1 KiB with the pseudonym; plus 64 bytes per set element for hidden predicates (`credentials.md`) | 128 to 256 bytes |
| Proving on a phone | Milliseconds (a few pairings' worth of G1 work, no pairings on the prover) | Hundreds of milliseconds to seconds in the published JS/WASM prover at depth 20; native mobile provers (mopro) exist but are a second toolchain |
| Verification | A pairing check, about a millisecond | A pairing check, 2 to 6 ms |
| Libraries | Rust: `zkryptium` 0.7.1 is the only library found that implements the base draft at -12, blind issuance (at -02 "with fixes") and pseudonyms at -03; it is unaudited research code from one organisation. `pairing_crypto` (MATTR) is at base draft -03 with no blind issuance and no pseudonyms, so it is not a candidate. No Python library exists; the drafts' own JSON fixtures serve the reference (`docs/research/seam-libraries.md`) | JS/Circom first; Solidity verifiers; Rust via arkworks or mopro, circuits compiled from Circom |
| Standards track | IRTF CFRG drafts with named ciphersuites and vectors | A project specification; the proof system is Groth16 |
| What a verifier learns | The issuer `kid` (a cohort), the `any` branch used, the pseudonym under this scope | Only "a member of this tree" and the nullifier |

Figures are approximate; the specs cite sources, not measurements of Hum's code.

## Decision

**BBS with the pseudonym extension**, one credential system for the resident card, the voting pseudonym, context membership, token issuance and authorship. The nullifier is `SHA-256("hum/nullifier/1" ‖ pseudonym)`; the scope is per use, and for ballots per deck (ADR 0021).

Why: Hum needs attribute policies regardless, so Semaphore would add a trusted setup, a group tree per context and a second toolchain to gain a smaller proof and per-person revocation. The group tree also hands the admitter a stable identifier, which is the kind of join this project forbids. Per-person revocation is wanted later and can come as an accumulator predicate inside the same proof (`credentials.md`, "Expiry and re-issuance").

What is bought with the larger proof: no setup, no per-member state anywhere, blind issuance in a draft, and proving that fits a phone without a native circuit prover.

## Consequences

- `verifier.md`'s issuer `alg` stays `bbs-bls12381-sha256`; nothing there changes.
- The one construction outside the drafts is the set-membership predicate for hidden attributes and for expiry (ADR 0022). Contexts with disclosable policies need none of it.
- The "Semaphore-style" wording in `docs/design.md` ("Privacy model and trust") should be updated to "a BBS pseudonym with a per-deck nullifier".
- Library choice for wave 1 is a seam dependency and is the owner's. The research pass (`docs/research/seam-libraries.md`, 2026-10-06) found one Rust candidate at the cited drafts, `zkryptium` 0.7.1 (Apache-2.0, LINKS Foundation, no audit, blind issuance tracking -02 rather than -03), to be pinned behind one Hum wrapper crate and run against all three drafts' fixtures in CI, and no Python library at all. Composite vectors (cards, presentations) would therefore come from the same library as the code under test unless a second implementation appears, which `CLAUDE.md` forbids today; the owner must choose between marking them "not independent" and waiting. `pairing_crypto` was named in an earlier version of this ADR in error.
- Revisit if the drafts change their pseudonym construction before wave 1 freezes vectors.
