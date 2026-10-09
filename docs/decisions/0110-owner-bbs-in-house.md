# 0110 · Implement BBS, blind issuance and pseudonyms in-house

**Status:** accepted by the owner 2026-10-07. Independent check and pairing libraries decided 2026-10-08: `blst` 0.3.17 behind one Hum wrapper for the Rust crate, `py_ecc` 8.0.0 for the Python reference. Open under it: an Android build of `blst` · `seam:` credential issuance and presentation, pseudonyms and nullifiers

*2026-10-08, from review:* the second implementation is independent only if it is written from the drafts by a different workstream and shares no code or helper with the crate. Both sides read the same Hum layout text, so a shared misreading of the header or the presentation header would pass; `zkryptium` stays a third check where its draft versions match.

*2026-10-08:* The independent check for the in-house BBS crate is a second implementation in the Python reference, over a vetted pairing library, so vectors never come from the code under test. Which pairing library each side uses stays open while the research runs.

*2026-10-07:* Follow-up 1 is done: the orchestrator reworded `CLAUDE.md`'s hand-roll rule to allow protocol constructions from a published draft with owner approval, the draft's vectors and outside review. Follow-ups 2 and 3 remain. Previous status: owner direction, 2026-10-07 ("we should probably just implement the stuff for BBS ourselves"). Not yet final: it needs the three follow-ups below before wave 1 builds on it..

## Context

`credentials.md` builds on draft-irtf-cfrg-bbs-signatures-12, draft-irtf-cfrg-bbs-blind-signatures-03 and draft-irtf-cfrg-bbs-per-verifier-linkability-03. The library research (`docs/research/seam-libraries.md`) found one Rust library at those drafts, `zkryptium` 0.7.1. It is unaudited, describes itself as research code, and implements the blind draft at -02 "with fixes". No Python library exists. ADR 0020 left the library to the owner.

`CLAUDE.md` says: "Never hand-roll cryptography or noise sampling. Use the libraries recorded in `docs/DECISIONS.md`."

## Decision

Hum implements the three drafts itself, in a Rust crate under `core/crates/`. `zkryptium` is used as a reference implementation to compare against, not as a dependency of shipped code.

## What this does and does not cover

- In-house: the BBS, blind BBS and pseudonym operations exactly as the drafts define them (`CommitWithNym`, `BlindSignWithNym`, `VerifyFinalizeWithNym`, `ProofGenWithNym`, `ProofVerifyWithNym` and the base operations they call).
- Not in-house: the pairing curve. BLS12-381 arithmetic, hash-to-curve and the hash functions come from an existing vetted library. Which one is still to choose.
- Not covered: anything beyond the drafts. The hidden-predicate construction stays out of draft 0.1 (ADR 0022).

## Follow-ups this needs

1. **Reword the rule in `CLAUDE.md`.** As written it forbids this. The owner edits that file. Suggested wording: protocol-level constructions may be implemented in-house only from a published draft or RFC, must pass that document's test vectors, and need the owner's approval and an outside review before real users; primitives (curves, hashes, AEADs, samplers) always come from a vetted library.
2. **Choose the BLS12-381 library** and record it in `docs/DECISIONS.md`.
3. **Put the crate in scope of the outside cryptography review** before real users, alongside ADRs 0022 and 0026.

## Consequences

- **Vectors.** The crate must pass the JSON fixtures the three drafts publish. Those fixtures are independent of Hum's code.
- **Composite vectors.** Cards, presentations and nullifiers in Hum's own layout have no outside source. Today the Python reference checks structure only. Three ways to get an independent second opinion: a second in-house implementation in the Python reference over a vetted pairing library; `zkryptium` driven as the cross-check; or both. To decide.
- **The blind draft gap.** `zkryptium` is at blind -02 and Hum cites -03, so a mismatch between the two on blind issuance is not by itself a bug in either.
- **Cost.** A wave 1 workstream owns the crate. Constant-time behaviour, input validation and zeroising secrets become Hum's job.
- **Unblocks** the vector gaps listed under BBS in `docs/specs/conformance.md`.

## Owner decision, 2026-10-08: the pairing libraries

- **Rust crate:** `blst` 0.3.17, called from one small Hum wrapper module that holds all the `unsafe` code.
- **Python reference:** `py_ecc` 8.0.0.
- Research and risks: `docs/research/bls12-381-libraries.md`.

What the wrapper must do, from that research:

- Check the subgroup on every decompression. `blst` does not, and the base draft requires it.
- Use separate constant-time multiplications for sums over secret scalars. `blst`'s multi-scalar multiplication makes no constant-time claim.
- Zeroise secrets.

Still to prove: an Android build of `blst` through uniffi. The `blst` audit dates from 2020 and predates its multi-scalar code, and the wrapper is new unsafe code in a seam, so both are in scope of the outside review.
