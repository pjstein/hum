# BLS12-381 library options

Oct 8, 2026 · research for the owner's library decision under ADR 0110 · `seam:` credential issuance and presentation, pseudonyms and nullifiers; key generation; anything that decides what leaves the phone

## How to read this

Hum implements three BBS drafts in-house, twice: a Rust crate for phones and services, and a second implementation in the Python reference (ADR 0110, `docs/DECISIONS.md` items 19 and 29). Both need a BLS12-381 library. This file lists the candidates. Nothing here is decided. The owner chooses and the choice goes in `docs/DECISIONS.md`.

Every version, date and download count comes from crates.io, PyPI and the GitHub API, queried on 2026-10-08. Source claims were read in a clone of each repository at its head commit on that day. "Ran" means the code was built and run on this machine (aarch64 macOS, Rust 1.99.0, Python 3.12). "No audit found" means the README, the repository's security advisories and a web search carry no audit. It does not mean no audit exists.

`credentials.md` uses the ciphersuite `BLS12-381-SHA-256`. The SHAKE-256 suite is assessed too, because the drafts publish fixtures for both.

## Findings to read first

1. **Only blst has a public audit.** The READMEs of `bls12_381`, `bls12_381_plus` and `py_ecc` each say the code is not audited. The arkworks README says "NOT ready for production use". `CLAUDE.md` asks for a "vetted library". Only blst meets that with an audit. The owner may accept production history instead, and should say so in the decision.
2. **The blst audit is from 2020 and does not cover everything Hum would call.** NCC Group reviewed commit `414ac6b` between 2020-10-13 and 2020-11-06. blst's multi-scalar multiplication (`src/multi_scalar.c`) was added on 2021-04-14. The Python binding was out of scope.
3. **blst has no SHAKE-256 hash-to-curve.** It implements `expand_message_xmd` with its own SHA-256 only. Hum's suite is SHA-256, so this does not block Hum. A blst-based crate cannot run the drafts' SHAKE-256 fixtures.
4. **blst does not check the subgroup when it decompresses a point.** `blst_p1_uncompress` and `blst_p2_uncompress` check only that the point is on the curve. The base draft requires the subgroup check (section 6.2). Hum's wrapper must call `blst_p1_affine_in_g1` and `blst_p2_affine_in_g2` itself. `blstrs`, `bls12_381` and `bls12_381_plus` do the check inside `from_compressed`.
5. **`zkryptium` is built on `bls12_381_plus` 0.8.13.** If production also used `bls12_381_plus`, the `zkryptium` cross-check in ADR 0110 would share the curve code with the code under test.
6. **arkworks scalar multiplication is not constant time.** `ark-ec` 0.6.0 uses double-and-add that skips leading zero bits and adds only on one bits. The base draft requires side-channel protection (section 6.3). arkworks is not suitable for the phone or the issuer.
7. **arkworks' public hasher does not give the draft's `hash_to_scalar`.** `DefaultFieldHasher<Sha256>` over the scalar field returned a different value from the draft's `msg_scalar_1` fixture. Its `expand_message` types are private to the crate.
8. **The Ethereum consensus specs no longer list `py_ecc`.** Their `pyproject.toml` pins `py_arkworks_bls12381==0.5.0` and no other curve library. `py_ecc` is still maintained: its last commit is 2026-10-07.
9. **A second Rust BBS crate exists for the base draft.** `affinidi-bbs` 0.4.0 (2026-10-01, Apache-2.0) implements the base draft with both suites on `bls12_381_plus` 0.9. It has no blind issuance and no pseudonyms. `seam-libraries.md` does not list it. It does not change ADR 0110.

## What the drafts need from the library

Section numbers refer to draft-irtf-cfrg-bbs-signatures-12 unless marked "blind" (draft-irtf-cfrg-bbs-blind-signatures-03) or "nym" (draft-irtf-cfrg-bbs-per-verifier-linkability-03). The blind draft (section 9) and the nym draft (section 11) define no new ciphersuite. They reuse the two below.

| # | Need | Where the drafts ask for it |
| --- | --- | --- |
| 1 | G1 and G2 addition, negation and scalar multiplication. Signatures are in G1 and public keys in G2 | 3.3.1; `SkToPk` 3.4.2; `B = P1 + Q_1 * domain + H_1 * msg_1 + ...` and `A = B * (1 / (SK + e))` in 3.6.1 |
| 2 | Scalar field arithmetic mod r, including inversion of a secret | 3.6.1 step 4; 3.7.2; nym 4 (`poly = sum nym_secrets[i] * z^i`) |
| 3 | Sums of many G1 scalar multiplications. The drafts do not name an algorithm. Multi-scalar multiplication is an optimisation | 3.6.1, 3.6.2, 3.7.1 (`T2`), 3.7.3; blind 4.3.1 (`C = J_1 * msg_1 + ... + Q_2 * secret_prover_blind`) |
| 4 | Optimal Ate pairing and a product of two pairings compared to the identity | 3.6.2 step 3 (`h(A, W) * h(A * e - B, BP2)`); 3.6.4; blind 4.3.5 step 10; Appendix B.1 |
| 5 | `hash_to_curve_g1` per RFC 9380 with a caller-chosen DST | 4.1.1 step 4 (`generator_dst = api_id ‖ "SIG_GENERATOR_DST_"`); 6.5 ("MUST meet the requirements of RFC 9380"); nym 7.3.1 (`OP = hash_to_curve_g1(context_id, api_id)`) |
| 6 | `expand_message` on its own, with 48 bytes of output | 4.1.1 steps 1 and 3; `hash_to_scalar` 4.2.2 (`OS2IP(expand_message(msg, dst, 48)) mod r`); `expand_len` in 7.2.1 and 7.2.2 |
| 7 | SHA-256 suite: `BLS12381G1_XMD:SHA-256_SSWU_RO_` from RFC 9380 section 8.8.1 | 7.2.2. This is Hum's suite |
| 8 | SHAKE-256 suite: `BLS12381G1_XOF:SHAKE-256_SSWU_RO_`. RFC 9380 does not define it. The base draft does, in Appendix A.1 | 7.2.1 |
| 9 | Compressed point encoding, 48 bytes for G1 and 96 for G2, in the format of the pairing-friendly-curves draft (the Zcash format) | 7.2.1, 7.2.2, Appendix B.2 |
| 10 | Subgroup checks on every decoded point, and a public key that is not the identity | 6.2 ("REQUIRED by all implementations"); 4.2.4.3, 4.2.4.5, 4.2.4.6 |
| 11 | Constant-time operations on secrets: the signer's key, and the prover's hidden messages, signature and random scalars | 6.3 ("implementations MUST apply proper side channel attack protection") |
| 12 | Zeroising secrets | Not in the drafts. A search of the three texts for "zeroize", "erase" and "wipe" found nothing. It is Hum's own requirement (ADR 0110, "Cost") |

Need 3 and need 11 interact. The prover's sums use hidden messages and random blinders as scalars. A variable-time multi-scalar routine must not be used for them.

## Rust candidates

| | `blst` | `blstrs` | `bls12_381` (zkcrypto) | `bls12_381_plus` | `ark-bls12-381` with `ark-ec` |
| --- | --- | --- | --- | --- | --- |
| Version, date | 0.3.17, 2026-07-24 | 0.7.1, 2023-08-14 | 0.9.0, 2026-09-15 | 0.9.0, 2026-07-31 | 0.6.0, 2026-04-26 |
| License | Apache-2.0 | MIT or Apache-2.0 | MIT or Apache-2.0 | MIT or Apache-2.0 | MIT or Apache-2.0 |
| Language | C and assembly (x86_64, ARM64), with a portable C fallback. Rust crate is an FFI binding | Rust wrapper over `blst` | Pure Rust | Pure Rust. A fork of `bls12_381` | Pure Rust. Optional x86_64 assembly |
| Audit | NCC Group, 2020-10-13 to 2020-11-06, 23 person-days, commit `414ac6b`. Scope: C, assembly, Rust and Go bindings. 0 critical or high, 3 medium, 14 low. Galois formal verification is partial and behind current blst | None found for the crate itself | README: "has not been reviewed or audited" | README: "has not been reviewed or audited" | README: "academic proof-of-concept prototype ... NOT ready for production use" |
| Constant time | `blst_p1_mult` and `blst_p2_mult` use constant-time windowed or GLV routines for scalars up to 256 bits. Scalar inversion calls `ct_inverse_mod_256`. `bulk_addition.c` and one point-addition family are marked not constant time. Pippenger carries no claim | Scalar multiplication calls `blst_p1_mult` with 255 bits | README: "All operations are constant time unless explicitly noted" | Same README claim. `sum_of_products` is documented as constant time in the scalars. `sum_of_products_vartime` is not | No. Double-and-add over the set bits |
| `hash_to_curve_g1` with any DST | Yes. `blst_hash_to_g1(msg, DST, aug)` | Yes. `G1Projective::hash_to_curve(msg, dst, aug)` | Yes, behind the `experimental` feature | Yes. `G1Projective::hash::<X>(msg, dst)` | Yes. `MapToCurveBasedHasher` with `WBMap` |
| `expand_message_xmd` SHA-256 | Yes. `blst_expand_message_xmd` | Through the `blst` crate | Yes. `ExpandMsgXmd<Sha256>` | Yes, from `elliptic-curve` 0.13 | Inside `hash_to_curve` only. The expander types are private |
| `expand_message_xof` SHAKE-256 | No | No | Yes. `ExpandMsgXof<Shake256>` | Yes | Not in the public hasher |
| Ran against the draft's fixtures (`Q_1`, `H_1`, `msg_scalar_1`) | SHA-256: pass | Not run | SHA-256 and SHAKE-256: pass | SHA-256 and SHAKE-256: pass | `Q_1`, `H_1` pass when fed blst's expander output. `msg_scalar_1` fails |
| Multi-scalar multiplication | Pippenger: `blst_p1s_mult_pippenger`, added 2021-04-14 | `G1Projective::multi_exp` (blst Pippenger) | None | Straus below 128 terms, Pippenger above | `VariableBaseMSM::msm`, variable time |
| Multi-pairing | `blst_miller_loop_n`, `blst_final_exp`, `blst_fp12_finalverify`, and the `Pairing` context | `pairing` crate traits | `multi_miller_loop` then `final_exponentiation` | Same as `bls12_381` | `multi_pairing`, `multi_miller_loop` |
| Compressed encoding | Zcash format. `blst_p1_compress`, `blst_p2_compress` | Zcash format | Zcash format | Zcash format | Zcash format since `ark-bls12-381` 0.4 |
| Subgroup check on decode | No. The caller must call `blst_p1_affine_in_g1` or `blst_p2_affine_in_g2` | Yes, in `from_compressed` | Yes, in `from_compressed` | Yes, in `from_compressed` | Yes, with `Validate::Yes` |
| Zeroising | `SecretKey` zeroises on drop. Raw `blst_scalar` and `blst_fr` do not | Not in 0.7.1. Added on the main branch, unreleased | Optional `zeroize` feature | `zeroize` is always on | `Zeroize` on fields and points |
| `no_std` | Yes | No | Yes | Yes | Yes |
| Mobile targets | Needs a C compiler for the target. `aarch64-apple-ios`: built and linked here with Rust 1.99.0 and the iOS 27.0 SDK, assembly included. `aarch64-linux-android`: not built here. `pairing_crypto` builds it with `cargo-ndk` | Same as `blst` | Pure Rust. `aarch64-apple-ios` built and linked here. Android not built here | Pure Rust. Not built for mobile here | Pure Rust. Not built for mobile here |
| Minimum Rust | Not stated | 1.56.1 for 0.7.1. Main branch: 1.85 | 1.85 | 1.87 | 1.75 |
| Maintenance | Last commit 2026-09-25. Six hardening commits since 0.3.17 are unreleased | Last commit 2026-09-11. No release for three years | Last commit 2026-09-16. First release since 2023-02. A 0.9.1 issue was opened 2026-10-05 | Last commit 2026-07-31. One main maintainer. 1 open issue | Last commit 2026-10-05. 233 open issues and pull requests |
| Advisories | Two, both fixed: GHSA-x279-68rr-jp4p (2021, wrong result in `blst_fp_eucl_inverse`, 0.3.0 to 0.3.2) and GHSA-8c37-7qx3-4c4p (2023, Go binding only). None in RustSec | None on GitHub or RustSec | None on GitHub or RustSec | None on GitHub or RustSec | None on GitHub or RustSec for these crates |
| Used by (crates.io reverse dependencies) | 33.0M downloads. `c-kzg`, `revm-precompile`, `solana-bls-signatures`, `fastcrypto` (Sui), `chia-bls`, `near-vm-runner`, `zksync_consensus_crypto` | 7.0M. Filecoin proofs, `solana-bls-signatures`, `bellperson` | 8.0M. `sapling-crypto`, `zcash_proofs`, `zebra-consensus`, `drand-verify`, `fedimint-*` | 1.1M. `zkryptium`, `blsful`, `affinidi-bbs`, `identity_credential` (IOTA) | 23.3M. `smoldot`, `revm-precompile`, `cosmwasm-crypto`, `soroban-env-host` |

Other Rust options looked at and set aside:

- **`pairing_crypto` internals.** It depends on a git fork, `mattrglobal/blstrs` at revision `a0cb960` (version 0.6.1), last pushed 2023-09-18. The fork adds the SHAKE-256 expander. It is not on crates.io. It is a pinned fork, so it is not a candidate.
- **`ic_bls12_381`** 0.10.1 (2025-03-13). DFINITY's fork of `bls12_381`. Not assessed further.
- **`mcl_rust`** 1.2.0 (2026-07-25), binding herumi's `mcl` (C++ and assembly, BSD-3-Clause). The hash-to-curve DST is process-wide state set by `mclBnG1_setDst`. BBS uses several DSTs, so this is a poor fit.
- **`constantine`** v0.2.0 (2025-01-26), written in Nim. Its README says Rust has only a low-level `constantine-sys` API. The crate is not on crates.io. The README lists an audit as a future goal.
- **`amcl`, `miracl_core`, `snowbridge-amcl`.** Last releases 2018, 2021 and 2024.

## Python candidates

The reference only generates and checks vectors. It never holds a real secret, so constant time and zeroising do not matter on this side.

| Library | Version, date | License | What runs underneath | Audit | `hash_to_curve_g1` with any DST | `expand_message` | Sums and pairings | Decode and subgroup check | Maintenance | Ran here |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `py_ecc` | 8.0.0, 2025-04-14. Pre-release 9.0.0b1, 2025-12-17 | MIT | Pure Python | README: "has NOT been audited" | Yes. `hash_to_G1(message, DST, hash_function)` | XMD with any `hashlib` hash. No XOF | No multi-scalar routine. `pairing(..., final_exponentiate=False)` allows a product, then `final_exponentiate` | `decompress_G1` checks the curve only. `subgroup_check` is a separate call | Ethereum Foundation. Last commit 2026-10-07. 2.7M downloads a month | `Q_1`, `H_1`, `msg_scalar_1` pass. Decode, subgroup check and a two-pairing product pass. G1 multiplication 5.8 ms, G2 20.6 ms, a two-pairing check 0.25 s |
| `py_arkworks_bls12381` | 0.5.0, 2026-06-23 | MIT or Apache-2.0 | Rust: `ark-bls12-381` 0.4, through PyO3. Wheels for Linux and macOS | None found. arkworks README warning applies | Yes. `G1Point.hash_to_curve(msg, dst)`, SHA-256 only | Not exposed | `multiexp_unchecked`, `GT.multi_pairing`, `GT.pairing_check` | `from_compressed_bytes` checks the subgroup | Now under the `ethereum` organisation. Pinned by the consensus specs | `Q_1`, `H_1` pass with `py_ecc`'s expander |
| blst Python binding | No release. Built from the blst repository with SWIG | Apache-2.0 | blst (C and assembly) | The NCC review left non-Rust, non-Go bindings out of scope | Yes. `P1.hash_to(msg, DST, aug)`, SHA-256 only | `Scalar.hash_to(msg, DST)` is the draft's `hash_to_scalar` for SHA-256 | `P1_Affines.mult_pippenger`, `Pairing`, `PT.finalverify` | `in_group()` is a separate call | Same repository as blst. Not on PyPI. Needs `swig` and a C++ compiler at build time | Not built. `swig` is not installed on this machine |
| `pyblst` | 0.3.15, 2025-10-14 | MIT | blst, through the Rust crate and PyO3 | None found | Yes. `BlstP1Element.hash_to_group` | Not exposed | `scalar_mul`, `miller_loop`, `final_verify`. No scalar type, no multi-scalar routine | `uncompress`. Subgroup behaviour not checked | OpShin, one author, PyPI status "Alpha". README: bindings are added "on a per-need basis" | `Q_1`, `H_1` pass with `py_ecc`'s expander |
| `milagro_bls_binding` | 1.9.1, 2026-06-13 | MIT | Rust `milagro_bls` | None found | BLS signature API only | No | No | No | Archived. The module prints "deprecated and no longer maintained" | Not run |
| `blspy` and `chia_rs` | 2.0.3, 2024-03-21, and 0.50.0, 2026-09-23 | Not stated on PyPI | Chia's BLS code | Not checked | BLS signature API. Not checked further | Not checked | Not checked | Not checked | `chia_rs` is active | Not run |
| `pymcl` | 1.0.2, 2026-01-16 | MIT | herumi `mcl` | None found | `G1.hash(bytes)` takes no DST | No | `pairing` | `deserialize` | One author, one release | Not run |

No Python binding of `bls12_381`, `bls12_381_plus` or `blstrs` was found on PyPI.

## Recommendation: Rust

**`blst` 0.3.17, called from one small Hum module that holds all the `unsafe` code.**

Reason: it is the only candidate with a public audit, and the audit covered the Rust binding. It has constant-time scalar multiplication and inversion, ARM64 assembly, and the widest production use. It passed the draft's SHA-256 fixtures here and linked for iOS here.

What the Hum module must do, because blst does not:

- Call the subgroup check after every decompression, and reject the identity as a public key (finding 4).
- Compute sums over secret scalars as separate `blst_p1_mult` calls and additions. Use Pippenger only where every scalar is public, as in verification.
- Zeroise every `blst_scalar` and `blst_fr` that held a secret.
- Pass 255 as the bit length to `blst_p1_mult`, so the constant-time path is taken.

Main risk: the wrapper is Hum-written `unsafe` FFI inside a seam, and nothing audited covers it. The audit is six years old, predates the Pippenger code, and found 8 of its 20 issues in the Rust binding. The outside cryptography review (ADR 0110, follow-up 3) should read the wrapper.

Second risk: mobile builds need a C toolchain for each target. Android was not built here. `pairing_crypto` pins Rust 1.82 for iOS because of a `___chkstk_darwin` linker error in blst. The same error is reported for other C code built by Rust (zstd-rs issue 337), where setting `IPHONEOS_DEPLOYMENT_TARGET` fixes it. The error did not occur here with Rust 1.99.0.

Alternatives, in order:

1. **`blstrs` 0.7.1 over the same blst.** It gives safe types, subgroup-checked decoding and the `group` traits, so Hum writes less `unsafe`. Against it: no release since 2023, no zeroising in the released version, no `no_std`, `serde` on by default, and no audit of its own. Hum would still call the `blst` crate directly for `expand_message_xmd`.
2. **`bls12_381` 0.9.0.** Pure Rust, `no_std`, constant time by design, both suites, subgroup-checked decoding, and the simplest mobile build. Zcash has run it for years. Against it: its README says it is unaudited, hash-to-curve sits behind a feature named `experimental`, and it has no multi-scalar routine. Choosing it means the owner accepts production history in place of an audit.
3. **`bls12_381_plus` 0.9.0.** The most complete API. Against it: unaudited, one main maintainer, and it removes the independence of the `zkryptium` cross-check (finding 5).

Not recommended: arkworks, because of findings 6 and 7.

## Recommendation: Python

**`py_ecc` 8.0.0.**

Reason: it is pure Python, so it shares no code with any Rust or C curve library. It has every operation the reference needs for the SHA-256 suite, and it passed the draft's fixtures here. It adds no compiler or native wheel to `reference/`. Its speed is enough: about 0.25 s per proof verification.

Main risk: it is unaudited and not constant time. Neither matters for a vector generator that holds only test keys. A bug in `py_ecc` would show up as a mismatch with the drafts' fixtures or with the Rust crate, which is the purpose of a second implementation.

What the reference must do, because `py_ecc` does not:

- Call `subgroup_check` after `decompress_G1` and `decompress_G2`.
- Sum scalar multiplications in a loop.
- For the SHAKE-256 fixtures only: write `expand_message_xof` over `hashlib.shake_256` and the Appendix A.1 suite. This is not needed for Hum's suite. Skip it unless the owner wants both suites checked.

Alternative: `py_arkworks_bls12381` 0.5.0. It is faster and is what the Ethereum consensus specs pin. Against it: it exposes no `expand_message`, it is tied to arkworks 0.4, and it adds a native wheel.

## Using different libraries on the two sides

`CLAUDE.md` requires the reference to be independent of the Rust protocol code. It does not forbid sharing a curve library. So the Python reference could bind blst too, through the SWIG binding or `pyblst`.

The trade: sharing blst means both sides agree by construction on every curve operation. A bug in blst's hash-to-curve, pairing or decoding would produce the same wrong bytes on both sides and no vector would catch it. The drafts' own fixtures would still catch a bug that affects their inputs. They would not catch one that shows only on Hum's inputs, such as its DSTs, its scopes or an edge-case point.

The recommended pair avoids this at no extra cost. With `zkryptium` as the third check, the curve code is independent three ways:

| Side | Protocol code | Curve code |
| --- | --- | --- |
| Production | Hum's Rust crate | blst (C and assembly) |
| Reference | Hum's Python reference | `py_ecc` (pure Python) |
| Cross-check | `zkryptium` 0.7.1 | `bls12_381_plus` 0.8.13 (pure Rust, `bls12_381` lineage) |

If the owner chooses `bls12_381` or `bls12_381_plus` for production instead, the third row stops being independent of the first at the curve level. The `py_ecc` row stays independent.

## Against `credentials.md` and ADR 0110

Nothing found contradicts `credentials.md`. Its suite, `BLS12-381-SHA-256`, is supported by every Rust candidate and by `py_ecc`. Its 48-byte compressed G1 and 96-byte compressed G2 sizes match the drafts and every library.

Two points touch ADR 0110:

- It says the curve comes from "an existing vetted library". Finding 1 limits what "vetted" can mean here.
- It says hash-to-curve and the hash functions come from the library. With blst that holds for SHA-256. With `py_ecc` the reference would write `expand_message_xof` itself if it wants the SHAKE-256 fixtures. That is about ten lines defined by RFC 9380 section 5.3.2, and RFC 9380 publishes vectors for it.

## What could not be verified

- No build for `aarch64-linux-android`. No Android NDK is installed on this machine.
- The iOS build linked. It was not run on a device or simulator.
- `blstrs` and the blst SWIG Python binding were read, not built.
- Constant-time behaviour of any library. The table reports each project's own claims and what the source shows. No timing test was run.
- Whether blst's Pippenger is constant time in its scalars. The source makes no claim either way.
- The full NCC Group report. Pages 1 to 7 were read, from a mirror, because the link in blst's README now redirects to NCC's research index. NCC's own summary page confirms the engagement.
- Whether any later audit covers blst. None is named in its README.
- The scope of the 2026 NCC Group and Least Authority reviews of Solana's `solana-bls-signatures`, which uses `blstrs`. They may cover part of `blstrs`. The reports were not read.
- Quarkslab's assessment of herumi's libraries. It exists. It was not read.
- Why `ark-ff`'s `DefaultFieldHasher` differs from the draft's `hash_to_scalar`. Only the mismatch was observed.
- Whether `pyblst.uncompress` checks the subgroup.
- The `blspy` and `chia_rs` APIs.
- Only three fixture values per suite were run (`Q_1`, `H_1`, `msg_scalar_1`). No signature or proof fixture was run, since no BBS code exists yet.

## Sources

- Drafts: `https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-12.txt`, `draft-irtf-cfrg-bbs-blind-signatures-03.txt`, `draft-irtf-cfrg-bbs-per-verifier-linkability-03.txt`
- blst: https://github.com/supranational/blst (head `4f72b30`, 2026-09-25), https://crates.io/crates/blst
- NCC Group, "BLST Cryptographic Implementation Review", 2021-01-20: https://www.nccgroup.com/research-blog/public-report-blst-cryptographic-implementation-review/
- Galois blst verification: https://github.com/GaloisInc/BLST-Verification
- blstrs: https://github.com/filecoin-project/blstrs (head `f2a59d0`, 2026-09-11)
- bls12_381: https://github.com/zkcrypto/bls12_381 (head `5d22dd7`, 2026-09-16)
- bls12_381_plus: https://github.com/mikelodder7/bls12_381_plus (head `537e06b`, 2026-07-31)
- arkworks: https://github.com/arkworks-rs/algebra (head `4a19a1c`, 2026-10-05)
- pairing_crypto: https://github.com/mattrglobal/pairing_crypto (head `ddb26d1`, 2026-09-24), pull request 339 for the iOS pin
- zkryptium: https://github.com/Cybersecurity-LINKS/zkryptium (head `d7be94a`, 2026-09-30)
- affinidi-bbs: https://crates.io/crates/affinidi-bbs
- py_ecc: https://github.com/ethereum/py_ecc (head `5233611`, 2026-10-07), https://pypi.org/project/py-ecc/
- py_arkworks_bls12381: https://github.com/ethereum/py-arkworks-bls12381 (head `846cf5e`, 2026-06-23)
- pyblst: https://github.com/OpShin/pyblst, https://pypi.org/project/pyblst/
- Ethereum consensus specs dependency list: https://github.com/ethereum/consensus-specs/blob/master/pyproject.toml
- iOS linker error: https://github.com/gyscos/zstd-rs/issues/337
