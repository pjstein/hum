# Seam library options

Oct 6, 2026 · research for the owner's library decisions · `seam:` every section below names a dependency inside a security seam

## How to read this

This file lists candidate libraries for eight needs. Nothing here is decided. Each choice needs the owner's approval and an ADR in `docs/decisions/`.

Versions and dates come from crates.io, PyPI, the GitHub API and the IETF datatracker, all queried on 2026-10-06. Draft texts were downloaded from `ietf.org/archive/id/`. Source claims were checked in the tagged source where the row says so. "No audit found" means the project's README, repository and site carry no audit statement. It does not mean no audit exists.

Production code is Rust. The reference is Python and must stay independent of the Rust code.

## Findings that contradict the specs

Read these first. Each one changes a spec, an ADR or a gap entry.

1. **The cited BBS draft versions exist.** `draft-irtf-cfrg-bbs-signatures-12` (2026-09-28), `draft-irtf-cfrg-bbs-blind-signatures-03` (2026-06-26) and `draft-irtf-cfrg-bbs-per-verifier-linkability-03` (2026-06-29) are each the latest published revision. The dates in `credentials.md` are right.
2. **`CalculatePseudonym` is not a defined operation.** The pseudonym draft -03 mentions the name twice in prose and never defines it. The defined operations are `CommitWithNym`, `BlindSignWithNym`, `VerifyFinalizeWithNym`, `ProofGenWithNym` and `ProofVerifyWithNym`. The calculation itself is section 4 and `PseudonymProofInit`. `credentials.md` should cite those. The names `commitment_with_proof`, `context_id` and `nym_secret` do exist. The draft calls the two shares `prover_nyms` and `signer_nym_entropy`.
3. **The nym secret is the last signed scalar, not message 0.** `VerifyFinalizeWithNym` builds the scalar vector as messages, then committed messages, then `nym_secrets`. `credentials.md` puts the nym secret at index 0 and `epoch` at index 1. A library that follows the draft numbers signer messages from 0, so `epoch` is index 0 and attribute `i` is index `1 + i`. The spec's layout table and every `disclosed` index need to be restated in the draft's order, or the spec must say how its indexes map.
4. **With `N` = 1 the draft does not promise long-term unlinkability across scopes.** Section 9.1 says pseudonyms stay unlinkable against a quantum adversary only while a prover uses fewer distinct `context_id` values than the length of the nym vector. Hum sets `N` = 1 and uses one scope per deck. The draft marks the proof as TODO. This belongs in the outside cryptography review.
5. **The draft allows a stable pseudonym across re-issuance.** Section 6.1.2 says `signer_nym_entropy` "can be reused for the same prover" on reissue. ADR 0026 files evidence-free renewal as needing a construction outside the drafts. Part of it is inside the draft.
6. **`pairing_crypto` is not a candidate.** ADR 0020 lists it. Its last release is 0.4.4 (2024-10-21), aligned to base draft -03. It has no blind issuance and no pseudonyms. The base draft's fixtures changed between -03 and -06, so it does not match -12.
7. **`pybbs` does not exist on PyPI.** `conformance.md` names it. PyPI `bbs` is 0.0.1 from 2022.
8. **`cryptography` already has Argon2id.** `conformance.md` says it does not. `Argon2id` arrived in 44.0.0. The pinned 50.0.2 reproduces the RFC 9106 Argon2id known answer in `reference/.venv`. No new dependency is needed.
9. **`cryptography` already has HPKE, but not the part Hum needs.** `conformance.md` says it has none. HPKE arrived in 47.0.0. The 50.0.2 API is `Suite.encrypt(plaintext, public_key, info)` and `Suite.decrypt`. It has no export interface, no AAD argument and no way to fix the ephemeral key. Hum needs all three. The gap stands for a different reason.
10. **Hum needs two HPKE AEADs.** The task brief names AES-128-GCM. `credentials.md` and `verifier.md` also seal issuance and evidence with ChaCha20-Poly1305. Every candidate below supports both.
11. **The DP samplers take σ, and `release.md` passes σ².** `release.md` says the sampler "is called with the exact rational σ²". OpenDP's `sample_discrete_gaussian(scale)` and libprio's `DiscreteGaussian::new(std)` both take the standard deviation as a rational. Hum's σ is the square root of a rational and is usually irrational. Either the spec defines a rational σ (rounded up), or Hum needs a sampler that takes σ². OpenDP's helper for that is `pub(crate)`, so it cannot be built from OpenDP's public API.
12. **`make_gaussian` takes a float scale.** OpenDP's measurement constructor takes `scale: f64` in Rust and Python. Sampling is exact, but the parameter is not Hum's exact rational.
13. **MIMI content is at -09.** `draft-ietf-mimi-content-09` was published 2026-07-04. `chat.md` pins -08 (2026-03-02). The pin is valid. ADR 0050 should say that -09 exists and was not adopted.
14. **`cargo-component` is stale.** `verifier.md` names `cargo-component 0.21` in the toolchain string. Its last release is 0.21.1 (2025-04-07), its last commit is 2025-07-14, and its README calls it experimental. `rustc` builds components with the `wasm32-wasip2` target alone.
15. **Privacy Pass in Rust is pre-release only.** The one crate with both token types is `privacypass` 0.2.0-pre.3. Its stable 0.1.0 is from 2022, before RFC 9578.

## 1. BBS signatures, blind issuance, pseudonyms

Draft status, from the datatracker:

| Draft | Latest | Published | Cited in specs | State |
| --- | --- | --- | --- | --- |
| `draft-irtf-cfrg-bbs-signatures` | -12 | 2026-09-28 | -12 | Active RG document |
| `draft-irtf-cfrg-bbs-blind-signatures` | -03 | 2026-06-26 | -03 | Active |
| `draft-irtf-cfrg-bbs-per-verifier-linkability` | -03 | 2026-06-29 | -03 | Active |

The base draft's fixtures are stable. All 129 hex values of 48 bytes or more in -06 appear unchanged in -07, -10 and -12. The draft's change log stops at -07. Blind -03 added "committed disclosure functionality". Pseudonym -02 changed the nym secret from one scalar to a vector.

| Library | Language | Version, date | Drafts implemented | Test vectors | Audit | License | Maintenance | Source |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `zkryptium` | Rust | 0.7.1, 2026-09-30 | Base -12, blind -02 "with some fixes", pseudonyms -03 | In repo: `fixture_data`, `fixture_data_blind`, `fixture_data_nym`, both ciphersuites | None found. README: "experimental implementation for research purposes" | Apache-2.0 | LINKS Foundation. Releases 2026-06, -08, -09. 0 open issues. GitHub marks releases alpha | https://github.com/Cybersecurity-LINKS/zkryptium |
| `pairing_crypto` | Rust, with C, Java, Obj-C, React Native, WASM wrappers | 0.4.4, 2024-10-21 | Base -03 only. No blind, no pseudonyms | Own fixtures | README: "has not undergone an independent implementation audit" | Apache-2.0 | MATTR. Not on crates.io. Depends on a git fork of `blstrs`. Recent commits are build chores | https://github.com/mattrglobal/pairing_crypto |
| `bbs_plus` (docknetwork/crypto) | Rust | 0.25.0, 2025-08-03 | BBS and BBS+ from the papers. README cites no IETF draft | Not checked | None found | Apache-2.0 | Last commit 2025-10-02 | https://github.com/docknetwork/crypto |
| `herculas/bbs-signature` | Rust | 0.6.3, 2025-03-16 | Base -08, blind -01, pseudonyms -01 | Not checked | None found | MIT | One author, 2 stars, idle since 2025-03 | https://github.com/herculas/bbs-signature |
| `zk-cred-bbs` | Rust | 0.0.7, 2026-08-30 | Blind issuance. Pseudonyms "not implemented" | Own reference vectors | README: "Not reviewed, not for production" | BSD-2-Clause | New, 0 stars | https://github.com/sirosfoundation/zk-cred-bbs |
| `libbbs` | C | No release. Last commit 2026-08-24 | Base draft, revision not stated | Not checked | None found | Apache-2.0 | Fraunhofer AISEC | https://github.com/Fraunhofer-AISEC/libbbs |
| `grotto-bbs-signatures` | JavaScript | No release. Last commit 2026-07-13 | README says base -05. Written by a draft co-author. `zkryptium` takes its blind fixes from it | Draft vectors | None found | BSD-3-Clause | One author | https://github.com/Wind4Greg/grotto-bbs-signatures |
| `bbs-node-reference` | TypeScript | No release. "draft12" merged 2026-09-28 | Base -12 | Draft vectors | README: "NOT a production-ready implementation" | MIT | Microsoft | https://github.com/microsoft/bbs-node-reference |
| `bbs` (PyPI) | Python | 0.0.1, 2022-03-11 | Pre-IETF | None | None | MIT | Dead | https://pypi.org/project/bbs/ |
| `ursa-bbs-signatures` (PyPI) | Python wrapper | 1.0.1, 2021-04-12 | Pre-IETF BBS+ | None | None | Not stated | Dead | https://pypi.org/project/ursa-bbs-signatures/ |

The drafts' own fixtures are JSON files in `cfrg/draft-irtf-cfrg-bbs-blind-signatures` and `cfrg/draft-irtf-cfrg-bbs-pseudonyms` under `fixtures/fixture_data/`. Both drafts also print them in section 12.

**Recommendation, Rust:** `zkryptium`, pinned to an exact version, behind one Hum wrapper crate, and only after the outside cryptography review reads it. It is the only library found that implements all three drafts at or near the cited revisions. Hum's CI should run all three drafts' fixtures against it.

**Main risk:** it is unaudited research code from one organisation. Its blind issuance tracks -02, not the cited -03. Its constant-time behaviour was not checked.

**Recommendation, Python:** there is no library. Take primitive vectors from the drafts' JSON fixtures, as `credentials.md` already says. For Hum's composite vectors (cards, presentations) the owner must choose: generate them from `zkryptium` through a small tool and mark them "not independent", or wait for a second implementation at -03.

**Main risk:** composite BBS vectors would come from the code under test, which `CLAUDE.md` forbids today.

## 2. MLS (RFC 9420)

| Library | Language | Version, date | Standard | Test vectors | Audit | License | Maintenance | Source |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| OpenMLS | Rust | 0.9.0, 2026-08-25 | RFC 9420 | The MLS working group's vector files in `openmls/test_vectors/` | No audit statement in the repo, the book or openmls.tech. NCC Group published a review of libxmtp, which is built on OpenMLS, in October 2024. Whether OpenMLS was in scope was not confirmed | MIT | Commits daily. 178 open issues. MSRV 1.91 | https://github.com/openmls/openmls |
| mls-rs | Rust | 0.56.0, 2026-08-19 | RFC 9420 | "tests against pre-computed test vectors" | README: "has not yet received a full security audit by a 3rd party" | Apache-2.0 OR MIT | AWS Labs. Last commit 2026-09-17 | https://github.com/awslabs/mls-rs |
| mls-rs-uniffi | Rust with uniffi bindings, Python possible | 0.13.0 in the repo. crates.io has only 0.1.0 (2024-03-26) | RFC 9420 through mls-rs | Through mls-rs | Same as mls-rs | Apache-2.0 OR MIT | Touched 2026-08-19. Uses uniffi 0.31 | https://github.com/awslabs/mls-rs/tree/main/mls-rs-uniffi |
| MLSpp | C++ | Tag v0.1.0. Last commit 2026-09-21 | RFC 9420 | Interop runner | None found | BSD-2-Clause | Cisco | https://github.com/cisco/mlspp |
| `rfc9420` (PyMLS) | Python | 1.3.0, 2026-08-25 | RFC 9420 | README claims an RFC vector runner | None | Apache-2.0 on PyPI, no license file in the repo | One author, 0 stars | https://github.com/MFDI-hub/PyMLS |
| `pure-mls` | Python | 4.0.0, 2026-07-13 | RFC 9420, partial | Passes `crypto-basics`, `key-schedule`, `passive-client-welcome`, `psk_secret` | README: "experimental, not audited" | GPL-3.0 | One author, 1 star | https://github.com/joanfgarcia/pure-mls |
| mls-implementations | Vectors and gRPC interop runner | Last commit 2026-04-22 | RFC 9420 | It is the vector source | n/a | Not stated | MLS working group | https://github.com/mlswg/mls-implementations |

Checked in the OpenMLS 0.9.0 source:

- Ciphersuite 0x0001 is listed as supported and mandatory to implement.
- The exporter is `MlsGroup::export_secret(crypto, label, context, key_length)`.
- `PURE_CIPHERTEXT_WIRE_FORMAT_POLICY` makes every outgoing and incoming handshake message a `PrivateMessage`.
- `MlsGroup::set_aad` sets authenticated data. `Extension::Unknown(u16, …)` carries a private-use extension such as `hum_tree_ref`.
- 0.9.0 fixes a case where "a commit from a sender outside the tree could be accepted" (#2186) and advisory GHSA-rrmv-c79f-cf5r. Do not use an earlier version.
- OpenMLS has no Python bindings. It ships a gRPC interop client, a CLI and a WASM build.

**Recommendation, Rust:** OpenMLS 0.9.x with the `PURE_CIPHERTEXT` policy.

**Main risk:** no public audit of OpenMLS itself was found. The API still breaks between minor versions.

**Recommendation, Python reference:** drive `mls-rs` from Python through `mls-rs-uniffi`. It is a second implementation, independent of OpenMLS, so the vectors stay independent of the code under test. Keep the reference's hand-written exporter arithmetic and check it against the working group's `key-schedule.json`.

**Main risk:** `mls-rs-uniffi` must be built from git, and nobody has checked that its binding surface exposes authenticated data, exporters and private-use extensions. The fallback is the OpenMLS interop client, which is not independent.

## 3. HPKE (RFC 9180)

Needed: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM and ChaCha20-Poly1305, the export interface (RFC 9180 §9.8), AAD, and a fixed ephemeral key for vectors.

| Library | Language | Version, date | Standard | Test vectors | Audit | License | Maintenance | Source |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `hpke` (rust-hpke) | Rust | 0.14.1, 2026-09-06 | RFC 9180. Has `export` and `setup_sender_with_rng` | RFC known-answer tests behind the `kat` feature | README: "nobody has performed a paid audit". Cloudflare did an internal review of 0.8 and "found no security issues" | MIT or Apache-2.0 | Last commit 2026-10-02. 11 M downloads | https://github.com/rozbb/rust-hpke |
| `hpke-rs` | Rust | 0.7.0, 2026-07-15. 0.8.0-pre.1 on 2026-10-06 | RFC 9180, including export-only | Not checked | None found. The libcrux backend is described as formally verified, with limited suites | MPL-2.0 | Moved into the libcrux repository in 2026-07. OpenMLS 0.9.0 depends on it | https://github.com/celabshq/libcrux |
| `cryptography` | Python | 50.0.2, 2026-09-30 | RFC 9180 single-shot only. No export, no AAD, no fixed ephemeral key | Not checked | pyca's own process | Apache-2.0 or BSD | Already a dependency | https://github.com/pyca/cryptography |
| `pyhpke` | Python | 0.6.5, 2026-07-16 | RFC 9180. Has an exporter context and an `eks` argument that fixes the ephemeral key | Passes the official RFC 9180 vectors | README: "has not been formally audited" | MIT | One author. Depends only on `cryptography` | https://github.com/dajiaji/pyhpke |
| `hpke` (hpke-py) | Python | 0.3.2, 2024-10-26 | RFC 9180 without X25519 | Not checked | None found | Apache-2.0 | Idle since 2024 | https://github.com/ctz/hpke-py |
| `rfc9180` | Python | 0.3.0, 2026-02-22 | RFC 9180 | Not checked | None | MIT | One author, 0 stars | https://github.com/MFDI-hub/rfc9180-py |

**Recommendation:** `hpke-rs` 0.7 in Rust, because OpenMLS already brings it into the dependency tree. `pyhpke` in the reference.

**Main risk:** neither is audited. `hpke-rs` just changed repositories and is MPL-2.0, which matters if Hum picks AGPL or Apache. If one dependency per seam matters less than review history, `hpke` (rust-hpke) is the alternative.

## 4. Argon2id (RFC 9106)

| Library | Language | Version, date | Standard | Test vectors | Audit | License | Maintenance | Source |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `argon2` (RustCrypto) | Rust | 0.6.0, 2026-08-27 | RFC 9106 | Not checked | None found | MIT OR Apache-2.0 | Last commit 2026-09-10. 59 M downloads | https://github.com/RustCrypto/password-hashes |
| `rust-argon2` | Rust | 3.0.0, 2025-07-17 | Argon2 | Not checked | None found | MIT or Apache-2.0 | Slow | https://github.com/sru-systems/rust-argon2 |
| `cryptography` | Python | 50.0.2, 2026-09-30 | RFC 9106 through OpenSSL 3.2 or later | The RFC 9106 Argon2id vector passes in `reference/.venv` | pyca's own process | Apache-2.0 or BSD | Already a dependency | https://github.com/pyca/cryptography |
| `argon2-cffi` | Python | 25.1.0, 2025-06-03. Bindings 26.1.0, 2026-08-20 | The Argon2 reference C code | Not checked | None found | MIT | Maintained | https://pypi.org/project/argon2-cffi/ |

**Recommendation:** `argon2` 0.6 in Rust. `cryptography` in the reference, with no new dependency.

**Main risk:** the RustCrypto crate has no audit on record. Put the RFC vector and the Hum backup vector in CI. The 64 MiB setting was not tested on a low-end phone.

## 5. Privacy Pass (RFC 9576 to 9578)

| Library | Language | Version, date | Standard | Test vectors | Audit | License | Maintenance | Source |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `privacypass` | Rust | 0.2.0-pre.3, 2026-08-18. Stable 0.1.0 is from 2022-07-12 | RFC 9578 type 0x0001 (VOPRF P-384) and 0x0002 (blind RSA 2048, SHA-384, PSS). Also batched-token drafts | Known-answer files from Go, Rust and TypeScript implementations in `tests/kat_vectors/` | README: "has not been independently audited" | MIT | One author. Pins `voprf-ng` =0.6.0-pre.3, the author's own fork | https://github.com/raphaelrobert/privacypass |
| `voprf` | Rust | 0.5.0 stable. 0.6.0-pre.1, 2026-04-06 | RFC 9497 | Not checked | None found | MIT or Apache-2.0 | Meta. Last commit 2026-04-06 | https://github.com/facebook/voprf |
| `blind-rsa-signatures` | Rust | 0.18.0, 2026-09-25 | RFC 9474 | Not checked | None found | MIT | One author, active | https://github.com/jedisct1/rust-blind-rsa-signatures |
| `privacypass` (PyPI) | Python | 0.2.2, 2024-04-07 | Not RFC 9578. It redeems Cloudflare CAPTCHA tokens | None | None | MIT | Not relevant | https://pypi.org/project/privacypass/ |
| `voprf` (PyPI) | Python over Rust | 0.2.0, 2026-08-07 | RFC 9497, P-384 and ristretto255 | Not checked | None | BSD-3-Clause | One author, two releases | https://pypi.org/project/voprf/ |

No Python implementation of RFC 9578 was found.

**Recommendation, Rust:** `privacypass` pinned to the exact pre-release. It is the only Rust crate found with both token types and cross-implementation known answers.

**Main risk:** a pre-release crate on a pre-release fork of the VOPRF crate, all by one author, unaudited. `chat.md` derives issuer keys with RFC 9497 `DeriveKeyPair`. Nobody has checked that the crate exposes it.

**Recommendation, Python:** add no library. Use the RFC 9578 appendix vectors and the crate's Go and TypeScript known-answer files as primitive vectors. A type 0x0002 token is an RSASSA-PSS signature, so `cryptography` can verify one. A type 0x0001 token needs P-384 hash-to-curve, which `cryptography` lacks.

**Main risk:** type 0x0001 issuance in the reference stays a gap.

## 6. Discrete Gaussian sampling

| Library | Language | Version, date | What it offers | Test vectors | Audit | License | Maintenance | Source |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| OpenDP | Rust core, Python bindings | 0.16.0, 2026-10-06 | `opendp::traits::samplers::sample_discrete_gaussian(scale: RBig) -> Fallible<IBig>`. Exact rational arithmetic, Canonne–Kamath–Steinke algorithm, marked `#[proven]` with a proof file. Takes σ. No caller-supplied random source: it reads OpenSSL `RAND_priv_bytes` under the default `use-openssl` feature | Statistical tests | The docs say OpenDP "has performed well in independent security audits" and link a 2023 ETH paper and arXiv 2602.17454. Neither was read. OpenDP also runs a proof review board | MIT, by license file. crates.io shows "non-standard" | Released today. 350 open issues. Old `rand` 0.7 | https://github.com/opendp/opendp |
| OpenDP `make_gaussian` | Rust and Python | 0.16.0 | A measurement with zCDP accounting over integer domains. `scale` is `f64` | Same | Same | Same | Same | Same |
| `prio::dp` (libprio-rs) | Rust | 0.18.1, 2026-09-25 | `DiscreteGaussian::new(std: Rational)`, sampled with any `Rng`. Same algorithm, exact rationals. Not feature-gated | `tests/discrete_gauss` | None found | MPL-2.0 AND Apache-2.0 AND MIT | Divvi Up, active | https://github.com/divviup/libprio-rs |
| discrete-gaussian-differential-privacy | Python | One commit, 2020-06-16 | `sample_dgauss(sigma2, rng)`. The paper authors' reference code. Takes σ² as a `Fraction` | None | None | Apache-2.0 | Archived | https://github.com/IBM/discrete-gaussian-differential-privacy |
| SampCert | Lean 4 | v4.29.0, 2026-04-09 | Formally verified samplers, discrete Gaussian included. No Rust output | Proofs | Machine-checked | Apache-2.0 | Active | https://github.com/leanprover/SampCert |

**Recommendation:** OpenDP's `sample_discrete_gaussian`, called directly, with Hum's own ρ accounting. Settle finding 11 in `release.md` first. The reference keeps drawing no noise, as ADR 0081 says.

**Main risk:** the σ against σ² mismatch. Rounding σ to a rational changes the distribution the spec names, and rounding down weakens the stated ρ. The second risk is that OpenDP's sampler cannot be seeded, so the statistical harness is the only test. `prio::dp` is the alternative if a seeded sampler matters more than OpenDP's proofs. It has the same σ interface.

## 7. WebAssembly component runtime and Parquet

| Library | Language | Version, date | Standard | Test vectors | Audit | License | Maintenance | Source |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `wasmtime` | Rust | 49.0.2, 2026-10-02. 50.0.0-rc.1 on 2026-10-05 | The component model is a Tier 1 feature in `docs/stability-tiers.md`, on x86_64 and aarch64 | Upstream spec tests | Not researched | Apache-2.0 WITH LLVM-exception | Bytecode Alliance. Monthly major releases, patch releases for 48 and 49 on 2026-10-02 | https://github.com/bytecodealliance/wasmtime |
| `wasmtime` (wasmtime-py) | Python | 49.0.0, 2026-09-21 | Has a `wasmtime.component` package. README: "Components are also supported" | `tests/component/` | Not researched | Apache-2.0 WITH LLVM-exception | Tracks each wasmtime major | https://github.com/bytecodealliance/wasmtime-py |
| `cargo-component` | Rust build tool | 0.21.1, 2025-04-07 | Component builds | n/a | n/a | Apache-2.0 WITH LLVM-exception | README: "experimental". Last commit 2025-07-14 | https://github.com/bytecodealliance/cargo-component |
| `parquet` (arrow-rs) | Rust | 60.0.0, 2026-09-15 | Apache Parquet | Upstream | Not researched | Apache-2.0 | Apache. A major release about every month | https://github.com/apache/arrow-rs |
| `pyarrow` | Python | 25.0.1, 2026-08-10 | Apache Parquet | Upstream | Not researched | Apache-2.0 | Apache | https://pypi.org/project/pyarrow/ |
| `fastparquet` | Python | 2026.9.0, 2026-09-25 | Apache Parquet | Upstream | Not researched | Apache-2.0 | dask | https://pypi.org/project/fastparquet/ |

**Recommendation:** `wasmtime` in the verifier host and `wasmtime` from PyPI in the reference, pinned to the same major. `parquet` in Rust and `pyarrow` as a dev dependency in the reference. Compare tables row-wise, as `conformance.md` already proposes.

**Main risk:** `verifier-runtime.md` sets the fuel budget "in Wasmtime's accounting". Wasmtime ships a new major every month, and nobody has checked that fuel counts are stable across majors. The fuel vectors may pin Hum to one wasmtime version. Parquet bytes differ between writers, so table CIDs are not reproducible across implementations.

## 8. Prio3 and DAP (phase 2, status only)

| Item | Version, date | Draft implemented | Status |
| --- | --- | --- | --- |
| `draft-irtf-cfrg-vdaf` | -22, 2026-08-15 | n/a | Awaiting IRSG reviews |
| `draft-ietf-ppm-dap` | -19, 2026-07-06 | n/a | WG consensus, waiting for write-up |
| `prio` (libprio-rs) | 0.18.1, 2026-09-25, MPL-2.0 AND Apache-2.0 AND MIT | VDAF -18, DAP -17. The README says later DAP drafts are likely compatible | Supported |
| `janus` release/0.7 | 0.7.141, 2026-10-06, MPL-2.0 | DAP -09 | Supported |
| `janus` main | 0.9.0-prerelease-1, 2026-10-06 | The README says DAP -18 and "Conforms to protocol? No" | In development |

The janus README says DAP -18 "has not yet been published". The datatracker shows -19. The README is behind.

**Recommendation:** nothing to adopt in draft 0.1. Re-check when phase 2 starts. Both drafts are in late review, so an RFC-aligned `prio` and `janus` are plausible by then.

**Main risk:** the library trails the VDAF draft by four revisions. Whether -19 to -22 changed the wire format was not checked.

## What could not be verified

- No library was built or run, except `cryptography` 50.0.2 in `reference/.venv` (HPKE API surface and one Argon2id known answer).
- Whether `zkryptium` passes the drafts' fixtures. The fixture files are in its repository. Its tests were not run.
- What "blind -02 with some fixes" in `zkryptium` means against blind -03.
- Constant-time behaviour of any library.
- Whether NCC Group's libxmtp review covered OpenMLS code. The full report was not read.
- Whether `mls-rs-uniffi` generates working Python bindings and exposes authenticated data, exporters and unknown extensions.
- Whether `rfc9420` or `pure-mls` passes the full working group vector set.
- The two papers OpenDP cites as audits.
- Whether `privacypass` exposes RFC 9497 `DeriveKeyPair` and deterministic issuance outside its `kat` feature.
- That `cryptography` verifies a type 0x0002 token from the RFC 9578 vectors. This follows from the RFC and was not run.
- Fuel stability across wasmtime versions, and fuel control for components in `wasmtime-py`.
- Where the base BBS draft keeps machine-readable fixtures. The blind and pseudonym draft repositories have them under `fixtures/fixture_data/`.
- Audit history for wasmtime, arrow-rs, RustCrypto `argon2`, `voprf` and `blind-rsa-signatures` beyond "no statement in the README".
- Whether `bbs_plus` or `libbbs` match the IETF base draft's fixtures.
- Wire changes between VDAF -18 and -22 and between DAP -17 and -19.
