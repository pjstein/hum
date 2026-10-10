# Pinned primary BBS drafts

Downloaded from the IETF archive on 2026-10-09. Tests extract the published
hex fixtures directly; no fixture is derived from Hum or a Rust implementation.
The original documents retain their copyright and license notices.

| File | SHA-256 |
| --- | --- |
| [draft-irtf-cfrg-bbs-blind-signatures-03.txt](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-03.txt) | `0e19cc388f42c88112daf601f337d60302814baf2bcdca7a34db236930c2cae7` |
| [draft-irtf-cfrg-bbs-per-verifier-linkability-03.txt](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-per-verifier-linkability-03.txt) | `e2d43f6f55df75ed679da2cd83c447bcb146b9fb3f82e4660b3166bc5fed172d` |
| [draft-irtf-cfrg-bbs-signatures-12.txt](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-12.txt) | `9f2123df0f33ee8c5ffa75efb746f71e24eafd2e895ab8ba3245eaf6bc5be409` |

Base -12 SHA-256 signatures/proofs reproduce exactly. Pseudonym -03 SHA-256
commitment and proof fixtures are used for public verification; private inputs
marked `undefined` block full regeneration. Blind -03 §10 contains no fixtures.
See `docs/research/bbs-pinned-draft-findings.md` for the unresolved adapter issues.
