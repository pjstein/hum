# HPKE known-answer fixtures

`rfc9180-base.json` is the unmodified subset with mode 0, KEM 32, KDF 1,
and AEAD 1 or 3 from the CFRG HPKE authors' machine-readable corpus:
https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/master/test-vectors.json
(retrieved 2026-10-09). The two suites correspond to RFC 9180 Appendix
A.1.1 and A.2.1. Each contains 257 sequential encryptions and three
export outputs, all checked against the reference wrapper, without network
access during tests. These fixtures are source data, not generated Hum vectors.
