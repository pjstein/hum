# HPKE known-answer fixtures

`rfc9180-base.json` is the unmodified subset with mode 0, KEM 32, KDF 1,
and AEAD 1 or 3 from the CFRG HPKE authors' machine-readable corpus:
https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/master/test-vectors.json
(retrieved 2026-10-09). The two suites correspond to RFC 9180 Appendix
A.1.1 and A.2.1. Each contains 257 sequential encryptions and three
export outputs, all checked against the reference wrapper, without network
access during tests. These fixtures are source data, not generated Hum vectors.

# BIP-39 twelve-word fixtures (proposed B1 only)

`bip39-english-128.json` contains only the entropy and mnemonic columns of all
eight English 128-bit rows from Trezor/python-mnemonic `vectors.json`, commit
`b57a5ad77a981e743f4167ab2f7927a55c1e82a8` (retrieved 2026-10-13):
https://github.com/trezor/python-mnemonic/blob/b57a5ad77a981e743f4167ab2f7927a55c1e82a8/vectors.json
Wallet seed and xprv outputs are deliberately omitted: Hum's proposed input uses
canonical phrase bytes with Argon2id, not the wallet PBKDF2 derivation. These
independent phrase fixtures do not independently verify the full Hum backup.
