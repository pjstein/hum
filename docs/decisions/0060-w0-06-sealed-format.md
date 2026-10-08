# 0060 · Sealed blob format details

**Status:** proposed (W0-06, 2026-10-06) · `seam:` sealed format, nonces, key derivation

## Context

`docs/specs/manifest.md` fixes the outline: Padmé padding, AES-128-GCM in 64 KiB chunks, nonces from chunk index and a last-chunk flag, a one-byte header, CID over the ciphertext. It leaves the exact bytes open. Two implementations (Rust core and the Python reference) have to produce identical output, so the storage spec fixes them.

## Decision

1. **Self-delimiting pad.** The plaintext is followed by `0x80` and zero bytes up to `padme(L + 1)`. Unpadding needs no external length. This lets keyring-form references in manifests omit `size`, so a logged manifest reveals nothing about a text's exact length.
2. **Nonce layout:** `0x00 0x00 0x00 || flags || uint64_be(chunk index)`, with `flags = 0x01` on the last chunk only. This is the layout the reference implementation already used provisionally (ADR 0005-w0-08), kept to avoid churn.
3. **AAD:** the ASCII bytes `hum/sealed/1` followed by the whole header. Domain separation costs nothing and binds the header to every chunk.
3a. **Two formats, one chunk layout.** Format `0x01` has a 1-byte header and a random key carried in a direct-form reference. Format `0x02` has a 17-byte header (format byte plus a 16-byte random salt) and a key derived from a keyring epoch secret and that salt. The salt lives in the blob rather than the reference so that a manifest needs only the CID and the epoch, which is exactly what `issue-map.md` already carries. (`issue-map.md` described the key as derived from the epoch and the CID; that is circular, since the CID depends on the key.)
4. **Key size:** AES-128, 16 random bytes per blob. Matches the MIMI content draft's default. The format byte allows a 256-bit format later.
5. **Keyring-derived keys** use HKDF-SHA256 with the header salt and info `hum/keyring-blob/1`, so one keyring epoch never yields the same key twice and the chunk-index nonce scheme stays safe. The exporter output is never used as an AES key directly; the reference implementation's provisional derivation did that and must change.
6. **Plaintext digest** is written as `0x01 || SHA-256(plaintext)`, the same shape as a CID. It equals the CID the plaintext would have as a public blob, which makes promotion verifiable by anyone who holds the reference.
7. **Delete commitment:** `SHA-256("hum/delete/1" || 32 random bytes)`, independent of the file key, so recipients of a reference cannot delete the file.

See `docs/specs/storage.md` §1, §2, §4.3, §8.1.

8. **Domain strings are namespaced under `hum/`** (`hum/sealed/1`, `hum/keyring-blob/1`, `hum/delete/1`, `hum/blob-delete/1`, `hum/blob-tokens/1`), per the spec review. The exporter label was `keyring/1` when this was written and became `hum/keyring/1` under ADR 0105.

## Consequences

- The sealed format is fully deterministic given key and plaintext; every nonce and tag is a vector.
- A sealed blob's minimum size is 1 + 1 + 16 = 18 bytes for format 1 and 34 bytes for format 2 (empty plaintext).
- Streaming decryptors that do not know the total length must read one chunk ahead to find the last chunk.
- Keyring-form references carry no name, size, digest or description. Clients derive the size after decrypting.
