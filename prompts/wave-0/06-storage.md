# W0-06 · Storage

**Owns:** `docs/specs/storage.md`

The manifest spec's "Blobs and storage" section sets the design. Turn it into a spec two teams could implement to the same bytes: the sealed format, references, keyrings, folders, the blob-store API and deletion.

## Read first

- `docs/specs/manifest.md`: "Blobs and storage", the `blob-store` type, security considerations
- `docs/design.md`: "Files and storage" and its diagram `docs/diagrams/files-one-upload.png`
- The MIMI content draft's ExternalPart; Privacy Pass (RFC 9576–9578); OHTTP (RFC 9458); the PURBs paper for Padmé
- `docs/specs/chat.md` as W0-05 drafts it (file operations and attachments travel in chat)

## Cover

- **Sealed format:** Padmé padding, AES-128-GCM in 64 KiB chunks, per-chunk nonces from the chunk index and a last-chunk flag, the one-byte header, key size, and exactly what's authenticated. Show it resists truncation, reordering and chunk swapping between files.
- **CIDs:** over the whole ciphertext for sealed blobs, over the bytes for public blobs; the media type for public blobs.
- **Sealed reference:** a CBOR structure with every field and its mapping onto MIMI's ExternalPart.
- **Keyrings:** derivation from the all-members MLS group's exporter (`keyring/1`), when epochs advance, and how earlier keys reach newcomers under the history policy.
- **Folders:** the file-operation messages, the encrypted index snapshot, conflicts between concurrent edits, versions.
- **Blob-store API:** put (the store recomputes the CID), get, range get and delete; token issuance against a context membership proof; per-context quotas and per-token rate limits; errors that don't leak whether a CID exists to someone without a token.
- **Deletion and retention:** the author's delete secret and its commitment, context deletion orders signed by the sign threshold, retention declared at upload and checked against the context's policy, and what clients show for a deleted blob.
- **Promotion:** making a public copy of a file when it's published with a release, with the author's consent.
- **Re-keying a sensitive folder** after a removal (the lazy-or-eager open question): recommend a default.
- Votes never touch storage; say what the conformance suite checks.

## Done when

`storage.md` defines every structure byte for byte, the API, and a vector list including failing cases (wrong CID, truncated stream, swapped chunk, reused delete secret). Mark it `seam:` and get the `spec-reviewer` subagent to no blockers.
