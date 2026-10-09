# Hum Storage Spec — Draft 0.1

Oct 6, 2026 · W0-06 · `seam:` sealed blob format, keyrings, delete secrets, what leaves the phone

## Scope

This spec turns the "Blobs and storage" section of `docs/specs/manifest.md` into bytes and an API. It defines:

- the sealed blob format (padding, chunking, nonces, what is authenticated);
- content IDs for sealed and public blobs;
- the sealed reference that carries a blob's key, and its mapping onto the MIMI content draft's ExternalPart;
- context keyrings: derivation, epochs, and delivery to newcomers;
- folders: file operations, the index snapshot, conflict rules and versions;
- the blob-store API and the `blob-store` manifest body;
- deletion, retention and promotion to a public blob;
- re-keying after a removal;
- the rule that votes never touch storage, and what the conformance suite checks.

Out of scope: how chat frames a reference inside an MLS message (`chat.md`), the context manifest's storage policy fields (`context.md`), the OHTTP relay and the resolver (`services.md`), and the membership proof used for token issuance (`credentials.md`). Where this spec depends on one of those and the sibling spec did not exist when this draft was written, the assumption is listed under "Assumptions about sibling specs".

Terms: a *blob* is bytes a store holds by CID. A *sealed* blob is encrypted on a phone. A *public* blob is plain. A *reference* is the structure that lets a member find and decrypt a sealed blob. A *keyring* is the per-context list of epoch secrets. A *folder* is a channel whose messages are file operations.

All CBOR in this spec uses the deterministic encoding of `manifest.md` (RFC 8949 §4.2.1 core requirements, integer map keys). All byte lengths are exact. All integers are unsigned unless stated.

## 1. Sealed blob format

A sealed blob is a short header followed by a sequence of AES-128-GCM chunks. Each chunk is independently decryptable, so files stream and ranges decrypt alone. The whole ciphertext, header included, is what the CID hashes.

### 1.1 Constants and formats

| Name | Value |
| --- | --- |
| `CHUNK` | 65,536 bytes of plaintext per chunk |
| `TAG` | 16 bytes (GCM tag) |
| `KEY` | 16 bytes (AES-128) |
| `NONCE` | 12 bytes |
| `AAD` | the ASCII bytes `hum/sealed/1` followed by the whole header |

Two formats share the chunk layout and differ only in the header and where the key comes from:

| Format byte | Name | Header | Key |
| --- | --- | --- | --- |
| `0x01` | direct | the format byte alone, 1 byte | 16 random bytes, carried in a direct-form reference (§3) |
| `0x02` | keyring | the format byte then a 16-byte random salt, 17 bytes | derived from a keyring epoch secret and the header's salt (§4.3) |

Both use AES-128-GCM, 64 KiB chunks and the Padmé pad below. `H` is the header length: 1 for format 1, 17 for format 2. The AAD is 13 or 29 bytes.

### 1.2 Padding

The phone pads before encrypting so the store sees only a padded length.

1. Let `L` be the plaintext length in bytes.
2. Append one byte `0x80`.
3. Append zero bytes until the total length is `padme(L + 1)`.

`padme(n)` is the Padmé function from the PURBs paper (Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and Communication with PURBs", 2019):

```
padme(n):
  if n < 2: return n
  E = floor(log2(n))
  S = floor(log2(E)) + 1
  lastBits = E - S
  mask = (1 << lastBits) - 1
  return (n + mask) & ~mask
```

The padded length `P = padme(L + 1)` is at least 1 and at most about 12% more than `L + 1`. The pad is self-delimiting: unpadding strips trailing zero bytes and then exactly one `0x80`. A decryptor MUST reject a padded plaintext that has no `0x80` after the trailing zeros, and MUST reject one whose padded length is not `padme(L + 1)` for the `L` it recovered.

Examples:

| `n` | `padme(n)` |
| --- | --- |
| 1 | 1 |
| 7 | 7 |
| 9 | 10 |
| 100 | 104 |
| 1,000 | 1,024 |
| 65,536 | 65,536 |
| 65,537 | 67,584 |
| 1,000,000 | 1,015,808 |

The reference implementation produces the full table as a vector.

### 1.3 Chunking and nonces

Split the padded plaintext into `n = ceil(P / CHUNK)` chunks. Chunks 0 through `n−2` hold exactly `CHUNK` bytes. Chunk `n−1` holds between 1 and `CHUNK` bytes. Because `P ≥ 1`, there is always at least one chunk, and the last chunk is never empty.

The nonce for chunk `i` is 12 bytes:

```
nonce(i, last) = 0x00 0x00 0x00 || flags || uint64_be(i)
flags = 0x01 if this is the last chunk, else 0x00
```

For format 1 the key is 16 random bytes from the phone's CSPRNG, fresh for every sealed blob. For format 2 the salt is 16 random bytes, fresh for every blob, and the key is derived from it (§4.3). A key MUST NOT be used for two blobs; the fresh salt guarantees it for format 2.

Each chunk is encrypted as `AES-128-GCM(key, nonce(i, last), plaintext_i, AAD)`, giving `ciphertext_i || tag_i`.

### 1.4 Layout

```
sealed blob = header || chunk_0 || chunk_1 || ... || chunk_{n-1}
header      = 0x01                      (format 1)
            | 0x02 || salt (16 bytes)   (format 2)
chunk_i     = ciphertext_i || tag_i     (len(plaintext_i) + 16 bytes)
```

The total length is `H + P + 16n`. Given a total ciphertext length `C`, the chunk count is `n = ceil((C − H) / (CHUNK + TAG))`, and this is unambiguous because the last chunk's ciphertext is between 17 and 65,552 bytes.

For a message-form reference, `C` follows from `size`: `P = padme(size + 1)`, `n = ceil(P / CHUNK)`, `C = H + P + 16n`. A phone computes `C` before fetching and rejects a store whose `Content-Length` differs with `size-mismatch`, without downloading. For a keyring-form reference there is no `size`; `C` is the `Content-Length` of a `HEAD` or the first response, untrusted, and a wrong value surfaces as `bad-tag` on the chunk that was wrongly taken as last.

The byte offset of chunk `i` inside the blob is `H + i × (CHUNK + TAG)`. A reader that wants plaintext bytes `[a, b)` fetches chunks `floor(a / CHUNK)` through `floor((b − 1) / CHUNK)` by byte range (§6.4) and decrypts each one on its own. For format 2 the reader needs the header too, so it fetches bytes `[0, 17)` once and caches the salt.

### 1.5 Decrypting

Given the ciphertext (or a range of it), the key or keyring secret, and the expected total length `C`:

1. The first byte MUST equal the reference's `format` and be a format this spec defines. Otherwise reject with `bad-format`. For format 2, read the salt and derive the key (§4.3).
2. Compute `n` from `C`. If the reader does not know `C` in advance, it reads one chunk ahead: a chunk is the last one if no bytes follow it.
3. For each chunk `i`, decrypt with `nonce(i, i == n − 1)` and `AAD`. A tag failure rejects the blob with `bad-tag`.
4. Any byte after chunk `n−1` rejects with `trailing-data`.
5. Unpad (§1.2). A malformed pad rejects with `bad-padding`.
6. If the reference carries `size`, the unpadded length MUST equal it (`size-mismatch`). If it carries `digest`, the plaintext's digest MUST equal it (`digest-mismatch`).
7. When the whole blob was fetched, its CID MUST equal the reference's CID (`cid-mismatch`). This check comes first in practice: a client hashes while it downloads and discards a blob whose CID is wrong before trying to decrypt it.

Partial reads skip step 7 and rely on the chunk tags. Steps 1 through 4 together are what the conformance vectors exercise.

### 1.6 What is authenticated, and what that buys

| Property | Mechanism |
| --- | --- |
| Chunk contents and length | GCM tag over the chunk ciphertext |
| Chunk position | Nonce carries the chunk index; a chunk moved to another index fails its tag |
| End of file | Nonce carries the last-chunk flag; dropping trailing chunks makes a middle chunk decrypt as "last" and fail |
| No extension | Bytes after the last chunk are rejected; a chunk appended after the last one would also carry a wrong flag |
| Header (format byte, and the salt for format 2) | In the AAD of every chunk; a swapped salt fails every tag even before the derived key is wrong |
| Not swappable between files | Every file has its own key, so a chunk from file A fails under file B's key |
| Whole-blob integrity | The CID over the entire ciphertext, checked whenever the whole blob is fetched |

Not authenticated by the blob itself: the metadata in the reference (name, type, size, digest). That metadata is authenticated by the MLS message or the sealed blob that carries the reference.

Resistance to the three attacks the prompt names:

- *Truncation.* The stream ends after chunk `k < n−1`. The reader treats chunk `k` as last and uses `flags = 0x01`, but it was encrypted with `0x00`. The tag fails.
- *Reordering.* Chunks `i` and `j` are swapped. Each is decrypted with the other's nonce. Both tags fail.
- *Swapping chunks between files.* Chunk `i` of file A replaces chunk `i` of file B. The key differs, so the tag fails. If an attacker reuses one key for two files, the attacker is the author of both and gains nothing.

### 1.7 Size limits

A blob has at most 2³² chunks (the GCM invocation limit per key, SP 800-38D), which is 256 TiB. Beyond that the format has no ceiling. Limits come from manifests: the `blob-store` manifest's `maxBlob` (§7) and the context's storage policy. Phones MUST refuse to seal a plaintext larger than the smaller of the two, and stores MUST reject a put larger than their `maxBlob` with `413`.

There is no format that seals to a public key. A blob meant for someone who holds no keyring, such as a members-only release table from an aggregator, is a format 1 blob whose direct-form reference is then wrapped by the sender's own means (`release.md`'s HPKE keybox, §9.1).

## 2. Content IDs

A CID is one algorithm byte followed by a digest, exactly as in `manifest.md`. `0x01` is SHA-256. The text form is `c` followed by lowercase unpadded base32.

| Blob class | CID is `0x01 || SHA-256(…)` over |
| --- | --- |
| Sealed | The whole sealed blob, format byte included |
| Public | The plain bytes |

A store recomputes the CID of every put and rejects a mismatch (§6.3). A sealed blob is always put with `Content-Type: application/vnd.hum.sealed`; the plaintext's media type (`image/jpeg`, `application/vnd.hum.mls-key-package`, and so on) lives only in the reference and never reaches the store. A store can therefore check what it holds without being able to read it.

Public blobs carry a media type. The CID does not cover it. The store records the type declared at put and serves it as `Content-Type`, but a client MUST take the media type from the manifest or reference that pointed it at the blob, never from the store. The store accepts only the media types listed in its `blob-store` manifest (§7).

The *plaintext digest* of a sealed blob is `0x01 || SHA-256(plaintext)`. It is written in the same form as a CID on purpose: it is exactly the CID the plaintext would have as a public blob. Promotion (§9) relies on that.

## 3. The sealed reference

A sealed reference is the only thing that carries a blob's key. It travels inside an MLS application message or inside another sealed blob, never in a manifest, a log, a store request, or a URL. It is a deterministic CBOR map.

### 3.1 Fields

| Key | Field | Type | Required | Meaning |
| --- | --- | --- | --- | --- |
| 0 | cid | bstr (33) | yes | CID of the sealed blob |
| 1 | format | uint | yes | The blob's format byte: 1 (direct) or 2 (keyring) |
| 2 | key | bstr (16) | direct form | The AES-128 key |
| 3 | size | uint | message form | Plaintext length `L` in bytes |
| 4 | media | tstr (≤ 127 bytes) | yes | Media type of the plaintext, such as `image/jpeg` |
| 5 | name | tstr (≤ 255 bytes) | optional, message form only | File name, NFC-normalized, no `/` or NUL |
| 6 | digest | bstr (33) | message form | Plaintext digest (§2) |
| 7 | expires | uint | optional | Seconds since the epoch when the store will delete the blob; absent when retention is "until deleted" |
| 8 | store | bstr (33) | optional | CID of the `blob-store` authority the uploader used; a hint for which of the context's stores to try first |
| 9 | description | tstr (≤ 1,024 bytes) | optional, message form only | Alt text or caption |
| 10 | epoch | uint | keyring form | Keyring epoch whose secret derives the key (§4.3) |

A reference has exactly one of two forms:

- **Direct form:** `format` is 1 and `key` is present; `epoch` is absent. Used in chat attachments, folder operations, folder indexes, history archives, and references nested inside other sealed blobs.
- **Keyring form:** `format` is 2 and `epoch` is present; `key` is absent. The salt lives in the blob's header, not in the reference, so a manifest needs only the CID and the epoch. Used in manifest bodies that pin a sealed blob (issue, position, argument in members-only contexts). A keyring-form reference MUST NOT carry `name`, `description`, `size` or `digest`, because manifests are logged in public and those fields describe a person's words. The media type is allowed because it is one of a short list.

In practice a manifest body does not embed this map. `issue-map.md` carries `refs.text` (the CID) and a body field `epoch`, which is the keyring form spelled out as two fields. A client builds the reference `{cid, format: 2, epoch, media}` from them.

"Message form" above means a direct-form reference inside a message or sealed blob: there `size` and `digest` are required. A phone MUST reject a reference that has both forms, neither, a `format` that does not match the form, or any field outside these constraints. The encoded reference MUST be at most 2,048 bytes.

Readable view of a chat attachment's reference:

```json
{
  "cid": "c3k9qp…x2m",
  "format": 1,
  "key": "9f3c…(16 bytes)",
  "size": 48213,
  "media": "image/jpeg",
  "name": "porch.jpg",
  "digest": "c7d1wa…n4q",
  "expires": 1799035200
}
```

### 3.2 Mapping onto the MIMI ExternalPart

`chat.md` carries attachments as an ExternalPart from draft-ietf-mimi-content and fixes the mapping in its §5.1. This table restates it. The CBOR map above is the normative form; the ExternalPart is a framing of it.

| ExternalPart field | Hum reference field | Note |
| --- | --- | --- |
| `contentType` | media | Same string |
| `url` | cid | `hum:blob:` followed by the CID text form (`chat.md` §5.1); phones ignore any other scheme |
| `expires` | expires | Absent maps to 0 |
| `size` | size | Plaintext length |
| `encAlg` | format | Format 1 maps to AEAD id 1 (AES-128-GCM); format 2 never appears in a message |
| `key` | key | 16 bytes |
| `nonce` | — | Empty: nonces are derived from chunk index (§1.3) |
| `aad` | — | Empty: the AAD is fixed by the format |
| `hashAlg` | digest[0] | `0x01` maps to hash id 1 (SHA-256) |
| `contentHash` | digest[1..] | The 32 digest bytes |
| `description` | description | |
| `filename` | name | |

Fields with no ExternalPart counterpart (`store`, `epoch`) have none because keyring-form references never appear in chat messages, and `store` is a hint chat may drop.

Reverse rule: a phone MUST ignore an ExternalPart whose `encAlg` is not 1, whose `hashAlg` is not 1, whose `key` is not 16 bytes, whose `nonce` or `aad` is not empty, whose `contentHash` is not 32 bytes, or whose `url` is not `hum:blob:` followed by the text form of a 33-byte CID. Vectors `external-part-bad-*` in §12 cover each case.

### 3.3 Re-sharing

Re-sharing a file means re-sending its reference. Pinning an attachment to a folder sends the same reference as a folder `add` operation. Citing it on the issue map nests the reference inside the argument's sealed text. The bytes are uploaded once and stored once. A reference never changes the blob it names; a new version of a file is a new blob with a new reference.

## 4. Keyrings

A context keyring is a list of epoch secrets held by members' phones. It exists so that a manifest can pin a sealed blob that every member can read without a key appearing in the manifest.

### 4.1 Epochs

Keyring epoch 1 is created when the context group (`chat.md`'s name for the all-members MLS group) is created. The keyring advances to epoch `k + 1` on every MLS commit to the context group that removes at least one leaf. Commits that only add leaves or update keys do not advance it, so a newcomer never makes existing manifest-sealed text unreadable for anyone. No other event advances it in this draft; see assumption A4 for explicit rotation.

Each member derives the secret for epoch `k` from the MLS exporter at the epoch of the commit that created it:

```
secret_k = MLS-Exporter(label = "hum/keyring/1", context = empty, length = 16)
```

The label, context and length are the ones `chat.md` §1.2 fixes. The epoch number `k` is not in the context: the MLS epoch already makes every export distinct.

A phone MUST export `secret_k` while it processes that commit and store it, because the exporter secret of a past MLS epoch is not recoverable later. A keyring entry is `(k, mls_epoch, secret_k)`. Members present at the commit all derive the same secret with no coordination. A member removed by that commit cannot derive it.

### 4.2 Reaching newcomers

A phone that joins after epoch `k` was created cannot export `secret_k`. It receives it in a `keyring-share` message.

- After any commit that adds leaves to the all-members group, the committing phone MUST send a `keyring-share` application message in the group. The newcomer can decrypt it because it was sent in an epoch they belong to.
- Payload (deterministic CBOR): `{0: [[k, mls_epoch, secret_k], …]}`, entries sorted by `k`.
- Which entries are included follows the context's `storage.keyringHistory` (`context.md`): `0` (the default) sends every epoch; `1` sends only the current epoch. The current epoch is always included, since without it the newcomer cannot read any current manifest-sealed text. This setting is separate from the message-history policy `storage.history`, because the keyring also unlocks issue-map text, which is current state.
- A phone accepts a `keyring-share` only from the leaf that committed its own Add (for its first share) or from a leaf whose chat identity holds the `members` capability. Shares from anyone else are ignored and noted for moderators. Vector `keyring-share-unauthorized-sender`.
- A phone MUST ignore a `keyring-share` entry whose `k` it already holds with a different secret, and MUST flag the sender, unless the entry it holds is marked suspect (below) and the new one comes from a `members` holder, in which case the new one replaces it. Vector `keyring-share-conflicting-secret`.
- A phone that fails a tag on a format 2 blob under a shared secret marks that entry suspect and asks any `members` holder for a re-share. Any member MAY send a `keyring-share` holding only the current epoch to a newcomer that asks, and a newcomer with no current-epoch entry after its first fetch asks for one.
- A `keyring-share` is never written to a history archive, and neither is a `folder-index` announcement. Archives (`chat.md` §10.1) carry only channel content; the all-members and organizers groups are never archived.
- A new device of an existing member is a newcomer leaf and is handled the same way.

### 4.3 Deriving a blob key from the keyring

A format 2 blob carries a 16-byte random `salt` in its header (§1.1), and its reference names the keyring `epoch`. The blob key is:

```
prk = HKDF-Extract(salt = salt, IKM = secret_epoch)          # RFC 5869, SHA-256
key = HKDF-Expand(prk, info = "hum/keyring-blob/1", L = 16)
```

The salt is fresh for every blob, so two blobs sealed under the same epoch never share a key, and the nonce scheme of §1.3 stays safe. The salt is public; the secret is the HKDF input keying material, and the AAD binds the salt to every chunk. The phone that writes a manifest-sealed object seals under the current keyring epoch. Objects sealed under earlier epochs are not re-sealed when the keyring advances; members who hold the earlier secret keep reading them. (`issue-map.md` describes the key as derived from the epoch and the blob's CID; that is not possible, because the CID depends on the ciphertext, which depends on the key. The salt in the header is what replaces it, and it needs no change to the issue-map body.)

A keyring epoch secret is never used as an AES key directly, even though it is 16 bytes long. Using the exporter output as the key for more than one blob would repeat nonces under one key, which breaks GCM.

### 4.4 Other uses of the exporter

No other secret is exported under the `hum/keyring/1` label, and `hum/keyring/1` and `hum/delivery/1` are the only MLS exporter labels in Hum (`chat.md` §1.2). The members-only results key is not an exporter label and involves no exporter call: `context.md` derives it from the keyring epoch secret, `seed = HKDF-Expand(HKDF-Extract(salt = "", IKM = secret_k), info = "hum/results-key/1", 32)`, X25519-clamped. That is why a newcomer who receives epoch `k` through `keyring-share` can also open releases sealed to `k`, and why `hum/keyring-blob/1` and `hum/results-key/1` must stay distinct info strings under the same secret. The `hum/keyring/1` export is never used directly as an AES key, only as HKDF input.

## 5. Folders

A folder is a channel: an MLS group of kind `folder` whose application messages are `file-op` messages. `chat.md` §5.7 fixes the bytes of a `file-op`; this section defines what phones do with them: the folder state, the conflict rules, the index snapshot, and versions. Ordering, authorship and read access come from MLS and from the delivery service's per-channel sequence numbers (`chat.md` §4.4).

### 5.1 Files and versions

A *file* is identified by the 16-byte random `file` id its `add` (or `pin`) assigned, stable across renames, moves and versions. A file has a *name*, a *path* (an array of sub-folder names, depth at most 16; empty means the folder root) and one or more *versions*. A version is identified by the message id of the `file-op` that added it and carries one direct-form sealed reference (the `ExternalPart`). The *current version* is the last one in sequence order. Sub-folders are not entries; they exist because some file's path names them.

### 5.2 Operations

`file-op` fields (`chat.md` §5.7): `v`, `op`, `file`, `name`, `path`, `prev`, `origin`, plus one `ExternalPart` for ops 1, 4 and 6.

| op | Name | Effect on folder state |
| --- | --- | --- |
| 1 | `add` | Creates the file with `name`, `path` and a first version from the `ExternalPart` |
| 2 | `rename` | Sets `name` |
| 3 | `move` | Sets `path` |
| 4 | `new version` | Appends a version; `prev` names the version the sender saw as current |
| 5 | `delete` | Removes the file from the folder |
| 6 | `pin` | Like `add`, with the reference copied from the message `origin` in another channel |
| 7 | `unpin` | Like `delete`, for a pinned file |

A `file-op` with a `v` other than 1, an unknown `op`, a missing required field, or the wrong number of `ExternalPart`s is ignored. The `ExternalPart` MUST map to a valid direct-form reference (§3); otherwise the op is ignored.

### 5.3 Who may do what

Read access is membership in the folder's MLS group. Write rights are the context capabilities in `chat.md` §3.1: `files-write` for `add`, `rename`, `move`, `new version`, `pin`, `unpin` and `delete` of the sender's own files; `files-delete-any` for `rename`, `move`, `new version` and `delete` of another member's file. "Own" means the sender's chat identity created the file. `chat.md` §3.1 states the same own-or-other split. A phone applies an operation only if the sender holds the right for it; otherwise it ignores the message and keeps a local note for moderators. Because the delivery service cannot read these messages, enforcement happens on every phone, and every honest phone reaches the same state.

### 5.4 Applying operations and resolving conflicts

Phones apply operations in the channel's sequence order. The rules below make every phone compute the same folder state from the same sequence and the same rights. Rights come from `roles` messages in the context group, a different channel with its own order, so two phones can transiently evaluate the same op against different `roles` serials. A phone evaluates rights against the highest `roles` serial it holds when it applies the op. When a later `roles` message lowers a member's rights, the phone re-derives the folder from the last `folder-index` it trusts, replaying ops after it under the rights now known. Phones may therefore differ until both have the same `roles` serial, and converge after. The `folder-rights` vector states the `roles` input it assumes.

1. An operation is applied at most once, keyed by its message id.
2. `add` or `pin` with a `file` id that already exists, deleted or not, is ignored.
3. `rename`, `move`, `new version`, `delete`, `unpin` on a `file` that does not exist or is deleted is ignored.
4. `new version` is appended whatever `prev` says. A `prev` that is not the current version means two members uploaded concurrently; both versions are kept, in sequence order, and the UI marks the older one as "also uploaded". Phones never drop a version to resolve this.
5. Two files may share a name and path. Phones do not rename them; the UI shows the creator and date to tell them apart. (Auto-renaming would depend on arrival order and break determinism.)
6. A path element that is empty, contains `/` or NUL, or is longer than 255 bytes, or a path deeper than 16, makes the op ignored.
7. `delete` and `unpin` remove the file from the folder. They do not delete any blob at the store; that is the author's or the context's separate decision (§8). A removed file's references stay on members' phones until the blob is gone.
8. Deleting one version only is not a folder operation. The author deletes that version's blob at the store with its delete secret; phones that get `410` for it show the version as removed (§8.4).

### 5.5 The index snapshot

So newcomers do not replay every operation, a phone snapshots the folder into a sealed blob and announces it with a `folder-index` message (`chat.md` §5.7: a body `{0: v, 1: seq}` plus exactly one ExternalPart carrying the snapshot below). The `seq` in the body MUST equal the `seq` inside the snapshot.

- The snapshot plaintext is deterministic CBOR, media type `application/vnd.hum.folder-index+cbor`:

```
{
  0: seq        (uint, the DS sequence number of the last file-op included),
  1: files      ([file, …], sorted by file id)
}
file = {
  0: id         (bstr 16),
  1: name       (tstr),
  2: path       ([tstr, …]),
  3: created_by (bstr 32, the creator's chat identity key),
  4: versions   ([version, …] in sequence order)
}
version = { 0: ref (sealed reference, direct form), 1: added_by (bstr 32, chat identity key), 2: msg (bstr 32, MIMI message id of the op), 3: seq (uint) }
```

- Deleted files are not in a snapshot. A newcomer applies only operations with a sequence number above `seq`, so earlier tombstones are not needed.
- A phone that commits an `add` of a member to the folder group MUST announce an index after the commit, with a snapshot current as of that moment. That is how a newcomer gets the folder's state and every file key in it. Reading a folder means being in its group; no separate key exchange exists.
- Any phone with `files-delete-any` MAY announce an index at other times, for example after every 500 operations. Phones ignore a `folder-index` from a sender with neither that capability nor the Add commit it follows.
- A phone that holds a snapshot and sees one whose `seq` is lower than its own state ignores it.
- A phone loading a folder takes the latest index it can decrypt, then applies later operations from the channel queue or a history archive (`chat.md` §10).

### 5.6 Versions in the UI

The UI shows the current version and a history of earlier ones with their `added_by` and time. Earlier versions stay readable until their blobs are deleted or expire.

## 6. Blob-store API

The store speaks HTTP. Every request from a phone goes through an OHTTP relay (RFC 9458), so the store never sees a phone's address. Every request that touches a sealed blob, and every put, carries a Privacy Pass token (RFC 9576 architecture, RFC 9577 HTTP authentication, RFC 9578 issuance) issued for one context. The store learns which context, never which member, which channel, or what the bytes mean.

### 6.1 Tokens

- **Type:** publicly verifiable tokens, RFC 9578 token type `0x0002` (blind RSA, RFC 9474, 2048-bit). The store verifies a token with the issuer's public key alone, so the issuer can be the store itself or a separate issuer the operator runs, as `services.md` rule T-3 expects. The store's `service` manifest names the issuers it accepts in `tokenIssuers`.
- **One issuer key per context.** The issuer keeps a key pair for each context that names the store. The token's `token_key_id` therefore tells the store which context's quota a request counts against. The context is identified by the key, not by token metadata; RFC 9578 tokens carry none, and this draft depends on no metadata extension.
- **Key consistency.** A unique key per *member* would turn tokens into identifiers. Two defenses: the issuer rotates a context's key at most every 30 days and publishes the current key in its issuer directory (RFC 9578 §4); and phones in the context post the current `token_key_id` in the all-members group (`chat.md` §5.15 `token-key`, at most daily per device), as they already do for log checkpoints. A phone that sees a different key than its peers stops using the store and shows a warning.
- **Challenge.** Tokens are issued in advance against a fixed `TokenChallenge` the phone builds itself: `token_type = 0x0002`, `issuer_name` = the issuer name from the store's manifest (§7), empty `redemption_context`, empty `origin_info`. No challenge round-trip is needed, and one token fits any request to that store for that context.
- **Issuance** (§6.2) requires a membership proof for the context. Issuance and redemption are unlinkable by the blinding in the blind signature, and when the issuer is separate from the store the store never sees a membership proof at all.
- **Single use.** The store keeps the nonce of every redeemed token for the lifetime of the issuing key, and rejects a repeat with `401 token_spent`, code only.
- **Rate limits.** Issuance is the limiter: at most `tokensPerMemberDay` (store manifest; a ceiling the store may lower) per membership proof per day. The membership proof is the per-context anonymous proof from `credentials.md`, scoped to `hum/blob-tokens/1` ‖ `token_key_id` (32 raw bytes) ‖ `day` (uint64 big-endian, `floor(now / 86400)`), so the issuer counts issuances per pseudonym without learning the pseudonym's other activity (assumption A6). Each token buys one request. There is no per-request byte cap beyond `maxBlob`; per-context byte quotas (§6.6) do the rest.

A request's token goes in the `Authorization` header as RFC 9577 defines: `Authorization: PrivateToken token="<base64url Token>"`. Rule T-4 of `services.md` applies: an issuance request and a request that spends a token never share a connection.

### 6.2 Issuance

```
POST /v1/tokens
Content-Type: application/cbor
```

Body:

```
{
  0: context   (bstr 33, CID of the context version the phone holds),
  1: proof     (bstr, membership proof for this context, scope as §6.1, bound message SHA-256 of the canonical CBOR of `requests`),
  2: requests  ([bstr, …], 1 to 64 RFC 9578 TokenRequest structures)
}
```

Response `200`, `application/cbor`: `{0: [bstr, …]}`, one RFC 9578 TokenResponse per request, in order. Issuing up to 64 at once is a Hum extension over the one-at-a-time issuance protocol; each element is an unmodified RFC 9578 exchange. This matches the endpoint shape `services.md` assumes.

The issuer resolves the context version through a log it trusts (manifest spec, verification steps 1–8), checks that it is the latest version of its lineage the issuer knows of, and checks that its body names this store's authority in `stores`. The store applies the storage policy of that version (`storage.retention`, `maxBlob`, `quota` from `context.md`) to every request made with a token under that key, which is what `context.md` means by "the context version a token was issued against". A newer context version takes effect when the issuer next rotates the key or when the store learns of the version, whichever is first. The issuer then verifies the proof and counts it against the per-day issuance limit. Errors: `404 not_found` if the context does not name this store or the version is not the latest; `401 unauthorized` if the proof fails; `429 rate_limited` if the day's issuance limit is spent.

The issuer directory is served at `/.well-known/private-token-issuer-directory` as RFC 9578 §4 describes. One entry per context key, each with its `token-key` and `token_key_id`, plus an extension member `hum-context` holding the context lineage CID in text form, so a phone can pick its key before building a `TokenRequest`. Contexts are public in the log, so this reveals nothing new. A phone that sees a `token_key_id` in the directory that differs from the one its peers gossiped for the same day MUST NOT request tokens under either and shows the warning of §6.1; a `members` holder can switch the context to another store.

A tightened context policy reaches the store late: up to `issuer.rotation` (30 days) after the new version is logged, if the store does not learn of it sooner. Phones enforce the new version at once, so the lag only widens what a modified client can do, and only within the old policy.

### 6.3 Put

```
PUT /v1/blobs/{cid}
Authorization: PrivateToken token="…"
Content-Type: application/vnd.hum.sealed | <public media type>
Content-Length: <bytes>
Hum-Retention: <seconds, or 0 for until-deleted>
Hum-Delete: <64 hex chars, the delete commitment (§8.1)>
```

The body is the blob. The store streams it, hashes it, and compares with `{cid}`.

Responses use the common error format of `services.md` (a CBOR map with `code` and a fixed `detail` string; §6.7). The `detail` strings for this endpoint are listed here.

- `201 Created` with an empty body when stored. The response echoes `Hum-Expires: <seconds since epoch>` when retention is finite.
- `200 OK` if the store already held this CID for this context. The put changes nothing: no new delete commitment, no retention change, no new bytes. Otherwise any member who can fetch a sealed blob could re-put it and delete it with a secret of their own. The one exception: a re-put that carries `Hum-Delete-Secret` matching the tuple's existing commitment may extend the retention to the later of the two declared values (capped by policy). Vector `store-reput-no-new-commitment`.
- `409 conflict`, detail `cid_mismatch`, if the recomputed CID differs. The store discards the bytes.
- `409 conflict`, detail `media_type`, if the CID exists as a public blob with a different declared media type.
- `409 conflict`, detail `class`, if the CID exists in the other class.
- `410 closed`, detail `tombstoned`, if the CID is in the tombstone list (§8.4).
- `413 too_large` if `Content-Length` exceeds the smaller of the store's `maxBlob` and the context's `maxBlob`, or the request has no `Content-Length`.
- `415 malformed`, detail `format`, if a public media type is not in the store's `formats` list, or a sealed blob's first byte is not a supported format byte.
- `422 rejected`, detail `retention`, if `Hum-Retention` exceeds the context's maximum (§8.3), or is 0 when the context sets a maximum.
- `422 rejected`, detail `commitment`, if `Hum-Delete` is missing or not 32 bytes of hex.
- `429 rate_limited`, detail `quota_stored` or `quota_put`, if the context's stored-byte quota or daily put quota would be exceeded.

**Puts by services.** Aggregators upload release tables and have no membership proof to get a token with. A put MAY instead carry an `authority` signature as `services.md` defines (`Hum-Authority` header: one COSE_Sign structure over the A-1 request hash with external AAD `hum/service-request/1`, meeting the signer's `sign` threshold) together with a `Hum-Context: <context version CID>` header. The store accepts it only when the signing authority is the context authority itself or one of the aggregator authorities the named context version lists; otherwise `403 forbidden`, detail `signer`. Aggregators may put either class, because members-only releases seal their tables (`release.md`); the context authority may put class `public` only. The blob counts against that context's quota and carries a delete commitment like any other put. Every other sealed put needs a token.

**Order of checks.** The store runs them in this order and stops at the first failure: token (or `authority` signature); `Content-Length` against `maxBlob`; `Hum-Delete` syntax; retention against policy; stream and hash the body; CID mismatch; class conflict; media type conflict; tombstone, for this context only; quota. Hashing before the tombstone check means a put with a junk body can never learn whether a CID was deleted, and "this context only" means a CID tombstoned in another context is accepted (vector `store-put-tombstone-other-context`, expecting `201`).

A sealed blob's class is `sealed` when `Content-Type` is `application/vnd.hum.sealed`; otherwise it is `public`. The store records, per `(cid, context)` tuple: class, media type (public), size, retention, upload time, delete commitments. It records nothing about the token beyond the fact of its redemption. A tuple holds exactly one delete commitment, the one from the put that created it.

### 6.4 Get and range get

```
GET /v1/blobs/{cid}
Authorization: PrivateToken token="…"         (required for sealed blobs)
Range: bytes=<first>-<last>                    (optional, one range)
```

- `200` with the bytes, `Content-Length`, and for public blobs `Content-Type` as declared.
- `206 Partial Content` with `Content-Range` for a single satisfiable byte range. Multi-range requests get `416`. A range beyond the end gets `416`.
- `HEAD` behaves like `GET` without a body, under the same rules.

Visibility rules, which exist so that nobody without a token for the right context can tell whether a sealed CID exists:

| Request | Blob state | Response |
| --- | --- | --- |
| No token | Public blob exists | `200` / `206` |
| No token | Anything else (sealed, absent, tombstoned) | `401 unauthorized`, code only |
| Valid token, context C | Public blob exists | `200` / `206` |
| Valid token, context C | Sealed blob held for C | `200` / `206` |
| Valid token, context C | Sealed blob held for another context only, or absent | `404 not_found`, code only |
| Valid token, context C | Tombstoned for C within the tombstone window | `410 closed`, detail `tombstoned` |
| Invalid or spent token | Any | `401 unauthorized` or `401 token_spent`, code only |

This is rule E-2 of `services.md` applied to blobs. The `401` and `404` responses are byte-identical for every case they cover and take the same time to produce. A store that serves public blobs also lets mirrors and the resolver fetch them without a token; mirrors are defined in `services.md`.

Clients verify every full fetch against the CID before using the bytes, and every range by chunk tag. A store that serves wrong bytes is detected on the first chunk.

### 6.5 Delete

```
DELETE /v1/blobs/{cid}
Authorization: PrivateToken token="…"
Hum-Delete-Secret: <64 hex chars>              (author's delete, §8.1)
```

or

```
DELETE /v1/blobs/{cid}
Authorization: PrivateToken token="…"
Content-Type: application/vnd.hum.delete-order+cbor
<body: a signed delete order, §8.2>
```

- `204` when the `(cid, context)` tuple is removed. When no tuple remains, the bytes are deleted and the CID enters the tombstone list.
- `204` also when the tuple was already gone within the tombstone window (idempotent).
- `403 forbidden`, detail `secret`, if the secret's commitment is not the tuple's commitment.
- `403 forbidden`, detail `order`, if the order's signatures do not meet the context's sign threshold, or the order does not list this CID.
- `404 not_found`, code only, under the same rules as get.

The token names the context; a secret or an order deletes that context's tuple only. For an order, the store MUST check that the context the token's key belongs to has the order's `authority` as its context authority; otherwise `403 forbidden`, detail `order`. Vector `delete-order-wrong-context`.

### 6.6 Quotas and limits

The store enforces, per context: bytes stored (`storage.quota` from the context, capped by the store's `quotaStored`), bytes put per day, bytes served per day, and tokens issued per member per day. Defaults come from the store's manifest (§7); the context's storage policy may set lower values, never higher. The store answers `429 rate_limited` with `retryAfter` and a `quota_*` detail naming the quota.

### 6.7 Errors

Error bodies use the one format `services.md` ("Errors") defines for every service: a deterministic CBOR map `{0: code, 1: detail?, 2: step?, 3: rule?, 4: retryAfter?}` with media type `application/vnd.hum.error+cbor`. Codes come only from that spec's table; this spec adds `detail` strings:

| Code | HTTP | Details this spec adds | Where |
| --- | --- | --- | --- |
| `conflict` | 409 | `cid_mismatch`, `media_type`, `class` | §6.3 |
| `closed` | 410 | `tombstoned` | §6.3, §6.4 |
| `malformed` | 415 | `format` | §6.3 |
| `rejected` | 422 | `retention`, `commitment` | §6.3 |
| `forbidden` | 403 | `secret`, `order`, `signer` | §6.3, §6.5, §8.2 |
| `rate_limited` | 429 | `quota_stored`, `quota_put`, `quota_served`, `quota_tokens` | §6.3, §6.6 |
| `too_large` | 413 | none | §6.3 |

No member of an error ever echoes a CID, a key, a token or any request field. The `401` and `404` responses carry the code and nothing else, because a detail could differ between the cases they must hide.

### 6.8 What the store sees

| Sees | Never sees |
| --- | --- |
| Ciphertext and padded sizes | Plaintext, names, media types of sealed blobs |
| Which context a blob counts against | Which member uploaded or fetched it |
| Timing of requests, through the relay | A phone's IP address, or which requests share a phone |
| Delete commitments and secrets | Why something was deleted |
| Per-context counters | Which channel or folder a blob belongs to |

Stores MUST NOT log request bodies, tokens, or anything beyond per-context counters and per-key redeemed nonces. The conformance suite checks the reference store's log output for the absence of CIDs and token bytes.

## 7. The blob-store manifest body

A store is an authority (a keyset lineage) that publishes a `service` manifest with `kind: blob-store` (`services.md`, ADR 0072). Contexts name stores by this authority's CID. The common `service` fields use keys 0 to 15 and are defined in `services.md`; this spec says which of them a store needs and defines the store's own fields from key 16. The manifest spec's registry lists `service` and retires the older type name `blob-store`.

Full key table for a store:

| Key | Field | Type | Required | Frozen | Meaning |
| --- | --- | --- | --- | --- | --- |
| 0 | kind | tstr | yes | yes | `blob-store` |
| 1 | endpoints | [tstr] | yes | no | HTTPS URL prefixes, hints only (`services.md`) |
| 2 | apiVersion | uint | yes | no | 1 |
| 3 | ohttp | bstr | yes | no | OHTTP gateway key configuration (RFC 9458 §3); phones reach a store only through the relay |
| 4 | tokenIssuers | [bstr 33] | yes | no | Keyset authorities whose tokens the store accepts; may include the store itself |
| 5 | limits | map | optional | no | Rate limits, as `services.md` defines |
| 8 | jurisdiction | tstr | optional | no | ISO 3166 country or region where the bytes are held |
| 9 | retention | map | optional | no | Retention of the store's own logs, as `services.md` defines |
| 16 | issuer | {0: name (tstr), 1: type (uint), 2: rotation (uint)} | yes | `name` yes; rest no | Privacy Pass issuer name for the TokenChallenge, token type (2), and the longest a per-context key stays in use, in seconds |
| 17 | blobLimits | {0: maxBlob, 1: quotaStored, 2: quotaPutDay, 3: quotaServedDay, 4: tokensPerMemberDay} (uint) | yes | no | Hard ceilings and per-context defaults, bytes or counts |
| 18 | blobRetention | {0: max (uint seconds, 0 = unlimited), 1: tombstone (uint seconds)} | yes | no | The longest retention the store honors, and how long a deleted CID stays tombstoned |
| 19 | formats | {0: sealed ([uint]), 1: public ([tstr])} | yes | `sealed` may only grow | Supported sealed format bytes and public media types |

Keys 6, 7, 10 and 11 belong to other kinds and MUST be absent. Keys 12 to 15 are reserved by `services.md`.

Validation rules (verification step 10 for a store, after `services.md` rules S-1 to S-8; S-5 requires a well-formed `ohttp` key configuration and S-6 requires `tokenIssuers` and the key 16 `issuer` map):

| Rule | Check | Failing vector |
| --- | --- | --- |
| BS-1 | `issuer.type` is 2 (presence of `tokenIssuers` and `issuer` is S-6) | `service-blob-store-bad-token-type` |
| BS-2 | `blobLimits.maxBlob` ≥ 65,536 and every `blobLimits` field is present | `service-blob-store-small-maxblob` |
| BS-3 | `formats.sealed` contains 1 and 2, and `formats.public` is non-empty | `service-blob-store-formats` |
| BS-4 | `blobRetention.tombstone` ≥ 86,400 | `service-blob-store-short-tombstone` |
| BS-5 | Between versions, `issuer.name` is unchanged and `formats.sealed` loses no value | `service-blob-store-name-changed`, `service-blob-store-format-dropped` |
| BS-6 | No key from 6, 7, 10, 11 is present | `service-blob-store-foreign-key` |

`issuer.name` is frozen because phones build a fixed TokenChallenge from it and the store recomputes the same challenge at redemption; a changed name would invalidate every token in flight. The passing vector is `service-blob-store-valid`. Clients act on the version in force at their latest checkpoint. Phones treat `blobLimits.maxBlob` and `blobRetention.max` as ceilings on top of the context's policy and take the smaller.

Draft defaults for the reference store: `maxBlob` 2 GiB, `quotaStored` 50 GiB per context, `tombstone` 30 days, `tokensPerMemberDay` 5,000, `issuer.rotation` 30 days, `formats.public` = `application/vnd.apache.parquet`, `text/plain; charset=utf-8`, `application/cbor`, `application/json`, `application/vnd.hum.keybox+hpke`, `image/png`, `image/jpeg`, `image/webp`.

## 8. Deletion and retention

Three things delete a blob: the author's secret, a context order, and the retention clock. Deleting the ciphertext makes every copy of its key useless, which is the only recall the design can offer once a reference has been sent.

### 8.1 The author's delete secret

At upload the phone draws a 32-byte random `delete_secret`, keeps it in the device keystore keyed by the blob's CID, and sends the commitment:

```
commitment = SHA-256("hum/delete/1" || delete_secret)
```

Presenting `delete_secret` later (§6.5) deletes the blob. The secret is never derived from the file key, so a recipient who holds the reference cannot delete the file. It is never sent anywhere except the delete request. It is per upload: a phone MUST NOT reuse a delete secret for two blobs. The reference implementation's failing vector `delete-reused-secret` presents blob A's secret for blob B and expects `403 forbidden`, detail `secret`.

A lost phone loses its delete secrets. The context order remains.

### 8.2 Context delete orders

A context deletes with a signed order. It is not a manifest and is not logged, because logging deletions would publish a context's activity. It is a deterministic CBOR map:

| Key | Field | Type |
| --- | --- | --- |
| 0 | spec | uint, 1 |
| 1 | authority | bstr (33), the context authority's CID |
| 2 | cids | [bstr (33), …], 1 to 1,024 entries, sorted bytewise |
| 3 | issued | uint, seconds since epoch |
| 4 | expires | uint, seconds since epoch; at most `issued` + the store's `blobRetention.tombstone` |

Signatures: COSE_Sign (RFC 9052) with a detached payload, Ed25519, one signature per signer, exactly as manifests are signed. The signed payload is the ASCII string `hum/blob-delete/1` followed by `SHA-256(canonical order bytes)`. The store verifies against the keyset of `authority` in force at the store's latest witnessed checkpoint, and requires the `sign` threshold. The body sent to the store is `{0: order (bstr, canonical bytes), 1: signatures ([bstr, …])}`.

The order is a standalone signed object rather than the per-request `authority` signature of `services.md`, for two reasons: a context's sign threshold is often 2-of-3, and the phone that carries the order to the store (with an ordinary token) is usually not a signer. The order can be signed by organizers on different phones, assembled, and sent by anyone.

A store that receives a valid order deletes every listed CID it holds for that context and ignores CIDs it does not hold. It rejects an order whose `expires` has passed, or whose `expires` exceeds `issued` plus its tombstone window, with `403 forbidden`, detail `order`, so a replayed order cannot delete a CID that was legitimately re-uploaded after the window. Within its validity an order is idempotent and may be re-sent to a second store.

### 8.3 Retention

The phone declares a retention in seconds at upload. The context's `storage.retention` (`context.md`) sets a maximum per kind of blob: 0 attachment, 1 folder file, 2 history archive, 3 issue-map text and evidence, 4 release table, where 0 seconds means keep until deleted. The store cannot tell kinds apart, so it enforces the largest of the five (unlimited if any kind is unlimited); the phone enforces the per-kind one, and the conformance suite checks that a client never declares more than its kind allows. A declared retention above the store's own `blobRetention.max` is also rejected. The store deletes the tuple at `uploaded + retention` and treats that like any other deletion. The reference's `expires` field tells recipients when that will happen, so the UI can say "expires in 3 days".

### 8.4 Tombstones and what clients show

When the last tuple for a CID is removed, the store keeps the bare CID in a tombstone list for `retention.tombstone` seconds and answers `410` to gets and puts from any context that held it. A tombstone stops a recipient from re-uploading ciphertext they kept and reviving the author's deleted file under the same reference. After the window, the CID is forgotten and could be uploaded again; this is a known limit.

A client that holds a reference and receives `410`, or `404` from every store the context names, shows the item as removed: the name and media type from its own copy of the reference, a "removed" marker, and no retry. It MUST NOT retry on an interval. It SHOULD delete any cached plaintext and ciphertext it holds for that CID when the removal came from a context order it can see (chat.md surfaces moderation events) and MAY offer to keep a local copy otherwise.

## 9. Promotion to a public blob

When a file is published with a release or a take, the plaintext becomes a public blob. This is the only path from sealed to public, and it needs the author.

1. The author's phone decrypts the sealed blob, uploads the plaintext as a public blob with its media type, and gets back a CID.
2. That CID equals the sealed reference's `digest`, by construction (§2). Anyone who holds the reference can confirm that the public copy is the same bytes without trusting the uploader.
3. The author's phone posts a `public-copy` message in the channel where the file lives (`chat.md` §5.7; payload `{0: sealed_cid, 1: public_cid, 2: media}`), signed by the author's leaf like any message.
4. A manifest (release, take) may then pin the public CID in its refs.

"The author" means a device that holds the delete secret for the CID, or whose chat identity key sent the message that first carried the reference in this context; a second device of the same person qualifies by the second test. Rules the conformance suite checks on the client: it uploads a public copy of a sealed blob only when the local user is the blob's author and has confirmed in the UI; it never uploads a public copy whose CID differs from the reference's `digest`. The public copy is a new upload with its own retention and its own delete secret. Deleting the sealed original does not delete the public copy, and the reverse is also true.

### 9.1 Release tables and the keybox

Members-only releases are the one case where a non-member, the aggregator, writes blobs that members decrypt. `release.md` (ADR 0011) settles the form, and this spec adds no format for it:

- Each table is an ordinary format 1 sealed blob under a fresh random key, put by the aggregator with the `authority` signature (§6.3), `Content-Type: application/vnd.hum.sealed`, counted against the context's quota.
- The direct-form references for the tables so far, in `t/` name order, are collected in a CBOR array and encrypted with HPKE (RFC 9180, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode, `info` = `hum/results-keybox/1` ‖ deck CID bytes, `aad` = deck CID bytes) to the context's `resultsKey`. The keybox bytes are `0x01 ‖ enc (32 bytes) ‖ HPKE ciphertext`, one keybox per release version; `release.md` is normative for this layout. It is not a sealed blob in this spec's sense: it is put as a public blob with media type `application/vnd.hum.keybox+hpke`, because anyone may mirror it and only holders of the results private key can open it.
- The release manifest pins the table CIDs and the keybox CID in `refs`. No key appears in it.

A store therefore never sees a third format, and `services.md`'s description of tables "sealed to `resultsKey`" means this two-layer form. The conformance vector for the keybox lives with `release.md`; this spec's `seal-*` vectors cover the tables.

## 10. Re-keying after a removal

When a member is removed, the keyring advances (§4.1) and every channel's MLS keys rotate, so new files are out of their reach. Files they already received cannot be recalled. The open question in the manifest spec is whether removal should also re-encrypt existing files (eager) or only rotate keys (lazy).

**Recommended default: lazy, with eager re-keying as a per-folder opt-in.** Recorded in `docs/decisions/0062-w0-06-rekeying-default.md`.

Why lazy by default:

- The removed member already holds every reference they received. For files they downloaded, re-keying changes nothing.
- Eager re-keying scales with the folder's size and runs on a phone: download, decrypt, re-seal under a fresh key, upload, re-send every reference, delete every old blob. For a folder of a few gigabytes that is hours on mobile data.
- The threat eager addresses is narrow: a removed member who kept references but never fetched the bytes, plus a store that is still serving the old ciphertext. Deleting the old blobs covers it, and for most folders the retention clock covers it too.

What eager re-keying is, when a folder opts in:

1. A folder has a `sensitive` flag: key 7 of its channel directory entry (`chat.md` §5.9), changeable only by `channels` holders. Phones show the flag.
2. When a member is removed from a sensitive folder's group, the phone that committed the removal performs the re-key: for every current version of every file, fetch, decrypt, seal under a fresh random key, upload, and send a `new version` operation with the new reference. Earlier versions are not re-keyed; they are deleted.
3. The committing phone then sends a context delete order (if it holds a sign key) or asks an organizer to, listing every old CID. Until the old blobs are deleted the re-key gives nothing, so the UI shows the folder as "re-keying" until the order is confirmed.
4. The cost falls on the phone that removed the member. A folder marked sensitive is capped at `storage.sensitiveMax` bytes from the context manifest (`context.md`, default 256 MiB) so that the work is bounded. Phones refuse an `add` or `new version` that would take a sensitive folder over the cap.

The conformance suite does not check re-keying in draft 0.1 beyond the folder operations it uses. The simulator's full run includes one removal from a sensitive folder and asserts that every pre-removal CID is deleted and every current version has a new CID.

## 11. Votes never touch storage

Ballots go only to aggregators. Hands and shields stay on the phone. No code path in the client may hand vote-related bytes to the sealing function or the store client, in any form, encrypted or not.

What the conformance suite checks:

- **Type boundary.** The core library's sealing entry point takes a `Plaintext` with a source tag from a closed set: `attachment`, `folder-file`, `folder-index`, `history-archive`, `map-text`, `key-package`, `ratchet-tree`, `public-copy`. The last three before `public-copy` come from `chat.md`: KeyPackages, history archives and large ratchet trees are also sealed blobs. Ballot, hand, shield and receipt types have no conversion to `Plaintext`. The suite compiles a test that attempts the conversion and asserts it fails to build.
- **Runtime trace.** The simulator wraps the store client and the sealing function. For every put it records the source tag and the plaintext's origin type. The fast simulator run fails if any put carries a tag outside the set above or any plaintext object that was ever reachable from a ballot, hand or shield.
- **Store side.** The reference store rejects any put whose `Content-Type` is not `application/vnd.hum.sealed` or a listed public media type. There is no "ballot" class, and a ballot cannot be mistaken for a sealed blob because it has no format byte.
- **Canary.** The simulator seeds each voter with a known marker inside their hand state and asserts the marker's bytes never appear in any store request body or in any sealed plaintext.

## 12. Vectors

The reference implementation (`reference/`) generates `vectors/storage/`. Each case has an id, a description, the section it tests, inputs, and either expected outputs or an expected rejection. Keys, salts and plaintexts are fixed and seeded. The list for draft 0.1:

**Padding (§1.2).** `padme-table`: `n` and `padme(n)` for 1…4,096 and selected larger values. `pad-roundtrip`: plaintexts of length 0, 1, 7, 100, 65,535, 65,536, 65,537, 200,000 padded and unpadded. Failing: `pad-no-marker` (all zeros), `pad-wrong-length` (valid marker but length not `padme(L+1)`).

**Sealing (§1.3–1.5).** `seal-empty` (L = 0, one chunk), `seal-small` (L = 100), `seal-one-chunk-exact` (P = 65,536), `seal-two-chunks` (P = 65,537 → 67,584), `seal-three-chunks` (L = 150,000), `seal-keyring` (format 2: epoch secret, salt, L = 100). Each gives key or secret, plaintext, ciphertext hex, CID, and the nonce and AAD for every chunk. Failing: `seal-bad-format` (first byte `0x03`), `seal-format-mismatch` (a format 1 blob under a reference that says 2), `seal-swapped-salt` (format 2 header salt replaced: `bad-tag`), `seal-truncated-chunk` (last chunk missing: `bad-tag` on the new last chunk), `seal-truncated-bytes` (last chunk cut mid-way: `bad-tag`), `seal-swapped-chunks` (chunks 0 and 1 exchanged: `bad-tag` at chunk 0), `seal-foreign-chunk` (chunk 1 of file B placed into file A: `bad-tag`), `seal-trailing-data` (16 extra bytes after the last chunk: `trailing-data`), `seal-wrong-cid` (reference CID does not match: `cid-mismatch`), `seal-size-mismatch`, `seal-digest-mismatch`.

**Range decryption (§1.4).** `range-c-from-size`: `size` → `P`, `n`, `C` for the sealing cases; `range-middle-chunk`: a three-chunk blob, bytes for chunk 1 only, decrypts; `range-wrong-index`: the same bytes decrypted as chunk 0 fail; failing `range-content-length-mismatch` (`size-mismatch` before any fetch). `seal-appended-chunk`: a full 65,552-byte chunk appended after the last one, so `n` recomputes and the old last chunk fails with `bad-tag`.

**CIDs (§2).** `cid-public`: bytes → CID and text form. `cid-sealed`: the sealed vectors' CIDs restated. `digest-equals-public-cid`: the plaintext digest of `seal-small` equals the public CID of its plaintext.

**References (§3).** `ref-direct` and `ref-keyring`: canonical CBOR bytes and the readable view. Failing: `ref-both-forms`, `ref-neither-form`, `ref-keyring-with-name`, `ref-keyring-with-key`, `ref-name-too-long`, `ref-media-too-long`, `ref-description-too-long`, `ref-key-wrong-length`, `ref-unknown-key`, `ref-format-3`, `ref-not-canonical` (same map, unsorted keys), `ref-too-large`. ExternalPart reverse rule (§3.2): `external-part-bad-enc-alg`, `-bad-hash-alg`, `-bad-key-length`, `-nonce-present`, `-aad-present`, `-bad-hash-length`, `-bad-url`.

**Keyring (§4).** `keyring-derive`: given `secret_k` (as the exporter output; the reference takes it as input) and a salt, the blob key. `keyring-two-blobs`: two format 2 blobs under one epoch with different salts have different keys and different first-chunk ciphertexts for the same plaintext. `keyring-share`: canonical payload bytes; failing `keyring-share-unauthorized-sender`, `keyring-share-conflicting-secret`. The exporter call itself is tested by `chat.md`'s vectors against an MLS implementation.

**Folders (§5).** `folder-replay`: a sequence of 40 `file-op` messages (bytes per `chat.md` §5.7) from three members and the resulting index snapshot bytes; the vector file names, for each rule 1 to 8 of §5.4, the op index that exercises it, so coverage is checkable. `folder-rights`: the same sequence with one member lacking `files-write`, the `roles` serial assumed, and the resulting state. `folder-index`: canonical snapshot bytes for a small folder.

**Delete (§8).** `delete-commitment`: secret → commitment. Failing: `delete-wrong-secret`, `delete-reused-secret` (blob A's secret against blob B's commitment). `delete-order`: canonical order bytes, the signed payload bytes, and a valid 2-of-3 signature set; failing `delete-order-threshold` (1 of 3), `delete-order-wrong-domain` (signed as `hum/manifest/1`), `delete-order-expired`, `delete-order-wrong-context` (order authority differs from the token's context authority).

**Store API (§6).** `store-visibility`: the table in §6.4 as a list of (token state, blob state) → status code, run against the reference store by `conformance.md`. `store-put-mismatch`: a put whose body does not hash to the path CID → `409 conflict`, detail `cid_mismatch`, with the exact CBOR error bytes. `store-reput-no-new-commitment`: re-put with a new commitment, then delete with that secret → `403 forbidden`, detail `secret`. `store-put-tombstone-other-context` → `201`. `promote-digest-mismatch`: a client refuses to upload a public copy whose CID differs from the reference's digest.

**Store manifest (§7).** `service-blob-store-valid` and the failing vectors named in the BS table.

The §6.4 visibility table and the §6.8 log scan are run by `conformance.md` and `simulator.md` (W0-08, W0-09), which did not exist when this draft was written.

Token issuance and redemption use the RFC 9578 test vectors for type `0x0002` unchanged.

## 13. Security considerations

| Threat | Mitigation |
| --- | --- |
| Store reads a file | AES-128-GCM under a key that never leaves phones and MLS; the store sees padded ciphertext |
| Store learns file sizes | Padmé padding; exact size travels only in the reference |
| Store links uploads to people | Per-context anonymous tokens; every request through an OHTTP relay; issuance unlinkable from redemption |
| Store turns tokens into identifiers | One key per context, rotated at most monthly; phones compare `token_key_id` in the all-members channel |
| Store serves wrong or stale bytes | CID over the whole blob; GCM tag per chunk for ranges |
| Store truncates, reorders or splices chunks | Nonce carries index and last flag; tag fails (§1.6) |
| Someone probes whether a CID exists | Identical `401`/`404` for every case they cover; sealed gets need a token for the right context |
| A recipient deletes someone else's file | The delete secret is random and never travels with the key |
| A recipient revives a deleted file | Tombstones for `retention.tombstone`; after that, a known limit |
| A removed member keeps files | Cannot be undone; the keyring advances; sensitive folders re-key and delete old blobs (§10) |
| A key is reused across blobs | Keys are random per blob; keyring-derived keys use a fresh salt; nonce reuse would break GCM, so this is a MUST |
| A manifest leaks a person's words | Keyring-form references carry no name, size, digest or description |
| Nonce misuse by a bad implementation | Nonces are fully determined by the format; the vectors check every one |
| A store lies about the context policy | The store learns policy from the logged context manifest; phones enforce the same policy at the edge |
| Floating-point in Padmé | `padme` uses integer bit operations only; `floor(log2(n))` is the bit length minus one |

Residual leaks, accepted by the design and stated so nobody is surprised:

- Padmé granularity. For a 280-byte text, `padme` rounds to a multiple of 16, so the store and anyone with a context token learn a sealed text's length to within 16 bytes. Short issue-map texts leak their approximate length.
- Shared CIDs across contexts. Re-sharing a reference into a second context puts the same CID under two `(cid, context)` tuples, so the store learns that the two contexts share at least one member. Not a person-level link.
- Redeemed nonces. At 5,000 tokens per member per day for a 30-day key, a 10,000-member context can leave 1.5 × 10⁹ nonces per key. Stores may lower `tokensPerMemberDay`.

## 14. Assumptions about sibling specs

When this draft was started, no sibling spec existed. By the time it was finished, `chat.md`, `context.md`, `issue-map.md` and `services.md` had landed and this draft was aligned with them; `credentials.md` landed later, and A6 records what it settled. Each item is also a question for the owning workstream.

- **A1 (`chat.md`, aligned): channel order and message ids.** Folders use the delivery service's per-channel sequence number (`chat.md` §4.4) as the total order and the 32-byte MIMI message id (`chat.md` §5.1) to identify versions. The `file-op` bytes are `chat.md` §5.7's; this spec only defines their effect.
- **A2 (`chat.md`, aligned): framing.** The ExternalPart mapping and the `hum:blob:` URL form are `chat.md`'s. The content types this spec relies on are all in `chat.md`: `folder-index` and `public-copy` (§5.7), `keyring-share` (§5.2, payload from this spec's §4.2) and `token-key` (§5.15).
- **A3 (`context.md`, aligned): storage policy.** This spec uses `context.md`'s `stores`, `storage.retention` (kinds 0–4), `storage.maxBlob`, `storage.history`, `storage.keyringHistory` (§4.2) and `storage.sensitiveMax` (§10) as written. Nothing is missing.
- **A4 (`chat.md`, aligned): when the keyring advances.** `chat.md` §1.2 now states that keyring epochs are not MLS epochs and that `hum/keyring/1` is exported only while processing a removal commit, as §4.1 says. If a `keyring-rotate` event is ever added, it advances the keyring the same way.
- **A5 (`chat.md`, aligned): rights.** Folder rights are `files-write` and `files-delete-any` from `chat.md` §3.1. The `sensitive` flag is key 7 of the channel directory entry (`chat.md` §5.9).
- **A6 (`credentials.md`, aligned): membership proof.** Token issuance uses the per-context anonymous membership proof with a scope string, so that the issuer can count issuances per pseudonym per day without identity. `credentials.md` defines that proof ("The uses", blob-tokens row: the scope of §6.1 and its bound message), so the exporter-MAC fallback (`storage-token/1`) this draft once held in reserve is not used.
- **A7 (`services.md`, aligned):** this draft uses the `service` type's common fields (keys 0 to 15) with store fields from 16, the common error format, token type `0x0002` via `POST /v1/tokens`, and `services.md` rule T-2 now says the context is identified by the per-context issuer key. Delete orders are standalone signed objects, as both specs now state (§8.2). Aggregator puts use the `authority` signature (§6.3). Which party runs the OHTTP relay, and how mirrors fetch public blobs, are defined in `services.md`.
- **A8 (`issue-map.md`, aligned):** `issue-map.md`'s Sealed text section now states format 2, the salt in the header and the HKDF derivation of §4.3, and rule IM-4 checks that the blob's first byte is `0x02`. It defers the keyring-history default to open question 1 here.

## 15. Open questions

Filed for the owner.

1. **Keyring history default.** Settled: `context.md` has `storage.keyringHistory`, default 0 (every epoch reaches newcomers), separate from message history. Left here so the owner sees the choice: a context that sets 1 hides earlier issue-map text from newcomers until an object is re-sealed under the new epoch, which `issue-map.md` allows only until it is dealt.
2. **Token issuance proof** (A6). Settled: the scoped membership proof from `credentials.md`. The exporter-MAC fallback is not used.
3. **Context in the key, or in token metadata.** Settled everywhere: the store uses per-context issuer keys with type `0x0002` (§6.1) and `services.md` T-2 says the same; the delivery service uses type `0x0001` context tokens issued at its own `POST /v1/tokens` against a membership proof scoped `hum/delivery-tokens/1` ‖ `token_key_id` ‖ `day`, the same shape as §6.2, plus per-channel tokens under a derived issuer key (`chat.md` §12.3 and §12.5). No token carries metadata. Closed; kept so the owner sees the two types side by side.
4. **Re-keying default.** Lazy by default with eager per sensitive folder, paid for by the removing member's phone (§10). Alternatives: eager everywhere (unbounded phone cost), or a server-side re-key (impossible without giving a server keys).
5. **Tombstone window.** 30 days is a guess. Longer windows protect deletions better and make the store remember more bare CIDs.
6. **Batched issuance.** This draft wraps up to 64 RFC 9578 exchanges in one request. If the IETF batched-tokens work lands, use it instead.
7. **Public GET without a token.** Lets anyone mirror public blobs and also lets anyone see which public CIDs a store holds. Public blobs are public, so this seems fine, but it means a store can be used to check whether a given release table exists.
8. **AES-128 versus AES-256.** 128 matches the MIMI content draft's default and halves nothing that matters on a phone. The format byte allows a 256-bit format later.
9. **History archives.** Their internal format is `chat.md`'s. This spec only says they are sealed blobs whose reference is sent after the add commit.
10. **Blob-store and delivery service as one manifest type.** `services.md` answers this with a `service` type and a `kind` field (ADR 0072). This draft keys its store-specific fields from 16, and the manifest spec's registry now lists `service`.

## 16. Conformance summary

An implementation is conformant with this spec when it passes every vector in §12 and the runtime checks in §11, and when:

- a client never sends a sealed reference, a key or a keyring secret anywhere except: inside an MLS application message; inside a sealed blob; inside a Welcome or a GroupInfo extension (`chat.md` §1.1, the ratchet-tree reference); in a QR code or join ticket shown on the device (`chat.md` §2.4 and §2.5, the KeyPackage handle); or, for the keybox, inside HPKE ciphertext to `resultsKey`. A delete secret leaves the device only in a delete request or in a re-put that extends retention (§6.3); the KeyPackage handle carries none. The conformance check enumerates these carriers and fails on any other;
- a client sends every store request through an OHTTP relay with a single-use token as §6 defines;
- a client rejects every sealed blob and reference the failing vectors reject, with the named reason;
- a store recomputes every CID, answers the visibility table in §6.4 exactly, enforces retention and quotas from the logged manifests, and logs nothing the §6.8 table forbids.

Seams touched by this spec: the sealed format and nonces, CID computation, key derivation from the keyring, delete secrets and their commitment, and what leaves the phone. Owner review is required before any of these is built.
