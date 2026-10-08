"""Vectors for docs/specs/storage.md section 12: padding, sealing, ranges, CIDs, references,
keyring, delete commitments. Folders, delete orders and the store API are left for the
second run (see conformance.md).
"""

from __future__ import annotations

import hashlib

from .. import cbor, storage
from ..cid import cid, cid_text
from . import File, hexify, jsonable

SPEC = "storage"
KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
KEY_B = bytes.fromhex("f0e1d2c3b4a5968778695a4b3c2d1e0f")
SECRET = hashlib.sha256(b"hum keyring epoch secret test").digest()[:16]
SALT = bytes.fromhex("a1a2a3a4a5a6a7a8a9aaabacadaeafb0")
SALT_2 = bytes.fromhex("b1b2b3b4b5b6b7b8b9babbbcbdbebfc0")


def pattern(n: int) -> bytes:
    """Deterministic test bytes: byte i = (i * 7 + 3) mod 256."""
    return bytes((i * 7 + 3) & 0xFF for i in range(n))


def plaintext_input(pt: bytes) -> dict:
    if len(pt) <= 4096:
        return {"plaintext": hexify(pt)}
    return {
        "plaintext_rule": "byte i = (i * 7 + 3) mod 256",
        "plaintext_length": len(pt),
        "plaintext_sha256": hashlib.sha256(pt).hexdigest(),
    }


def ciphertext_output(ct: bytes, header_len: int) -> dict:
    out = {"ciphertext_length": len(ct), "cid": hexify(cid(ct))}
    body = ct[header_len:]
    n = -(-len(body) // (storage.CHUNK + storage.TAG))
    chunks = []
    for i in range(n):
        piece = body[i * (storage.CHUNK + storage.TAG) : (i + 1) * (storage.CHUNK + storage.TAG)]
        chunks.append(
            {
                "index": i,
                "last": i == n - 1,
                "nonce": hexify(storage.chunk_nonce(i, i == n - 1)),
                "aad": hexify(storage.chunk_aad(ct[:header_len])),
                "plaintext_bytes": len(piece) - storage.TAG,
                "tag": hexify(piece[-storage.TAG :]),
            }
        )
    out["chunks"] = chunks
    if len(ct) <= 8192:
        out["ciphertext"] = hexify(ct)
    else:
        out["ciphertext_sha256"] = hashlib.sha256(ct).hexdigest()
    return out


def padding_file() -> File:
    f = File(
        SPEC,
        "padding",
        "§1.2. padme-table covers 1..4096 and selected larger values; pad-roundtrip gives "
        "the padded bytes (or their digest) for the listed lengths.",
    )
    table = {str(n): storage.padme(n) for n in range(1, 4097)}
    for n in [
        65535, 65536, 65537, 100_000, 131_072, 131_073, 150_001, 1_000_000, 10_000_000,
        2**31 - 1, 2**40 + 1,
    ]:  # fmt: skip
        table[str(n)] = storage.padme(n)
    f.add(
        "padme-table",
        "padme(n) for n in 1..4096 and selected larger values",
        "1.2",
        {"n": "keys of the expected table"},
        {"padme": table},
    )
    for n in [0, 1, 7, 100, 65535, 65536, 65537, 200_000]:
        pt = pattern(n)
        padded = storage.pad(pt)
        exp = {"padded_length": len(padded), "padded_sha256": hashlib.sha256(padded).hexdigest()}
        if len(padded) <= 4096:
            exp["padded"] = hexify(padded)
        f.add(
            "pad-roundtrip", f"Pad and unpad a {n}-byte plaintext", "1.2", plaintext_input(pt), exp
        )
    f.add(
        "reject",
        "pad-no-marker: all zeros has no 0x80 after the trailing zeros",
        "1.2",
        {"padded": hexify(bytes(16))},
        rejection={"step": None, "check": "unpad", "reason": "bad-padding"},
    )
    f.add(
        "reject",
        "pad-wrong-length: valid marker but 20 bytes is not padme(18) = 18",
        "1.2",
        {"padded": hexify(pattern(17) + b"\x80" + bytes(2))},
        rejection={"step": None, "check": "unpad", "reason": "bad-padding"},
    )
    return f


def sealed_file() -> File:
    f = File(
        SPEC,
        "sealed",
        "§1.3 to §1.5. Format 1 (direct key) and format 2 (keyring, salted); AAD hum/sealed/1 || header. Each case gives "
        "every chunk's nonce, AAD and tag; small blobs give the full ciphertext and large "
        "ones its SHA-256.",
    )
    cases = [
        ("seal-empty", 0),
        ("seal-small", 100),
        ("seal-one-chunk-exact", 65_535),  # L + 1 = 65,536 = P
        ("seal-two-chunks", 65_536),  # L + 1 = 65,537 -> P = 67,584
        ("seal-three-chunks", 150_000),
    ]
    for name, n in cases:
        pt = pattern(n)
        ct = storage.seal(pt, KEY)
        f.add(
            name,
            f"Format 1, {n}-byte plaintext",
            "1.3",
            {"format": 1, "key": hexify(KEY), **plaintext_input(pt)},
            {
                "padded_length": storage.padme(n + 1),
                **ciphertext_output(ct, 1),
                "plaintext_digest": hexify(storage.plaintext_digest(pt)),
            },
        )
    pt = pattern(100)
    ct = storage.seal_keyring(pt, SECRET, SALT)
    f.add(
        "seal-keyring",
        "Format 2, 100-byte plaintext under a keyring epoch secret and salt",
        "4.3",
        {
            "format": 2,
            "epoch_secret": hexify(SECRET),
            "salt": hexify(SALT),
            "plaintext": hexify(pt),
        },
        {
            "header": hexify(ct[:17]),
            "key": hexify(storage.blob_key_from_keyring(SECRET, SALT)),
            "padded_length": storage.padme(101),
            **ciphertext_output(ct, 17),
        },
    )

    # failing opens
    small = storage.seal(pattern(100), KEY)
    two = storage.seal(pattern(65_536), KEY)
    two_b = storage.seal(pattern(65_536), KEY_B)
    end0 = 1 + storage.CHUNK + storage.TAG
    kr = storage.seal_keyring(pattern(100), SECRET, SALT)

    def reject(name, data, why, reason, *, key=KEY, secret=None, fmt=None, size=None):
        try:
            storage.open_sealed(
                data,
                key if secret is None else None,
                epoch_secret=secret,
                expected_format=fmt,
                size=size,
            )
            raise AssertionError(name)
        except storage.SealedError as e:
            assert e.reason == reason, (name, e.reason)
        inputs: dict = {"key": hexify(key)} if secret is None else {"epoch_secret": hexify(secret)}
        if fmt is not None:
            inputs["reference_format"] = fmt
        if size is not None:
            inputs["reference_size"] = size
        if len(data) <= 8192:
            inputs["ciphertext"] = hexify(data)
        else:
            inputs["ciphertext_sha256"] = hashlib.sha256(data).hexdigest()
            inputs["ciphertext_length"] = len(data)
            inputs["ciphertext_rule"] = why
        f.add(
            name,
            f"Open fails with {reason}: {why}",
            "1.5",
            inputs,
            rejection={"step": None, "check": "open-sealed", "reason": reason},
        )

    reject("seal-bad-format", b"\x03" + small[1:], "first byte 0x03", "bad-format")
    reject(
        "seal-format-mismatch",
        small,
        "a format 1 blob under a reference that says format 2",
        "bad-format",
        fmt=2,
    )
    reject(
        "seal-swapped-salt",
        kr[:1] + SALT_2 + kr[17:],
        "format 2 header salt replaced",
        "bad-tag",
        secret=SECRET,
    )
    reject(
        "seal-truncated-chunk", two[:end0], "seal-two-chunks with its last chunk missing", "bad-tag"
    )
    reject(
        "seal-truncated-bytes", two[:-5], "seal-two-chunks cut five bytes before its end", "bad-tag"
    )
    reject(
        "seal-swapped-chunks",
        two[:1] + two[end0:] + two[1:end0],
        "seal-two-chunks with chunks 0 and 1 exchanged",
        "bad-tag",
    )
    reject(
        "seal-foreign-chunk",
        two[:end0] + two_b[end0:],
        "seal-two-chunks with chunk 1 taken from the same plaintext sealed under key "
        + KEY_B.hex(),
        "bad-tag",
    )
    reject(
        "seal-trailing-data",
        small + bytes(16),
        "16 zero bytes after the last chunk; the reference's size fixes the expected length",
        "trailing-data",
        size=100,
    )
    reject(
        "seal-trailing-data-unknown-size",
        small + bytes(16),
        "the same bytes with no size known: the extra bytes become part of the last chunk",
        "bad-tag",
    )
    reject("seal-wrong-key", small, "a different key", "bad-tag", key=KEY_B)

    # range decryption
    three = storage.seal(pattern(150_000), KEY)
    off1 = 1 + (storage.CHUNK + storage.TAG)
    chunk1 = three[off1 : off1 + storage.CHUNK + storage.TAG]
    plain1 = storage.open_chunk(chunk1, 1, False, KEY, three[:1])
    f.add(
        "range-middle-chunk",
        "Chunk 1 of seal-three-chunks decrypts alone with nonce(1, false)",
        "1.4",
        {
            "key": hexify(KEY),
            "header": hexify(three[:1]),
            "chunk_index": 1,
            "last": False,
            "byte_offset": off1,
            "chunk_sha256": hashlib.sha256(chunk1).hexdigest(),
        },
        {
            "plaintext_sha256": hashlib.sha256(plain1).hexdigest(),
            "plaintext_equals": "bytes 65536..131072 of the padded plaintext",
        },
    )
    try:
        storage.open_chunk(chunk1, 0, False, KEY, three[:1])
        raise AssertionError
    except storage.SealedError:
        pass
    f.add(
        "range-wrong-index",
        "The same bytes decrypted as chunk 0 fail",
        "1.4",
        {
            "key": hexify(KEY),
            "header": hexify(three[:1]),
            "chunk_index": 0,
            "last": False,
            "chunk_sha256": hashlib.sha256(chunk1).hexdigest(),
        },
        rejection={"step": None, "check": "open-chunk", "reason": "bad-tag"},
    )
    return f


def cid_file() -> File:
    f = File(
        SPEC,
        "cid",
        "§2. Public CIDs, sealed CIDs, and the plaintext digest equal to the public CID.",
    )
    for name, data in [("empty", b""), ("hello", b"hello"), ("pattern-100", pattern(100))]:
        c = cid(data)
        f.add(
            "cid-public",
            f"Public blob CID of {name}",
            "2",
            {"bytes": hexify(data)},
            {"cid": hexify(c), "text": cid_text(c)},
        )
    ct = storage.seal(pattern(100), KEY)
    f.add(
        "cid-sealed",
        "Sealed CID of seal-small is over the whole blob, header included",
        "2",
        {"ciphertext": hexify(ct)},
        {"cid": hexify(cid(ct))},
    )
    f.add(
        "digest-equals-public-cid",
        "The plaintext digest of seal-small equals the public CID of its plaintext",
        "2",
        {"plaintext": hexify(pattern(100))},
        {
            "digest": hexify(storage.plaintext_digest(pattern(100))),
            "public_cid": hexify(cid(pattern(100))),
        },
    )
    return f


def reference_file() -> File:
    f = File(
        SPEC,
        "reference",
        "§3. Direct (message form) and keyring references, their canonical bytes and readable "
        "view, and the forms a phone rejects.",
    )
    pt = b"An argument's text, cited from chat."
    store = cid(b"a blob-store keyset")
    ref, ct = storage.SealedReference.direct(
        pt, KEY, "text/plain", "argument.txt", 1_792_800_000, store, "A short caption"
    )
    f.add(
        "ref-direct",
        "Direct form with every optional field",
        "3.1",
        {
            "plaintext": hexify(pt),
            "key": hexify(KEY),
            "media": "text/plain",
            "name": "argument.txt",
            "expires": 1_792_800_000,
            "store": hexify(store),
            "description": "A short caption",
        },
        {
            "ciphertext": hexify(ct),
            "reference": hexify(ref.encode()),
            "view": jsonable(ref.to_item()),
        },
    )
    kref, kct = storage.SealedReference.keyring(pt, SECRET, 3, SALT, "text/plain")
    f.add(
        "ref-keyring",
        "Keyring form: cid, format 2, epoch, media; nothing that describes the text",
        "3.1",
        {
            "plaintext": hexify(pt),
            "epoch_secret": hexify(SECRET),
            "epoch": 3,
            "salt": hexify(SALT),
            "media": "text/plain",
        },
        {
            "ciphertext": hexify(kct),
            "reference": hexify(kref.encode()),
            "view": jsonable(kref.to_item()),
        },
    )
    f.add(
        "ref-open",
        "Opening with the direct reference: CID, decrypt, unpad, size, digest",
        "1.5",
        {"reference": hexify(ref.encode()), "ciphertext": hexify(ct)},
        {"plaintext": hexify(pt)},
    )
    f.add(
        "ref-open-keyring",
        "Opening with the keyring reference and the epoch secret",
        "1.5",
        {
            "reference": hexify(kref.encode()),
            "ciphertext": hexify(kct),
            "epoch_secret": hexify(SECRET),
        },
        {"plaintext": hexify(pt)},
    )

    def reject(name: str, item, why: str):
        data = item if isinstance(item, bytes) else cbor.encode(item)
        try:
            storage.SealedReference.decode(data)
            raise AssertionError(name)
        except storage.SealedError as e:
            assert e.reason == "bad-reference", name
        f.add(
            name,
            f"Reject: {why}",
            "3.1",
            {"reference": hexify(data)},
            rejection={"step": None, "check": "decode-reference", "reason": "bad-reference"},
        )

    base = ref.to_item()
    both = dict(base)
    both[storage.REF_EPOCH] = 3
    reject("ref-both-forms", both, "key and epoch both present")
    neither = {k: v for k, v in base.items() if k != storage.REF_KEY}
    reject("ref-neither-form", neither, "neither key nor epoch")
    kn = dict(kref.to_item())
    kn[storage.REF_NAME] = "secret.txt"
    reject("ref-keyring-with-name", kn, "keyring form carrying a file name")
    kk_ = dict(kref.to_item())
    kk_[storage.REF_KEY] = KEY
    reject("ref-keyring-with-key", kk_, "keyring form carrying a key (and an epoch)")
    long_name = dict(base)
    long_name[storage.REF_NAME] = "n" * 256
    reject("ref-name-too-long", long_name, "name of 256 bytes")
    items = sorted(
        ((cbor.encode(k), cbor.encode(v)) for k, v in base.items()), key=lambda kv: kv[0]
    )
    items[0], items[1] = items[1], items[0]
    unsorted = bytes([0xA0 | len(items)]) + b"".join(k + v for k, v in items)
    reject("ref-not-canonical", unsorted, "the same map with two keys out of order")
    too_big = dict(base)
    too_big[storage.REF_DESCRIPTION] = "d" * 1024
    too_big[storage.REF_NAME] = "n" * 255
    too_big[storage.REF_MEDIA] = "m" * 127
    too_big[storage.REF_DESCRIPTION] = "d" * 2000
    reject("ref-too-large", too_big, "description of 2,000 bytes; the map is over 2,048 bytes")
    other = storage.seal(b"different bytes entirely.............", KEY)
    f.add(
        "seal-wrong-cid",
        "Reference CID does not match the ciphertext",
        "1.5",
        {"reference": hexify(ref.encode()), "ciphertext": hexify(other)},
        rejection={"step": None, "check": "open-reference", "reason": "cid-mismatch"},
    )
    wrong_size = storage.SealedReference(
        ref.cid, 1, ref.media, ref.key, ref.size + 1, ref.name, ref.digest, ref.expires,
        ref.store, ref.description,
    )  # fmt: skip
    f.add(
        "seal-size-mismatch",
        "Reference size is one more than the plaintext",
        "1.5",
        {"reference": hexify(wrong_size.encode()), "ciphertext": hexify(ct)},
        rejection={"step": None, "check": "open-reference", "reason": "size-mismatch"},
    )
    wrong_digest = storage.SealedReference(
        ref.cid, 1, ref.media, ref.key, ref.size, ref.name, b"\x01" + bytes(32), ref.expires,
        ref.store, ref.description,
    )  # fmt: skip
    f.add(
        "seal-digest-mismatch",
        "Reference digest does not match the plaintext",
        "1.5",
        {"reference": hexify(wrong_digest.encode()), "ciphertext": hexify(ct)},
        rejection={"step": None, "check": "open-reference", "reason": "digest-mismatch"},
    )
    return f


def keyring_file() -> File:
    f = File(
        SPEC,
        "keyring",
        "§4. Blob keys from an epoch secret and a salt, two blobs under one epoch, the "
        "keyring-share payload, and the exporter arithmetic for the epoch secret.",
    )
    for name, secret in [("zero", bytes(16)), ("test", SECRET)]:
        for salt in (SALT, SALT_2):
            f.add(
                "keyring-derive",
                f"Blob key for secret '{name}' and salt {salt[:2].hex()}…",
                "4.3",
                {"epoch_secret": hexify(secret), "salt": hexify(salt)},
                {
                    "prk": hexify(storage._hkdf_extract(salt, secret)),
                    "key": hexify(storage.blob_key_from_keyring(secret, salt)),
                },
            )
    pt = pattern(100)
    a = storage.seal_keyring(pt, SECRET, SALT)
    b = storage.seal_keyring(pt, SECRET, SALT_2)
    f.add(
        "keyring-two-blobs",
        "Two format 2 blobs of one plaintext under one epoch differ in key and ciphertext",
        "4.3",
        {
            "epoch_secret": hexify(SECRET),
            "salts": [hexify(SALT), hexify(SALT_2)],
            "plaintext": hexify(pt),
        },
        {
            "keys": [
                hexify(storage.blob_key_from_keyring(SECRET, SALT)),
                hexify(storage.blob_key_from_keyring(SECRET, SALT_2)),
            ],
            "first_chunk_ciphertext": [hexify(a[17:33]), hexify(b[17:33])],
            "cids": [hexify(cid(a)), hexify(cid(b))],
            "keys_differ": True,
            "ciphertexts_differ": a != b,
        },
    )
    entries = [(2, 9, bytes(range(16, 32))), (1, 4, bytes(range(16)))]
    f.add(
        "keyring-share",
        "keyring-share payload {0: [[k, mls_epoch, secret]...]} sorted by k",
        "4.2",
        {"entries": [{"k": k, "mls_epoch": e, "secret": hexify(s)} for k, e, s in entries]},
        {"payload": hexify(storage.keyring_share(entries))},
    )
    exporter_secret = hashlib.sha256(b"mls exporter secret").digest()
    f.add(
        "exporter",
        'Epoch secret = MLS-Exporter("hum/keyring/1", "", 16) with HKDF-SHA256 (RFC 9420 section '
        "8.5); chat.md's vectors are the normative check against an MLS stack",
        "4.1",
        {"exporter_secret": hexify(exporter_secret)},
        {
            "derived_secret": hexify(storage.derive_secret(exporter_secret, "hum/keyring/1")),
            "epoch_secret": hexify(storage.keyring_secret(exporter_secret)),
        },
    )
    return f


def delete_file() -> File:
    f = File(
        SPEC,
        "delete",
        "§8.1. Delete secret to commitment; a wrong or reused secret does not match.",
    )
    sa = hashlib.sha256(b"delete secret A").digest()
    sb = hashlib.sha256(b"delete secret B").digest()
    ca, cb = storage.delete_commitment(sa), storage.delete_commitment(sb)
    f.add(
        "delete-commitment",
        'commitment = SHA-256("hum/delete/1" || secret)',
        "8.1",
        {"delete_secret": hexify(sa)},
        {"commitment": hexify(ca)},
    )
    f.add(
        "delete-wrong-secret",
        "A different secret against blob A's commitment",
        "8.1",
        {"delete_secret": hexify(bytes(32)), "commitment": hexify(ca)},
        rejection={"step": None, "check": "delete", "reason": "bad-secret"},
    )
    f.add(
        "delete-reused-secret",
        "Blob A's secret against blob B's commitment",
        "8.1",
        {"delete_secret": hexify(sa), "commitment": hexify(cb)},
        rejection={"step": None, "check": "delete", "reason": "bad-secret"},
    )
    return f


def generate() -> list[File]:
    return [
        padding_file(),
        sealed_file(),
        cid_file(),
        reference_file(),
        keyring_file(),
        delete_file(),
    ]
