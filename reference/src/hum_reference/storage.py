"""Sealed blobs: Padmé padding, chunked AES-128-GCM, sealed references, keyring keys,
delete commitments. Written from ``docs/specs/storage.md`` sections 1 to 4 and 8.1.

- Padding (§1.2): plaintext, one ``0x80`` byte, then zeros to ``padme(L + 1)``.
- Chunks (§1.3): 64 KiB of padded plaintext per chunk, the last between 1 and
  64 KiB. Nonce ``000000 || flags || uint64_be(index)`` with ``flags = 0x01``
  on the last chunk. AAD is ``hum/sealed/1`` followed by the whole header.
- Formats (§1.1): ``0x01`` direct, 1-byte header, random 16-byte key carried in
  the reference. ``0x02`` keyring, header ``0x02 || salt(16)``, key derived as
  ``HKDF-Expand(HKDF-Extract(salt, secret_epoch), "hum/keyring-blob/1", 16)`` (§4.3).
- CID (§2): ``0x01 || SHA-256`` over the whole sealed blob. The plaintext digest
  is ``0x01 || SHA-256(plaintext)``, the CID the plaintext would have in public.
- Reference (§3): deterministic CBOR map with keys 0..10, direct or keyring form.
- Keyring secret (§4.1, chat.md §1.2): ``MLS-Exporter("hum/keyring/1", "", 16)``.
  The exporter itself is tested against an MLS implementation by chat.md's
  vectors; this module takes the epoch secret as input and also provides the
  RFC 9420 exporter arithmetic for completeness.
- Delete commitment (§8.1): ``SHA-256("hum/delete/1" || delete_secret)``.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import unicodedata
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import cbor
from .cid import cid as compute_cid
from .cid import parse_cid

__all__ = [
    "AAD_PREFIX",
    "CHUNK",
    "FORMAT_DIRECT",
    "FORMAT_KEYRING",
    "SealedError",
    "SealedReference",
    "blob_key_from_keyring",
    "chunk_aad",
    "chunk_nonce",
    "delete_commitment",
    "keyring_secret",
    "keyring_share",
    "mls_exporter",
    "open_chunk",
    "open_sealed",
    "pad",
    "padme",
    "plaintext_digest",
    "seal",
    "seal_keyring",
    "unpad",
]

CHUNK = 65_536
TAG = 16
KEY = 16
NONCE = 12
SALT = 16
AAD_PREFIX = b"hum/sealed/1"
FORMAT_DIRECT = 0x01
FORMAT_KEYRING = 0x02
HEADER_LEN = {FORMAT_DIRECT: 1, FORMAT_KEYRING: 1 + SALT}
KEYRING_LABEL = "hum/keyring/1"
KEYRING_BLOB_INFO = b"hum/keyring-blob/1"
MAX_REFERENCE_BYTES = 2048


class SealedError(ValueError):
    """A sealed blob or reference that must be rejected. ``reason`` is the spec's name."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


# ---------------------------------------------------------------- Padmé (§1.2)


def padme(n: int) -> int:
    """Padmé padded length (PURBs paper). ``n < 2`` is unchanged."""
    if n < 2:
        return n
    e = n.bit_length() - 1  # floor(log2 n)
    s = e.bit_length()  # floor(log2 e) + 1
    last_bits = e - s
    mask = (1 << last_bits) - 1
    return (n + mask) & ~mask


def pad(plaintext: bytes) -> bytes:
    """Append ``0x80`` and zeros up to ``padme(L + 1)``."""
    marked = plaintext + b"\x80"
    return marked + b"\x00" * (padme(len(marked)) - len(marked))


def unpad(padded: bytes) -> bytes:
    """Strip trailing zeros and one ``0x80``; reject a missing marker or a wrong padded length."""
    end = len(padded)
    while end > 0 and padded[end - 1] == 0:
        end -= 1
    if end == 0 or padded[end - 1] != 0x80:
        raise SealedError("bad-padding", "no 0x80 marker after the trailing zeros")
    if padme(end) != len(padded):
        raise SealedError("bad-padding", f"padded length {len(padded)} is not padme({end})")
    return padded[: end - 1]


# ---------------------------------------------------------------- chunks (§1.3, §1.4)


def chunk_nonce(index: int, last: bool) -> bytes:
    return b"\x00\x00\x00" + bytes([1 if last else 0]) + index.to_bytes(8, "big")


def chunk_aad(header: bytes) -> bytes:
    return AAD_PREFIX + header


def _chunks(padded: bytes) -> list[bytes]:
    return [padded[i : i + CHUNK] for i in range(0, len(padded), CHUNK)]


def seal(plaintext: bytes, key: bytes, header: bytes = bytes([FORMAT_DIRECT])) -> bytes:
    """Pad, chunk and encrypt under ``key``. ``header`` is the 1- or 17-byte format header."""
    if len(key) != KEY:
        raise ValueError("AES-128-GCM key must be 16 bytes")
    if not header or header[0] not in HEADER_LEN or len(header) != HEADER_LEN[header[0]]:
        raise ValueError("malformed sealed header")
    aead = AESGCM(key)
    aad = chunk_aad(header)
    chunks = _chunks(pad(plaintext))
    out = [header]
    for i, chunk in enumerate(chunks):
        out.append(aead.encrypt(chunk_nonce(i, i == len(chunks) - 1), chunk, aad))
    return b"".join(out)


def seal_keyring(plaintext: bytes, epoch_secret: bytes, salt: bytes) -> bytes:
    """Format 2: header ``0x02 || salt`` and a key derived from the keyring epoch secret."""
    if len(salt) != SALT:
        raise ValueError("salt must be 16 bytes")
    header = bytes([FORMAT_KEYRING]) + salt
    return seal(plaintext, blob_key_from_keyring(epoch_secret, salt), header)


def open_sealed(
    ciphertext: bytes,
    key: bytes | None = None,
    *,
    epoch_secret: bytes | None = None,
    expected_format: int | None = None,
    size: int | None = None,
) -> bytes:
    """Decrypt a whole sealed blob and unpad it (§1.5 steps 1 to 5).

    Pass ``key`` for format 1 or ``epoch_secret`` for format 2. ``expected_format`` and
    ``size`` come from the reference when one is at hand; ``size`` fixes the expected total
    length ``C = H + padme(L + 1) + 16n``, which is how bytes after the last chunk are told
    apart from a truncated or tampered last chunk. Without it the reader goes one chunk
    ahead and any damage shows up as ``bad-tag``.
    """
    if not ciphertext or ciphertext[0] not in HEADER_LEN:
        raise SealedError("bad-format", "unknown format byte")
    fmt = ciphertext[0]
    if expected_format is not None and fmt != expected_format:
        raise SealedError("bad-format", f"blob is format {fmt}, reference says {expected_format}")
    h = HEADER_LEN[fmt]
    if len(ciphertext) < h:
        raise SealedError("bad-format", "truncated header")
    header = ciphertext[:h]
    if fmt == FORMAT_KEYRING:
        if epoch_secret is None:
            raise SealedError("bad-format", "format 2 needs a keyring epoch secret")
        key = blob_key_from_keyring(epoch_secret, header[1:])
    elif key is None:
        raise SealedError("bad-format", "format 1 needs a key")
    body = ciphertext[h:]
    if len(body) < 1 + TAG:
        raise SealedError("bad-tag", "no complete chunk")
    if size is not None:
        padded = padme(size + 1)
        expected = padded + TAG * math.ceil(padded / CHUNK)
        if len(body) > expected:
            raise SealedError("trailing-data", f"{len(body) - expected} bytes after the last chunk")
        if len(body) < expected:
            raise SealedError("bad-tag", f"{expected - len(body)} bytes short")
    n = math.ceil(len(body) / (CHUNK + TAG))
    aead = AESGCM(key)
    aad = chunk_aad(header)
    out = []
    for i in range(n):
        piece = body[i * (CHUNK + TAG) : (i + 1) * (CHUNK + TAG)]
        last = i == n - 1
        if last and len(piece) < 1 + TAG:
            raise SealedError("trailing-data", f"{len(piece)} bytes after the last chunk")
        try:
            out.append(aead.decrypt(chunk_nonce(i, last), piece, aad))
        except Exception as e:  # cryptography raises InvalidTag
            raise SealedError("bad-tag", f"chunk {i}") from e
    return unpad(b"".join(out))


def open_chunk(ciphertext_chunk: bytes, index: int, last: bool, key: bytes, header: bytes) -> bytes:
    """Decrypt one chunk fetched by range (§1.4). Returns that chunk's padded plaintext."""
    try:
        return AESGCM(key).decrypt(chunk_nonce(index, last), ciphertext_chunk, chunk_aad(header))
    except Exception as e:
        raise SealedError("bad-tag", f"chunk {index}") from e


def plaintext_digest(plaintext: bytes) -> bytes:
    """``0x01 || SHA-256(plaintext)``: the CID the plaintext would have as a public blob."""
    return compute_cid(plaintext)


# ---------------------------------------------------------------- references (§3)

REF_CID, REF_FORMAT, REF_KEY, REF_SIZE, REF_MEDIA, REF_NAME, REF_DIGEST, REF_EXPIRES = range(8)
REF_STORE, REF_DESCRIPTION, REF_EPOCH = 8, 9, 10
_REF_KEYS = set(range(11))


def _text_ok(value: object, limit: int) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value.encode()) <= limit
        and unicodedata.is_normalized("NFC", value)
        and not any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)
    )


@dataclass(frozen=True)
class SealedReference:
    """A sealed reference in direct form (``key`` set) or keyring form (``epoch`` set)."""

    cid: bytes
    format: int
    media: str
    key: bytes | None = None
    size: int | None = None
    name: str | None = None
    digest: bytes | None = None
    expires: int | None = None
    store: bytes | None = None
    description: str | None = None
    epoch: int | None = None

    @classmethod
    def direct(
        cls,
        plaintext: bytes,
        key: bytes,
        media: str,
        name: str | None = None,
        expires: int | None = None,
        store: bytes | None = None,
        description: str | None = None,
    ) -> tuple[SealedReference, bytes]:
        """Seal under the given fresh key and build the message-form reference."""
        sealed = seal(plaintext, key)
        ref = cls(
            cid=compute_cid(sealed),
            format=FORMAT_DIRECT,
            media=media,
            key=key,
            size=len(plaintext),
            name=name,
            digest=plaintext_digest(plaintext),
            expires=expires,
            store=store,
            description=description,
        )
        return ref, sealed

    @classmethod
    def keyring(
        cls,
        plaintext: bytes,
        epoch_secret: bytes,
        epoch: int,
        salt: bytes,
        media: str,
        expires: int | None = None,
        store: bytes | None = None,
    ) -> tuple[SealedReference, bytes]:
        sealed = seal_keyring(plaintext, epoch_secret, salt)
        ref = cls(
            cid=compute_cid(sealed),
            format=FORMAT_KEYRING,
            media=media,
            epoch=epoch,
            expires=expires,
            store=store,
        )
        return ref, sealed

    def to_item(self) -> dict[int, object]:
        item: dict[int, object] = {
            REF_CID: self.cid,
            REF_FORMAT: self.format,
            REF_MEDIA: self.media,
        }
        for k, v in (
            (REF_KEY, self.key),
            (REF_SIZE, self.size),
            (REF_NAME, self.name),
            (REF_DIGEST, self.digest),
            (REF_EXPIRES, self.expires),
            (REF_STORE, self.store),
            (REF_DESCRIPTION, self.description),
            (REF_EPOCH, self.epoch),
        ):
            if v is not None:
                item[k] = v
        return item

    def encode(self) -> bytes:
        return cbor.encode(self.to_item())

    @classmethod
    def decode(cls, data: bytes, *, in_message: bool = True) -> SealedReference:
        """Parse and validate (§3.1). Message form (``in_message``) needs size and digest."""
        if len(data) > MAX_REFERENCE_BYTES:
            raise SealedError("bad-reference", "over 2,048 bytes")
        try:
            item = cbor.decode(data)
        except cbor.CborError as e:
            raise SealedError("bad-reference", f"not deterministic CBOR: {e}") from e
        if not isinstance(item, dict) or not set(item) <= _REF_KEYS:
            raise SealedError("bad-reference", "unknown keys")
        for required in (REF_CID, REF_FORMAT, REF_MEDIA):
            if required not in item:
                raise SealedError("bad-reference", f"missing key {required}")
        ref = cls(
            cid=item[REF_CID],
            format=item[REF_FORMAT],
            media=item[REF_MEDIA],
            key=item.get(REF_KEY),
            size=item.get(REF_SIZE),
            name=item.get(REF_NAME),
            digest=item.get(REF_DIGEST),
            expires=item.get(REF_EXPIRES),
            store=item.get(REF_STORE),
            description=item.get(REF_DESCRIPTION),
            epoch=item.get(REF_EPOCH),
        )
        ref.validate(in_message=in_message)
        return ref

    def validate(self, *, in_message: bool = True) -> None:
        try:
            parse_cid(self.cid)
        except (ValueError, TypeError) as e:
            raise SealedError("bad-reference", f"cid: {e}") from e
        if self.format not in HEADER_LEN:
            raise SealedError("bad-reference", "unknown format")
        if not _text_ok(self.media, 127):
            raise SealedError("bad-reference", "media type")
        has_key, has_epoch = self.key is not None, self.epoch is not None
        if has_key == has_epoch:
            raise SealedError("bad-reference", "exactly one of key and epoch")
        if has_key:
            if self.format != FORMAT_DIRECT:
                raise SealedError("bad-reference", "direct form must be format 1")
            if not isinstance(self.key, bytes) or len(self.key) != KEY:
                raise SealedError("bad-reference", "key must be 16 bytes")
            if in_message and (self.size is None or self.digest is None):
                raise SealedError("bad-reference", "message form needs size and digest")
        else:
            if self.format != FORMAT_KEYRING:
                raise SealedError("bad-reference", "keyring form must be format 2")
            if not isinstance(self.epoch, int) or self.epoch < 0:
                raise SealedError("bad-reference", "epoch")
            for field in ("name", "description", "size", "digest"):
                if getattr(self, field) is not None:
                    raise SealedError("bad-reference", f"keyring form must not carry {field}")
        if self.size is not None and (not isinstance(self.size, int) or self.size < 0):
            raise SealedError("bad-reference", "size")
        if self.digest is not None:
            try:
                parse_cid(self.digest)
            except (ValueError, TypeError) as e:
                raise SealedError("bad-reference", f"digest: {e}") from e
        if self.name is not None and (
            not _text_ok(self.name, 255) or "/" in self.name or "\x00" in self.name
        ):
            raise SealedError("bad-reference", "name")
        if self.description is not None and not _text_ok(self.description, 1024):
            raise SealedError("bad-reference", "description")
        if self.expires is not None and (not isinstance(self.expires, int) or self.expires < 0):
            raise SealedError("bad-reference", "expires")
        if self.store is not None:
            try:
                parse_cid(self.store)
            except (ValueError, TypeError) as e:
                raise SealedError("bad-reference", f"store: {e}") from e
        if len(self.encode()) > MAX_REFERENCE_BYTES:
            raise SealedError("bad-reference", "over 2,048 bytes")

    def open(self, ciphertext: bytes, epoch_secret: bytes | None = None) -> bytes:
        """§1.5 steps 7, 1 to 5, then 6: CID, decrypt, unpad, size and digest."""
        if compute_cid(ciphertext) != self.cid:
            raise SealedError("cid-mismatch")
        plain = open_sealed(
            ciphertext,
            self.key,
            epoch_secret=epoch_secret,
            expected_format=self.format,
            size=self.size,
        )
        if self.size is not None and len(plain) != self.size:
            raise SealedError("size-mismatch", f"{len(plain)} bytes, reference says {self.size}")
        if self.digest is not None and plaintext_digest(plain) != self.digest:
            raise SealedError("digest-mismatch")
        return plain


# ---------------------------------------------------------------- keyring (§4)


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt if salt else bytes(32), ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def blob_key_from_keyring(epoch_secret: bytes, salt: bytes) -> bytes:
    """§4.3: ``HKDF-Expand(HKDF-Extract(salt, secret_epoch), "hum/keyring-blob/1", 16)``."""
    if len(salt) != SALT:
        raise ValueError("salt must be 16 bytes")
    return _hkdf_expand(_hkdf_extract(salt, epoch_secret), KEYRING_BLOB_INFO, KEY)


def _varint(n: int) -> bytes:
    if n < 0x40:
        return bytes([n])
    if n < 0x4000:
        return (0x4000 | n).to_bytes(2, "big")
    if n < 0x4000_0000:
        return (0x8000_0000 | n).to_bytes(4, "big")
    raise ValueError("too long for a varint")


def _opaque(data: bytes) -> bytes:
    return _varint(len(data)) + data


def expand_with_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    """RFC 9420 section 8: KDFLabel = {uint16 length, opaque "MLS 1.0 " + label, opaque context}."""
    kdf_label = length.to_bytes(2, "big") + _opaque(b"MLS 1.0 " + label.encode()) + _opaque(context)
    return _hkdf_expand(secret, kdf_label, length)


def derive_secret(secret: bytes, label: str) -> bytes:
    return expand_with_label(secret, label, b"", 32)


def mls_exporter(exporter_secret: bytes, label: str, context: bytes, length: int) -> bytes:
    """MLS-Exporter (RFC 9420 section 8.5) for ciphersuite 1 (SHA-256)."""
    return expand_with_label(
        derive_secret(exporter_secret, label), "exported", hashlib.sha256(context).digest(), length
    )


def keyring_secret(exporter_secret: bytes) -> bytes:
    """§4.1: ``MLS-Exporter("hum/keyring/1", context = empty, 16)`` at the epoch-making commit."""
    return mls_exporter(exporter_secret, KEYRING_LABEL, b"", KEY)


def keyring_share(entries: list[tuple[int, int, bytes]]) -> bytes:
    """§4.2 payload: ``{0: [[k, mls_epoch, secret_k], ...]}`` sorted by ``k``."""
    return cbor.encode({0: [[k, e, s] for k, e, s in sorted(entries)]})


# ---------------------------------------------------------------- deletion (§8.1)


def delete_commitment(delete_secret: bytes) -> bytes:
    if len(delete_secret) != 32:
        raise ValueError("delete secret must be 32 bytes")
    return hashlib.sha256(b"hum/delete/1" + delete_secret).digest()
