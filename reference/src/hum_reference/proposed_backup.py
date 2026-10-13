"""Executable B1 proposal from ADR 0113, NOT an accepted Hum wire format.

Pure pack/unpack operations do not install state or write files. Callers must
commit restored state only after complete success and apply shield restore rules.
E1 card key 6 is explicitly experimental; serialization is not BBS validation.
All primitives use the existing approved helpers. Explicit randomness is solely
for fixtures; omitted values use operating-system randomness.
"""

from __future__ import annotations

import re
import secrets
import unicodedata
from hashlib import sha256
from pathlib import Path

from pyhpke.exceptions import PyHPKEError

from . import bbs, cbor, hpke, storage

PROFILE = "proposed-B1-E1-ADR0113"
WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
WORDLIST_PATH = Path(__file__).parent / "data" / "proposed-backup" / "english.txt"


class BackupError(ValueError):
    """Invalid proposed backup; messages never contain secret input material."""


def _words():
    raw = WORDLIST_PATH.read_bytes()
    if sha256(raw).hexdigest() != WORDLIST_SHA256:
        raise BackupError("pinned wordlist hash mismatch")
    words = raw.decode("ascii").splitlines()
    if len(words) != 2048 or len(set(words)) != 2048:
        raise BackupError("invalid pinned wordlist")
    return words


def phrase_from_entropy(entropy: bytes | None = None) -> str:
    entropy = secrets.token_bytes(16) if entropy is None else entropy
    _bytes(entropy, 16)
    value = (int.from_bytes(entropy, "big") << 4) | (sha256(entropy).digest()[0] >> 4)
    words = _words()
    return " ".join(words[(value >> (11 * i)) & 2047] for i in reversed(range(12)))


def canonical_phrase(phrase: str) -> bytes:
    if type(phrase) is not str:
        raise BackupError("phrase must be text")
    normalized = unicodedata.normalize("NFKD", phrase)
    normalized = normalized.translate(
        str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
    )
    if not normalized.isascii():
        raise BackupError("phrase contains non-ASCII characters")
    words = re.split(r"[\x09-\x0d\x20]+", normalized.strip("\x09\x0a\x0b\x0c\x0d\x20"))
    if len(words) != 12:
        raise BackupError("phrase must contain twelve full words")
    indices = {word: index for index, word in enumerate(_words())}
    try:
        value = 0
        for word in words:
            value = (value << 11) | indices[word]
    except KeyError:
        raise BackupError("phrase contains a word outside the pinned list") from None
    entropy = (value >> 4).to_bytes(16, "big")
    if value & 15 != sha256(entropy).digest()[0] >> 4:
        raise BackupError("phrase checksum mismatch")
    return " ".join(words).encode("ascii")


def _bytes(value, size=None):
    if type(value) is not bytes or (size is not None and len(value) != size):
        raise BackupError("invalid byte string or length")


def _uint(value):
    if type(value) is not int or not 0 <= value < 2**64:
        raise BackupError("invalid unsigned integer")


def _map(value, keys):
    if type(value) is not dict or any(type(k) is not int for k in value) or set(value) != set(keys):
        raise BackupError("unknown or missing map key")


def _cid(value):
    _bytes(value, 33)
    if value[0] != 1:
        raise BackupError("invalid CID")


def validate_plaintext(value, mode):
    if type(mode) is not int or mode not in (1, 2):
        raise BackupError("unknown plaintext mode")
    _map(value, range(6) if mode == 1 else range(3))
    if type(value[0]) is not int or value[0] != 1:
        raise BackupError("unknown plaintext version")
    _bytes(value[1], 32)
    _bytes(value[2], 32)
    if mode == 2:
        return
    if type(value[3]) is not list or type(value[4]) is not list:
        raise BackupError("cards and contexts must be arrays")
    _uint(value[5])
    for card in value[3]:
        # E1 explicitly adds secret_prover_blind at key 6. Old opaque layouts are
        # not silently migrated; proof validity needs the proposed E1 implementation.
        _map(card, range(7))
        _cid(card[0])
        _bytes(card[1])
        if not 4 <= len(card[1]) <= 32:
            raise BackupError("issuer kid must be four to thirty-two bytes")
        _uint(card[2])
        if type(card[3]) is not list or not card[3] or card[2] != len(card[3]) + 2:
            raise BackupError("invalid E1 signed-message layout")
        for message in card[3]:
            _bytes(message, 8)
        _bytes(card[4], 80)
        for key in (5, 6):
            _bytes(card[key], 32)
            scalar = int.from_bytes(card[key], "big")
            if scalar >= bbs.ORDER or (key == 5 and scalar == 0):
                raise BackupError("invalid retained E1 scalar")
    for context in value[4]:
        if type(context) is not dict:
            raise BackupError("invalid context")
        _map(context, (0, 1) if 1 in context else (0,))
        _cid(context[0])
        if 1 in context:
            _uint(context[1])


def _seal(value, mode, recipient, *, salt=None, content_key=None, ephemeral_private=None):
    validate_plaintext(value, mode)
    _bytes(recipient, 32)
    key = secrets.token_bytes(16) if content_key is None else content_key
    _bytes(key, 16)
    envelope = {
        0: 1,
        1: mode,
        3: hpke.wrap_backup_key(recipient, key, ephemeral_private=ephemeral_private),
        4: storage.seal(cbor.encode(value), key),
    }
    if mode == 1:
        _bytes(salt, 16)
        envelope[2] = salt
    return cbor.encode(envelope)


def pack_backup(value, phrase, *, salt=None, content_key=None, ephemeral_private=None):
    """Pack a complete proposed recovery file, without writing it anywhere."""
    validate_plaintext(value, 1)
    salt = secrets.token_bytes(16) if salt is None else salt
    _bytes(salt, 16)
    private = hpke.backup_private_key(canonical_phrase(phrase), salt)
    return _seal(
        value,
        1,
        hpke.public_key(private),
        salt=salt,
        content_key=content_key,
        ephemeral_private=ephemeral_private,
    )


def pack_chat_export(value, recipient_public, *, content_key=None, ephemeral_private=None):
    return _seal(
        value, 2, recipient_public, content_key=content_key, ephemeral_private=ephemeral_private
    )


def _envelope(encoded, mode, max_envelope_bytes):
    _bytes(encoded)
    if type(max_envelope_bytes) is not int or max_envelope_bytes <= 0:
        raise BackupError("caller must provide a positive receive size limit")
    if len(encoded) > max_envelope_bytes:
        raise BackupError("file exceeds caller receive policy")
    try:
        value = cbor.decode(encoded)
    except ValueError:
        raise BackupError("invalid canonical envelope") from None
    _map(value, (0, 1, 2, 3, 4) if mode == 1 else (0, 1, 3, 4))
    if type(value[0]) is not int or value[0] != 1 or type(value[1]) is not int or value[1] != mode:
        raise BackupError("unknown envelope version or mode")
    if mode == 1:
        _bytes(value[2], 16)
    _bytes(value[3], 64)
    _bytes(value[4])
    if not value[4] or value[4][0] != storage.FORMAT_DIRECT:
        raise BackupError("contents must use sealed format 1")
    return value


def _open(value, private, mode):
    try:
        key = hpke.unwrap_backup_key(private, value[3])
        plaintext = storage.open_sealed(value[4], key=key)
        decoded = cbor.decode(plaintext)
        validate_plaintext(decoded, mode)
    except (PyHPKEError, ValueError):
        raise BackupError("backup authentication or plaintext validation failed") from None
    return decoded


def unpack_backup(encoded, phrase, *, max_envelope_bytes):
    """Return a fully authenticated/validated object, or return no restored state."""
    value = _envelope(encoded, 1, max_envelope_bytes)
    private = hpke.backup_private_key(canonical_phrase(phrase), value[2])
    return _open(value, private, 1)


def unpack_chat_export(encoded, recipient_private, *, max_envelope_bytes):
    value = _envelope(encoded, 2, max_envelope_bytes)
    _bytes(recipient_private, 32)
    return _open(value, recipient_private, 2)
