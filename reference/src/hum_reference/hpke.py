"""Hum's RFC 9180 base-mode bindings, backed by approved pyhpke 0.6.5.

Explicit ephemeral keys exist only for reproducible reference fixtures. Callers must
supply fresh randomness in real use. These functions validate encryption framing;
credential, ticket proof and manifest authorization remain their callers' checks.
"""

from __future__ import annotations

from hashlib import sha256

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMKeyPair

AES = AEADId.AES128_GCM
CHACHA = AEADId.CHACHA20_POLY1305


def suite(aead=AES):
    return CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, aead)


def public_key(private_key: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()


def sender(recipient: bytes, info: bytes, *, aead=AES, ephemeral_private=None):
    hpke = suite(aead)
    ephemeral = None
    if ephemeral_private is not None:
        private = X25519PrivateKey.from_private_bytes(ephemeral_private)
        ephemeral = KEMKeyPair(
            KEMKey.from_pyca_cryptography_key(private),
            KEMKey.from_pyca_cryptography_key(private.public_key()),
        )
    return hpke.create_sender_context(
        hpke.kem.deserialize_public_key(recipient), info, eks=ephemeral
    )


def seal(recipient, info, plaintext, *, aad=b"", aead=AES, ephemeral_private=None):
    enc, context = sender(recipient, info, aead=aead, ephemeral_private=ephemeral_private)
    return enc + context.seal(plaintext, aad), context


def open_seal(private_key, info, sealed, *, aad=b"", aead=AES):
    if len(sealed) < 48:
        raise ValueError("truncated HPKE encapsulation or tag")
    hpke = suite(aead)
    context = hpke.create_recipient_context(
        sealed[:32], hpke.kem.deserialize_private_key(private_key), info
    )
    return context.open(sealed[32:], aad), context


def _cid(value):
    if len(value) != 33 or value[0] != 1:
        raise ValueError("expected a version-1 CID")
    return value


def _session(value):
    if len(value) != 16:
        raise ValueError("session ID must be 16 bytes")
    return value


def seal_issue(recipient, authority, plaintext, *, ephemeral_private=None):
    return seal(
        recipient,
        b"hum/issue/1" + _cid(authority),
        plaintext,
        aead=CHACHA,
        ephemeral_private=ephemeral_private,
    )


def open_issue(private_key, authority, sealed):
    return open_seal(private_key, b"hum/issue/1" + _cid(authority), sealed, aead=CHACHA)


def response_material(context):
    return (
        context.export(b"hum/issue-response/1 key", 32),
        context.export(b"hum/issue-response/1 nonce", 12),
    )


def seal_response(context, session, plaintext):
    """Exactly one response per issue context; retries reuse identical response bytes."""
    key, nonce = response_material(context)
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, _session(session))


def open_response(context, session, ciphertext):
    key, nonce = response_material(context)
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, _session(session))


def evidence_binding(authority, name, session, request):
    return (
        b"hum/evidence/1" + _cid(authority) + name.encode("utf-8"),
        _session(session) + sha256(request).digest(),
    )


def seal_evidence(
    recipient, authority, name, session, request, plaintext, *, ephemeral_private=None
):
    info, aad = evidence_binding(authority, name, session, request)
    return seal(
        recipient, info, plaintext, aad=aad, aead=CHACHA, ephemeral_private=ephemeral_private
    )[0]


def open_evidence(private_key, authority, name, session, request, sealed):
    info, aad = evidence_binding(authority, name, session, request)
    return open_seal(private_key, info, sealed, aad=aad, aead=CHACHA)[0]


def seal_keybox(recipient, deck, plaintext, *, ephemeral_private=None):
    return (
        b"\x01"
        + seal(
            recipient,
            b"hum/results-keybox/1" + _cid(deck),
            plaintext,
            aad=deck,
            ephemeral_private=ephemeral_private,
        )[0]
    )


def open_keybox(private_key, deck, sealed):
    if not sealed or sealed[0] != 1:
        raise ValueError("unknown keybox version")
    return open_seal(private_key, b"hum/results-keybox/1" + _cid(deck), sealed[1:], aad=deck)[0]


def seal_ticket(recipient, lineage, plaintext, *, ephemeral_private=None):
    if len(plaintext) != 4096:
        raise ValueError("join ticket plaintext must be TICKET_BYTES (4096)")
    return seal(
        recipient,
        b"hum/join-ticket/1" + _cid(lineage),
        plaintext,
        ephemeral_private=ephemeral_private,
    )[0]


def open_ticket(private_key, lineage, sealed):
    if len(sealed) != 4096 + 32 + 16:
        raise ValueError("join ticket ciphertext must be 4144 bytes")
    return open_seal(private_key, b"hum/join-ticket/1" + _cid(lineage), sealed)[0]


def backup_private_key(phrase: bytes, salt: bytes) -> bytes:
    """Derive from the caller's encoded BIP-39 phrase; word validation is external."""
    if len(salt) != 16:
        raise ValueError("backup salt must be 16 bytes")
    raw = bytearray(
        Argon2id(salt=salt, length=32, iterations=3, lanes=1, memory_cost=64 * 1024).derive(phrase)
    )
    raw[0] &= 248
    raw[31] = (raw[31] & 127) | 64
    return bytes(raw)


def wrap_backup_key(recipient, key, *, ephemeral_private=None):
    if len(key) != 16:
        raise ValueError("sealed-blob key must be 16 bytes")
    return seal(recipient, b"hum/backup/1", key, ephemeral_private=ephemeral_private)[0]


def unwrap_backup_key(private_key, sealed):
    key = open_seal(private_key, b"hum/backup/1", sealed)[0]
    if len(key) != 16:
        raise ValueError("sealed-blob key must be 16 bytes")
    return key
