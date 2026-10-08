"""Ed25519 keys through ``cryptography`` (RFC 8032). No primitive is implemented here.

Vectors use keys derived from fixed 32-byte seeds so regeneration is byte-identical.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = ["SigningKey", "key_from_label", "verify"]


class SigningKey:
    """An Ed25519 private key with its 32-byte seed and public key."""

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        self.seed = seed
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        self.public = self._key.public_key().public_bytes_raw()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """True when ``signature`` is a valid Ed25519 signature by ``public`` over ``message``."""
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def key_from_label(label: str) -> SigningKey:
    """A deterministic test key: seed = SHA-256("hum-vectors/key/" + label). Test use only."""
    return SigningKey(hashlib.sha256(b"hum-vectors/key/" + label.encode()).digest())
