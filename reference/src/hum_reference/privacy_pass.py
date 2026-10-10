"""RFC 9578 framing and type-2 redemption, using cryptography's RSA-PSS verifier.

Type-1 OPRF authentication and blind issuance are deliberately not implemented here.
The RFC fixtures supply independent issuance inputs/outputs, not generated signatures.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

AUTHENTICATOR_LENGTH = {1: 48, 2: 256}


@dataclass(frozen=True)
class Token:
    token_type: int
    nonce: bytes
    challenge_digest: bytes
    key_id: bytes
    authenticator: bytes

    @classmethod
    def decode(cls, encoded: bytes) -> Token:
        if len(encoded) < 2:
            raise ValueError("truncated token")
        kind = int.from_bytes(encoded[:2], "big")
        if kind not in AUTHENTICATOR_LENGTH or len(encoded) != 98 + AUTHENTICATOR_LENGTH[kind]:
            raise ValueError("unsupported token type or wrong token length")
        return cls(kind, encoded[2:34], encoded[34:66], encoded[66:98], encoded[98:])

    def authenticator_input(self) -> bytes:
        return self.token_type.to_bytes(2, "big") + self.nonce + self.challenge_digest + self.key_id


def verify_public_token(encoded: bytes, challenge: bytes, issuer_key: bytes) -> bool:
    """Verify a type-2 token against its exact challenge and RFC-encoded issuer key.

    This is cryptographic verification only; the store must also atomically reject
    a spent nonce and enforce the token-key/context binding before redemption.
    """
    try:
        token = Token.decode(encoded)
        if token.token_type != 2 or challenge[:2] != b"\x00\x02":
            return False
        if token.challenge_digest != hashlib.sha256(challenge).digest():
            return False
        if token.key_id != hashlib.sha256(issuer_key).digest():
            return False
        key = serialization.load_der_public_key(issuer_key)
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048:
            return False
        key.verify(
            token.authenticator,
            token.authenticator_input(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48),
            hashes.SHA384(),
        )
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


def rfc_fixtures() -> dict:
    """Unmodified hex fields extracted from RFC 9578 Appendices A and B."""
    return json.loads((Path(__file__).parent / "data" / "rfc9578.json").read_text())
