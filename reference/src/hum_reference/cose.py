"""COSE_Sign (RFC 9052) with a detached payload, for manifest signatures.

Manifest spec, "The envelope":

- COSE_Sign, one ``COSE_Signature`` per signer, detached payload equal to the CID.
- The protected header of each signature carries the key ID (label 4) and the
  algorithm (label 1). Ed25519 is EdDSA, algorithm ``-8``.
- Domain separation: ``hum/manifest/1`` is the COSE ``external_aad`` (ADR 0105).

How the domain string enters the COSE structure is a format detail the spec
leaves open. This reference puts it in ``external_aad`` (ADR 0082-w0-08), so
the bytes under the Ed25519 signature are::

    Sig_structure = ["Signature", body_protected, sign_protected, external_aad, payload]
                  = ["Signature", h'', <protected>, "hum/manifest/1", <cid>]

encoded deterministically. The body protected header is empty.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import cbor
from .keys import SigningKey, verify

__all__ = [
    "ALG_EDDSA",
    "COSE_SIGN_TAG",
    "DOMAIN_MANIFEST",
    "HEADER_ALG",
    "HEADER_KID",
    "Signature",
    "decode_cose_sign",
    "encode_cose_sign",
    "sig_structure",
    "sign_cid",
    "verify_signature",
]

COSE_SIGN_TAG = 98
HEADER_ALG = 1
HEADER_KID = 4
ALG_EDDSA = -8
DOMAIN_MANIFEST = b"hum/manifest/1"


@dataclass(frozen=True)
class Signature:
    """One COSE_Signature: raw protected header bytes, key ID, algorithm, signature bytes."""

    protected: bytes
    kid: bytes
    alg: int
    signature: bytes


def protected_header(kid: bytes, alg: int = ALG_EDDSA) -> bytes:
    return cbor.encode({HEADER_ALG: alg, HEADER_KID: kid})


def sig_structure(protected: bytes, payload: bytes, external_aad: bytes = DOMAIN_MANIFEST) -> bytes:
    """The ``Sig_structure`` bytes (RFC 9052 section 4.4) for a COSE_Sign signature."""
    return cbor.encode(["Signature", b"", protected, external_aad, payload])


def sign_cid(key: SigningKey, kid: bytes, cid: bytes) -> Signature:
    """Sign a manifest CID under the ``hum/manifest/1`` domain."""
    protected = protected_header(kid)
    return Signature(protected, kid, ALG_EDDSA, key.sign(sig_structure(protected, cid)))


def verify_signature(public: bytes, sig: Signature, cid: bytes) -> bool:
    """True when ``sig`` is a valid EdDSA signature by ``public`` over ``hum/manifest/1`` + CID."""
    if sig.alg != ALG_EDDSA:
        return False
    return verify(public, sig_structure(sig.protected, cid), sig.signature)


def encode_cose_sign(signatures: list[Signature]) -> bytes:
    """Tagged COSE_Sign with a nil (detached) payload: 98([h'', {}, null, [sigs...]])."""
    sigs = [[s.protected, {}, s.signature] for s in signatures]
    return cbor.encode(cbor.Tag(COSE_SIGN_TAG, [b"", {}, None, sigs]))


def decode_cose_sign(data: bytes) -> list[Signature]:
    """Parse a tagged COSE_Sign. Raises ``ValueError`` on anything but the shape above."""
    item = cbor.decode(data)
    if not isinstance(item, cbor.Tag) or item.tag != COSE_SIGN_TAG:
        raise ValueError("not a tagged COSE_Sign")
    body = item.value
    if not (isinstance(body, list) and len(body) == 4):
        raise ValueError("COSE_Sign must have four elements")
    protected, unprotected, payload, sigs = body
    if protected != b"" or unprotected != {} or payload is not None:
        raise ValueError("COSE_Sign body headers must be empty and the payload detached")
    if not isinstance(sigs, list) or not sigs:
        raise ValueError("COSE_Sign needs at least one signature")
    out = []
    for s in sigs:
        if not (isinstance(s, list) and len(s) == 3):
            raise ValueError("COSE_Signature must have three elements")
        prot, unprot, sig = s
        if not isinstance(prot, bytes) or unprot != {} or not isinstance(sig, bytes):
            raise ValueError("malformed COSE_Signature")
        hdr = cbor.decode(prot)
        if not isinstance(hdr, dict) or set(hdr) != {HEADER_ALG, HEADER_KID}:
            raise ValueError("protected header must carry exactly alg and kid")
        if not isinstance(hdr[HEADER_KID], bytes) or not isinstance(hdr[HEADER_ALG], int):
            raise ValueError("protected header types")
        out.append(Signature(prot, hdr[HEADER_KID], hdr[HEADER_ALG], sig))
    return out
