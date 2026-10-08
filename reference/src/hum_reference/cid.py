"""Content IDs: one algorithm byte then the digest.

Manifest spec, "Encoding and content addressing".

Algorithm ``0x01`` is SHA-256. The text form is ``c`` followed by lowercase
base32 (RFC 4648 alphabet) with no padding.
"""

from __future__ import annotations

import base64
import hashlib

__all__ = ["SHA256", "cid", "cid_from_text", "cid_text", "parse_cid"]

SHA256 = 0x01
_LENGTHS = {SHA256: 32}


def cid(data: bytes, alg: int = SHA256) -> bytes:
    """The CID of ``data``: algorithm byte plus digest."""
    if alg != SHA256:
        raise ValueError(f"unknown CID algorithm {alg:#04x}")
    return bytes([alg]) + hashlib.sha256(data).digest()


def parse_cid(value: bytes) -> tuple[int, bytes]:
    """Split a CID into (algorithm, digest), checking the length for the algorithm."""
    if not value:
        raise ValueError("empty CID")
    alg = value[0]
    if alg not in _LENGTHS:
        raise ValueError(f"unknown CID algorithm {alg:#04x}")
    if len(value) != 1 + _LENGTHS[alg]:
        raise ValueError("CID length does not match its algorithm")
    return alg, value[1:]


def cid_text(value: bytes) -> str:
    """Text form: ``c`` + lowercase base32, no padding."""
    parse_cid(value)
    return "c" + base64.b32encode(value).decode("ascii").rstrip("=").lower()


def cid_from_text(text: str) -> bytes:
    """Inverse of ``cid_text``. Rejects uppercase, padding and a missing prefix."""
    if not text.startswith("c"):
        raise ValueError("CID text must start with 'c'")
    body = text[1:]
    if body != body.lower() or "=" in body:
        raise ValueError("CID text must be lowercase with no padding")
    padded = body.upper() + "=" * (-len(body) % 8)
    raw = base64.b32decode(padded)
    parse_cid(raw)
    return raw
