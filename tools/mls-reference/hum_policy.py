"""Hum chat §11.1/§12.6 primitives, using existing CBOR and vetted cryptography.

This does not validate roles, report MLS attribution, delivery keysets or credentials.
"""

import hashlib
import hmac
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "reference/src"))
from hum_reference import cbor


def frank_aad(group_id, epoch, mimi_bytes):
    if len(group_id) != 32 or not 0 <= epoch < 2**64:
        raise ValueError("group/epoch")
    content = cbor.decode(mimi_bytes)
    if (
        not isinstance(content, list)
        or len(content) != 7
        or not isinstance(content[5], dict)
    ):
        raise ValueError("MIMI shape")
    key = content[5].get("hum.frank")
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("franking key")
    tag = hmac.digest(
        key,
        b"hum/frank/1" + group_id + epoch.to_bytes(8, "big") + mimi_bytes,
        hashlib.sha256,
    )
    return b"\x01" + tag


def verify_frank(group_id, epoch, mimi_bytes, aad):
    if not hmac.compare_digest(frank_aad(group_id, epoch, mimi_bytes), aad):
        raise ValueError("franking mismatch")


def stamp_input(group_id, seq, received, aad):
    if len(group_id) != 32 or not 0 <= seq < 2**64 or not 0 <= received < 2**64:
        raise ValueError("stamp field range")
    if aad != b"\x00" and not (len(aad) == 33 and aad[0] == 1):
        raise ValueError("stamp AAD")
    return (
        b"hum/stamp/1"
        + group_id
        + seq.to_bytes(8, "big")
        + received.to_bytes(8, "big")
        + aad
    )
