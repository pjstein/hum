"""Chat content types and derivations from docs/specs/chat.md that need no live MLS state.

- Section 5.2 to 5.16 content bodies: deterministic CBOR maps with integer keys, key 0 the
  body version (1), with the required keys and maxima the tables give. ``decode(name, bytes)``
  rejects an unknown version, a missing required key, an array over its maximum, bytes that
  do not re-encode to themselves, and the ExternalPart count rule for ``file-op`` and
  ``folder-index``.
- Section 5.1 message ids, as draft-ietf-mimi-content-09's message-ID section and chat.md
  §5.1 fix them: ``0x01 || SHA-256(len(senderUri) || senderUri || len(roomUri) || roomUri ||
  message || salt)[0..31]``, each length a big-endian unsigned 16-bit integer, ``message`` the
  serialized ``MimiContent`` (which already holds the salt, so the salt is in the input twice).
- Section 4.2 ``authenticated_data`` (``0x01 || tag``) and section 4.3 MLS padding buckets.
- Section 2.2 safety code.
- The MIMI ``ExternalPart`` carried for attachments: draft-09's ``nestedPart`` is one flat
  CBOR array ``[disposition, language, cardinality, ...part fields]``; for an ExternalPart
  that is the fifteen elements ``[disposition, language, 2, contentType, url, expires, size,
  encAlg, key, nonce, aad, hashAlg, contentHash, description, filename]`` (chat.md §5.1), with
  storage.md section 3.2's forward mapping and reverse reject rule.

seam: ``hum/chat-roles/1`` (signature), ``hum/safety/1`` (hash).
"""

from __future__ import annotations

import hashlib
from typing import Any

from . import cbor, cose, storage
from .bodies import LANG_RE
from .cid import cid_from_text, cid_text, parse_cid
from .keys import SigningKey, verify

__all__ = [
    "CONTENT_TYPES",
    "TYPES",
    "authenticated_data",
    "decode",
    "encode",
    "external_part_from_reference",
    "external_part_to_reference",
    "media_type",
    "message_id",
    "mls_bucket",
    "roles_sign",
    "roles_verify",
    "safety_code",
    "uri_length",
]

DOMAIN_ROLES = b"hum/chat-roles/1"
DOMAIN_SAFETY = b"hum/safety/1"


class ChatError(ValueError):
    pass


# ---------------------------------------------------------------- content types
# name -> (required keys, optional keys, array maxima {key: max}, validators)
TYPES: dict[str, dict[str, Any]] = {
    "promote-proposal": {"req": {0, 1, 2, 3, 4, 5}, "opt": set(), "max": {}},
    "promote-confirm": {"req": {0, 1, 2}, "opt": {3}, "max": {}},
    "merge-proposal": {"req": {0, 1, 2}, "opt": {3}, "max": {}},
    "deck-dealt": {"req": {0, 1, 2}, "opt": {3, 4, 5, 6}, "max": {5: 64}},
    "release-digest": {"req": {0, 1, 2}, "opt": {3}, "max": {}},
    "file-op": {"req": {0, 1, 2}, "opt": {3, 4, 5, 6}, "max": {4: 16}},
    "folder-index": {"req": {0, 1}, "opt": set(), "max": {}},
    "public-copy": {"req": {0, 1, 2}, "opt": set(), "max": {}, "no_version": True},
    "keyring-share": {"req": {0}, "opt": set(), "max": {}, "no_version": True},
    "token-key": {"req": {0, 1, 2, 3}, "opt": set(), "max": {}},
    "greeting-key": {"req": {0, 1, 2}, "opt": set(), "max": {}},
    "agent-membership": {"req": {0, 1, 2, 3, 4}, "opt": {5}, "max": {}},
    "roles": {"req": {0, 1, 2, 3, 6, 7}, "opt": {4, 5}, "max": {3: 10_000}},
    "directory": {"req": {0, 1, 2}, "opt": {3, 4}, "max": {4: 1000}},
    "checkpoint": {"req": {0, 1, 2, 3}, "opt": set(), "max": {}},
    "history-offer": {"req": {0, 1, 2, 3}, "opt": {4}, "max": {}},
    "join-request": {"req": {0, 1, 2}, "opt": set(), "max": {2: 8}},
}
CONTENT_TYPES = {name: f"application/vnd.hum.{name}+cbor" for name in TYPES}
# ops that carry exactly one ExternalPart
FILE_OP_WITH_PART = {1, 4, 6}


def media_type(name: str) -> str:
    return CONTENT_TYPES[name]


def _is_cid(v: Any) -> bool:
    try:
        parse_cid(v)
        return True
    except (ValueError, TypeError):
        return False


def _text(v: Any, limit: int) -> bool:
    return isinstance(v, str) and len(v.encode()) <= limit


def _b(v: Any, n: int | None = None) -> bool:
    return isinstance(v, bytes) and (n is None or len(v) == n)


def _u(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


_FIELD_CHECKS: dict[str, dict[int, Any]] = {
    "promote-proposal": {
        1: lambda v: v in (1, 2, 3, 4),
        2: _is_cid,
        3: _is_cid,
        4: lambda v: _text(v, 2000) and v,
        5: lambda v: _b(v, 32),
    },
    "promote-confirm": {1: lambda v: _b(v, 32), 2: lambda v: v in (1, 2), 3: _is_cid},
    "merge-proposal": {1: _is_cid, 2: _is_cid, 3: lambda v: _text(v, 500)},
    "deck-dealt": {
        1: _is_cid,
        2: _is_cid,
        3: lambda v: _text(v, 200),
        4: _u,
        5: lambda v: isinstance(v, list) and all(_is_cid(c) for c in v),
        6: _u,
    },
    "release-digest": {1: _is_cid, 2: _is_cid, 3: lambda v: _text(v, 200)},
    "file-op": {
        1: lambda v: v in range(1, 8),
        2: lambda v: _b(v, 16),
        3: lambda v: _text(v, 255) and "/" not in v and "\x00" not in v and v,
        4: lambda v: (
            isinstance(v, list)
            and all(_text(e, 255) and e and "/" not in e and "\x00" not in e for e in v)
        ),
        5: lambda v: _b(v, 32),
        6: lambda v: _b(v, 32),
    },
    "folder-index": {1: _u},
    "public-copy": {0: _is_cid, 1: _is_cid, 2: lambda v: _text(v, 127)},
    "keyring-share": {
        0: lambda v: (
            isinstance(v, list)
            and all(
                isinstance(e, list) and len(e) == 3 and _u(e[0]) and _u(e[1]) and _b(e[2], 16)
                for e in v
            )
        )
    },
    "token-key": {1: _is_cid, 2: lambda v: _b(v) and v, 3: _u},
    "greeting-key": {1: _is_cid, 2: lambda v: _b(v, 32)},
    "agent-membership": {
        1: lambda v: v in (1, 2),
        2: _is_cid,
        3: lambda v: v in (1, 2),
        4: _u,
        5: lambda v: _b(v, 32),
    },
    "roles": {
        1: _is_cid,
        2: _u,
        3: lambda v: (
            isinstance(v, list)
            and all(
                isinstance(g, list) and len(g) == 2 and _b(g[0], 32) and g[1] in (1, 2) for g in v
            )
        ),
        4: lambda v: (
            isinstance(v, dict)
            and all(k in (1, 2, 3) and isinstance(c, list) and len(c) <= 16 for k, c in v.items())
        ),
        5: lambda v: (
            isinstance(v, dict)
            and len(v) <= 1000
            and all(_b(k, 32) and isinstance(c, list) and len(c) <= 256 for k, c in v.items())
        ),
        6: lambda v: isinstance(v, dict) and all(_b(k, 32) and _b(x) for k, x in v.items()),
        7: _b,
    },
    "directory": {
        1: _u,
        2: lambda v: v in range(1, 6),
        3: lambda v: isinstance(v, dict) and _b(v.get(0), 32) and _text(v.get(1, ""), 100),
        4: lambda v: isinstance(v, list),
    },
    "checkpoint": {1: _is_cid, 2: _u, 3: lambda v: _b(v, 32)},
    "history-offer": {1: _b, 2: _u, 3: _u, 4: _is_cid},
    "join-request": {
        1: lambda v: _b(v, 32),
        2: lambda v: isinstance(v, list) and all(_b(h) for h in v),
    },
}

_FILE_OP_REQUIRED = {1: {3, 4}, 2: {3}, 3: {4}, 4: {5}, 5: set(), 6: {3, 4, 6}, 7: set()}


def encode(name: str, body: dict[int, Any]) -> bytes:
    decode(name, cbor.encode(body))  # validate before handing out bytes
    return cbor.encode(body)


def decode(name: str, data: bytes, *, external_parts: int = 0) -> dict[int, Any]:
    """Validate a content body per section 5.2 and the type's table. Raises ``ChatError``."""
    spec = TYPES[name]
    try:
        body = cbor.decode(data)
    except cbor.CborError as e:
        raise ChatError(f"not canonical: {e}") from e
    if not isinstance(body, dict) or not all(isinstance(k, int) for k in body):
        raise ChatError("body must be a map with integer keys")
    if not spec.get("no_version") and body.get(0) != 1:
        raise ChatError("unknown body version")
    missing = spec["req"] - set(body)
    if missing:
        raise ChatError(f"missing required keys {sorted(missing)}")
    extra = set(body) - spec["req"] - spec["opt"]
    if extra:
        raise ChatError(f"unknown keys {sorted(extra)}")
    for key, limit in spec["max"].items():
        if key in body and isinstance(body[key], list) and len(body[key]) > limit:
            raise ChatError(f"array at key {key} over maximum {limit}")
    for key, check in _FIELD_CHECKS[name].items():
        if key in body and not check(body[key]):
            raise ChatError(f"field {key} invalid")
    if name == "file-op":
        op = body[1]
        need = _FILE_OP_REQUIRED[op]
        if need - set(body):
            raise ChatError(f"file-op {op} missing keys {sorted(need - set(body))}")
        want = 1 if op in FILE_OP_WITH_PART else 0
        if external_parts != want:
            raise ChatError(f"file-op {op} needs {want} ExternalPart, got {external_parts}")
    if name == "folder-index" and external_parts != 1:
        raise ChatError("folder-index needs exactly one ExternalPart")
    if name == "directory":
        if body[2] in (1, 2, 3, 4) and 3 not in body:
            raise ChatError("directory op needs channel")
        if body[2] == 5 and 4 not in body:
            raise ChatError("snapshot needs channels")
    if name == "agent-membership" and body[3] == 1 and 5 not in body:
        raise ChatError("runtime 1 needs host")
    if name == "promote-confirm" and body[2] == 1 and 3 not in body:
        raise ChatError("confirmed needs object")
    return body


# ---------------------------------------------------------------- roles signature (5.8)


def roles_payload(body: dict[int, Any]) -> bytes:
    unsigned = {k: v for k, v in body.items() if k != 7}
    return DOMAIN_ROLES + hashlib.sha256(cbor.encode(unsigned)).digest()


def roles_sign(body: dict[int, Any], signers: list[tuple[bytes, SigningKey]]) -> dict[int, Any]:
    """Sign keys 0..6 with a COSE_Sign whose detached payload is the roles payload. The
    external AAD is empty: the domain string is the payload prefix the spec names."""
    payload = roles_payload(body)
    sigs = []
    for kid, key in signers:
        protected = cose.protected_header(kid)
        sigs.append(
            cose.Signature(
                protected,
                kid,
                cose.ALG_EDDSA,
                key.sign(cose.sig_structure(protected, payload, external_aad=b"")),
            )
        )
    out = dict(body)
    out[7] = cose.encode_cose_sign(sigs)
    return out


def roles_verify(body: dict[int, Any], keys: dict[bytes, bytes]) -> int:
    payload = roles_payload(body)
    good = set()
    for s in cose.decode_cose_sign(body[7]):
        pub = keys.get(s.kid)
        if pub and verify(
            pub, cose.sig_structure(s.protected, payload, external_aad=b""), s.signature
        ):
            good.add(s.kid)
    return len(good)


# ---------------------------------------------------------------- message ids (5.1)


def uri_length(n: int) -> bytes:
    """A URI's size in octets as a big-endian unsigned 16-bit integer (draft-09 message IDs)."""
    if not 0 <= n <= 0xFFFF:
        raise ValueError("URI longer than 65535 octets")
    return n.to_bytes(2, "big")


def _b32(data: bytes) -> str:
    import base64

    return base64.b32encode(data).decode().rstrip("=").lower()


def sender_uri(identity_key: bytes) -> str:
    return "hum:member:" + _b32(identity_key)


def room_uri(group_id: bytes) -> str:
    return "hum:channel:" + _b32(group_id)


def message_id(identity_key: bytes, group_id: bytes, message: bytes, salt: bytes) -> bytes:
    """``0x01 || SHA-256(len(senderUri) || senderUri || len(roomUri) || roomUri || message ||
    salt)[0..31]``, lengths as ``uri_length`` (chat.md §5.1, draft-09). ``message`` is the
    serialized MimiContent, which already carries ``salt``; the salt is appended again."""
    s = sender_uri(identity_key).encode()
    r = room_uri(group_id).encode()
    h = hashlib.sha256(uri_length(len(s)) + s + uri_length(len(r)) + r + message + salt).digest()
    return b"\x01" + h[:31]


# ---------------------------------------------------------------- framing (4.2, 4.3)

APP_BUCKETS = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
COMMIT_BUCKETS = APP_BUCKETS + [131072, 262144, 524288, 1048576]


def mls_bucket(size: int, commit: bool = False) -> int | None:
    for b in COMMIT_BUCKETS if commit else APP_BUCKETS:
        if size <= b:
            return b
    return None


def authenticated_data(frank_tag: bytes | None) -> bytes:
    if frank_tag is None:
        return b"\x00"
    if len(frank_tag) != 32:
        raise ChatError("franking tag must be 32 bytes")
    return b"\x01" + frank_tag


def check_authenticated_data(ad: bytes, application: bool) -> bool:
    return (len(ad) == 33 and ad[0] == 1) if application else ad == b"\x00"


# ---------------------------------------------------------------- safety code (2.2)


def safety_code(identity_key: bytes) -> tuple[bytes, str]:
    code = hashlib.sha512(DOMAIN_SAFETY + identity_key).digest()
    groups = [f"{int.from_bytes(code[5 * i : 5 * i + 5], 'big') % 100000:05d}" for i in range(12)]
    return code, " ".join(groups)


# ---------------------------------------------------------------- ExternalPart (storage.md 3.2)

DISPOSITION_RENDER, DISPOSITION_REACTION = 1, 2
CARDINALITY_EXTERNAL = 2
EP_FIELDS = (
    "disposition", "language", "cardinality", "contentType", "url", "expires", "size", "encAlg",
    "key", "nonce", "aad", "hashAlg", "contentHash", "description", "filename",
)  # fmt: skip
EP_LEN = len(EP_FIELDS)


def external_part_from_reference(
    ref: storage.SealedReference, *, disposition: int = DISPOSITION_RENDER, language: str = ""
) -> list[Any]:
    """The flat fifteen-element ``nestedPart`` of draft-09 for a direct-form reference."""
    if (
        ref.format != storage.FORMAT_DIRECT
        or ref.key is None
        or ref.size is None
        or ref.digest is None
    ):
        raise ChatError("only a message-form direct reference maps onto an ExternalPart")
    return [
        disposition,
        language,
        CARDINALITY_EXTERNAL,
        ref.media,
        "hum:blob:" + cid_text(ref.cid),
        ref.expires or 0,
        ref.size,
        1,
        ref.key,
        b"",
        b"",
        1,
        ref.digest[1:],
        ref.description or "",
        ref.name or "",
    ]


def external_part_to_reference(part: list[Any]) -> storage.SealedReference:
    """The reverse rule: ignore (raise) any part that is not a Hum format 1 reference."""
    if not isinstance(part, list) or len(part) != EP_LEN:
        raise ChatError(f"an ExternalPart nestedPart has {EP_LEN} elements")
    disposition, language, cardinality = part[:3]
    ct, url, expires, size, enc_alg, key, nonce, aad, hash_alg, content_hash, desc, fname = part[3:]
    if not isinstance(disposition, int) or disposition < 0:
        raise ChatError("disposition must be a uint")
    if not isinstance(language, str) or (language != "" and not LANG_RE.match(language)):
        raise ChatError("language must be empty or a language tag")
    if cardinality != CARDINALITY_EXTERNAL:
        raise ChatError("cardinality must be 2 (external)")
    if not isinstance(expires, int) or not isinstance(size, int) or expires < 0 or size < 0:
        raise ChatError("expires and size must be uints")
    if enc_alg != 1:
        raise ChatError("encAlg must be 1")
    if hash_alg != 1:
        raise ChatError("hashAlg must be 1")
    if not _b(key, 16):
        raise ChatError("key must be 16 bytes")
    if nonce != b"" or aad != b"":
        raise ChatError("nonce and aad must be empty")
    if not _b(content_hash, 32):
        raise ChatError("contentHash must be 32 bytes")
    if not isinstance(url, str) or not url.startswith("hum:blob:"):
        raise ChatError("url must be hum:blob:<cid>")
    try:
        cid = cid_from_text(url[len("hum:blob:") :])
    except ValueError as e:
        raise ChatError("url CID is malformed") from e
    ref = storage.SealedReference(
        cid=cid,
        format=storage.FORMAT_DIRECT,
        media=ct,
        key=key,
        size=size,
        name=fname or None,
        digest=b"\x01" + content_hash,
        expires=expires or None,
        description=desc or None,
    )
    ref.validate(in_message=True)
    return ref
