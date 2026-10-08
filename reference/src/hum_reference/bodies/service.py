"""The ``service`` body: docs/specs/services.md "Services are named by key" (S-1 to S-8) and
docs/specs/storage.md section 7 for ``kind: blob-store`` (BS-1 to BS-6).

Shape rules and the single-version rules run at step 4; rules that need the previous
version (S-4, BS-5) and S-3 run at step 10. The manifest spec's older ``blob-store``
type name is accepted as the same body with ``kind`` fixed to ``blob-store``.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from .. import manifest as m
from . import (
    TypeRule,
    is_bytes,
    is_cid,
    is_text,
    is_uint,
    no_unknown_keys,
    require,
    require_keys,
)

__all__ = [
    "KINDS",
    "LOG_CEILINGS",
    "RETENTION_CLASSES",
    "body",
    "key_config",
    "parse_key_config",
    "rules",
    "schema",
]

# Common keys 0..15
KIND, ENDPOINTS, API_VERSION, OHTTP, TOKEN_ISSUERS, LIMITS, WITNESSES, ORIGIN = range(8)
JURISDICTION, RETENTION, HPKE, PHASE = 8, 9, 10, 11
RESERVED = {12, 13, 14, 15}
# blob-store keys from 16 (storage.md section 7)
ISSUER, BLOB_LIMITS, BLOB_RETENTION, FORMATS = 16, 17, 18, 19
ISS_NAME, ISS_TYPE, ISS_ROTATION = 0, 1, 2
BL_MAX_BLOB, BL_QUOTA_STORED, BL_QUOTA_PUT, BL_QUOTA_SERVED, BL_TOKENS_DAY = range(5)
BR_MAX, BR_TOMBSTONE = 0, 1
FMT_SEALED, FMT_PUBLIC = 0, 1
W_NAME, W_KEY = 0, 1

KINDS = (
    "log",
    "witness",
    "aggregator",
    "issuer",
    "delivery",
    "blob-store",
    "resolver",
    "relay",
    "gallery",
)
RELAYED_KINDS = {"log", "aggregator", "issuer", "delivery", "blob-store", "resolver", "gallery"}
TOKEN_KINDS = {"delivery", "blob-store"}
RETENTION_CLASSES = {"requests", "errors", "counters", "content"}
MIN_WITNESSES = 2
DAY = 86_400
# Ceilings from the "What services log" table; None means the sibling spec sets them.
LOG_CEILINGS: dict[str, int | None] = {
    "log": 90 * DAY,
    "witness": 90 * DAY,
    "aggregator": 7 * DAY,
    "issuer": None,
    "delivery": None,
    "blob-store": None,
    "resolver": 30 * DAY,
    "gallery": 30 * DAY,
    "relay": DAY,
}
KEM_LENGTHS = {0x0010: 65, 0x0011: 97, 0x0012: 133, 0x0020: 32, 0x0021: 56}


# ---------------------------------------------------------------- OHTTP KeyConfig (RFC 9458 §3)


def key_config(
    public: bytes, key_id: int = 1, kem: int = 0x0020, suites=((0x0001, 0x0001),)
) -> bytes:
    """``key_id(1) || kem_id(2) || public key || suites length(2) || (kdf(2) || aead(2))*``."""
    body_ = b"".join(k.to_bytes(2, "big") + a.to_bytes(2, "big") for k, a in suites)
    return bytes([key_id]) + kem.to_bytes(2, "big") + public + len(body_).to_bytes(2, "big") + body_


def parse_key_config(data: bytes) -> dict[str, Any]:
    """Parse one KeyConfig; raise ``ValueError`` when malformed."""
    if len(data) < 3:
        raise ValueError("too short")
    key_id = data[0]
    kem = int.from_bytes(data[1:3], "big")
    if kem not in KEM_LENGTHS:
        raise ValueError("unknown KEM")
    n = KEM_LENGTHS[kem]
    pub = data[3 : 3 + n]
    if len(pub) != n:
        raise ValueError("public key truncated")
    pos = 3 + n
    if len(data) < pos + 2:
        raise ValueError("suites length missing")
    slen = int.from_bytes(data[pos : pos + 2], "big")
    suites_bytes = data[pos + 2 : pos + 2 + slen]
    if len(suites_bytes) != slen or slen == 0 or slen % 4:
        raise ValueError("cipher suites malformed")
    if len(data) != pos + 2 + slen:
        raise ValueError("trailing bytes")
    suites = [
        (
            int.from_bytes(suites_bytes[i : i + 2], "big"),
            int.from_bytes(suites_bytes[i + 2 : i + 4], "big"),
        )
        for i in range(0, slen, 4)
    ]
    return {"key_id": key_id, "kem": kem, "public": pub, "suites": suites}


# ---------------------------------------------------------------- builders


def body(
    kind: str,
    endpoints: list[str],
    *,
    ohttp: bytes | None = None,
    token_issuers: list[bytes] | None = None,
    limits: dict | None = None,
    witnesses: list[tuple[str, bytes]] | None = None,
    origin: str | None = None,
    jurisdiction: str | None = None,
    retention: dict[str, int] | None = None,
    hpke: bytes | None = None,
    phase: int | None = None,
    issuer: dict[int, Any] | None = None,
    blob_limits: dict[int, int] | None = None,
    blob_retention: dict[int, int] | None = None,
    formats: dict[int, list] | None = None,
    api_version: int = 1,
) -> dict[int, Any]:
    out: dict[int, Any] = {KIND: kind, ENDPOINTS: list(endpoints), API_VERSION: api_version}
    for k, v in (
        (OHTTP, ohttp),
        (TOKEN_ISSUERS, token_issuers),
        (LIMITS, limits),
        (ORIGIN, origin),
        (JURISDICTION, jurisdiction),
        (RETENTION, retention),
        (HPKE, hpke),
        (PHASE, phase),
        (ISSUER, issuer),
        (BLOB_LIMITS, blob_limits),
        (BLOB_RETENTION, blob_retention),
        (FORMATS, formats),
    ):
        if v is not None:
            out[k] = v
    if witnesses is not None:
        out[WITNESSES] = [{W_NAME: n, W_KEY: k} for n, k in witnesses]
    return out


def blob_store_defaults() -> dict[str, Any]:
    """storage.md section 7 draft defaults for the reference store."""
    return {
        "issuer": {ISS_NAME: "hum-store", ISS_TYPE: 2, ISS_ROTATION: 30 * DAY},
        "blob_limits": {
            BL_MAX_BLOB: 2 * 1024**3,
            BL_QUOTA_STORED: 50 * 1024**3,
            BL_QUOTA_PUT: 10 * 1024**3,
            BL_QUOTA_SERVED: 100 * 1024**3,
            BL_TOKENS_DAY: 5000,
        },
        "blob_retention": {BR_MAX: 0, BR_TOMBSTONE: 30 * DAY},
        "formats": {
            FMT_SEALED: [1, 2],
            FMT_PUBLIC: [
                "application/vnd.apache.parquet",
                "text/plain; charset=utf-8",
                "application/cbor",
                "application/json",
                "application/vnd.hum.keybox+hpke",
                "image/png",
                "image/jpeg",
                "image/webp",
            ],
        },
    }


# ---------------------------------------------------------------- step 4


def _https_url(u: Any) -> bool:
    if not isinstance(u, str):
        return False
    parts = urlsplit(u)
    return parts.scheme == "https" and bool(parts.netloc) and not parts.query and not parts.fragment


def schema(env: dict[int, Any]) -> None:
    b = env[m.BODY]
    require_keys(b, {KIND, ENDPOINTS, API_VERSION}, "S-1")
    kind = b[KIND]
    if env[m.TYPE] == "blob-store":
        require(kind == "blob-store", "S-1", "a blob-store manifest's kind is blob-store")
    require(kind in KINDS, "S-1", f"unknown kind {kind!r}")
    require(not (set(b) & RESERVED), "S-1", "keys 12 to 15 are reserved")
    store = kind == "blob-store"
    allowed = set(range(12))
    if store:
        allowed |= {ISSUER, BLOB_LIMITS, BLOB_RETENTION, FORMATS}
    elif kind in TOKEN_KINDS:
        allowed |= {ISSUER}  # S-6: the delivery service carries the same issuer map at key 16
    no_unknown_keys(b, allowed, "S-1")
    if store:
        require(
            not (set(b) & {WITNESSES, ORIGIN, HPKE, PHASE}),
            "BS-6",
            "keys 6, 7, 10, 11 are foreign to a store",
        )
    eps = b[ENDPOINTS]
    require(
        isinstance(eps, list) and len(eps) >= 1, "S-2", "endpoints must have at least one entry"
    )
    require(
        all(_https_url(u) for u in eps),
        "S-2",
        "every endpoint is an absolute https URL without query or fragment",
    )
    require(is_uint(b[API_VERSION], 1), "S-1", "apiVersion")
    # S-5
    if kind in RELAYED_KINDS:
        require(
            OHTTP in b and is_bytes(b[OHTTP]) and b[OHTTP],
            "S-5",
            "ohttp required for kinds reached through the relay",
        )
        try:
            parse_key_config(b[OHTTP])
        except ValueError as e:
            raise TypeRule("S-5", f"ohttp is not a well-formed KeyConfig: {e}") from e
    else:
        require(OHTTP not in b, "S-5", "ohttp must be absent for witness and relay")
    # S-6
    if kind in TOKEN_KINDS:
        ti = b.get(TOKEN_ISSUERS)
        require(
            isinstance(ti, list) and ti and all(is_cid(c) for c in ti),
            "S-6",
            "tokenIssuers required and non-empty",
        )
        iss = b.get(ISSUER)
        require(isinstance(iss, dict), "S-6", "issuer map (key 16) required")
        require_keys(iss, {ISS_NAME, ISS_TYPE, ISS_ROTATION}, "S-6", "issuer")
        no_unknown_keys(iss, {ISS_NAME, ISS_TYPE, ISS_ROTATION}, "S-6", "issuer")
        require(is_text(iss[ISS_NAME], 255, min_bytes=1), "S-6", "issuer.name")
        require(is_uint(iss[ISS_TYPE]) and is_uint(iss[ISS_ROTATION]), "S-6", "issuer types")
    elif TOKEN_ISSUERS in b:
        require(
            isinstance(b[TOKEN_ISSUERS], list) and all(is_cid(c) for c in b[TOKEN_ISSUERS]),
            "S-6",
            "tokenIssuers shape",
        )
    # S-7
    if kind == "aggregator":
        require(PHASE in b and b[PHASE] in (1, 2), "S-7", "aggregator phase must be 1 or 2")
        require((HPKE in b) == (b[PHASE] == 2), "S-7", "hpke present iff phase 2")
        if HPKE in b:
            require(is_bytes(b[HPKE]) and b[HPKE], "S-7", "hpke bytes")
    else:
        require(PHASE not in b and HPKE not in b, "S-7", "phase and hpke are aggregator-only")
    # S-3 shape (log-only fields)
    if kind == "log":
        require(ORIGIN in b and WITNESSES in b, "S-3", "log needs origin and witnesses")
    else:
        require(ORIGIN not in b and WITNESSES not in b, "S-3", "origin and witnesses are log-only")
    if WITNESSES in b:
        w = b[WITNESSES]
        require(isinstance(w, list), "S-3", "witnesses must be a list")
        for entry in w:
            require_keys(entry, {W_NAME, W_KEY}, "S-3", "witness")
            no_unknown_keys(entry, {W_NAME, W_KEY}, "S-3", "witness")
            require(is_text(entry[W_NAME], 255, min_bytes=1), "S-3", "witness name")
            require(is_bytes(entry[W_KEY], 32), "S-3", "witness key must be 32 bytes")
    if ORIGIN in b:
        require(is_text(b[ORIGIN], 255, min_bytes=1), "S-3", "origin")
    if JURISDICTION in b:
        require(is_text(b[JURISDICTION], 64, min_bytes=1), "S-1", "jurisdiction")
    if LIMITS in b:
        require(isinstance(b[LIMITS], dict), "S-1", "limits must be a map")
    # S-8
    if RETENTION in b:
        ret = b[RETENTION]
        require(isinstance(ret, dict), "S-8", "retention must be a map")
        require(set(ret) <= RETENTION_CLASSES, "S-8", "retention keys must be the four classes")
        ceiling = LOG_CEILINGS[kind]
        for cls, secs in ret.items():
            require(is_uint(secs), "S-8", f"retention.{cls}")
            if ceiling is not None:
                require(secs <= ceiling, "S-8", f"retention.{cls} above the ceiling for {kind}")
    if store:
        _store_schema(b)


def _store_schema(b: dict[int, Any]) -> None:
    require(
        not (set(b) & {WITNESSES, ORIGIN, HPKE, PHASE}),
        "BS-6",
        "keys 6, 7, 10, 11 are foreign to a store",
    )
    require_keys(
        b, {OHTTP, TOKEN_ISSUERS, ISSUER, BLOB_LIMITS, BLOB_RETENTION, FORMATS}, "S-6", "store"
    )
    bl = b[BLOB_LIMITS]
    require(isinstance(bl, dict), "BS-2", "blobLimits must be a map")
    require_keys(bl, set(range(5)), "BS-2", "blobLimits")
    no_unknown_keys(bl, set(range(5)), "BS-2", "blobLimits")
    require(all(is_uint(v) for v in bl.values()), "BS-2", "blobLimits values")
    br = b[BLOB_RETENTION]
    require(
        isinstance(br, dict) and set(br) == {BR_MAX, BR_TOMBSTONE}, "BS-4", "blobRetention shape"
    )
    require(all(is_uint(v) for v in br.values()), "BS-4", "blobRetention values")
    fm = b[FORMATS]
    require(isinstance(fm, dict) and set(fm) == {FMT_SEALED, FMT_PUBLIC}, "BS-3", "formats shape")
    require(
        isinstance(fm[FMT_SEALED], list) and all(is_uint(v) for v in fm[FMT_SEALED]),
        "BS-3",
        "formats.sealed",
    )
    require(
        isinstance(fm[FMT_PUBLIC], list)
        and all(is_text(v, 127, min_bytes=1) for v in fm[FMT_PUBLIC]),
        "BS-3",
        "formats.public",
    )
    # single-version value rules
    require(b[ISSUER][ISS_TYPE] == 2, "BS-1", "issuer.type must be 2")
    require(bl[BL_MAX_BLOB] >= 65_536, "BS-2", "blobLimits.maxBlob below 65536")
    require(
        {1, 2} <= set(fm[FMT_SEALED]) and fm[FMT_PUBLIC],
        "BS-3",
        "formats must list sealed 1 and 2 and a public type",
    )
    require(br[BR_TOMBSTONE] >= DAY, "BS-4", "blobRetention.tombstone below 86400")


# ---------------------------------------------------------------- step 10


def rules(view: m.Resolved) -> None:
    b = view.body
    kind = b[KIND]
    if kind == "log":
        w = b[WITNESSES]
        keys = [e[W_KEY] for e in w]
        require(len(keys) >= MIN_WITNESSES, "S-3", f"log needs at least {MIN_WITNESSES} witnesses")
        require(len(set(keys)) == len(keys), "S-3", "witness keys must be distinct")
    prev = view.prev_env
    if prev is not None:
        pb = prev[m.BODY]
        require(pb[KIND] == kind, "S-4", "kind changed between versions")
        if kind == "log":
            require(pb.get(ORIGIN) == b.get(ORIGIN), "S-4", "origin changed between versions")
        if kind == "blob-store":
            require(pb[ISSUER][ISS_NAME] == b[ISSUER][ISS_NAME], "BS-5", "issuer.name changed")
            require(
                set(pb[FORMATS][FMT_SEALED]) <= set(b[FORMATS][FMT_SEALED]),
                "BS-5",
                "formats.sealed lost a value",
            )


m.register("service", schema=schema, rules=rules)
# The registry name ``blob-store`` is retired (manifest.md type registry, ADR 0072): a store is a
# ``service`` with ``kind: blob-store``, and no manifest of type ``blob-store`` is valid.
