"""docs/specs/storage.md section 5 (folders), 6 (store API decisions), 8.2 (delete orders),
9 (promotion) and the range arithmetic of 1.4, as pure functions.

seam: ``hum/blob-delete/1`` (signature) and the delete-order verification.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from typing import Any

from . import cbor, cose, storage
from .cid import cid as compute_cid
from .keys import SigningKey, verify

__all__ = [
    "DeleteOrder",
    "Folder",
    "FolderOp",
    "apply_ops",
    "check_promotion",
    "delete_decision",
    "delete_order_payload",
    "put_decision",
    "range_params",
    "sign_order",
    "snapshot",
    "verify_order",
    "visibility",
]

DOMAIN_DELETE_ORDER = b"hum/blob-delete/1"
MAX_PATH_DEPTH = 16


# ---------------------------------------------------------------- 1.4 range arithmetic


def range_params(size: int) -> dict[str, int]:
    """Padded length P, chunk count n and total ciphertext length C (format 1 header) for a
    plaintext of ``size`` bytes."""
    p = storage.padme(size + 1)
    n = max(1, math.ceil(p / storage.CHUNK))
    return {"P": p, "n": n, "C": 1 + p + storage.TAG * n, "C_format2": 17 + p + storage.TAG * n}


def check_content_length(size: int, content_length: int, header_len: int = 1) -> str | None:
    """``size-mismatch`` before any fetch when the store's Content-Length cannot hold a blob of
    the reference's size (section 12, ``range-content-length-mismatch``)."""
    params = range_params(size)
    expected = params["C"] if header_len == 1 else params["C_format2"]
    return None if content_length == expected else "size-mismatch"


# ---------------------------------------------------------------- 5. folders


@dataclass
class FolderOp:
    seq: int
    sender: bytes  # chat identity key
    msg: bytes  # MIMI message id
    body: dict[int, Any]  # file-op body (chat.md 5.7)
    part: list[Any] | None = None  # ExternalPart, when the op carries one


@dataclass
class Version:
    ref: storage.SealedReference
    added_by: bytes
    msg: bytes
    seq: int


@dataclass
class File:
    id: bytes
    name: str
    path: list[str]
    created_by: bytes
    versions: list[Version] = field(default_factory=list)
    deleted: bool = False


@dataclass
class Folder:
    files: dict[bytes, File] = field(default_factory=dict)
    applied: set[bytes] = field(default_factory=set)
    ignored: list[tuple[int, str]] = field(default_factory=list)  # (seq, rule)
    last_seq: int = 0


def _path_ok(path: list[str]) -> bool:
    if len(path) > MAX_PATH_DEPTH:
        return False
    return all(
        isinstance(e, str) and e and "/" not in e and "\x00" not in e and len(e.encode()) <= 255
        for e in path
    )


def apply_ops(ops: list[FolderOp], rights: dict[bytes, set[str]]) -> Folder:
    """Replay ``file-op`` messages in sequence order under ``rights`` (identity -> capabilities,
    ``files-write`` and ``files-delete-any``). Records which §5.4 rule ignored an op."""
    from . import chat

    folder = Folder()
    for op in sorted(ops, key=lambda o: o.seq):
        folder.last_seq = max(folder.last_seq, op.seq)
        if op.msg in folder.applied:
            folder.ignored.append((op.seq, "5.4-1"))
            continue
        folder.applied.add(op.msg)
        if 4 in op.body and not _path_ok(op.body[4]):
            folder.ignored.append((op.seq, "5.4-6"))  # before decoding: the rule names it
            continue
        try:
            body = chat.decode(
                "file-op", cbor.encode(op.body), external_parts=1 if op.part is not None else 0
            )
        except chat.ChatError:
            folder.ignored.append((op.seq, "5.2-malformed"))
            continue
        kind = body[1]
        ref = None
        if op.part is not None:
            try:
                ref = chat.external_part_to_reference(op.part)
            except chat.ChatError:
                folder.ignored.append((op.seq, "5.2-reference"))
                continue
        if 4 in body and not _path_ok(body[4]):
            folder.ignored.append((op.seq, "5.4-6"))
            continue
        fid = body[2]
        caps = rights.get(op.sender, set())
        existing = folder.files.get(fid)
        if kind in (1, 6):
            if existing is not None:
                folder.ignored.append((op.seq, "5.4-2"))
                continue
            if "files-write" not in caps:
                folder.ignored.append((op.seq, "5.3"))
                continue
            folder.files[fid] = File(
                fid, body[3], list(body[4]), op.sender, [Version(ref, op.sender, op.msg, op.seq)]
            )
            continue
        if existing is None or existing.deleted:
            folder.ignored.append((op.seq, "5.4-3"))
            continue
        own = existing.created_by == op.sender
        allowed = ("files-write" in caps and own) or ("files-delete-any" in caps and kind != 7)
        if kind == 7 and not own and "files-delete-any" not in caps:
            allowed = False
        if not allowed:
            folder.ignored.append((op.seq, "5.3"))
            continue
        if kind == 2:
            existing.name = body[3]
        elif kind == 3:
            existing.path = list(body[4])
        elif kind == 4:
            existing.versions.append(
                Version(ref, op.sender, op.msg, op.seq)
            )  # 5.4-4: kept whatever prev says
        elif kind in (5, 7):
            existing.deleted = True  # 5.4-7
    return folder


def snapshot(folder: Folder, seq: int | None = None) -> bytes:
    """Section 5.5 index snapshot bytes (deleted files omitted, files sorted by id)."""
    files = []
    for fid in sorted(f for f in folder.files if not folder.files[f].deleted):
        f = folder.files[fid]
        files.append(
            {
                0: f.id,
                1: f.name,
                2: list(f.path),
                3: f.created_by,
                4: [{0: v.ref.encode(), 1: v.added_by, 2: v.msg, 3: v.seq} for v in f.versions],
            }
        )
    return cbor.encode({0: folder.last_seq if seq is None else seq, 1: files})


# ---------------------------------------------------------------- 8.2 delete orders

O_SPEC, O_AUTHORITY, O_CIDS, O_ISSUED, O_EXPIRES = range(5)


@dataclass(frozen=True)
class DeleteOrder:
    authority: bytes
    cids: tuple[bytes, ...]
    issued: int
    expires: int

    def encode(self) -> bytes:
        if not 1 <= len(self.cids) <= 1024:
            raise ValueError("1 to 1024 CIDs")
        return cbor.encode(
            {
                O_SPEC: 1,
                O_AUTHORITY: self.authority,
                O_CIDS: sorted(self.cids),
                O_ISSUED: self.issued,
                O_EXPIRES: self.expires,
            }
        )


def delete_order_payload(order_bytes: bytes) -> bytes:
    return DOMAIN_DELETE_ORDER + hashlib.sha256(order_bytes).digest()


def sign_order(
    order: DeleteOrder, signers: list[tuple[bytes, SigningKey]], domain: bytes = DOMAIN_DELETE_ORDER
) -> bytes:
    """The body sent to the store: ``{0: order bytes, 1: [COSE_Sign]}``. One COSE_Sign holds every
    signer's COSE_Signature, detached payload = domain || SHA-256(order), empty external AAD."""
    data = order.encode()
    payload = domain + hashlib.sha256(data).digest()
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
    return cbor.encode({0: data, 1: [cose.encode_cose_sign(sigs)]})


def verify_order(
    body: bytes,
    keys: dict[bytes, bytes],
    threshold: int,
    *,
    now: int,
    tombstone_window: int,
    token_context_authority: bytes,
    cid: bytes | None = None,
) -> tuple[bool, str | None]:
    """Returns (ok, detail). ``detail`` is ``order`` on any failure (storage.md 6.5, 8.2)."""
    try:
        item = cbor.decode(body)
        order = cbor.decode(item[0])
    except (cbor.CborError, KeyError, TypeError):
        return False, "order"
    if not isinstance(order, dict) or order.get(O_SPEC) != 1:
        return False, "order"
    if order[O_AUTHORITY] != token_context_authority:
        return False, "order"
    if order[O_EXPIRES] < now or order[O_EXPIRES] > order[O_ISSUED] + tombstone_window:
        return False, "order"
    if order[O_CIDS] != sorted(order[O_CIDS]) or not 1 <= len(order[O_CIDS]) <= 1024:
        return False, "order"
    if cid is not None and cid not in order[O_CIDS]:
        return False, "order"
    payload = delete_order_payload(item[0])
    good = set()
    for cs in item[1]:
        for s in cose.decode_cose_sign(cs):
            pub = keys.get(s.kid)
            if pub and verify(
                pub, cose.sig_structure(s.protected, payload, external_aad=b""), s.signature
            ):
                good.add(s.kid)
    if len(good) < threshold:
        return False, "order"
    return True, None


# ---------------------------------------------------------------- 6.3 / 6.4 / 6.5 store decisions


@dataclass
class StoredTuple:
    cls: str  # "sealed" or "public"
    media: str | None
    commitment: bytes
    retention: int


@dataclass
class StoreState:
    context_max_blob: int = 2**31
    store_max_blob: int = 2**31
    context_retention_max: int = 0  # 0 = until deleted
    store_retention_max: int = 0
    quota_left: int = 2**40
    public_formats: tuple[str, ...] = ("text/plain; charset=utf-8", "application/cbor")
    tuples: dict[tuple[bytes, bytes], StoredTuple] = field(default_factory=dict)  # (cid, ctx)
    tombstones: dict[bytes, set[bytes]] = field(
        default_factory=dict
    )  # cid -> contexts that held it


def put_decision(
    state: StoreState,
    *,
    context: bytes,
    path_cid: bytes,
    body: bytes,
    content_type: str,
    content_length: int | None,
    retention: int | None,
    delete_header: str | None,
    credential_ok: bool,
) -> dict[str, Any]:
    """Section 6.3 in its stated order. Returns status, code, detail."""
    if not credential_ok:
        return {"status": 401, "code": "unauthorized"}
    if content_length is None or content_length > min(state.store_max_blob, state.context_max_blob):
        return {"status": 413, "code": "too_large"}
    if (
        delete_header is None
        or len(delete_header) != 64
        or any(c not in "0123456789abcdef" for c in delete_header)
    ):
        return {"status": 422, "code": "rejected", "detail": "commitment"}
    if retention is None:
        return {"status": 422, "code": "rejected", "detail": "retention"}
    ceiling = state.context_retention_max
    if state.store_retention_max and (not ceiling or state.store_retention_max < ceiling):
        ceiling = state.store_retention_max
    if ceiling and (retention == 0 or retention > ceiling):
        return {"status": 422, "code": "rejected", "detail": "retention"}
    sealed = content_type == "application/vnd.hum.sealed"
    if sealed:
        if not body or body[0] not in (1, 2):
            return {"status": 415, "code": "malformed", "detail": "format"}
    elif content_type not in state.public_formats:
        return {"status": 415, "code": "malformed", "detail": "format"}
    if compute_cid(body) != path_cid:
        return {"status": 409, "code": "conflict", "detail": "cid_mismatch"}
    cls = "sealed" if sealed else "public"
    others = [(t, c) for (cid_, c), t in state.tuples.items() if cid_ == path_cid]
    existing = state.tuples.get((path_cid, context))
    if existing is not None:
        return {"status": 200, "code": None, "note": "no new commitment, retention unchanged"}
    for t, _ in others:
        if t.cls != cls:
            return {"status": 409, "code": "conflict", "detail": "class"}
        if cls == "public" and t.media != content_type:
            return {"status": 409, "code": "conflict", "detail": "media_type"}
    if context in state.tombstones.get(path_cid, set()):
        return {"status": 410, "code": "closed", "detail": "tombstoned"}
    if content_length > state.quota_left:
        return {"status": 429, "code": "rate_limited", "detail": "quota_stored"}
    state.tuples[(path_cid, context)] = StoredTuple(
        cls, None if sealed else content_type, bytes.fromhex(delete_header), retention
    )
    state.quota_left -= content_length
    return {"status": 201, "code": None}


def visibility(token: str, blob: str) -> dict[str, Any]:
    """Section 6.4 table. ``token`` in {none, valid, invalid, spent}; ``blob`` in
    {public, sealed-own, sealed-other, absent, tombstoned}."""
    if token == "invalid":
        return {"status": 401, "code": "unauthorized", "bare": True}
    if token == "spent":
        return {"status": 401, "code": "token_spent", "bare": True}
    if token == "none":
        return (
            {"status": 200}
            if blob == "public"
            else {"status": 401, "code": "unauthorized", "bare": True}
        )
    if blob in ("public", "sealed-own"):
        return {"status": 200}
    if blob == "tombstoned":
        return {"status": 410, "code": "closed", "detail": "tombstoned"}
    return {"status": 404, "code": "not_found", "bare": True}


def delete_decision(
    state: StoreState, *, context: bytes, cid: bytes, secret: bytes | None, order_ok: bool | None
) -> dict[str, Any]:
    t = state.tuples.get((cid, context))
    if t is None:
        if context in state.tombstones.get(cid, set()):
            return {"status": 204}
        return {"status": 404, "code": "not_found", "bare": True}
    if secret is not None:
        if storage.delete_commitment(secret) != t.commitment:
            return {"status": 403, "code": "forbidden", "detail": "secret"}
    elif not order_ok:
        return {"status": 403, "code": "forbidden", "detail": "order"}
    del state.tuples[(cid, context)]
    state.tombstones.setdefault(cid, set()).add(context)
    return {"status": 204}


# ---------------------------------------------------------------- 9. promotion


def check_promotion(ref: storage.SealedReference, public_bytes: bytes) -> bool:
    """A client uploads a public copy only when its CID equals the reference's digest."""
    return compute_cid(public_bytes) == ref.digest
