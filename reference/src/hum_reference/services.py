"""Byte-level rules of docs/specs/services.md that are not manifest bodies.

- Errors: the CBOR map ``{0 code, 1 detail?, 2 step?, 3 rule?, 4 retryAfter?}`` and the
  code table.
- Signed requests: the A-1 payload hash, the A-2 COSE_Sign under ``hum/service-request/1``,
  and the A-3 freshness and replay check.
- Task ids (``hum/dap-task/1``) and receipt signatures (``hum/receipt/1``).
- Receipt pages: the ``k`` rule, page assignment over a bytewise-sorted padded leaf list,
  the tree root, and the root blob, which this reference encodes as the deterministic CBOR
  map ``{0: k, 1: [page CID, ...]}`` (services.md names the fields and not the bytes).
- Relay padding buckets (O-3), the witness protocol bodies (tlog-witness) and its status
  decision, the relay authority check (O-5) and the bootstrap witness rule.

seam: signing and domain-separation strings (``hum/service-request/1``, ``hum/receipt/1``,
``hum/dap-task/1``).
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from . import cbor, cose, log, merkle
from . import credentials as cr
from .cid import cid as compute_cid
from .keys import SigningKey, verify

__all__ = [
    "CODES",
    "DOMAIN_REQUEST",
    "ErrorBody",
    "log_submission_check",
    "check_bootstrap_witnesses",
    "check_freshness",
    "check_relay_authority",
    "decode_error",
    "encode_error",
    "padding_bucket",
    "receipt_pages",
    "receipt_sign",
    "receipt_verify",
    "request_payload",
    "sign_request",
    "task_id",
    "verify_request",
    "witness_decide",
    "witness_request",
]

DOMAIN_REQUEST = b"hum/service-request/1"
DOMAIN_RECEIPT = b"hum/receipt/1"
DOMAIN_TASK = b"hum/dap-task/1"
MAX_REQUEST_AGE = 300
MIN_WITNESSES = 2

# code -> (HTTP status, bare body allowed only)
CODES: dict[str, tuple[int, bool]] = {
    "malformed": (400, False),
    "too_large": (413, False),
    "unauthorized": (401, True),
    "token_spent": (401, True),
    "forbidden": (403, False),
    "not_found": (404, True),
    "rejected": (422, False),
    "floor": (422, False),
    "conflict": (409, False),
    "not_padded": (400, False),
    "replay": (409, False),
    "closed": (410, False),
    "pending": (202, False),
    "rate_limited": (429, False),
    "unavailable": (503, False),
}
E_CODE, E_DETAIL, E_STEP, E_RULE, E_RETRY = range(5)
ERROR_MEDIA_TYPE = "application/vnd.hum.error+cbor"


# ---------------------------------------------------------------- errors


@dataclass(frozen=True)
class ErrorBody:
    code: str
    detail: str | None = None
    step: int | None = None
    rule: str | None = None
    retry_after: int | None = None

    @property
    def status(self) -> int:
        return CODES[self.code][0]


def encode_error(err: ErrorBody) -> bytes:
    if err.code not in CODES:
        raise ValueError(f"unknown error code {err.code!r}")
    item: dict[int, Any] = {E_CODE: err.code}
    if err.detail is not None:
        if not err.detail.replace("_", "").isalnum() or len(err.detail) > 64:
            raise ValueError("E-1: detail must be a fixed snake_case string")
        item[E_DETAIL] = err.detail
    if err.step is not None:
        if not 1 <= err.step <= 11:
            raise ValueError("step must be 1..11")
        item[E_STEP] = err.step
    if err.rule is not None:
        item[E_RULE] = err.rule
    if err.retry_after is not None:
        item[E_RETRY] = err.retry_after
    return cbor.encode(item)


def decode_error(data: bytes) -> ErrorBody:
    item = cbor.decode(data)
    if not isinstance(item, dict) or E_CODE not in item or set(item) - set(range(5)):
        raise ValueError("error body shape")
    if item[E_CODE] not in CODES:
        raise ValueError("unknown code")
    err = ErrorBody(
        item[E_CODE], item.get(E_DETAIL), item.get(E_STEP), item.get(E_RULE), item.get(E_RETRY)
    )
    if CODES[err.code][1] and len(item) != 1:
        raise ValueError(f"{err.code} carries the code only")
    return err


# ---------------------------------------------------------------- signed requests (A-1 to A-3)


def request_payload(method: str, target: str, body: bytes, nonce: bytes, issued: int) -> bytes:
    """A-1: SHA-256 of ``hum/service-request/1 || 0 || METHOD SP target || 0 || SHA-256(body) ||
    nonce(16) || issued(uint64 BE)``."""
    if len(nonce) != 16:
        raise ValueError("nonce must be 16 bytes")
    pre = (
        DOMAIN_REQUEST
        + b"\x00"
        + method.encode("ascii")
        + b" "
        + target.encode("ascii")
        + b"\x00"
        + hashlib.sha256(body).digest()
        + nonce
        + issued.to_bytes(8, "big")
    )
    return hashlib.sha256(pre).digest()


def _request_sig(key: SigningKey, kid: bytes, payload: bytes) -> cose.Signature:
    protected = cose.protected_header(kid)
    structure = cose.sig_structure(protected, payload, external_aad=DOMAIN_REQUEST)
    return cose.Signature(protected, kid, cose.ALG_EDDSA, key.sign(structure))


def sign_request(
    signers: list[tuple[bytes, SigningKey]],
    method: str,
    target: str,
    body: bytes,
    nonce: bytes,
    issued: int,
) -> tuple[bytes, str]:
    """A-2: one COSE_Sign over the A-1 hash with external AAD ``hum/service-request/1``.
    Returns (COSE_Sign bytes, base64url header value)."""
    payload = request_payload(method, target, body, nonce, issued)
    cs = cose.encode_cose_sign([_request_sig(k, kid, payload) for kid, k in signers])
    return cs, base64.urlsafe_b64encode(cs).rstrip(b"=").decode()


def verify_request(
    cose_sign: bytes,
    keys: dict[bytes, bytes],
    threshold: int,
    method: str,
    target: str,
    body: bytes,
    nonce: bytes,
    issued: int,
) -> int:
    """Count distinct listed ``sign`` keys (kid -> public) with a valid signature; must reach
    ``threshold``. Returns the count."""
    payload = request_payload(method, target, body, nonce, issued)
    sigs = cose.decode_cose_sign(cose_sign)
    good: set[bytes] = set()
    for s in sigs:
        pub = keys.get(s.kid)
        if pub is None or s.alg != cose.ALG_EDDSA:
            continue
        if verify(
            pub, cose.sig_structure(s.protected, payload, external_aad=DOMAIN_REQUEST), s.signature
        ):
            good.add(s.kid)
    return len(good)


def check_freshness(issued: int, now: int, nonce: bytes, seen: set[bytes]) -> str | None:
    """A-3: ``None`` when fresh, else the error code (``replay``)."""
    if now - issued > MAX_REQUEST_AGE or issued - now > MAX_REQUEST_AGE:
        return "replay"
    if nonce in seen:
        return "replay"
    return None


# ---------------------------------------------------------------- tasks and receipts


def task_id(deck_lineage: bytes, round_: int, part: int) -> bytes:
    """``SHA-256("hum/dap-task/1" || deck lineage CID || uint8(round) || uint8(part))``.

    One DAP task per (round, part) over the deck lineage CID, as services.md and ballot.md
    both say since ADR 0024; the receipt for round ``r`` uses the round's first part.
    """
    if not 0 <= round_ <= 255 or not 0 <= part <= 255:
        raise ValueError("round and part fit in a byte")
    return hashlib.sha256(DOMAIN_TASK + deck_lineage + bytes([round_, part])).digest()


def receipt_sign(key: SigningKey, task: bytes, leaf: bytes) -> bytes:
    return key.sign(DOMAIN_RECEIPT + task + leaf)


def receipt_verify(public: bytes, task: bytes, leaf: bytes, signature: bytes) -> bool:
    return verify(public, DOMAIN_RECEIPT + task + leaf, signature)


def receipt_pages(leaves: list[bytes]) -> dict[str, Any]:
    """Pages over a padded leaf list (real and dummy leaves together).

    Leaves are sorted bytewise; ``k`` is the smallest integer with ``L / 2^k <= 4096``
    (0 when ``L <= 4096``); page ``i`` holds the leaves whose first ``k`` bits equal ``i``,
    concatenated; the root is the RFC 9162 tree over the sorted leaf *hashes* treated as
    already-hashed leaves (ballot.md defines the leaf as a fixed-length hash, so the tree
    hashes it once more as a leaf input, exactly as logs do).
    """
    srt = sorted(leaves)
    n = len(srt)
    k = 0
    while n / (1 << k) > 4096:
        k += 1
    pages: list[bytes] = [b"" for _ in range(1 << k)]
    for leaf in srt:
        idx = int.from_bytes(leaf[:4], "big") >> (32 - k) if k else 0
        pages[idx] += leaf
    page_cids = [compute_cid(p) for p in pages]
    root = merkle.root_hash(srt)
    blob = cbor.encode({0: k, 1: page_cids})
    return {
        "k": k,
        "pages": pages,
        "page_cids": page_cids,
        "root": root,
        "root_blob": blob,
        "root_blob_cid": compute_cid(blob),
        "sorted": srt,
    }


# ---------------------------------------------------------------- padding (O-3)

_BUCKETS = [1024, 4 * 1024, 16 * 1024, 64 * 1024, 256 * 1024]


def padding_bucket(size: int) -> int:
    for b in _BUCKETS:
        if size <= b:
            return b
    unit = 256 * 1024
    return -(-size // unit) * unit


# ---------------------------------------------------------------- witness protocol (tlog-witness)


def witness_request(old_size: int, proof: list[bytes], note_text: str) -> str:
    lines = [f"old {old_size}"] + [base64.b64encode(h).decode() for h in proof]
    return "\n".join(lines) + "\n\n" + note_text


def witness_decide(
    request: str, log_public: bytes, known_size: int, known_root: bytes | None
) -> tuple[int, str]:
    """The witness's checks in order. Returns (status, body)."""
    head, _, note_text = request.partition("\n\n")
    lines = head.split("\n")
    if not lines or not lines[0].startswith("old "):
        return 400, ""
    old = int(lines[0][4:])
    proof = [base64.b64decode(x) for x in lines[1:] if x]
    try:
        note = log.parse_note(note_text)
    except ValueError:
        return 400, ""
    cp = note.checkpoint
    if not any(log.verify_log_signature(cp, s, log_public) for s in note.signatures):
        return 403, ""
    if old > cp.size:
        return 400, ""
    if old != known_size:
        return 409, str(known_size)
    if old == cp.size:
        return (200, "") if known_root == cp.root else (409, str(known_size))
    if known_size == 0:
        return 200, ""
    if not merkle.verify_consistency(old, cp.size, known_root, cp.root, proof):
        return 422, ""
    return 200, ""


# ---------------------------------------------------------------- O-5 and bootstrap


def check_relay_authority(relay_authority: bytes, service_authorities: list[bytes]) -> bool:
    """O-5: a phone refuses a relay signed by the authority of any service it reaches through it."""
    return relay_authority not in service_authorities


def check_bootstrap_witnesses(cosigners: set[bytes], constants: list[bytes]) -> bool:
    """A context-less first checkpoint needs at least MIN_WITNESSES cosignatures from the
    shipped constant keys, however many keys the constants list."""
    return len(cosigners & set(constants)) >= MIN_WITNESSES


# ---------------------------------------------------------------- what the log runs: proofs


def log_submission_check(
    issued: int, log_now: int, cards: list[tuple[int, int]]
) -> ErrorBody | None:
    """The log's clock check on an object that carries a membership or sponsor proof ("What the
    log runs"): every card's disclosed epoch is the log's current epoch (or the previous
    period's in the first hour of a period) and ``issued`` is within 3,600 seconds of the log's
    clock ``log_now``. ``cards`` are ``(disclosed epoch, V)`` per card proof. Returns the
    ``rejected`` body under rule ``P5`` with detail ``issued_skew`` or ``epoch_not_current``,
    or None when the log may append. The same test, with reasons as text, is
    ``credentials.log_submission_check``."""
    if abs(issued - log_now) > cr.HOUR:
        return ErrorBody("rejected", "issued_skew", None, "P5")
    for epoch, v in cards:
        if not cr.card_accepted(epoch, v, log_now, use="other"):
            return ErrorBody("rejected", "epoch_not_current", None, "P5")
    return None
