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
- "Body keys": the integer-keyed encoding of every request and response body services.md
  defines (``BODIES``), with the six provisional rows marked.
- The ballot receipt ``{0: leaf, 1: signature, 2: kid}`` and the receipts endpoint's answer
  below the minimum (404).
- Evidence HPKE strings: ``info`` = ``hum/evidence/1`` ‖ verifier authority CID ‖ item name,
  ``aad`` = the 16-byte session ID. HPKE itself is pending a library; the structural check
  compares the info and aad bytes an implementation must seal under.
- V-2 at the host: one issuance request per session, identical retry, ``conflict`` within the
  session, the masked code across sessions. L-5: what an aggregator log line may carry.

seam: signing and domain-separation strings (``hum/service-request/1``, ``hum/receipt/1``,
``hum/dap-task/1``).
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import date
from typing import Any

from . import cbor, cose, log, merkle
from . import credentials as cr
from . import manifest as _manifest
from .cid import cid as compute_cid
from .keys import SigningKey, verify

__all__ = [
    "AGG_CODES_PER_DECK",
    "LOG_SCHEMA",
    "BODIES",
    "CODES",
    "DOMAIN_REQUEST",
    "EVIDENCE_INFO",
    "check_log_line",
    "check_receipts_response",
    "RELAY_PICK_LABEL",
    "RelayPicker",
    "check_gateway_log_line",
    "evidence_rejection",
    "gallery_score",
    "gallery_takes_element",
    "relay_set",
    "request_hash",
    "ErrorBody",
    "HostSessions",
    "PROVISIONAL_BODIES",
    "check_aggregator_log_line",
    "decode_body",
    "encode_body",
    "evidence_aad",
    "evidence_info",
    "gateway_accepts_config",
    "host_rejection",
    "open_evidence_structural",
    "receipt_body",
    "receipts_response",
    "verify_receipt_body",
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
EVIDENCE_INFO = b"hum/evidence/1"
MAX_REQUEST_AGE = 300
MIN_WITNESSES = 2
SESSION_ID_LEN = 16

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


# ---------------------------------------------------------------- body keys

# services.md "Body keys": each body is a CBOR map whose integer keys follow the order the
# fields are written. ``BODIES`` maps a body name to its field names in key order; a field
# whose value is itself a map or an array of maps names its element body in ``NESTED``.
BODIES: dict[str, tuple[str, ...]] = {
    "log-add-response": ("index", "checkpoint", "path"),
    "log-entry": ("index", "type", "authority"),
    "log-lineage-element": ("index", "cid", "version", "authority"),
    "agg-deck-open": ("taskIds", "round0", "cap", "phase", "leader", "helper"),
    "agg-deck-round0": ("opens", "closes"),
    "agg-deck-state": (
        "taskIds",
        "round0",
        "cap",
        "phase",
        "leader",
        "helper",
        "state",
        "rounds",
        "versions",
    ),
    "agg-deck-round": ("n", "opens", "closes", "version"),
    "ballot-receipt": ("leaf", "signature", "kid"),
    "agg-receipts": ("root", "k", "pages"),
    "receipt-root-blob": ("k", "pages"),
    "agg-daily": ("sigma", "buckets", "total"),
    "agg-daily-bucket": ("bucket", "increment"),
    "agg-propose-request": ("bundle", "tables", "pages"),
    "agg-propose-response": ("signature",),
    "verifier-session-request": ("manifest",),
    "verifier-session-response": ("id", "expires"),
    "verifier-evidence": ("name", "kid", "ciphertext"),
    "verifier-issue": ("kid", "ciphertext"),
    "verifier-revocation": ("method", "accumulator"),
    "releases-element": ("cid", "index", "deck", "context", "issued", "parts"),
    "log-proof-inclusion": ("index", "size", "path"),
    "log-proof-consistency": ("from", "to", "path"),
    "gallery-takes": ("takes", "ratings", "next"),
    "gallery-takes-element": ("cid", "logIndex", "rated", "hasGroupScore", "score", "forkCount"),
    "gallery-take": ("bundle", "ratings", "versions", "releases"),
    "gallery-take-forks": ("takes", "next"),
    "gallery-ratings": ("releases",),
}
NESTED: dict[tuple[str, str], str] = {
    ("agg-deck-open", "round0"): "agg-deck-round0",
    ("agg-deck-state", "round0"): "agg-deck-round0",
    ("agg-deck-state", "rounds"): "agg-deck-round",
    ("agg-daily", "buckets"): "agg-daily-bucket",
    ("gallery-takes", "takes"): "gallery-takes-element",
}
# Rows that had no earlier definition anywhere (cross-spec.md 12.10): keys and shapes are
# provisional until the owner confirms them.
PROVISIONAL_BODIES = frozenset(
    {
        "log-proof-inclusion",
        "log-proof-consistency",
        "gallery-takes",
        "gallery-take",
        "gallery-take-forks",
        "gallery-ratings",
    }
)
# Fields that may be absent (the spec says "or absent" / "optional").
OPTIONAL_FIELDS: dict[str, frozenset[str]] = {
    "gallery-takes": frozenset({"next"}),
    "gallery-takes-element": frozenset({"score"}),
    "gallery-take-forks": frozenset({"next"}),
    "agg-deck-round": frozenset(),
}


def _to_item(body: str, field: str, value: Any) -> Any:
    nested = NESTED.get((body, field))
    if nested is None:
        return value
    if isinstance(value, list):
        return [_to_item_map(nested, v) for v in value]
    return _to_item_map(nested, value)


def _to_item_map(body: str, named: dict[str, Any]) -> dict[int, Any]:
    fields = BODIES[body]
    unknown = set(named) - set(fields)
    if unknown:
        raise ValueError(f"{body}: unknown fields {sorted(unknown)}")
    out: dict[int, Any] = {}
    for i, name in enumerate(fields):
        if name in named:
            out[i] = _to_item(body, name, named[name])
        elif name not in OPTIONAL_FIELDS.get(body, frozenset()):
            raise ValueError(f"{body}: missing field {name}")
    return out


def encode_body(body: str, named: dict[str, Any]) -> bytes:
    """Deterministic CBOR of a services.md body given by field names."""
    return cbor.encode(_to_item_map(body, named))


def _from_item(body: str, item: dict[int, Any]) -> dict[str, Any]:
    fields = BODIES[body]
    if not isinstance(item, dict) or any(not isinstance(k, int) or k >= len(fields) for k in item):
        raise ValueError(f"{body}: bad key")
    out: dict[str, Any] = {}
    for k, v in item.items():
        name = fields[k]
        nested = NESTED.get((body, name))
        if nested is not None:
            v = [_from_item(nested, x) for x in v] if isinstance(v, list) else _from_item(nested, v)
        out[name] = v
    for i, name in enumerate(fields):
        if i not in item and name not in OPTIONAL_FIELDS.get(body, frozenset()):
            raise ValueError(f"{body}: missing field {name}")
    return out


def decode_body(body: str, data: bytes) -> dict[str, Any]:
    return _from_item(body, cbor.decode(data))


def gallery_score(score: float) -> int:
    """``score`` in a gallery listing element: the take.md score rounded to six decimals half to
    even in binary64 (as take.md's sort key rounds it), times 10⁶, as an integer that may be
    negative. Absent (not 0) for an unrated take."""
    return round(round(score, 6) * 10**6)


def gallery_takes_element(
    cid_: bytes, log_index: int, fork_count: int, score: float | None, has_group_score: bool
) -> dict[str, Any]:
    """One element of ``GET /v1/gallery/takes``; ``rated`` false and no ``score`` when the take
    has no rating yet."""
    out: dict[str, Any] = {
        "cid": cid_,
        "logIndex": log_index,
        "rated": score is not None,
        "hasGroupScore": has_group_score if score is not None else False,
    }
    if score is not None:
        out["score"] = gallery_score(score)
    out["forkCount"] = fork_count
    return out


# ---------------------------------------------------------------- receipts (body and 404)


def receipt_body(leaf: bytes, signature: bytes, kid: bytes) -> bytes:
    """The ballot receipt ``{0: leaf, 1: signature, 2: kid}``."""
    return encode_body("ballot-receipt", {"leaf": leaf, "signature": signature, "kid": kid})


def verify_receipt_body(data: bytes, sign_keys: dict[bytes, bytes], task: bytes) -> bool:
    """A receipt verifies under the aggregator ``sign`` key its ``kid`` names; another listed
    ``kid`` fails even when that key did not sign."""
    r = decode_body("ballot-receipt", data)
    public = sign_keys.get(r["kid"])
    if public is None or len(r["leaf"]) != 32:
        return False
    return receipt_verify(public, task, r["leaf"], r["signature"])


def receipts_response(
    below_minimum: bool, root: bytes | None = None, k: int = 0, pages: list[bytes] | None = None
) -> tuple[int, bytes]:
    """``GET .../rounds/{n}/receipts``: 404 for a release below the minimum (no receipt tree);
    otherwise ``{0: root, 1: k, 2: pages}`` and nothing else."""
    if below_minimum:
        return 404, encode_error(ErrorBody("not_found"))
    return 200, encode_body("agg-receipts", {"root": root, "k": k, "pages": pages or []})


def check_receipts_response(
    body: bytes, release_root: bytes, pinned_root_blob: bytes
) -> str | None:
    """A phone checks the ``GET .../receipts`` response ``{0: root, 1: k, 2: pages}`` against
    the logged release (its ``receipts[n]`` root) and the pinned root blob ``{0: k, 1: pages}``
    before fetching a page; it rejects a response whose ``k`` or ``pages`` differ from the
    pinned blob's or whose ``root`` differs from the release's (services.md Receipts). Returns
    None or the reason."""
    try:
        resp = decode_body("agg-receipts", body)
        blob = decode_body("receipt-root-blob", pinned_root_blob)
    except Exception:  # noqa: BLE001
        return "malformed"
    if resp["root"] != release_root:
        return "root_mismatch"
    if resp["k"] != blob["k"]:
        return "k_mismatch"
    if list(resp["pages"]) != list(blob["pages"]):
        return "pages_mismatch"
    return None


# ---------------------------------------------------------------- host: evidence strings, V-2


def evidence_info(verifier_authority: bytes, item_name: str) -> bytes:
    """HPKE ``info`` for an evidence item: ``hum/evidence/1`` ‖ authority CID (33) ‖ name."""
    if len(verifier_authority) != 33:
        raise ValueError("authority CID is 33 bytes")
    return EVIDENCE_INFO + verifier_authority + item_name.encode()


def request_hash(request_plaintext: bytes) -> bytes:
    """SHA-256 of the issuance request plaintext (canonical CBOR): the second half of the
    evidence ``aad`` and the input of the nym share (credentials.md)."""
    return hashlib.sha256(request_plaintext).digest()


def evidence_aad(session_id: bytes, request_plaintext: bytes) -> bytes:
    """HPKE ``aad`` for an evidence item: the 16-byte session ID ‖ SHA-256(issuance request
    plaintext), 48 bytes (verifier.md "Host key", RT1). The phone builds the request before it
    seals any evidence."""
    if len(session_id) != SESSION_ID_LEN:
        raise ValueError("session ID is 16 bytes")
    return session_id + request_hash(request_plaintext)


def open_evidence_structural(
    sealed: dict[str, Any],
    verifier_authority: bytes,
    item_name: str,
    session_id: bytes,
    request_plaintext: bytes,
) -> str | None:
    """What opening an item checks, without HPKE (pending a library): the ``info`` and ``aad``
    the phone sealed under must equal the ones this host computes for this item, in this
    session, beside this issuance request. Returns None or the reason the AEAD would fail;
    every reason ends the session with ``rejected``, rule V-4."""
    if sealed["info"] != evidence_info(verifier_authority, item_name):
        if sealed["info"][: len(EVIDENCE_INFO) + 33] != EVIDENCE_INFO + verifier_authority:
            return "other_verifier"
        return "other_item_name"
    want = evidence_aad(session_id, request_plaintext)
    if sealed["aad"] != want:
        if sealed["aad"][:SESSION_ID_LEN] != session_id:
            return "other_session"
        return "other_request"
    return None


def evidence_rejection() -> ErrorBody:
    """V-4: an evidence item that does not open beside the session's issuance request."""
    return ErrorBody("rejected", "evidence_mismatch", None, "V-4")


def host_rejection(masked_code: int) -> ErrorBody:
    """A verifier host's rejection: ``rejected`` with ``rule`` = ``vr-<code>``, the masked code."""
    return ErrorBody("rejected", rule=f"vr-{masked_code}")


class HostSessions:
    """V-2 as a state machine. A session answers one issuance request; an identical request
    (same bytes) returns the identical response, in the session or in a later session mapping
    to the same dedup row; a different request in the session is ``conflict``; a different
    request in a later session against a spent row gets the masked code, never ``conflict``.
    The response here is a placeholder derived from the host secret and the request hash, the
    way the nym share is (deterministic, so the retry test is byte-exact)."""

    def __init__(self, host_secret: bytes, verifier_authority: bytes | None = None) -> None:
        self.secret = host_secret
        self.authority = verifier_authority
        self.answered: dict[bytes, tuple[bytes, bytes]] = {}  # session -> (request, response)
        self.rows: dict[bytes, tuple[bytes, bytes]] = {}  # dedup key -> (request, response)
        self.evidence: dict[bytes, list[tuple[str, dict[str, Any]]]] = {}  # held sealed
        self.ended: set[bytes] = set()

    def submit_evidence(self, session: bytes, name: str, sealed: dict[str, Any]) -> None:
        """``POST .../evidence``: the item is held sealed; nothing opens before the issue call."""
        self.evidence.setdefault(session, []).append((name, sealed))

    def _open_all(self, session: bytes, request: bytes) -> str | None:
        if self.authority is None:
            return None
        for name, sealed in self.evidence.get(session, []):
            why = open_evidence_structural(sealed, self.authority, name, session, request)
            if why is not None:
                return why
        return None

    def _response(self, request: bytes) -> bytes:
        return hashlib.sha256(
            b"hum/issue-response/1 placeholder" + self.secret + hashlib.sha256(request).digest()
        ).digest()

    def issue(
        self, session: bytes, request: bytes, dedup_key: bytes
    ) -> tuple[int, bytes | ErrorBody, str]:
        """Returns (status, response bytes or ErrorBody, outcome name)."""
        if session in self.ended:
            err = evidence_rejection()
            return err.status, err, "session_ended"
        prior = self.answered.get(session)
        if prior is not None:
            if prior[0] == request:
                return 200, prior[1], "identical_retry"
            return 409, ErrorBody("conflict"), "conflict_in_session"
        why = self._open_all(session, request)
        if why is not None:
            # V-4: the request differs from the one the evidence was sealed for, or the
            # session ID the phone sealed under is not this session's. Nothing is issued.
            self.ended.add(session)
            err = evidence_rejection()
            return err.status, err, f"evidence_{why}"
        row = self.rows.get(dedup_key)
        if row is not None:
            if row[0] == request:
                self.answered[session] = row
                return 200, row[1], "identical_retry_new_session"
            err = host_rejection(0)
            self.answered[session] = (request, encode_error(err))
            return err.status, err, "duplicate_masked"
        resp = self._response(request)
        self.answered[session] = (request, resp)
        self.rows[dedup_key] = (request, resp)
        return 200, resp, "issued"


# ---------------------------------------------------------------- L-5, L-6: log lines

# Codes that say nothing about a voter: may be counted per deck (logging table, L-5, L-6).
AGG_CODES_PER_DECK = frozenset({"malformed", "too_large", "rejected", "forbidden"})
# Codes only a pseudonym that already voted can cause: never counted by code at any grain;
# they appear only inside the service's daily total of all rejections (RT2, RU3).
AGG_CODES_NULLIFIER = frozenset({"closed", "conflict"})
AGG_STATES = frozenset(
    {
        "scheduled",
        "open",
        "round 0",
        "round 1",
        "round 2",
        "round 3",
        "releasing",
        "final",
        "abandoned",
    }
)
BALLOT_PATH_MARK = "/ballots"
# Field names the aggregator row forbids by name because each is a count of accepted ballots
# (L-5), or a per-request mark; everything else outside the row is forbidden by L-6.
AGG_COUNT_FIELDS = frozenset({"accepted", "ballots", "leaves", "nullifiers", "received"})
_COUNT_WORDS = ("accepted", "ballot", "received", "voter", "200", "intake")


def _is_cid(v: Any) -> bool:
    if isinstance(v, bytes):
        return len(v) == 33 and v[0] == 1
    return isinstance(v, str) and re.fullmatch(r"01[0-9a-f]{64}", v) is not None


def _uint(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _day(v: Any) -> bool:
    if _uint(v):
        return True
    if not isinstance(v, str) or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", v) is None:
        return False
    try:
        date.fromisoformat(v)
    except ValueError:
        return False
    return True


def _minute(v: Any) -> bool:
    return _uint(v) and v % 60 == 0


def _code(v: Any) -> bool:
    return (isinstance(v, str) and v in CODES) or (_uint(v) and 100 <= v <= 599)


def _text(v: Any) -> bool:
    return isinstance(v, str) and 0 < len(v) <= 256


def _service_name(name: str):
    return lambda v: v == name


def _bytes_n(n: int):
    return lambda v: (
        isinstance(v, bytes)
        and len(v) == n
        or (isinstance(v, str) and re.fullmatch(rf"[0-9a-f]{{{2 * n}}}", v) is not None)
    )


def _one_of(*names: str):
    return lambda v: v in names


LOG_SCHEMA: dict[str, dict[str, Any]] = {
    "log": {
        "service": _service_name("log"), "day": _day, "cid": _is_cid,
        "type": lambda v: isinstance(v, str) and v in _manifest.TYPES, "authority": _is_cid,
        "code": _code, "index": _uint, "minute": _minute, "size": _uint, "window": _uint,
        "chat_key_count": _uint, "nullifier_set_size": _uint,
    },
    "witness": {
        "service": _service_name("witness"), "day": _day, "origin": _text,
        "tree_size": _uint, "code": _code, "minute": _minute,
    },
    "aggregator": {
        "service": _service_name("aggregator"), "day": _day, "deck": _is_cid,
        "round": lambda v: _uint(v) and v <= 3,
        "state": lambda v: isinstance(v, str) and v in AGG_STATES,
        "code": lambda v: isinstance(v, str) and v in CODES, "rejected_count": _uint,
        "n_hat": _uint, "part": lambda v: _uint(v) and v <= 8, "part_n": _uint,
        "padded_leaves": _uint, "k": lambda v: _uint(v) and v <= 32, "daily_bucket": _uint,
        "daily_increment": _int, "release": _is_cid, "version": lambda v: _uint(v) and v >= 1,
    },
    "host": {
        "session_id": _bytes_n(SESSION_ID_LEN), "authority": _is_cid,
        "version": lambda v: _uint(v) and v >= 1, "day": _uint,
        "outcome": lambda v: v == "issued" or v == "module-limit" or (_uint(v) and v <= 999),
        "memory_bucket": _uint, "fuel_bucket": _uint,
    },
    "delivery": {
        # L-6 fixes these field names; chat.md §12.9 limits retention and content.
        "service": _service_name("delivery"), "day": _day, "code": _code, "minute": _minute,
        "context": _is_cid,
    },
    "store": {
        "context": _is_cid, "counter": _text, "value": _uint, "token_key_id": _uint,
        "nonce_count": _uint,
    },
    "resolver": {
        "service": _service_name("resolver"), "day": _day, "cid": _is_cid, "code": _code,
        "size": _uint, "minute": _minute, "count": _uint,
    },
    "gallery": {
        "service": _service_name("gallery"), "day": _day, "query_shape": _text, "code": _code,
        "minute": _minute,
    },
    "relay": {
        "day": _day, "client_ip": _text, "window": _uint, "request_count": _uint,
        "gateway": lambda v: _is_cid(v) or _text(v), "code": _code,
    },
    "gateway": {
        "service": _service_name("gateway"), "day": _day,
        "path": lambda v: _text(v) and v.startswith("/"), "code": _code, "count": _uint,
    },
}  # fmt: skip
LOG_SERVICES = frozenset(LOG_SCHEMA)


def check_log_line(service: str, line: dict[str, Any]) -> str | None:
    """L-6 and L-5 for one log line of ``service``. Returns None when the line is allowed,
    otherwise the rule that fails: ``L-5`` for a count of accepted ballots or a per-request
    mark on ballot intake (also forbidden by L-6 as a field outside the row), ``L-6`` for any
    other field outside the service's row or a value outside its domain."""
    if service not in LOG_SCHEMA:
        raise ValueError(f"unknown service {service!r}")
    schema = LOG_SCHEMA[service]
    for key, value in line.items():
        if not isinstance(key, str):
            return "L-6"
        if key not in schema:
            lowered = key.lower()
            if service == "aggregator" and (
                key in AGG_COUNT_FIELDS
                or any(w in lowered for w in _COUNT_WORDS)
                or "minute" in lowered
                or "path" in lowered
                or "request" in lowered
                or "timing" in lowered
            ):
                return "L-5"
            if service == "gateway" and (
                any(w in lowered for w in _COUNT_WORDS) or "connection" in lowered
            ):
                return "L-5" if "connection" not in lowered else "L-6"
            return "L-6"
        if not schema[key](value):
            return "L-6"
    if service == "aggregator":
        code = line.get("code")
        if code is not None and "deck" in line and code not in AGG_CODES_PER_DECK:
            return "L-5"
        if code is not None and code in AGG_CODES_NULLIFIER and "rejected_count" in line:
            return "L-5"
    if service == "gateway":
        path = line.get("path", "")
        if isinstance(path, str) and BALLOT_PATH_MARK in path:
            return "L-5"
    if service == "host" and set(line) != set(schema):
        return "L-6"
    if service == "resolver" and "count" in line and set(line) != {"cid", "count"}:
        return "L-6"
    return None


def check_aggregator_log_line(line: dict[str, Any]) -> str | None:
    """L-5 and the aggregator rows of the logging and L-6 tables (see ``check_log_line``)."""
    return check_log_line("aggregator", line)


def check_gateway_log_line(line: dict[str, Any]) -> str | None:
    """The gateway rows and L-5: nothing per request and no counter on a ballot-intake path;
    ballot requests appear only inside ``count`` with no ``path``, the daily total of all
    requests to every service the gateway fronts (see ``check_log_line``)."""
    return check_log_line("gateway", line)


# ---------------------------------------------------------------- O-6 relay selection

RELAY_PICK_LABEL = b"hum/relay-pick/1"
# The four kinds a context relay may carry (O-6), and nothing else.
CONTEXT_RELAY_KINDS = frozenset(
    {"delivery", "delivery-token", "store", "store-token", "log-read", "resolver-read"}
)
# Every other kind the vectors name uses the shipped relays only, whichever context it is for.
SHIPPED_ONLY_KINDS = frozenset(
    {
        "ballot",
        "receipt-lookup",
        "receipt-page",
        "deck-status",
        "round-published",
        "aggregator-organizer",
        "log-submit",
        "log-submit-poll",
        "store-put-authored-text",
        "store-put-authored-evidence",
        "store-token-authored",
        "gallery",
        "open-data",
        "no-context",
    }
)


def relay_set(kind: str, shipped: list[bytes], context_relays: list[bytes] | None) -> list[bytes]:
    """O-6: the shipped relays, plus the pinned context version's ``relays`` when the request is
    that context's and its kind is one a context relay may carry. ``context_relays`` is None
    for a request that belongs to no context. Order: shipped first, then the context's, each
    in manifest order, duplicates removed; the pick below is uniform over this list."""
    if kind not in CONTEXT_RELAY_KINDS and kind not in SHIPPED_ONLY_KINDS:
        raise ValueError(f"unknown request kind {kind!r}")
    out = list(shipped)
    if context_relays and kind in CONTEXT_RELAY_KINDS:
        out += [r for r in context_relays if r not in out]
    return out


class RelayPicker:
    """Uniform picks from a fixed stream: SHA-256(``hum/relay-pick/1`` ‖ seed ‖ uint32be(counter))
    read as 32-bit draws with rejection sampling. A reference device so vectors are
    deterministic, not a protocol rule: a phone uses its CSPRNG (O-6)."""

    def __init__(self, seed: bytes) -> None:
        self.seed = seed
        self.counter = 0
        self.draws: list[int] = []

    def _draw(self) -> int:
        block = hashlib.sha256(RELAY_PICK_LABEL + self.seed + self.counter.to_bytes(4, "big"))
        self.counter += 1
        return int.from_bytes(block.digest()[:4], "big")

    def pick(self, candidates: list[bytes], failed: list[bytes] | None = None) -> bytes | None:
        """One relay from ``candidates`` minus ``failed``, uniformly; None when none is left
        (the phone then waits and never connects directly)."""
        rest = [c for c in candidates if c not in (failed or [])]
        n = len(rest)
        if n == 0:
            return None
        limit = (2**32 // n) * n
        while True:
            d = self._draw()
            self.draws.append(d)
            if d < limit:
                return rest[d % n]


# ---------------------------------------------------------------- bootstrap gateway configs


def gateway_accepts_config(
    shipped_key_id: int, supported_key_ids: list[int], current_key_id: int
) -> dict[str, Any]:
    """ "Who runs it": the reference gateway keeps decrypting under every key configuration
    shipped in a build that is still supported, and at first contact the phone replaces each
    shipped bundle with the latest version of its lineage from the log."""
    accepted = shipped_key_id in supported_key_ids
    return {
        "accepted": accepted,
        "phone_refreshes_bundle": accepted,
        "uses_key_id_after": current_key_id if accepted else None,
    }
