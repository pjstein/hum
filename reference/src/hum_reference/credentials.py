"""docs/specs/credentials.md without a BBS library.

``seam:`` credential issuance and presentation, pseudonyms and nullifiers, the domain
strings ``hum/credential/1``, ``hum/presentation/1``, ``hum/nullifier/1``,
``hum/nym-share/1``, ``hum/issue/1``, ``hum/backup/1``.

What is here: periods, epochs, handover and the ballot window; the card's message layout
and BBS ``header`` bytes; key-of-epoch selection; every scope and bound message of the
uses table; the nullifier; the presentation and card-proof CBOR layouts and the ``ph``
header; verification rules P1 to P8 with P4 (the BBS proof itself) taken as an input flag;
the host's epoch-issuing rule; issuance request and response plaintexts and the phone's
checks on a response; the backup and chat-only export plaintexts.

What is pending a library: BBS signatures, blind issuance and per-verifier pseudonyms
(draft-irtf-cfrg-bbs-signatures -12, -blind-signatures -03, -per-verifier-linkability -03),
HPKE sealing of issuance traffic (RFC 9180 with the §9.8 export), Argon2id and the HPKE
wrap of the backup. Nothing is hand-rolled here; those paths take their result as input.

The BBS operations the spec names, in the pseudonym draft's terms: the phone runs
``CommitWithNym`` (commits to the nym secret, message ``L - 1``), the host ``BlindSignWithNym``
over the message vector in layout order (``0`` epoch, ``1 + i`` attribute ``i``, ``L - 1`` the
nym secret, ``L = A + 2``), the phone ``VerifyFinalizeWithNym``; a presentation is
``ProofGenWithNym`` and P4 is ``ProofVerifyWithNym``. ``approved`` in the issuance request
and the values in the response are those message indexes ``1 + i``.

HPKE, one suite per use (credentials.md, "HPKE"): the host path (issuance request and
response) is DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 with info
``hum/issue/1`` ‖ verifier authority CID, and the response key and nonce are the §9.8 exports
labelled ``hum/issue-response/1 key`` and ``hum/issue-response/1 nonce``; the backup and the
chat-only export use the same KEM and KDF with AES-128-GCM and info ``hum/backup/1``.

Key-of-epoch selection takes explicit ``(kid, fromEpoch)`` records, the same facts the
verifier body module (``bodies.verifier.key_of_epoch``) reads from a manifest.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any

from . import cbor
from .bodies.context import (
    NODE_ALL,
    NODE_ANY,
    NODE_ATTR,
    NODE_TRUE,
    PRED_PRESENT,
    PRED_RANGE,
    PRED_SET,
)
from .cid import parse_cid

__all__ = [
    "ABSENT",
    "PERIOD",
    "CardProof",
    "DedupRow",
    "Presentation",
    "PresentationError",
    "ballot_window_epoch",
    "card_accepted",
    "card_header",
    "accepts_entry",
    "check_issuance_response",
    "choose_accepts_entry",
    "decide_issuance",
    "issuers_by_authority",
    "log_accepts_logged_object",
    "log_of_record",
    "object_in_log_of_record",
    "epoch_of_period",
    "handover",
    "is_logged_use",
    "key_of_epoch",
    "layout_length",
    "log_submission_check",
    "logged_epochs",
    "message_bytes",
    "nullifier",
    "period",
    "possession_leaf",
    "presentation_header",
    "scopes",
    "verify_presentation",
    "write_backup",
    "write_chat_export",
]

PERIOD = 2_419_200  # 28 days
HOUR = 3600
ABSENT = 0xFFFFFFFFFFFFFFFF
MAX_PRESENTATION = 16 * 1024
MAX_BALLOT_PRESENTATION = 8 * 1024
MAX_CREDS = 8
NYM_SHARE_SALT = b"hum/nym-share/1"

# ---------------------------------------------------------------- periods and epochs


def period(t: int) -> int:
    return t // PERIOD


def validity_periods(validity: int) -> int:
    """``V``: a verifier's validity in periods, at least 1."""
    return max(1, validity // PERIOD)


def epoch_of_period(p: int, v: int) -> int:
    return p // v


def handover(p: int, v: int) -> bool:
    """True in the last two periods of an epoch (a one-period epoch is always in handover)."""
    return p % v >= max(v - 2, 0)


def epoch_now(t: int, v: int) -> int:
    return epoch_of_period(period(t), v)


def ballot_window_epoch(closes_v1: int, v: int) -> int:
    """The epoch a ballot's cards must carry: ``epoch(period(closes))`` of the deck's version 1."""
    return epoch_of_period(period(closes_v1), v)


LOGGED_USES = ("author-once", "author-slot", "sponsor")


def is_logged_use(use: str) -> bool:
    """A logged presentation: signed or unsigned authorship, or a sponsor proof."""
    return use in LOGGED_USES


def logged_epochs(issued: int, v: int) -> set[int]:
    """The epochs a later verifier (no clock) accepts for a logged presentation:
    ``epoch(period(issued − 7200))`` and ``epoch(period(issued + 3600))``."""
    return {
        epoch_of_period(period(issued - 2 * HOUR), v),
        epoch_of_period(period(issued + HOUR), v),
    }


def log_submission_check(card_epoch: int, v: int, log_now: int, issued: int) -> str | None:
    """The log's own check at submission ("Validity", logged presentations row). Returns a
    reason (rule P5) or ``None``. ``log_now`` is the log's clock ``T``; ``issued`` is the
    object's envelope time."""
    if abs(issued - log_now) > HOUR:
        return "issued is more than 3600 seconds from the log's clock"
    if not card_accepted(card_epoch, v, log_now, use="other"):
        return "disclosed epoch is not the log's current epoch or its first-hour grace"
    return None


def log_of_record(logs: list[bytes]) -> bytes:
    """The context's log of record: the first entry of its ``logs`` (credentials.md, "in
    force"; issue-map.md, "Several logs"). A sponsor manifest's is the log whose proof its
    bundle carries (agent-sponsor.md AS-8)."""
    if not logs:
        raise ValueError("a context names at least one log")
    return logs[0]


def object_in_log_of_record(logs: list[bytes], proof_logs: list[bytes]) -> bool:
    """A phone's check: an authored object is valid only if it is in its context's log of
    record, whatever other listed logs hold it."""
    return log_of_record(logs) in proof_logs


def log_accepts_logged_object(
    *,
    this_log: bytes,
    logs: list[bytes],
    proof_logs: list[bytes],
    issuer_lineage_in_history: bool,
    card_epoch: int,
    v: int,
    log_now: int,
    issued: int,
) -> str | None:
    """What one listed log checks at submission (services.md, "What the log runs"). The log
    of record refuses an object whose issuer's ``verifier`` lineage is not in its own history
    and otherwise makes the clock check. Another listed log accepts the object, whatever its
    clock says about ``issued``, when the bundle carries an inclusion proof from the log of
    record, and then applies the later-verifier rule. Returns the refusal reason or None."""
    record = log_of_record(logs)
    if this_log == record:
        if not issuer_lineage_in_history:
            return "issuer's verifier lineage is not in this log's history"
        return log_submission_check(card_epoch, v, log_now, issued)
    if this_log not in logs:
        return "this log is not one the context lists"
    if record not in proof_logs:
        return "no inclusion proof from the log of record"
    if not card_accepted(card_epoch, v, None, use="logged", issued=issued):
        return "disclosed epoch is not that of issued (later-verifier rule)"
    return None


def card_accepted(
    card_epoch: int,
    v: int,
    now: int | None,
    *,
    use: str = "other",
    closes_v1: int | None = None,
    issued: int | None = None,
) -> bool:
    """The validity rule per use. ``use`` is ``"ballot"``, ``"logged"`` or ``"other"``.

    Ballots: ``epoch = epoch(period(closes₁))`` and the card has started (``p_now ≥ epoch·V``).
    Logged presentations verified after submission: no clock; the epoch is one of
    ``logged_epochs(issued, V)``. Everything else: ``epoch = E_now``, with the previous period's
    value accepted in the first hour of a period.
    """
    if use == "logged":
        if issued is None:
            raise ValueError("a logged presentation needs the object's issued")
        return card_epoch in logged_epochs(issued, v)
    if now is None:
        raise ValueError("this use needs the verifier's clock")
    p_now = period(now)
    if use == "ballot":
        if closes_v1 is None:
            raise ValueError("a ballot needs the deck's version-1 closes")
        return card_epoch == ballot_window_epoch(closes_v1, v) and p_now >= card_epoch * v
    if card_epoch == epoch_of_period(p_now, v):
        return True
    in_first_hour = now - p_now * PERIOD < HOUR
    return in_first_hour and card_epoch == epoch_of_period(p_now - 1, v)


# ---------------------------------------------------------------- the card


def layout_length(attribute_count: int) -> int:
    """``L`` = 2 + attributes: epoch, one message per attribute of the layout, nym secret last."""
    return 2 + attribute_count


def layout_length_at(from_epochs: list[int], epoch: int) -> int:
    """``L(E)``: 2 plus the number of attributes with ``fromEpoch ≤ E``."""
    return layout_length(sum(1 for fe in from_epochs if fe <= epoch))


def message_bytes(
    index: int, value: int | None, epoch: int | None = None, length: int | None = None
) -> bytes:
    """Bytes before ``messages_to_scalars`` for message ``index``: 0 is the epoch, ``1 + i`` is
    attribute ``i`` (``0xFFFF…`` when absent). Index ``L − 1`` is the nym secret, a scalar that
    is never encoded here; pass ``length`` to have it refused."""
    if index == 0:
        if epoch is None:
            raise ValueError("message 0 is the epoch")
        return epoch.to_bytes(8, "big")
    if length is not None and index == length - 1:
        raise ValueError("message L - 1 is the nym secret; it is never encoded here")
    return (ABSENT if value is None else value).to_bytes(8, "big")


def card_header(authority: bytes, kid: bytes) -> bytes:
    """BBS ``header``: ``hum/credential/1`` ‖ verifier authority CID (33) ‖ kid."""
    parse_cid(authority)
    return b"hum/credential/1" + authority + kid


def key_of_epoch(keys: list[tuple[bytes, int]], epoch: int) -> bytes | None:
    """The listed key with the largest ``fromEpoch ≤ epoch``; ``keys`` are (kid, fromEpoch)."""
    best = None
    for kid, from_epoch in keys:
        if from_epoch <= epoch and (best is None or from_epoch > best[1]):
            best = (kid, from_epoch)
    return best[0] if best else None


# ---------------------------------------------------------------- scopes and nullifiers


def _u64(n: int) -> bytes:
    return n.to_bytes(8, "big")


def _u16(n: int) -> bytes:
    return n.to_bytes(2, "big")


def _sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


class scopes:
    """Every row of the uses table: ``(scope bytes, bound message)``. All inputs are raw bytes."""

    PREFIXES = (
        b"hum/ballot/1",
        b"hum/join/1",
        b"hum/blob-tokens/1",
        b"hum/delivery-tokens/1",
        b"hum/author-once/1",
        b"hum/author-slot/1",
        b"hum/sponsor/1",
        b"hum/issuance/1",
    )

    @staticmethod
    def ballot(deck_lineage: bytes, body_keys_0_to_4: bytes) -> tuple[bytes, bytes]:
        return b"hum/ballot/1" + deck_lineage, b"hum/ballot-bound/1" + _sha(body_keys_0_to_4)

    @staticmethod
    def join(context_lineage: bytes, handles: list[bytes]) -> tuple[bytes, bytes]:
        return b"hum/join/1" + context_lineage, _sha(cbor.encode(handles))

    @staticmethod
    def blob_tokens(token_key_id: bytes, day: int, requests: list[bytes]) -> tuple[bytes, bytes]:
        return b"hum/blob-tokens/1" + token_key_id + _u64(day), _sha(cbor.encode(requests))

    @staticmethod
    def delivery_tokens(
        token_key_id: bytes, day: int, requests: list[bytes]
    ) -> tuple[bytes, bytes]:
        return b"hum/delivery-tokens/1" + token_key_id + _u64(day), _sha(cbor.encode(requests))

    @staticmethod
    def author_once(object_cid: bytes) -> tuple[bytes, bytes]:
        return b"hum/author-once/1" + object_cid, b"hum/author/1" + object_cid

    @staticmethod
    def author_slot(
        context_lineage: bytes, window: int, slot: int, object_cid: bytes
    ) -> tuple[bytes, bytes]:
        scope = b"hum/author-slot/1" + context_lineage + _u64(window) + _u16(slot)
        return scope, b"hum/author/1" + object_cid

    @staticmethod
    def sponsor(sponsor_authority: bytes, agent_key: bytes) -> tuple[bytes, bytes]:
        return b"hum/sponsor/1" + sponsor_authority, agent_key

    @staticmethod
    def issuance(verifier_authority: bytes, request_plaintext: bytes) -> tuple[bytes, bytes]:
        return b"hum/issuance/1" + verifier_authority, _sha(request_plaintext)

    @staticmethod
    def prefixes_distinct() -> bool:
        ps = scopes.PREFIXES
        return all(not a.startswith(b) for a in ps for b in ps if a != b) and not any(
            p.startswith(b"hum/author-") for p in (b"hum/ballot/1",)
        )


def nullifier(pseudonym_octets: bytes) -> bytes:
    """``SHA-256("hum/nullifier/1" ‖ pseudonym)``; the pseudonym is 48 compressed G1 bytes."""
    if len(pseudonym_octets) != 48:
        raise ValueError("a pseudonym is 48 bytes")
    return _sha(b"hum/nullifier/1" + pseudonym_octets)


# ---------------------------------------------------------------- presentations

P_V, P_CONTEXT, P_CREDS, P_BRANCHES = range(4)
CP_ISSUER, CP_KID, CP_LEN, CP_DISCLOSED, CP_PROOF, CP_PSEUDONYM = range(6)


class PresentationError(Exception):
    def __init__(self, rule: str, reason: str) -> None:
        super().__init__(f"{rule}: {reason}")
        self.rule = rule
        self.reason = reason


@dataclass
class CardProof:
    issuer: bytes
    kid: bytes
    len: int
    disclosed: dict[int, int]
    proof: bytes
    pseudonym: bytes
    proof_valid: bool = True  # P4 stands in for the BBS verification, pending a library

    def to_item(self) -> dict[int, Any]:
        return {
            CP_ISSUER: self.issuer,
            CP_KID: self.kid,
            CP_LEN: self.len,
            CP_DISCLOSED: dict(self.disclosed),
            CP_PROOF: self.proof,
            CP_PSEUDONYM: self.pseudonym,
        }

    @classmethod
    def from_item(cls, item: Any) -> CardProof:
        if not (isinstance(item, dict) and set(item) == set(range(6))):
            raise PresentationError("P1", "card proof keys")
        if not (
            isinstance(item[CP_DISCLOSED], dict)
            and all(
                isinstance(k, int) and isinstance(v, int) for k, v in item[CP_DISCLOSED].items()
            )
        ):
            raise PresentationError("P1", "disclosed map")
        if not (isinstance(item[CP_PSEUDONYM], bytes) and len(item[CP_PSEUDONYM]) == 48):
            raise PresentationError("P1", "pseudonym must be 48 bytes")
        return cls(
            item[CP_ISSUER], item[CP_KID], item[CP_LEN], dict(item[CP_DISCLOSED]),
            item[CP_PROOF], item[CP_PSEUDONYM],
        )  # fmt: skip


@dataclass
class Presentation:
    creds: list[CardProof]
    branches: list[int] = field(default_factory=list)
    context: bytes | None = None

    def to_item(self) -> dict[int, Any]:
        item: dict[int, Any] = {
            P_V: 1,
            P_CREDS: [c.to_item() for c in self.creds],
            P_BRANCHES: list(self.branches),
        }
        if self.context is not None:
            item[P_CONTEXT] = self.context
        return item

    def encode(self) -> bytes:
        return cbor.encode(self.to_item())

    @classmethod
    def decode(cls, data: bytes, *, in_ballot: bool = False) -> Presentation:
        limit = MAX_BALLOT_PRESENTATION if in_ballot else MAX_PRESENTATION
        if len(data) > limit:
            raise PresentationError("P1", f"presentation over {limit} bytes")
        try:
            item = cbor.decode(data)
        except cbor.CborError as e:
            raise PresentationError("P1", f"not canonical CBOR: {e}") from e
        if not isinstance(item, dict) or not {P_V, P_CREDS, P_BRANCHES} <= set(item):
            raise PresentationError("P1", "presentation keys")
        if set(item) - {P_V, P_CONTEXT, P_CREDS, P_BRANCHES}:
            raise PresentationError("P1", "unknown key")
        if item[P_V] != 1:
            raise PresentationError("P1", "version")
        creds = item[P_CREDS]
        if not isinstance(creds, list) or len(creds) > MAX_CREDS:
            raise PresentationError("P1", "creds must be a list of at most 8")
        branches = item[P_BRANCHES]
        if not isinstance(branches, list) or not all(isinstance(b, int) for b in branches):
            raise PresentationError("P1", "branches")
        ctx = item.get(P_CONTEXT)
        if ctx is not None and not (isinstance(ctx, bytes) and len(ctx) == 33):
            raise PresentationError("P1", "context must be a 33-byte CID")
        return cls([CardProof.from_item(c) for c in creds], branches, ctx)


def presentation_header(scope: bytes, bound: bytes, context: bytes | None) -> bytes:
    """``ph`` = "hum/presentation/1" ‖ u16 len ‖ scope ‖ u16 len ‖ bound ‖ context (or 33 zeros)."""
    return (
        b"hum/presentation/1"
        + _u16(len(scope))
        + scope
        + _u16(len(bound))
        + bound
        + (context if context is not None else bytes(33))
    )


@dataclass
class IssuerInfo:
    """What the verifier knows about one issuer, read from the verifier version in force.

    ``attributes`` are ``(name, fromEpoch)`` in manifest order; the layout of epoch ``E`` is the
    attributes with ``fromEpoch ≤ E`` and attribute ``i`` of that layout is message ``1 + i``.
    ``kids`` are the version's ``issuerKeys``. ``kids_removed_at`` maps a kid that a later
    version removed to the log index of that version, for a caller that holds the latest
    version rather than the one in force: a removal above the object's position does not
    invalidate the object (P3, "in force").
    """

    authority: bytes
    class_: str
    retired: bool
    kids: set[bytes]
    retired_kids: set[bytes]
    attributes: list[tuple[str, int]]
    key_of_epoch: dict[int, bytes] = field(default_factory=dict)  # epoch -> kid
    since: dict[bytes, int] = field(default_factory=dict)
    kids_removed_at: dict[bytes, int] = field(default_factory=dict)
    lineage: bytes | None = None  # the verifier lineage CID, when the caller knows it

    @property
    def attribute_names(self) -> list[str]:
        return [name for name, _ in self.attributes]

    def layout(self, epoch: int) -> list[str]:
        return [name for name, fe in self.attributes if fe <= epoch]

    def layout_length(self, epoch: int) -> int:
        return layout_length(len(self.layout(epoch)))

    def attribute_index(self, name: str, epoch: int) -> int | None:
        """Message index of ``name`` in epoch ``epoch``'s layout, or None when not in it."""
        layout = self.layout(epoch)
        return 1 + layout.index(name) if name in layout else None

    def kid_in_force(self, kid: bytes, position: int | None) -> bool:
        if kid in self.kids:
            return True
        removed = self.kids_removed_at.get(kid)
        return removed is not None and position is not None and removed > position


def issuers_by_authority(infos: list[IssuerInfo]) -> dict[bytes, IssuerInfo]:
    """Index verifier versions by authority for ``verify_presentation``. P3: an authority has
    one ``verifier`` lineage (verifier.md rule 31), so two logged lineages under one authority
    make every card from that authority unresolvable."""
    out: dict[bytes, IssuerInfo] = {}
    for info in infos:
        seen = out.get(info.authority)
        if seen is not None and seen.lineage != info.lineage:
            raise PresentationError("P3", "authority has more than one verifier lineage")
        out[info.authority] = info
    return out


@dataclass
class Row:
    """A trust-list.md resolution row for the leaf's source."""

    authority: bytes
    filter: str  # attribute name or "*"
    min_assurance: int
    min_version: int
    classes: tuple[str, ...]
    assurance: int = 3


NODE_POSSESSION = 4  # the possession leaf ``[4, authority]`` (credentials.md, "Policies")


def possession_leaf(authority: bytes) -> list:
    """The possession leaf ``[4, authority]``: ``authority`` is a verifier authority CID given
    directly, not through a context's ``refs`` or ``issuers``. It requires a card proof from
    that authority with the attribute leaf's ``kid``, ``since``, ``len`` and ``class`` checks and
    discloses nothing but index 0. A use states it itself (the sponsor row, each ``accepts``
    alternative of issuance evidence); context manifests never carry it in draft 0.1."""
    return [NODE_POSSESSION, bytes(authority)]


def choose_accepts_entry(accepts: list[tuple[bytes, list[str]]], held: set[bytes]) -> int | None:
    """The phone's choice for issuance evidence: the lowest-index ``accepts`` entry whose
    authority it holds a valid card for (credentials.md, "The uses"), or None."""
    for k, (authority, _) in enumerate(accepts):
        if authority in held:
            return k
    return None


def accepts_entry(
    pres: Presentation, accepts: list[tuple[bytes, list[str]]], issuers: dict[bytes, IssuerInfo]
) -> tuple[int, list, set[int]]:
    """Issuance evidence: ``accepts`` entries ``(authority, attribute names)`` are alternatives.
    Exactly one card, satisfying the possession leaf ``[4, accepts[k].authority]`` of one entry
    and disclosing that entry's attributes. Returns ``(k, policy, allowed indexes)``."""
    if len(pres.creds) != 1:
        raise PresentationError("P6", "issuance evidence carries exactly one card")
    cp = pres.creds[0]
    matches = [k for k, (authority, _) in enumerate(accepts) if authority == cp.issuer]
    if not matches:
        raise PresentationError("P6", "the card is from no accepts entry's verifier")
    k = matches[0]
    info = issuers.get(cp.issuer)
    allowed: set[int] = set()
    if info is not None and 0 in cp.disclosed:
        for name in accepts[k][1]:
            idx = info.attribute_index(name, cp.disclosed[0])
            if idx is None or idx not in cp.disclosed:
                raise PresentationError("P7", f"accepts attribute {name} is not disclosed")
            allowed.add(idx)
    return k, possession_leaf(accepts[k][0]), allowed


def _has_any(node) -> bool:
    kind = node[0]
    if kind == NODE_ANY:
        return True
    if kind == NODE_ALL:
        return any(_has_any(c) for c in node[1])
    return False


def verify_presentation(
    pres: Presentation,
    *,
    use: str,
    policy: Any,
    scope: bytes,
    bound: bytes,
    expected_context: bytes | None,
    issuers: dict[bytes, IssuerInfo],
    rows_for_source: dict[tuple[int, int], list[Row]],
    now: int | None,
    v_of: dict[bytes, int],
    closes_v1: int | None = None,
    designated_leaf: tuple[list[int], str] | None = None,
    allowed_disclosures: set[int] | None = None,
    issued: int | None = None,
    object_position: int | None = None,
    accepts: list[tuple[bytes, list[str]]] | None = None,
) -> dict[str, Any]:
    """Rules P1 to P8. P1's byte checks happen in ``Presentation.decode``; here P1 is the field
    rules. P4 is the per-card ``proof_valid`` flag (pending BBS). Returns the nullifiers.

    ``now`` is the verifier's clock for ballots and one-time uses. A logged use (author-once,
    author-slot, sponsor) verified after submission passes ``issued`` (the object's envelope
    time) and ``object_position`` (its log index) instead; ``now`` is then ignored. The log's
    own submission check is ``log_submission_check``.

    For ``use="issuance"`` pass ``accepts`` (the evidence item's alternatives) instead of a
    policy: the possession leaf and the allowed disclosures come from ``accepts_entry``, and
    the result carries the entry index used (``"accepts_entry"``). A possession leaf
    ``[4, authority]`` needs no ``rows_for_source`` entry.
    """
    row_class = "agent" if use == "sponsor" else "person"
    logged = is_logged_use(use)
    if logged and issued is None:
        raise ValueError("a logged presentation needs the object's issued")
    entry_used = None
    if accepts is not None:
        entry_used, policy, allowed_disclosures = accepts_entry(pres, accepts, issuers)
        rows_for_source = {}
    # P2
    if (expected_context is None) != (pres.context is None):
        raise PresentationError("P2", "context present when the use forbids it, or absent")
    if expected_context is not None and pres.context != expected_context:
        raise PresentationError("P2", "context is not the version the use names")
    # P3
    for cp in pres.creds:
        info = issuers.get(cp.issuer)
        if info is None or info.retired:
            raise PresentationError("P3", "issuer unknown or retired")
        if info.class_ != row_class:
            raise PresentationError("P3", f"issuer class is not {row_class}")
        if cp.kid in info.retired_kids or not info.kid_in_force(cp.kid, object_position):
            raise PresentationError("P3", "kid not in issuerKeys of the version in force")
        if 0 in cp.disclosed and cp.len != info.layout_length(cp.disclosed[0]):
            raise PresentationError("P3", "len is not L(E) for the disclosed epoch")
    # P4
    for cp in pres.creds:
        if not cp.proof_valid:
            raise PresentationError("P4", "BBS proof does not verify")
    # P5
    for cp in pres.creds:
        if 0 not in cp.disclosed:
            raise PresentationError("P5", "index 0 (the epoch) must be disclosed")
        if cp.len - 1 in cp.disclosed:
            raise PresentationError("P5", "index L - 1 (the nym secret) must never be disclosed")
        v = v_of[cp.issuer]
        kind = "ballot" if use == "ballot" else "logged" if logged else "other"
        ok = card_accepted(cp.disclosed[0], v, now, use=kind, closes_v1=closes_v1, issued=issued)
        if not ok:
            raise PresentationError("P5", "epoch outside the use's window")
    # P6: the policy walk (no any nodes and no branches in draft 0.1, context.md C16)
    if _has_any(policy):
        raise PresentationError("P6", "the policy contains an any node (C16)")
    if pres.branches:
        raise PresentationError("P6", "branches must be empty (C16)")
    used: set[int] = set()
    satisfied_by: dict[int, list[tuple[int, int, str]]] = {}

    def leaf_rows(node) -> list[Row]:
        source, name = tuple(node[1]), node[2]
        rows = [r for r in rows_for_source.get(source, []) if r.filter == name or r.filter == "*"]
        if len({r.authority for r in rows}) != 1:
            raise PresentationError("P6", f"leaf {name} does not resolve to exactly one verifier")
        return rows

    def leaf_index(node, cp: CardProof) -> int | None:
        """The attribute's message index, when this card is admitted for the leaf."""
        rows, name, pred = leaf_rows(node), node[2], node[3]
        info = issuers[cp.issuer]
        if not any(
            r.authority == cp.issuer
            and name in info.attribute_names
            and r.assurance >= r.min_assurance
            and info.since.get(cp.kid, 1) >= r.min_version
            and info.class_ in r.classes
            for r in rows
        ):
            return None
        idx = info.attribute_index(name, cp.disclosed[0])
        if idx is None or idx not in cp.disclosed:
            return None
        value = cp.disclosed[idx]
        if pred[0] == PRED_PRESENT:
            return idx if value == 1 else None
        if pred[0] == PRED_SET and len(pred[1]) == 1:
            return idx if value == pred[1][0] else None
        if pred[0] == PRED_RANGE and pred[1] == pred[2]:
            return idx if value == pred[1] else None
        return None  # multi-valued leaves are unsatisfiable in draft 0.1

    def walk(node) -> None:
        kind = node[0]
        if kind == NODE_TRUE:
            return
        if kind == NODE_ALL:
            for c in node[1]:
                walk(c)
            return
        if kind == NODE_ATTR:
            found = {i: leaf_index(node, cp) for i, cp in enumerate(pres.creds)}
            candidates = [i for i, idx in found.items() if idx is not None]
            if not candidates:
                raise PresentationError("P6", f"no card satisfies leaf {node[2]}")
            chosen = min(candidates, key=lambda i: pres.creds[i].issuer + pres.creds[i].kid)
            used.add(chosen)
            satisfied_by.setdefault(chosen, []).append((found[chosen], node[1][0], node[2]))
            return
        if kind == NODE_POSSESSION:
            # [4, authority]: a card from that authority of the use's class; kid and len
            # were checked under P3. No trust-list row applies, so there is no minVersion
            # test on since. It discloses index 0 only (P7 below).
            candidates = [
                i
                for i, cp in enumerate(pres.creds)
                if cp.issuer == node[1] and issuers[cp.issuer].class_ == row_class
            ]
            if not candidates:
                raise PresentationError("P6", "no card from the possession leaf's verifier")
            chosen = min(candidates, key=lambda i: pres.creds[i].kid)
            used.add(chosen)
            satisfied_by.setdefault(chosen, []).append((0, NODE_POSSESSION, None))
            return
        raise PresentationError("P6", "unknown node")

    walk(policy)
    allowed = allowed_disclosures or set()
    for i, cp in enumerate(pres.creds):
        attr_keys = {k for k in cp.disclosed if 1 <= k <= cp.len - 2}
        if i not in used and not (attr_keys & allowed):
            raise PresentationError("P6", f"card proof {i} satisfies no leaf")
    # P7
    for i, cp in enumerate(pres.creds):
        needed = {idx for idx, _, _ in satisfied_by.get(i, [])}
        for k in cp.disclosed:
            if k == 0:
                continue
            if k > cp.len - 2:
                raise PresentationError("P7", f"message {k} is outside the layout")
            if k not in needed and k not in allowed:
                raise PresentationError("P7", f"message {k} disclosed without a leaf requiring it")
    # P8
    nullifiers = [nullifier(cp.pseudonym) for cp in pres.creds]
    primary = None
    if designated_leaf is not None:
        src, name = tuple(designated_leaf[0]), designated_leaf[1]
        for i, leaves in satisfied_by.items():
            if any(leaf_src == src[0] and leaf_name == name for _, leaf_src, leaf_name in leaves):
                rows = rows_for_source.get(src, [])
                if any(r.authority == pres.creds[i].issuer for r in rows):
                    primary = nullifiers[i]
                    break
        if primary is None:
            raise PresentationError("P8", "no card satisfies the designated nullifier leaf")
    out = {"nullifiers": nullifiers, "primary": primary, "used": sorted(used)}
    if entry_used is not None:
        out["accepts_entry"] = entry_used
    return out


# ---------------------------------------------------------------- issuance (host side)

RQ_V, RQ_MANIFEST, RQ_KID, RQ_COMMITS, RQ_APPROVED = range(5)
RS_V, RS_KID, RS_VALUES, RS_CARDS = range(4)
CARD_EPOCH, CARD_KID, CARD_SIG, CARD_NYM = range(4)


@dataclass
class DedupRow:
    last_epoch: int
    kid: bytes
    request_hash: bytes


def issuance_request(
    manifest: bytes, kid: bytes, commits: list[bytes], approved: list[int]
) -> bytes:
    """The plaintext of the issuance request (HPKE sealing to a host key is pending)."""
    return cbor.encode(
        {
            RQ_V: 1,
            RQ_MANIFEST: manifest,
            RQ_KID: kid,
            RQ_COMMITS: list(commits),
            RQ_APPROVED: sorted(approved),
        }
    )


def issuance_response(kid: bytes, values: dict[int, int], cards: list[dict[int, Any]]) -> bytes:
    return cbor.encode({RS_V: 1, RS_KID: kid, RS_VALUES: dict(values), RS_CARDS: list(cards)})


def nym_share(host_secret: bytes, request_plaintext: bytes, epoch: int) -> bytes:
    """HKDF-SHA256: IKM the host secret, salt ``hum/nym-share/1``, info SHA-256(request) ‖ epoch."""
    prk = hmac.new(NYM_SHARE_SALT, host_secret, hashlib.sha256).digest()
    info = _sha(request_plaintext) + _u64(epoch)
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def decide_issuance(
    rows: list[DedupRow],
    now: int,
    v: int,
    request_hash: bytes,
    live_kids: set[bytes],
) -> dict[str, Any]:
    """ "Which epochs a session issues". Returns ``{"issue": [epochs], "retry": bool,
    "refuse": bool, "last_epoch": int}``; a refusal is the dedup code (masked elsewhere)."""
    p_now = period(now)
    e_now = epoch_of_period(p_now, v)
    in_handover = handover(p_now, v)
    live = [r for r in rows if r.kid in live_kids]
    governing = max(live, key=lambda r: r.last_epoch) if live else None
    if (
        governing is not None
        and governing.last_epoch >= e_now
        and governing.request_hash == request_hash
    ):
        return {"issue": [], "retry": True, "refuse": False, "last_epoch": governing.last_epoch}
    if governing is None or governing.last_epoch < e_now:
        epochs = [e_now, e_now + 1] if in_handover else [e_now]
        return {"issue": epochs, "retry": False, "refuse": False, "last_epoch": epochs[-1]}
    if governing.last_epoch == e_now and in_handover:
        return {"issue": [e_now + 1], "retry": False, "refuse": False, "last_epoch": e_now + 1}
    return {"issue": [], "retry": False, "refuse": True, "last_epoch": governing.last_epoch}


def check_issuance_response(
    response: dict[int, Any],
    *,
    request_kid: bytes,
    keys: list[tuple[bytes, int]],
    now: int,
    v: int,
    declared: dict[int, set[int] | None],
    approved: set[int],
    signature_valid: bool = True,
) -> None:
    """The phone's checks on a response (step 4 of Issuance). ``declared`` maps message index
    to its value set (None for an unbounded uint). Raises ``PresentationError`` with "issuance"."""
    if response.get(RS_KID) != request_kid:
        raise PresentationError("issuance", "response kid differs from the request")
    p_now = period(now)
    e_now = epoch_of_period(p_now, v)
    for card in response[RS_CARDS]:
        e = card[CARD_EPOCH]
        if not (e == e_now or (e == e_now + 1 and handover(p_now, v))):
            raise PresentationError("issuance", "epoch is not E_now, or E_now + 1 in handover")
        if card[CARD_KID] != key_of_epoch(keys, e):
            raise PresentationError("issuance", "kid is not the key of the card's epoch")
        if not signature_valid:
            raise PresentationError("issuance", "signature does not verify")
    for idx, value in response[RS_VALUES].items():
        if idx not in approved:
            raise PresentationError("issuance", f"unapproved attribute {idx} present")
        allowed = declared.get(idx)
        if idx not in declared or (allowed is not None and value not in allowed):
            raise PresentationError("issuance", f"value {value} outside the declared set")


# ---------------------------------------------------------------- backup

BK_V, BK_CHAT_KEY, BK_EDIT_ROOT, BK_CARDS, BK_CONTEXTS, BK_WRITTEN = range(6)
FORBIDDEN_BACKUP_KEYS = {"hand", "shield", "receipt", "receipts", "order", "selection", "group"}


def write_backup(
    chat_key: bytes,
    edit_root: bytes,
    cards: list[dict[str, Any]],
    contexts: list[dict[str, Any]],
    written: int,
    extra: dict | None = None,
) -> bytes:
    """The backup plaintext. Refuses any key outside the layout and any vote-related key.
    Sealing (storage format 1) and the Argon2id/HPKE wrap under ``hum/backup/1`` are pending."""
    if extra:
        for k in extra:
            raise ValueError(f"backup refuses unknown or forbidden key {k!r}")
    for card in cards:
        for k in card:
            if k in FORBIDDEN_BACKUP_KEYS:
                raise ValueError(f"backup refuses key {k!r}")
    item = {
        BK_V: 1,
        BK_CHAT_KEY: chat_key,
        BK_EDIT_ROOT: edit_root,
        BK_CARDS: [
            {
                0: c["issuer"],
                1: c["kid"],
                2: c["len"],
                3: c["messages"],
                4: c["signature"],
                5: c["nym_secret"],
            }
            for c in cards
        ],
        BK_CONTEXTS: [
            ({0: c["lineage"], 1: c["left"]} if c.get("left") is not None else {0: c["lineage"]})
            for c in contexts
        ],
        BK_WRITTEN: written,
    }
    return cbor.encode(item)


def write_chat_export(chat_key: bytes, edit_root: bytes) -> bytes:
    return cbor.encode({BK_V: 1, BK_CHAT_KEY: chat_key, BK_EDIT_ROOT: edit_root})
