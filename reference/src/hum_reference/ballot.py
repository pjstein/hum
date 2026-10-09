"""Ballots: docs/specs/ballot.md.

``seam:`` ballot construction, contribution caps, what leaves the phone; domain strings
``hum/ballot/1``, ``hum/ballot-bound/1``, ``hum/receipt-leaf/1``, ``hum/dap-task/1``.

What is here: the ballot map and its frame (B1), the round payloads and the per-part
integer vectors they stand for, the intake checks B4, B5, B6, B10, the round-0 replacement
and later-round rules B7 and B8 over a decoded presentation outcome (the presentation
itself is credentials.md's and is pending), the receipt leaf, task and report ids, receipt
checking against the padded pages, and the client-side selections and send schedule.

The ratings selection and the send schedule use "a fixed seed" in the spec; the reference
expands a seed with ``SHA-256("hum/ratings-selection/1" ‖ seed ‖ uint32be(counter))`` and
``SHA-256("hum/send-schedule/1" ‖ seed ‖ uint32be(counter))`` into 64-bit draws with
rejection sampling. That expansion is a reference choice for vectors, not a protocol rule.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from . import cbor, merkle

__all__ = [
    "BALLOT_BYTES",
    "Intake",
    "ballot_map",
    "body_bytes",
    "bound_message",
    "check_receipt",
    "check_round0",
    "check_round1",
    "check_round2",
    "check_round3",
    "counted_hand",
    "frame",
    "groups_vector",
    "movement_selection",
    "movement_vector",
    "ratings_selection",
    "ratings_vector",
    "receipt_leaf",
    "report_id",
    "scope",
    "send_schedule",
    "tallies_vector",
    "task_id",
    "unframe",
]

BALLOT_BYTES = 49_152
PRESENTATION_MAX = 8_192
V, DECK, ROUND, NONCE, PAYLOAD, PRESENTATION = range(6)
P_VOTES, P_MOVEMENT, P_RATINGS, P_GROUP = range(4)
R1_COV, R2_CELL = 0, 0
R3_GROUP, R3_VOTES, R3_RATINGS = 0, 1, 2
AGREE, DISAGREE, UNSURE = 1, 2, 3

SCOPE_PREFIX = b"hum/ballot/1"
BOUND_PREFIX = b"hum/ballot-bound/1"
LEAF_PREFIX = b"hum/receipt-leaf/1"
TASK_PREFIX = b"hum/dap-task/1"


class BallotError(ValueError):
    """A ballot the aggregator refuses: ``rule`` (B1..B10) and ``error`` (services.md code)."""

    def __init__(self, rule: str, error: str, reason: str, detail: str | None = None) -> None:
        super().__init__(f"{rule} {error}: {reason}")
        self.rule = rule
        self.error = error
        self.reason = reason
        self.detail = detail


# ---------------------------------------------------------------- the ballot and its frame


def ballot_map(
    deck: bytes, round_: int, nonce: bytes, payload: dict[int, Any], presentation: bytes
) -> dict[int, Any]:
    return {
        V: 1,
        DECK: deck,
        ROUND: round_,
        NONCE: nonce,
        PAYLOAD: payload,
        PRESENTATION: presentation,
    }


def body_bytes(ballot: dict[int, Any]) -> bytes:
    """Canonical CBOR of keys 0–4 only."""
    return cbor.encode({k: ballot[k] for k in (V, DECK, ROUND, NONCE, PAYLOAD)})


def bound_message(ballot: dict[int, Any]) -> bytes:
    return BOUND_PREFIX + hashlib.sha256(body_bytes(ballot)).digest()


def scope(deck_lineage: bytes) -> bytes:
    return SCOPE_PREFIX + deck_lineage


def frame(ballot_bytes: bytes) -> bytes:
    """``uint32be(len) ‖ ballot ‖ zero bytes`` of exactly ``BALLOT_BYTES``."""
    if len(ballot_bytes) > BALLOT_BYTES - 4:
        raise BallotError("B1", "malformed", "ballot larger than the frame")
    return (
        len(ballot_bytes).to_bytes(4, "big")
        + ballot_bytes
        + bytes(BALLOT_BYTES - 4 - len(ballot_bytes))
    )


def unframe(
    data: bytes, *, round_: int | None = None, deck_versions: set[bytes] | None = None
) -> dict[int, Any]:
    """B1: parse a request body into the ballot map or raise ``BallotError``."""
    if len(data) != BALLOT_BYTES:
        raise BallotError("B1", "malformed", f"frame is {len(data)} bytes")
    n = int.from_bytes(data[:4], "big")
    if n > BALLOT_BYTES - 4:
        raise BallotError("B1", "malformed", "length prefix larger than the frame")
    if any(data[4 + n :]):
        raise BallotError("B1", "malformed", "non-zero byte after the ballot")
    try:
        ballot = cbor.decode(data[4 : 4 + n])
    except cbor.CborError as e:
        raise BallotError("B1", "malformed", f"not canonical CBOR: {e}") from e
    if not isinstance(ballot, dict) or set(ballot) != set(range(6)):
        raise BallotError("B1", "malformed", "ballot must have exactly keys 0..5")
    if ballot[V] != 1:
        raise BallotError("B1", "malformed", "version")
    if not isinstance(ballot[DECK], bytes) or len(ballot[DECK]) != 33:
        raise BallotError("B1", "malformed", "deck must be a 33-byte CID")
    if not isinstance(ballot[ROUND], int) or not 0 <= ballot[ROUND] <= 3:
        raise BallotError("B1", "malformed", "round must be 0..3")
    if round_ is not None and ballot[ROUND] != round_:
        raise BallotError("B1", "malformed", "round does not match the URL")
    if not isinstance(ballot[NONCE], bytes) or len(ballot[NONCE]) != 32:
        raise BallotError("B1", "malformed", "nonce must be 32 bytes")
    if not isinstance(ballot[PAYLOAD], dict):
        raise BallotError("B1", "malformed", "payload must be a map")
    pres = ballot[PRESENTATION]
    if not isinstance(pres, bytes):
        raise BallotError("B1", "malformed", "presentation must be bytes")
    if len(pres) > PRESENTATION_MAX:
        raise BallotError("B1", "too_large", "presentation over 8 KiB")
    if deck_versions is not None and ballot[DECK] not in deck_versions:
        raise BallotError("B1", "malformed", "deck is not a version this endpoint serves")
    return ballot


# ---------------------------------------------------------------- payloads and vectors


def round0_payload(
    votes: bytes,
    movement: dict[int, list[int]] | None = None,
    ratings: dict[int, int] | None = None,
    group: int | None = None,
) -> dict[int, Any]:
    out: dict[int, Any] = {P_VOTES: votes}
    if movement is not None:
        out[P_MOVEMENT] = dict(movement)
    if ratings is not None:
        out[P_RATINGS] = dict(ratings)
    if group is not None:
        out[P_GROUP] = group
    return out


def encode_cov(entries: list[int]) -> bytes:
    return b"".join(e.to_bytes(4, "big", signed=True) for e in entries)


def decode_cov(data: bytes) -> list[int]:
    if len(data) % 4:
        raise BallotError("B10", "rejected", "cov length is not a multiple of 4")
    return [int.from_bytes(data[i : i + 4], "big", signed=True) for i in range(0, len(data), 4)]


def tallies_vector(votes: bytes, cards: int) -> list[int]:
    """Part 0: ``3C + 1`` entries; ``3i + (vote − 1)`` per counted card, participant last."""
    v = [0] * (3 * cards + 1)
    for i, b in enumerate(votes):
        if b:
            v[3 * i + (b - 1)] = 1
    v[3 * cards] = 1
    return v


def movement_vector(movement: dict[int, list[int]], cards: int, arguments: int) -> list[int]:
    """Part 5: ``9C + A`` entries."""
    v = [0] * (9 * cards + arguments)
    for i, (first, second, moved) in movement.items():
        v[9 * i + 3 * (first - 1) + (second - 1)] = 1
        if moved:
            v[9 * cards + _moved_argument(i, moved)] = 1
    return v


def _moved_argument(card: int, moved: int) -> int:
    """Placeholder index for "moved me" when the argument index map is not given."""
    return card * 2 + (moved - 1)


def movement_vector_with_args(
    movement: dict[int, list[int]], cards: int, arg_index: dict[tuple[int, str], int]
) -> list[int]:
    """Part 5 with the deck's argument indexes (ref names sorted bytewise)."""
    a = len(arg_index)
    v = [0] * (9 * cards + a)
    for i, (first, second, moved) in movement.items():
        v[9 * i + 3 * (first - 1) + (second - 1)] = 1
        if moved:
            v[9 * cards + arg_index[(i, "pro" if moved == 1 else "con")]] = 1
    return v


def ratings_vector(ratings: dict[int, int], arguments: int) -> list[int]:
    v = [0] * (3 * arguments)
    for a, r in ratings.items():
        v[3 * a + r] = 1
    return v


def groups_vector(
    group: int,
    groups_k: int,
    votes: bytes,
    cards: int,
    ratings: dict[int, int] | None,
    arguments: int,
) -> list[int]:
    """Part 3: slot ``g`` holds the tallies vector then the ratings vector (``3A`` is 0
    without part 6, which is also the rating-deck round-0 form)."""
    slot = 3 * cards + 1 + 3 * arguments
    v = [0] * (groups_k * slot)
    base = group * slot
    t = tallies_vector(votes, cards)
    v[base : base + len(t)] = t
    if arguments:
        r = ratings_vector(ratings or {}, arguments)
        v[base + len(t) : base + slot] = r
    return v


def weight(vector: list[int]) -> int:
    return sum(vector)


def argument_indexes(refs: dict[str, bytes]) -> dict[tuple[int, str], int]:
    """Argument refs ``card/<i>/pro|con`` indexed 0..A−1 by bytewise ref name."""
    names = sorted(n for n in refs if n.startswith("card/") and n.count("/") == 2)
    out = {}
    for idx, name in enumerate(names):
        _, i, side = name.split("/")
        out[(int(i), side)] = idx
    return out


# ---------------------------------------------------------------- intake checks


@dataclass
class DeckParams:
    cards: int
    cap: int
    cap_movement: int | None = None
    cap_ratings: int | None = None
    arg_index: dict[tuple[int, str], int] = field(default_factory=dict)
    rating: bool = False
    groups_k: int | None = None
    cov_m: int = 0
    cov_scale: int = 65_536
    delta_cov: int = 0
    grid: int = 24
    closes: int = 0

    @property
    def arguments(self) -> int:
        return len(self.arg_index)


def check_round0(payload: dict[int, Any], d: DeckParams) -> dict[str, Any]:
    """B4, B5, B6 over a round-0 payload. Returns the vectors it stands for."""
    if set(payload) - {P_VOTES, P_MOVEMENT, P_RATINGS, P_GROUP}:
        raise BallotError("B4", "rejected", "unknown payload key")
    votes = payload.get(P_VOTES)
    if not isinstance(votes, bytes) or len(votes) != d.cards:
        raise BallotError("B4", "rejected", "votes must be C bytes")
    if any(b > 3 for b in votes):
        raise BallotError("B4", "rejected", "vote byte outside 0..3")
    if sum(1 for b in votes if b) > d.cap:
        raise BallotError("B4", "rejected", "more than K counted votes")
    if d.rating:
        g = payload.get(P_GROUP)
        if not isinstance(g, int) or g < 0 or g >= (d.groups_k or 0):
            raise BallotError("B4", "rejected", "group absent or not below groupsK")
    elif P_GROUP in payload:
        raise BallotError("B4", "rejected", "group in a vote deck")
    out: dict[str, Any] = {"tallies": tallies_vector(votes, d.cards)}
    has_m = d.cap_movement is not None
    if (P_MOVEMENT in payload) != has_m:
        raise BallotError("B5", "rejected", "movement present iff the plan has part 5")
    if has_m:
        mv = payload[P_MOVEMENT]
        if not isinstance(mv, dict) or len(mv) > d.cap_movement:
            raise BallotError("B5", "rejected", "more than K_m movement entries")
        for i, t in mv.items():
            if not isinstance(i, int) or i >= d.cards:
                raise BallotError("B5", "rejected", "movement key not a card")
            if not (isinstance(t, list) and len(t) == 3):
                raise BallotError("B5", "rejected", "movement entry shape")
            first, second, moved = t
            if first not in (1, 2, 3) or second not in (1, 2, 3):
                raise BallotError("B5", "rejected", "first/second outside 1..3")
            if moved not in (0, 1, 2):
                raise BallotError("B5", "rejected", "moved outside 0..2")
            if moved and (i, "pro" if moved == 1 else "con") not in d.arg_index:
                raise BallotError("B5", "rejected", "moved names an argument the card lacks")
            if votes[i] and second != votes[i]:
                raise BallotError("B5", "rejected", "second differs from the counted vote")
        out["movement"] = movement_vector_with_args(mv, d.cards, d.arg_index)
    has_r = d.cap_ratings is not None
    if (P_RATINGS in payload) != has_r:
        raise BallotError("B6", "rejected", "ratings present iff the plan has part 6")
    if has_r:
        rt = payload[P_RATINGS]
        if not isinstance(rt, dict) or len(rt) > d.cap_ratings:
            raise BallotError("B6", "rejected", "more than K_r ratings")
        for a, r in rt.items():
            if not isinstance(a, int) or a >= d.arguments:
                raise BallotError("B6", "rejected", "rating key not an argument")
            if r not in (0, 1, 2):
                raise BallotError("B6", "rejected", "rating value outside 0..2")
        out["ratings"] = ratings_vector(rt, d.arguments)
    if d.rating:
        out["groups"] = groups_vector(payload[P_GROUP], d.groups_k, votes, d.cards, None, 0)
    return out


def check_round1(payload: dict[int, Any], d: DeckParams) -> dict[str, Any]:
    """B10 for round 1."""
    cov = payload.get(R1_COV)
    m = d.cov_m
    if set(payload) != {R1_COV} or not isinstance(cov, bytes):
        raise BallotError("B10", "rejected", "round 1 payload is {0: cov}")
    if len(cov) != 4 * m * (m + 1) // 2:
        raise BallotError("B10", "rejected", "cov of the wrong length")
    entries = decode_cov(cov)
    if any(abs(e) > d.cov_scale for e in entries):
        raise BallotError("B10", "rejected", "cov entry outside [-covScale, covScale]")
    norm_sq = sum(e * e for e in entries)
    if norm_sq > d.delta_cov * d.delta_cov:
        raise BallotError("B10", "rejected", "cov norm over delta_cov")
    return {"entries": entries, "norm_squared": norm_sq}


def check_round2(payload: dict[int, Any], d: DeckParams) -> dict[str, Any]:
    cell = payload.get(R2_CELL)
    if set(payload) != {R2_CELL} or not isinstance(cell, int) or cell < 0:
        raise BallotError("B10", "rejected", "round 2 payload is {0: cell}")
    if cell >= d.grid * d.grid:
        raise BallotError("B10", "rejected", "cell not below grid²")
    v = [0] * (d.grid * d.grid)
    v[cell] = 1
    return {"map": v}


def check_round3(
    payload: dict[int, Any], d: DeckParams, round0_payload: dict[int, Any]
) -> dict[str, Any]:
    if set(payload) - {R3_GROUP, R3_VOTES, R3_RATINGS} or R3_GROUP not in payload:
        raise BallotError("B10", "rejected", "round 3 payload shape")
    g = payload[R3_GROUP]
    if not isinstance(g, int) or g < 0 or g >= (d.groups_k or 0):
        raise BallotError("B10", "rejected", "group not below groupsK")
    if payload.get(R3_VOTES) != round0_payload.get(P_VOTES):
        raise BallotError("B10", "rejected", "votes differ from the accepted round-0 payload")
    if payload.get(R3_RATINGS) != round0_payload.get(P_RATINGS):
        raise BallotError("B10", "rejected", "ratings differ from the accepted round-0 payload")
    vec = groups_vector(
        g, d.groups_k, payload[R3_VOTES], d.cards, payload.get(R3_RATINGS), d.arguments
    )
    if weight(vec) > d.cap + (d.cap_ratings or 0) + 1:
        raise BallotError("B10", "rejected", "group vector weight over K + K_r + 1")
    return {"groups": vec}


# ---------------------------------------------------------------- receipts, tasks, reports


def receipt_leaf(round_: int, nonce: bytes, payload: dict[int, Any]) -> tuple[bytes, bytes]:
    """(commitment, leaf): ``SHA-256("hum/receipt-leaf/1" ‖ uint8(round) ‖ nonce ‖ commitment)``."""
    commitment = hashlib.sha256(cbor.encode(payload)).digest()
    leaf = hashlib.sha256(LEAF_PREFIX + bytes([round_]) + nonce + commitment).digest()
    return commitment, leaf


def task_id(deck_lineage: bytes, round_: int, part: int) -> bytes:
    """ballot.md's task id: SHA-256("hum/dap-task/1" ‖ lineage CID ‖ uint8(round) ‖ uint8(part)).

    services.md's ``taskId(round)`` hashes the deck CID and the round only; the two specs
    disagree and the reference carries both (``services.task_id`` for the other).
    """
    return hashlib.sha256(TASK_PREFIX + deck_lineage + bytes([round_, part])).digest()


def report_id(nonce: bytes, part: int) -> bytes:
    return hashlib.sha256(nonce + bytes([part])).digest()[:16]


def check_receipt(leaf: bytes, k: int, pages: list[bytes], root: bytes) -> dict[str, Any]:
    """Receipt checking steps 2 and 3: the page the leaf's first ``k`` bits select contains
    the leaf, and the pages (in order) hash to ``root`` as the RFC 9162 tree over the sorted
    padded list."""
    idx = int.from_bytes(leaf[:4], "big") >> (32 - k) if k else 0
    page = pages[idx]
    leaves = [page[i : i + 32] for i in range(0, len(page), 32)]
    present = leaf in leaves
    all_leaves = []
    for p in pages:
        all_leaves.extend(p[i : i + 32] for i in range(0, len(p), 32))
    computed = merkle.root_hash(all_leaves)
    return {
        "page": idx,
        "present": present,
        "root_matches": computed == root,
        "counted": present and computed == root,
    }


# ---------------------------------------------- the aggregator's state (B3, B7, B8)


@dataclass
class Outcome:
    """A decoded presentation outcome (credentials.md is pending): what B3 reads."""

    nullifiers: list[bytes]
    primary: bytes | None
    cards: list[dict[str, Any]]  # {"class": "person"|"agent", "issuer": bytes, "satisfies": bool}


class Intake:
    """Round-0 replacement and later-round rules for one deck, keyed by primary nullifier."""

    def __init__(self, closes: int) -> None:
        self.closes = closes
        self.accepted: dict[bytes, dict[str, Any]] = {}  # primary -> {body, payload, leaf, set}
        self.seen: set[bytes] = set()  # every nullifier seen in round 0
        self.later: dict[tuple[int, bytes], dict[str, Any]] = {}

    def check_b3(self, outcome: Outcome, *, replacing: bool = False) -> None:
        cards = [c for c in outcome.cards if c.get("satisfies")]
        if not cards:
            raise BallotError("B3", "rejected", "no card proof satisfies a leaf")
        if any(c["class"] != "person" for c in outcome.cards):
            raise BallotError("B3", "rejected", "a card is not from a person-class verifier")
        if outcome.primary is None or outcome.primary not in outcome.nullifiers:
            raise BallotError("B3", "rejected", "no primary nullifier")
        if replacing:
            return
        for n in outcome.nullifiers:
            if n in self.seen:
                raise BallotError("B3", "conflict", "nullifier already in the deck", "nullifier")

    def round0(self, ballot: dict[int, Any], outcome: Outcome, now: int) -> dict[str, Any]:
        body = body_bytes(ballot)
        primary = outcome.primary
        known = self.accepted.get(primary) if primary else None
        if known is not None:
            if known["body"] == body:
                return {"status": 200, "receipt": known["leaf"], "replaced": False}
            if set(outcome.nullifiers) != known["set"]:
                raise BallotError("B7", "conflict", "different nullifier set", "nullifiers")
            if now >= self.closes:
                raise BallotError("B7", "closed", "different body at or after closes")
            self.check_b3(outcome, replacing=True)
            _, leaf = receipt_leaf(0, ballot[NONCE], ballot[PAYLOAD])
            self.accepted[primary] = {
                "body": body,
                "payload": ballot[PAYLOAD],
                "leaf": leaf,
                "set": set(outcome.nullifiers),
            }
            return {"status": 200, "receipt": leaf, "replaced": True, "deleted": known["leaf"]}
        if now >= self.closes:
            raise BallotError("B7", "closed", "round 0 is closed")
        self.check_b3(outcome)
        _, leaf = receipt_leaf(0, ballot[NONCE], ballot[PAYLOAD])
        self.accepted[primary] = {
            "body": body,
            "payload": ballot[PAYLOAD],
            "leaf": leaf,
            "set": set(outcome.nullifiers),
        }
        self.seen.update(outcome.nullifiers)
        return {"status": 200, "receipt": leaf, "replaced": False}

    def later_round(self, ballot: dict[int, Any], outcome: Outcome) -> dict[str, Any]:
        primary = outcome.primary
        if primary not in self.accepted:
            raise BallotError("B8", "forbidden", "primary nullifier never voted in round 0")
        key = (ballot[ROUND], primary)
        body = body_bytes(ballot)
        known = self.later.get(key)
        if known is not None:
            if known["body"] == body:
                return {"status": 200, "receipt": known["leaf"]}
            raise BallotError(
                "B8", "conflict", "different body under a known nullifier", "duplicate"
            )
        _, leaf = receipt_leaf(ballot[ROUND], ballot[NONCE], ballot[PAYLOAD])
        self.later[key] = {"body": body, "leaf": leaf}
        return {"status": 200, "receipt": leaf}

    def counted_leaves(self) -> list[bytes]:
        return [v["leaf"] for v in self.accepted.values()]


# ---------------------------------------------------------------- client side


def counted_hand(cast_order: list[int], current_votes: dict[int, int], cap: int) -> dict[int, int]:
    """The first K cards cast, with their current votes."""
    return {i: current_votes[i] for i in cast_order[:cap]}


def votes_bytes(counted: dict[int, int], cards: int) -> bytes:
    return bytes(counted.get(i, 0) for i in range(cards))


def movement_selection(revote_order: list[int], cap_movement: int) -> list[int]:
    """The first K_m re-voted cards in the order they were re-voted."""
    return revote_order[:cap_movement]


def _draws(prefix: bytes, seed: bytes):
    counter = 0
    while True:
        h = hashlib.sha256(prefix + seed + counter.to_bytes(4, "big")).digest()
        counter += 1
        yield int.from_bytes(h[:8], "big")


def ratings_selection(seed: bytes, arguments: int, cap_ratings: int) -> list[int]:
    """A uniform random K_r of the A argument indexes (all when A ≤ K_r), ascending.

    Reference expansion of the seed (see the module docstring): Fisher–Yates with draws
    reduced by rejection sampling, then sorted.
    """
    if arguments <= cap_ratings:
        return list(range(arguments))
    pool = list(range(arguments))
    draws = _draws(b"hum/ratings-selection/1", seed)
    chosen = []
    for _ in range(cap_ratings):
        n = len(pool)
        limit = (1 << 64) - ((1 << 64) % n)
        d = next(draws)
        while d >= limit:
            d = next(draws)
        chosen.append(pool.pop(d % n))
    return sorted(chosen)


def send_schedule(
    edits: list[int], first_leave: int, closes: int, seed: bytes
) -> list[dict[str, Any]]:
    """Send times from hand edits (timestamps), the first leave of the deck, and ``closes``.

    First send at ``first_leave``. After that, a replacement only if the hand changed, at most
    once per interval drawn uniformly from 2 to 6 hours (reference expansion of the seed),
    plus one final replacement at a random time in the last 2 to 6 hours before ``closes``
    when the hand changed since the last send.
    """
    draws = _draws(b"hum/send-schedule/1", seed)

    def interval() -> int:
        return 7200 + next(draws) % (14400 + 1)

    sends = [{"at": first_leave, "kind": "first"}]
    last_sent = first_leave
    next_allowed = first_leave + interval()
    pending_edit = False
    for t in sorted(edits):
        if t <= first_leave:
            continue
        if t >= closes:
            break
        pending_edit = True
        if t >= next_allowed:
            sends.append({"at": t, "kind": "replacement"})
            last_sent = t
            next_allowed = t + interval()
            pending_edit = False
    if pending_edit:
        final_at = closes - interval()
        if final_at > last_sent:
            sends.append({"at": final_at, "kind": "final"})
    return sends
