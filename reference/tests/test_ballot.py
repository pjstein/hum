import hashlib

import pytest

from hum_reference import ballot as bl
from hum_reference import cbor


def h(label: str, n: int = 32) -> bytes:
    return (b"\x01" + hashlib.sha256(label.encode()).digest())[-n:]


def test_frame_round_trip_and_b1():
    deck = h("deck", 33)
    b = bl.ballot_map(deck, 0, h("nonce"), bl.round0_payload(bytes([1, 2, 3])), b"p")
    fr = bl.frame(cbor.encode(b))
    assert len(fr) == bl.BALLOT_BYTES
    assert bl.unframe(fr, round_=0, deck_versions={deck}) == b
    with pytest.raises(bl.BallotError):
        bl.unframe(fr[:-1])
    with pytest.raises(bl.BallotError):
        bl.unframe(fr, round_=1)
    with pytest.raises(bl.BallotError):
        bl.unframe(fr, deck_versions={h("other", 33)})
    assert bl.bound_message(b) == b"hum/ballot-bound/1" + hashlib.sha256(bl.body_bytes(b)).digest()
    assert bl.scope(deck) == b"hum/ballot/1" + deck


def test_vectors_and_weights():
    votes = bytes([1, 2, 3, 0])
    t = bl.tallies_vector(votes, 4)
    assert (
        len(t) == 13 and bl.weight(t) == 4 and t[0] == 1 and t[4] == 1 and t[8] == 1 and t[12] == 1
    )
    idx = bl.argument_indexes({"card/0/pro": b"", "card/0/con": b"", "card/1/pro": b""})
    assert idx == {(0, "con"): 0, (0, "pro"): 1, (1, "pro"): 2}
    mv = bl.movement_vector_with_args({0: [2, 1, 1], 1: [3, 3, 0]}, 4, idx)
    assert len(mv) == 39 and bl.weight(mv) == 3
    r = bl.ratings_vector({0: 2, 2: 0}, 3)
    assert r == [0, 0, 1, 0, 0, 0, 1, 0, 0]
    g = bl.groups_vector(1, 2, votes, 4, {0: 1}, 3)
    assert len(g) == 2 * (13 + 9) and bl.weight(g) == 5 and g[22] == 1


def test_round0_checks():
    d = bl.DeckParams(
        cards=4, cap=3, cap_movement=2, cap_ratings=2, arg_index={(0, "pro"): 0, (1, "con"): 1}
    )
    good = bl.round0_payload(bytes([1, 2, 0, 0]), {0: [1, 1, 1]}, {1: 2})
    out = bl.check_round0(good, d)
    assert bl.weight(out["tallies"]) == 3 and bl.weight(out["movement"]) == 2
    for bad, rule in (
        (bl.round0_payload(bytes([1, 2, 3, 1]), {}, {}), "B4"),
        (bl.round0_payload(bytes([1, 2, 0, 0]), {0: [1, 1, 2]}, {}), "B5"),
        (bl.round0_payload(bytes([1, 2, 0, 0]), {0: [1, 2, 0]}, {}), "B5"),
        (bl.round0_payload(bytes([1, 2, 0, 0]), {}, {5: 0}), "B6"),
    ):
        with pytest.raises(bl.BallotError) as e:
            bl.check_round0(bad, d)
        assert e.value.rule == rule


def test_intake_replacement_and_later_rounds():
    deck = h("deck", 33)
    closes = 1000
    o = bl.Outcome(
        [h("n1")], h("n1"), [{"class": "person", "issuer": h("i", 33), "satisfies": True}]
    )
    it = bl.Intake(closes)
    b1 = bl.ballot_map(deck, 0, h("a"), bl.round0_payload(bytes([1])), b"")
    b2 = bl.ballot_map(deck, 0, h("a"), bl.round0_payload(bytes([2])), b"")
    r = it.round0(b1, o, 10)
    assert it.round0(b1, o, 2000)["receipt"] == r["receipt"]
    r2 = it.round0(b2, o, 20)
    assert r2["replaced"] and it.counted_leaves() == [r2["receipt"]]
    with pytest.raises(bl.BallotError) as e:
        it.round0(b1, o, 1000)
    assert e.value.rule == "B7" and e.value.error == "closed"
    pooled = bl.Outcome([h("n9"), h("n1")], h("n9"), o.cards * 2)
    with pytest.raises(bl.BallotError) as e:
        it.round0(b1, pooled, 20)
    assert e.value.rule == "B3" and e.value.error == "conflict"
    later = bl.ballot_map(deck, 2, h("c"), {0: 5}, b"")
    with pytest.raises(bl.BallotError):
        it.later_round(later, bl.Outcome([h("nx")], h("nx"), o.cards))
    rr = it.later_round(later, o)
    assert it.later_round(later, o)["receipt"] == rr["receipt"]


def test_receipt_leaf_task_and_selection_determinism():
    payload = bl.round0_payload(bytes([1, 2]))
    c, leaf = bl.receipt_leaf(0, h("n"), payload)
    assert c == hashlib.sha256(cbor.encode(payload)).digest()
    assert leaf == hashlib.sha256(b"hum/receipt-leaf/1" + b"\x00" + h("n") + c).digest()
    lin = h("lin", 33)
    assert bl.task_id(lin, 1, 2) == hashlib.sha256(b"hum/dap-task/1" + lin + b"\x01\x02").digest()
    sel = bl.ratings_selection(h("s"), 25, 10)
    assert (
        sel == bl.ratings_selection(h("s"), 25, 10) and len(set(sel)) == 10 and sel == sorted(sel)
    )
    assert bl.ratings_selection(h("s"), 5, 10) == [0, 1, 2, 3, 4]
    sched = bl.send_schedule([100_000, 200_000], 50_000, 300_000, h("x"))
    assert sched[0] == {"at": 50_000, "kind": "first"} and sched == bl.send_schedule(
        [100_000, 200_000], 50_000, 300_000, h("x")
    )
