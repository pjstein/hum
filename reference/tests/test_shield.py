from fractions import Fraction

import pytest

from hum_reference import shield as sh

DAY = 86_400
NOW = 1_791_259_200
Q = Fraction(127, 500)


def cid(label: str) -> bytes:
    return b"\x01" + label.encode().ljust(32, b"\x00")


def test_s1_and_display():
    assert sh.check_s1()["holds"]
    assert sh.display_eps(Fraction(576, 1000)) == 6.2
    assert sh.display_eps(4 * Q) == 8.5
    lg = sh.Ledger(
        [
            sh.Entry(cid("a"), cid("c"), Q, NOW, sh.CHARGED),
            sh.Entry(cid("b"), cid("c"), Fraction(169, 2500), NOW, sh.RELEASED),
            sh.Entry(cid("d"), cid("c"), Q, NOW, sh.CHARGED),
            sh.Entry(cid("e"), cid("c"), Q, NOW, sh.PENDING),
        ]
    )
    board = lg.board(NOW)
    assert board["settled_eps"] == 6.2 and board["displayed_eps"] == 7.6
    assert round(board["headline_settled"] * 100) == 69
    assert round(board["headline_including_pending"] * 100) == 62


def test_window_anchor():
    # anchored at settledAt
    e = sh.Entry(cid("s"), cid("c"), Q, NOW - 400 * DAY, sh.RELEASED, settled_at=NOW - 30 * DAY)
    assert sh.anchor(e) == NOW - 30 * DAY and sh.in_window(e, NOW)
    e.settled_at = NOW - 365 * DAY
    assert not sh.in_window(e, NOW)
    # unsettled: anchored at expires, moved by an extension
    u = sh.Entry(cid("u"), cid("c"), Q, NOW - 500 * DAY, sh.CHARGED, expires=NOW - 366 * DAY)
    assert not sh.in_window(u, NOW)
    lg = sh.Ledger([u])
    lg.extend(cid("u"), NOW - 10 * DAY)
    assert sh.in_window(u, NOW)
    # final seen after expires is capped at expires
    lg.final(cid("u"), NOW)
    assert u.settled_at == NOW - 10 * DAY and u.state == sh.RELEASED
    # a future anchor counts (clock set back frees nothing)
    fut = sh.Entry(cid("f"), cid("c"), Q, NOW + 3 * DAY, sh.CHARGED)
    assert sh.in_window(fut, NOW)


def test_fit_and_long_decks():
    lg = sh.Ledger([sh.Entry(cid("x"), cid("c"), sh.SHIELD_RHO - Fraction(1, 4), NOW, sh.CHARGED)])
    assert lg.reserve(cid("p1"), cid("c"), Fraction(1, 5), NOW, [])
    assert not lg.reserve(cid("p2"), cid("c"), Fraction(1, 5), NOW, [])
    assert lg.reserve(cid("p3"), cid("c"), Fraction(1, 20), NOW, [])  # equality fits
    day0 = NOW - 400 * DAY
    long = sh.Ledger()
    for i in range(17):
        assert long.reserve(cid(f"l{i}"), cid("c"), Q, day0, [], expires=day0 + 372 * DAY)
        long.send(cid(f"l{i}"))
        long.final(cid(f"l{i}"), day0 + 366 * DAY, issued=day0 + 366 * DAY)
    for day in (365, 400):
        assert long.remaining(day0 + day * DAY) == sh.SHIELD_RHO - 17 * Q
    assert long.remaining(day0 + 740 * DAY) == sh.SHIELD_RHO


def test_settled_at_and_lookup():
    # settledAt = max(clock, issued) capped at expires
    assert sh.settled_at(100, 300, 500) == 300
    assert sh.settled_at(400, 300, 500) == 400
    assert sh.settled_at(900, 300, 500) == 500
    assert sh.settled_at(100, None, None) == 100
    lg = sh.Ledger()
    lg.reserve(cid("b"), cid("c"), Q, NOW - 60 * DAY, [], expires=NOW - 20 * DAY)
    lg.send(cid("b"))
    lg.final(cid("b"), NOW - 230 * DAY, issued=NOW - 30 * DAY)
    assert lg.find(cid("b")).settled_at == NOW - 30 * DAY
    # a final version issued after expires is refused by the phone
    lg.reserve(cid("late"), cid("c"), Q, NOW - 60 * DAY, [], expires=NOW - 20 * DAY)
    lg.send(cid("late"))
    with pytest.raises(sh.ShieldRule) as e:
        lg.final(cid("late"), NOW, issued=NOW - 19 * DAY)
    assert e.value.rule == "S8" and lg.find(cid("late")).settled_at is None
    # an unsettled entry leaves the window only after a successful lookup
    u = sh.Entry(cid("u"), cid("c"), Q, NOW - 390 * DAY, sh.CHARGED, expires=NOW - 365 * DAY)
    lg = sh.Ledger([u])
    assert lg.spent(NOW) == 0  # the arithmetic rule alone
    assert lg.spent(NOW, lambda _d: (_ for _ in ()).throw(ConnectionError())) == Q
    assert lg.spent(NOW, lambda _d: NOW - 365 * DAY) == 0
    assert lg.spent(NOW, lambda _d: NOW - 100 * DAY) == Q and u.expires == NOW - 100 * DAY
    assert lg.spent(NOW, lambda _d: NOW - 365 * DAY) == Q  # expires never moves back
    # a settled entry needs no lookup
    s = sh.Entry(cid("s"), cid("c"), Q, NOW - 400 * DAY, sh.RELEASED, settled_at=NOW - 366 * DAY)
    assert sh.Ledger([s]).spent(NOW, lambda _d: NOW) == 0


def test_state_machine_no_refund():
    lg = sh.Ledger()
    d = cid("d")
    assert lg.apply({"event": "open", "deck": d, "context": cid("c"), "rho": Q}, NOW)["reserved"]
    assert lg.apply({"event": "leave", "deck": d, "cast": False}, NOW)["dropped"]
    assert lg.spent(NOW) == 0
    assert lg.apply({"event": "open", "deck": d, "context": cid("c"), "rho": Q}, NOW)["reserved"]
    lg.apply({"event": "send", "deck": d}, NOW)
    assert lg.apply({"event": "rejected", "deck": d}, NOW)["refund"] is False
    assert lg.spent(NOW) == Q
    with pytest.raises(sh.ShieldRule) as err:
        lg.apply({"event": "drop", "deck": d}, NOW)
    assert err.value.rule == "S7"
    with pytest.raises(sh.ShieldRule) as err:
        lg.apply({"event": "refund", "deck": d}, NOW)
    assert err.value.rule == "S6"
    lg.apply({"event": "receipt", "deck": d}, NOW)
    assert lg.apply({"event": "replace", "deck": d}, NOW)["added"] is False
    lg.apply({"event": "final", "deck": d, "seenAt": NOW + DAY, "issued": NOW + 2 * DAY}, NOW)
    assert lg.find(d).state == sh.RELEASED and lg.find(d).settled_at == NOW + 2 * DAY
    lg.apply(
        {"event": "estimate", "deck": cid("e"), "context": cid("c"), "rho": Q, "chargedAt": NOW},
        NOW,
    )
    with pytest.raises(sh.ShieldRule) as err:
        lg.apply({"event": "remove", "deck": cid("e")}, NOW)
    assert err.value.rule == "S9"
    lg.apply({"event": "open", "deck": cid("e"), "context": cid("c"), "rho": Q}, NOW)
    lg.apply({"event": "send", "deck": cid("e")}, NOW)
    assert lg.find(cid("e")).state == sh.PENDING and lg.spent(NOW) == 2 * Q
    assert len(lg.entries) == 3  # the dropped one, d and e


def test_restore():
    ctxs = [{"lineage": cid("A"), "left": None}, {"lineage": cid("B"), "left": NOW - 400 * DAY}]
    decks = [
        {
            "deck": cid("1"),
            "context": cid("A"),
            "closes": NOW - DAY,
            "expires": NOW + DAY,
            "rho": Q,
        },
        {
            "deck": cid("2"),
            "context": cid("A"),
            "closes": NOW - 380 * DAY,
            "expires": NOW - 366 * DAY,
            "rho": Q,
        },
        {"deck": cid("3"), "context": cid("B"), "closes": NOW - 5 * DAY, "expires": NOW, "rho": Q},
    ]
    est = sh.restore_estimate(ctxs, decks, NOW)
    assert [e.deck for e in est] == [cid("1"), cid("3")]
    assert est[0].charged_at == NOW - DAY and est[0].expires == NOW + DAY
    assert est[0].settled_at is None and sh.anchor(est[0]) == NOW + DAY


def test_vectors_deterministic():
    from hum_reference.vectors import shield_vectors

    a = shield_vectors.generate()[0].cases
    b = shield_vectors.generate()[0].cases
    assert a == b
    assert sum(1 for c in a if "rejection" in c) >= 10
