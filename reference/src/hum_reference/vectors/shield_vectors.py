"""Vectors for docs/specs/shield.md: the arithmetic rules S1, S2, S8, S9 and the refusals the
ledger's state machine makes (S4 to S7, S9). The behavioral halves of S3 to S7 and S10 to S12
are simulator checks and are listed as such."""

from __future__ import annotations

from fractions import Fraction

from .. import shield as sh
from ..release import DELTA, eps_to_rho, rho_to_eps
from . import File, hexify

SPEC = "shield"
DAY = 86_400
NOW = 1_791_259_200
Q = Fraction(127, 500)


def frac(x: Fraction) -> list[int]:
    return [x.numerator, x.denominator]


def cid(label: str) -> bytes:
    import hashlib

    return b"\x01" + hashlib.sha256(f"shield-vectors/{label}".encode()).digest()


def entry_view(e: sh.Entry) -> dict:
    return e.view()


def run_events(name: str, events: list[dict], now: int = NOW) -> tuple[list[dict], sh.Ledger]:
    """Apply a sequence of events to a fresh ledger; a ShieldRule stops the sequence."""
    lg = sh.Ledger()
    after = []
    deck = cid("s-" + name)
    for ev in events:
        ev = {"deck": deck, "context": cid("c"), "rho": Q, **ev}
        try:
            out = lg.apply(ev, ev.get("now", now))
            refused = None
        except sh.ShieldRule as err:
            out = None
            refused = {"rule": err.rule, "reason": err.reason}
        e = lg.find(deck) or next((x for x in lg.entries if x.deck == deck), None)
        after.append(
            {
                "event": ev["event"],
                "outcome": out,
                "refused": refused,
                "state": e.state if e else None,
                "counts": bool(e and e.state in sh.COUNTING_STATES),
                "spent": frac(lg.spent(ev.get("now", now))),
            }
        )
        if refused is not None:
            break
    return after, lg


def generate() -> list[File]:
    f = File(
        SPEC,
        "shield",
        "Shield arithmetic: exact rationals until display; display is binary64 rho_to_eps "
        "rounded half to even to one decimal. The window is anchored per ADR 0102: an entry "
        "counts while now < anchor + 365 days, anchor = max(chargedAt, settledAt, or expires "
        "while unsettled); settledAt = max(phone clock, final version's issued) capped at "
        "expires. An unsettled entry leaves the window only after a successful lookup of the "
        "deck lineage's latest version (inputs.lookup: the expires it returned, or 'failed'). "
        "Rejecting cases are the ledger's refusals (check shield-fit or shield-ledger, rule "
        "S4..S9). The behavioral halves of S3 to S7 and S10 to S12 are simulator scenarios "
        "(sim-shield-*).",
    )
    # shield-eps-rho
    for eps in (1, 2, 4, 8, 16, 20):
        rho = eps_to_rho(eps, DELTA)
        f.add(
            "shield-eps-rho",
            f"eps_to_rho and rho_to_eps at ε {eps}",
            "The budget",
            {"eps": eps, "delta": DELTA},
            {"rho": rho, "eps_back": rho_to_eps(rho, DELTA)},
        )
    s1 = sh.check_s1()
    f.add(
        "shield-eps-rho",
        "S1: rho_to_eps(2201/500) ≤ 20 < rho_to_eps(4403/1000)",
        "Conformance",
        {"shield_rho": frac(sh.SHIELD_RHO), "above": frac(Fraction(4403, 1000))},
        s1,
    )
    above = rho_to_eps(float(Fraction(4403, 1000)), DELTA)
    assert above > 20
    f.add(
        "shield-eps-rho",
        "S1 fails for a shield of 4403/1000: its ε is above 20",
        "Conformance",
        {"shield_rho": frac(Fraction(4403, 1000)), "eps": above},
        rejection={"step": None, "check": "shield-s1", "rule": "S1", "reason": "eps above 20"},
    )
    # shield-compose-board
    board = sh.Ledger(
        [
            sh.Entry(cid("d1"), cid("c"), Q, NOW - 30 * DAY, sh.CHARGED),
            sh.Entry(cid("d2"), cid("c"), Fraction(169, 2500), NOW - 20 * DAY, sh.RELEASED),
            sh.Entry(cid("d3"), cid("c"), Q, NOW - 10 * DAY, sh.CHARGED),
            sh.Entry(cid("d4"), cid("c"), Q, NOW - DAY, sh.PENDING),
        ]
    )
    f.add(
        "shield-compose-board",
        "The P-Budget ledger: three settled entries and one pending",
        "The budget",
        {"entries": [entry_view(e) for e in board.entries], "now": NOW},
        {
            **board.board(NOW),
            "expected_display": {
                "eps": 6.2,
                "pending": 1.4,
                "headline_settled_pct": 69,
                "headline_pending_pct": 62,
            },
        },
    )
    four = sh.Ledger(
        [sh.Entry(cid(f"f{i}"), cid("c"), Q, NOW - i * DAY, sh.RELEASED) for i in range(4)]
    )
    f.add(
        "shield-compose-four-at-four",
        "Four entries at 127/500 display as ε 8.5",
        "Composition",
        {"entries": [entry_view(e) for e in four.entries], "now": NOW},
        four.board(NOW),
    )
    # shield-fit
    remaining = Fraction(1, 4)
    for plan in (Fraction(127, 500), Fraction(1, 4), Fraction(1, 20)):
        inputs = {"remaining": frac(remaining), "plan_rho": frac(plan)}
        if sh.fits(plan, remaining):
            f.add(
                "shield-fit",
                f"Plan {plan} against remaining 1/4 fits",
                "Reserving and charging",
                inputs,
                {"fits": True},
            )
        else:
            f.add(
                "shield-fit",
                f"Plan {plan} against remaining 1/4 does not fit: the deck is sat out",
                "Reserving and charging",
                inputs,
                rejection={
                    "step": None,
                    "check": "shield-fit",
                    "rule": "S4",
                    "reason": "plan.rho > remaining",
                },
            )
    lg = sh.Ledger(
        [sh.Entry(cid("spent"), cid("c"), sh.SHIELD_RHO - Fraction(1, 4), NOW - DAY, sh.CHARGED)]
    )
    first = lg.reserve(cid("p1"), cid("c"), Fraction(1, 5), NOW, [])
    assert first
    f.add(
        "shield-fit",
        "Two plans of 1/5 against remaining 1/4: the first fits and is reserved",
        "Reserving and charging",
        {"remaining_before": frac(Fraction(1, 4)), "plan_rho": frac(Fraction(1, 5))},
        {"reserved": True, "remaining_after": frac(lg.remaining(NOW))},
    )
    second = lg.reserve(cid("p2"), cid("c"), Fraction(1, 5), NOW, [])
    assert not second
    f.add(
        "shield-fit",
        "Two plans of 1/5 against remaining 1/4: the second does not fit after the reservation",
        "Reserving and charging",
        {
            "remaining_before": frac(lg.remaining(NOW)),
            "plan_rho": frac(Fraction(1, 5)),
            "ledger": [entry_view(e) for e in lg.entries],
        },
        rejection={
            "step": None,
            "check": "shield-fit",
            "rule": "S4",
            "reason": "second deck does not fit after the first reservation",
        },
    )
    over = sh.Ledger(
        [
            sh.Entry(
                cid(f"o{i}"), cid("c"), Q, NOW - 10 * DAY, sh.ESTIMATED, expires=NOW + 20 * DAY
            )
            for i in range(18)
        ]
    )
    f.add(
        "shield-fit",
        "A restored ledger whose estimated entries exceed SHIELD_RHO: remaining is zero and no plan fits",
        "Restore",
        {
            "ledger": [entry_view(e) for e in over.entries],
            "now": NOW,
            "plan_rho": frac(Fraction(1, 400)),
        },
        rejection={
            "step": None,
            "check": "shield-fit",
            "rule": "S4",
            "reason": "spent above SHIELD_RHO; remaining clamped at zero",
            "board": over.board(NOW),
        },
    )
    # shield-window: anchors at offsets
    offsets = [0, 100, 364, 365, 366, -3]
    entries = [
        sh.Entry(cid(f"w{d}"), cid("c"), Q, NOW - d * DAY, sh.RELEASED, settled_at=NOW - d * DAY)
        for d in offsets
    ]
    f.add(
        "shield-window",
        "Entries whose anchors are at days 0, 100, 364, 365, 366 before now and 3 days ahead",
        "The budget",
        {"anchor_offset_days": offsets, "now": NOW, "entries": [entry_view(e) for e in entries]},
        {
            "in_window": [sh.in_window(e, NOW) for e in entries],
            "spent": frac(sh.Ledger(entries).spent(NOW)),
        },
    )
    anchor_cases = [
        (
            "reserved 400 days ago, deck still open (expires 10 days ahead): in",
            sh.Entry(cid("a1"), cid("c"), Q, NOW - 400 * DAY, sh.CHARGED, expires=NOW + 10 * DAY),
            True,
        ),
        (
            "reserved 400 days ago, final version seen 30 days ago: in",
            sh.Entry(
                cid("a2"),
                cid("c"),
                Q,
                NOW - 400 * DAY,
                sh.RELEASED,
                settled_at=NOW - 30 * DAY,
                expires=NOW - 20 * DAY,
            ),
            True,
        ),
        (
            "final version seen 366 days ago: out",
            sh.Entry(
                cid("a3"),
                cid("c"),
                Q,
                NOW - 500 * DAY,
                sh.RELEASED,
                settled_at=NOW - 366 * DAY,
                expires=NOW - 360 * DAY,
            ),
            False,
        ),
        (
            "no final version, expires 366 days ago: out",
            sh.Entry(cid("a4"), cid("c"), Q, NOW - 500 * DAY, sh.CHARGED, expires=NOW - 366 * DAY),
            False,
        ),
        (
            "no final version, expires extended to 10 days ago by a later deck version: in",
            sh.Entry(cid("a5"), cid("c"), Q, NOW - 500 * DAY, sh.CHARGED, expires=NOW - 10 * DAY),
            True,
        ),
        (
            "final version first seen after expires: the anchor is expires (settledAt capped)",
            sh.Entry(
                cid("a6"),
                cid("c"),
                Q,
                NOW - 500 * DAY,
                sh.RELEASED,
                settled_at=NOW - 364 * DAY,
                expires=NOW - 364 * DAY,
            ),
            True,
        ),
        (
            "estimated entry anchored at expires 365 days ago: out",
            sh.Entry(
                cid("a7"), cid("c"), Q, NOW - 380 * DAY, sh.ESTIMATED, expires=NOW - 365 * DAY
            ),
            False,
        ),
    ]
    for desc, e, expect in anchor_cases:
        assert sh.in_window(e, NOW) == expect, desc
        f.add(
            "shield-window",
            desc,
            "The budget",
            {"entry": entry_view(e), "now": NOW},
            {"anchor": sh.anchor(e), "in_window": expect},
        )
    # before an unsettled entry leaves the window, the phone looks the deck lineage up

    def unsettled_v1():
        return sh.Entry(
            cid("lk"), cid("c"), Q, NOW - 390 * DAY, sh.CHARGED, expires=NOW - 365 * DAY
        )

    def unreachable(_deck):
        raise ConnectionError("relay unreachable")

    lookup_cases = [
        (
            "unsettled entry voted under deck version 1, 365 days past version 1's expires; the "
            "log holds a version 2 whose expires is 100 days ago: kept, expires updated",
            lambda _deck: NOW - 100 * DAY,
            NOW - 100 * DAY,
            True,
        ),
        (
            "the same entry with the log unreachable: kept, tried again later",
            unreachable,
            "failed",
            True,
        ),
        (
            "the same entry when the lookup confirms version 1 is the latest: out",
            lambda _deck: NOW - 365 * DAY,
            NOW - 365 * DAY,
            False,
        ),
    ]
    for desc, lookup, shown, expect in lookup_cases:
        e = unsettled_v1()
        lg = sh.Ledger([e])
        before = entry_view(e)
        assert not sh.in_window(e, NOW)
        got = lg.counts(e, NOW, lookup)
        assert got == expect, desc
        f.add(
            "shield-window",
            desc,
            "The budget",
            {"entry": before, "now": NOW, "lookup": shown},
            {
                "in_window_before_lookup": False,
                "counts": got,
                "expires_after": e.expires,
                "anchor_after": sh.anchor(e),
                "spent": frac(lg.spent(NOW, lookup)),
            },
        )
    # settledAt is never earlier than the final version's issued
    back = sh.Ledger()
    back.reserve(cid("back"), cid("c"), Q, NOW - 60 * DAY, [], expires=NOW - 20 * DAY)
    back.send(cid("back"))
    back.receipt(cid("back"), {"round": 0})
    issued = NOW - 30 * DAY
    back.final(cid("back"), issued - 200 * DAY, issued)
    bk = back.find(cid("back"))
    assert bk.settled_at == issued
    f.add(
        "shield-window",
        "final version verified while the phone's clock reads 200 days before that version's "
        "issued: settledAt is issued",
        "The budget",
        {"chargedAt": NOW - 60 * DAY, "expires": NOW - 20 * DAY, "issued": issued,
         "clock_at_verification": issued - 200 * DAY},
        {"settledAt": bk.settled_at, "anchor": sh.anchor(bk), "state": bk.state},
    )  # fmt: skip
    # a clock set back, before or after settling, frees nothing
    set_back = sh.Ledger(
        [
            sh.Entry(cid("sb1"), cid("c"), Q, NOW - 30 * DAY, sh.RELEASED, settled_at=NOW - DAY),
            sh.Entry(cid("sb2"), cid("c"), Q, NOW - 30 * DAY, sh.CHARGED, expires=NOW + 10 * DAY),
        ]
    )
    f.add(
        "shield-window",
        "a clock set back 400 days: the settled and the unsettled entry both still count",
        "The budget",
        {"entries": [entry_view(e) for e in set_back.entries], "now": NOW - 400 * DAY},
        {
            "in_window": [sh.in_window(e, NOW - 400 * DAY) for e in set_back.entries],
            "spent": frac(set_back.spent(NOW - 400 * DAY)),
            "spent_at_now": frac(set_back.spent(NOW)),
        },
    )
    # the extension moves the anchor, and a final version after expires is capped
    ext = sh.Ledger()
    ext.reserve(cid("ext"), cid("c"), Q, NOW - 500 * DAY, [], expires=NOW - 370 * DAY)
    ext.send(cid("ext"))
    before = sh.anchor(ext.find(cid("ext")))
    ext.extend(cid("ext"), NOW - 10 * DAY)
    after_ext = sh.anchor(ext.find(cid("ext")))
    ext.final(cid("ext"), NOW)  # seen after expires
    f.add(
        "shield-window",
        "An extension of closes moves an unsettled entry's anchor; a final version seen after expires settles at expires",
        "The budget",
        {
            "chargedAt": NOW - 500 * DAY,
            "expires_first": NOW - 370 * DAY,
            "expires_extended": NOW - 10 * DAY,
            "final_seen_at": NOW,
        },
        {
            "anchor_before": before,
            "anchor_after_extension": after_ext,
            "settledAt": ext.find(cid("ext")).settled_at,
            "anchor_final": sh.anchor(ext.find(cid("ext"))),
            "in_window": sh.in_window(ext.find(cid("ext")), NOW),
        },
    )
    # shield-long-decks
    day0 = NOW - 400 * DAY
    long = sh.Ledger()
    for i in range(17):
        assert long.reserve(cid(f"long{i}"), cid("c"), Q, day0, [], expires=day0 + 372 * DAY)
        long.send(cid(f"long{i}"))
        long.receipt(cid(f"long{i}"), {"round": 0})
    for i in range(17):
        long.final(cid(f"long{i}"), day0 + 366 * DAY, issued=day0 + 366 * DAY)
    for day in (365, 400):
        now = day0 + day * DAY
        rem = long.remaining(now)
        assert rem == sh.SHIELD_RHO - 17 * Q
        f.add(
            "shield-long-decks",
            f"Seventeen year-long decks reserved on day 0, closed day 360, released day 366: remaining on day {day}",
            "Conformance",
            {
                "entries": 17,
                "rho_each": frac(Q),
                "closes_day": 360,
                "released_day": 366,
                "expires_day": 372,
                "now_day": day,
            },
            {"remaining": frac(rem), "fits_eighteenth": sh.fits(Q, rem)},
        )
        f.add(
            "shield-long-decks",
            f"On day {day} an eighteenth deck at 127/500 does not fit",
            "Conformance",
            {"remaining": frac(rem), "plan_rho": frac(Q), "now_day": day},
            rejection={
                "step": None,
                "check": "shield-fit",
                "rule": "S8",
                "reason": "the seventeen entries are anchored at their releases, not their reservations",
            },
        )
    # a late Leader: a version 2 issued after expires is refused by the phone, so the entry
    # stays unsettled and anchored at expires (the simulator covers the Helper and the ledger)
    late = sh.Ledger()
    assert late.reserve(cid("late"), cid("c"), Q, day0, [], expires=day0 + 372 * DAY)
    late.send(cid("late"))
    late.receipt(cid("late"), {"round": 0})
    try:
        late.final(cid("late"), day0 + 373 * DAY, issued=day0 + 373 * DAY)
        raise AssertionError("late final accepted")
    except sh.ShieldRule as err:
        refused = {"rule": err.rule, "reason": err.reason}
    le = late.find(cid("late"))
    f.add(
        "shield-long-decks",
        "A late Leader issues a final version on day 373, after expires on day 372: the phone "
        "refuses it, the entry stays unsettled with its anchor at expires and counts on day 400",
        "Conformance",
        {"chargedAt_day": 0, "expires_day": 372, "final_issued_day": 373, "now_day": 400},
        rejection={
            "step": None,
            "check": "shield-ledger",
            **refused,
            "entry": entry_view(le),
            "in_window_day_400": sh.in_window(le, day0 + 400 * DAY),
            "in_window_day_738": sh.in_window(le, day0 + 738 * DAY),
        },
    )
    # shield-states
    seqs = {
        "leave-without-casting": [{"event": "open"}, {"event": "leave", "cast": False}],
        "lost-response-then-retry": [
            {"event": "open"},
            {"event": "cast"},
            {"event": "send"},
            {"event": "lost"},
            {"event": "receipt", "receipt": {"round": 0, "retry": True}},
        ],
        "rejected": [{"event": "open"}, {"event": "send"}, {"event": "rejected"}],
        "released": [
            {"event": "open", "expires": NOW + 30 * DAY},
            {"event": "send"},
            {"event": "receipt"},
            {"event": "final", "seenAt": NOW + 10 * DAY, "issued": NOW + 9 * DAY},
        ],
        "released-clock-behind-issued": [
            {"event": "open", "expires": NOW + 30 * DAY},
            {"event": "send"},
            {"event": "receipt"},
            {"event": "final", "seenAt": NOW + 5 * DAY, "issued": NOW + 9 * DAY},
        ],
        "abandoned": [
            {"event": "open"},
            {"event": "send"},
            {"event": "receipt"},
            {"event": "abandoned"},
        ],
        "restore-then-vote": [
            {"event": "estimate", "chargedAt": NOW - 5 * DAY, "expires": NOW + 5 * DAY},
            {"event": "open"},
            {"event": "send"},
        ],
        "extend-then-final-after-expires": [
            {"event": "open", "expires": NOW + 10 * DAY},
            {"event": "send"},
            {"event": "receipt"},
            {"event": "extend", "expires": NOW + 20 * DAY},
            {"event": "final", "seenAt": NOW + 25 * DAY},
        ],
        "later-rounds-add-nothing": [
            {"event": "open"},
            {"event": "send"},
            {"event": "receipt"},
            {"event": "replace"},
            {"event": "round"},
            {"event": "round"},
        ],
    }
    for name, events in seqs.items():
        after, _ = run_events(name, events)
        assert all(a["refused"] is None for a in after), name
        f.add(
            "shield-states",
            f"Event sequence {name}",
            "Reserving and charging",
            {"events": events, "rho": frac(Q)},
            {"after_each": after},
        )
    refusals = {
        "drop-after-send": ([{"event": "open"}, {"event": "send"}, {"event": "drop"}], "S7"),
        "refund-after-rejected": (
            [{"event": "open"}, {"event": "send"}, {"event": "rejected"}, {"event": "refund"}],
            "S6",
        ),
        "remove-estimated": (
            [{"event": "estimate", "chargedAt": NOW - DAY}, {"event": "remove"}],
            "S9",
        ),
        "second-entry-on-replacement": (
            [{"event": "open"}, {"event": "send"}, {"event": "estimate", "chargedAt": NOW}],
            "S5",
        ),
        "round-without-round0": ([{"event": "open"}, {"event": "round"}], "S5"),
        "drop-charged": (
            [{"event": "open"}, {"event": "send"}, {"event": "receipt"}, {"event": "drop"}],
            "S7",
        ),
        "final-issued-after-expires": (
            [
                {"event": "open", "expires": NOW + 10 * DAY},
                {"event": "send"},
                {"event": "receipt"},
                {"event": "final", "seenAt": NOW + 12 * DAY, "issued": NOW + 11 * DAY},
            ],
            "S8",
        ),
    }
    for name, (events, rule) in refusals.items():
        after, _ = run_events(name, events)
        last = after[-1]["refused"]
        assert last is not None and last["rule"] == rule, (name, after)
        f.add(
            "shield-states",
            f"Refused event sequence {name}",
            "Reserving and charging",
            {"events": events, "rho": frac(Q)},
            rejection={
                "step": None,
                "check": "shield-ledger",
                "rule": rule,
                "reason": last["reason"],
                "after_each": after,
            },
        )
    # shield-restore
    contexts = [
        {"lineage": cid("ctxA"), "left": None},
        {"lineage": cid("ctxB"), "left": NOW - 100 * DAY},
    ]
    decks = [
        {
            "name": "released",
            "deck": cid("r1"),
            "context": cid("ctxA"),
            "closes": NOW - 200 * DAY,
            "expires": NOW - 190 * DAY,
            "rho": Q,
        },
        {
            "name": "in-rounds",
            "deck": cid("r2"),
            "context": cid("ctxA"),
            "closes": NOW - 2 * DAY,
            "expires": NOW + 10 * DAY,
            "rho": Q,
        },
        {
            "name": "closed-unreleased",
            "deck": cid("r3"),
            "context": cid("ctxB"),
            "closes": NOW - 10 * DAY,
            "expires": NOW - 7 * DAY,
            "rho": Fraction(1, 20),
        },
        {
            "name": "abandoned",
            "deck": cid("r4"),
            "context": cid("ctxB"),
            "closes": NOW - 300 * DAY,
            "expires": NOW - 288 * DAY,
            "rho": Q,
        },
        {
            "name": "open",
            "deck": cid("r5"),
            "context": cid("ctxA"),
            "closes": NOW + 5 * DAY,
            "expires": NOW + 17 * DAY,
            "rho": Q,
        },
        {
            "name": "extended",
            "deck": cid("r6"),
            "context": cid("ctxA"),
            "closes": NOW - 364 * DAY,
            "expires": NOW - 350 * DAY,
            "rho": Q,
        },
        {
            "name": "too-old",
            "deck": cid("r7"),
            "context": cid("ctxA"),
            "closes": NOW - 380 * DAY,
            "expires": NOW - 366 * DAY,
            "rho": Q,
        },
        {
            "name": "exactly-365",
            "deck": cid("r8"),
            "context": cid("ctxA"),
            "closes": NOW - 370 * DAY,
            "expires": NOW - 365 * DAY,
            "rho": Q,
        },
    ]
    est = sh.restore_estimate(
        contexts, [{k: v for k, v in d.items() if k != "name"} for d in decks], NOW
    )
    f.add(
        "shield-restore",
        "Estimated entries after a restore: every deck of every backed-up context whose latest expires is within the window; chargedAt = closes, anchor = expires, no settledAt",
        "Restore",
        {
            "contexts": [{"lineage": hexify(c["lineage"]), "left": c["left"]} for c in contexts],
            "decks": [
                {
                    **{k: v for k, v in d.items() if k not in ("deck", "context", "rho")},
                    "deck": hexify(d["deck"]),
                    "context": hexify(d["context"]),
                    "rho": frac(d["rho"]),
                }
                for d in decks
            ],
            "now": NOW,
        },
        {"estimated": [entry_view(e) for e in est], "spent": frac(sh.Ledger(est).spent(NOW))},
    )
    # shield-display
    for rho in (Q, Fraction(576, 1000), Fraction(1016, 1000), Fraction(0), sh.SHIELD_RHO):
        f.add(
            "shield-display",
            f"Display of ρ {rho}",
            "The budget",
            {"rho": frac(rho)},
            {"eps_binary64": rho_to_eps(float(rho), DELTA), "displayed": sh.display_eps(rho)},
        )
    for value in (6.25, 6.35, 8.45):
        f.add(
            "shield-display",
            f"round half to even at {value}",
            "The budget",
            {"eps": value},
            {"displayed": round(value, 1)},
        )
    return [f]
