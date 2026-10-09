"""Vectors for docs/specs/ballot.md. Decks come from the deck world (`deck_vectors.get_world`):
`valid-full` (18 cards, cap 18, covStatements 18) and `valid-ibis` (K_m 10, K_r 10, A = 10).
Presentations are pending credentials.md: B2 and B3 cases that need a real proof are listed
as pending; B3's set logic runs over a decoded outcome. DAP reports (B11) are pending Prio3.

The rating-deck ballot uses `deck.plan_rating()` with a synthetic deck CID rather than the
take world's logged rating deck, to keep this generator independent of that world's build.
"""

from __future__ import annotations

import hashlib
import math

from .. import ballot as bl
from .. import cbor, fixtures, services
from .. import manifest as m
from .. import release as rmath
from ..bodies import deck as dk
from ..bodies import release as rb
from ..services import receipt_pages
from . import File, hexify
from .deck_vectors import CLOSES, get_world

SPEC = "ballot"


def h(label: str, n: int = 32) -> bytes:
    """Fixed bytes: the last ``n`` of ``0x01 ‖ SHA-256(label)`` (33 bytes make a CID)."""
    return (b"\x01" + hashlib.sha256(f"ballot-vectors/{label}".encode()).digest())[-n:]


def params_for(env: dict, rating: bool = False, groups_k: int | None = None) -> bl.DeckParams:
    body = env[m.BODY]
    plan_ = body[dk.PLAN]
    cards = len(body[dk.CARDS])
    rp = dk.to_release_plan(plan_, cards)
    m_ = rp.cov_m(cards)
    delta_cov = rp.cov_scale + math.ceil(math.sqrt(m_ * (m_ + 1) / 2) / 2)
    return bl.DeckParams(
        cards=cards,
        cap=rp.cap,
        cap_movement=rp.cap_movement,
        cap_ratings=rp.cap_ratings,
        arg_index=bl.argument_indexes(env[m.REFS]),
        rating=rating,
        groups_k=groups_k,
        cov_m=m_,
        cov_scale=rp.cov_scale,
        delta_cov=delta_cov,
        grid=rp.grid,
        closes=body[dk.CLOSES],
    )


def outcome(label: str, n: int = 1, cls: str = "person", satisfies: bool = True) -> bl.Outcome:
    nulls = [h(f"null/{label}/{i}") for i in range(n)]
    return bl.Outcome(
        nulls,
        nulls[0] if nulls else None,
        [{"class": cls, "issuer": h(f"issuer/{i}", 33), "satisfies": satisfies} for i in range(n)],
    )


def outcome_json(o: bl.Outcome) -> dict:
    return {
        "nullifiers": [hexify(x) for x in o.nullifiers],
        "primary": hexify(o.primary) if o.primary else None,
        "cards": [{**c, "issuer": hexify(c["issuer"])} for c in o.cards],
    }


def ballot_json(ballot: dict) -> dict:
    return {
        "deck": hexify(ballot[bl.DECK]),
        "round": ballot[bl.ROUND],
        "nonce": hexify(ballot[bl.NONCE]),
        "payload": _payload_json(ballot[bl.PAYLOAD]),
        "presentation": hexify(ballot[bl.PRESENTATION]),
        "canonical": hexify(cbor.encode(ballot)),
        "body": hexify(bl.body_bytes(ballot)),
        "bound_message": hexify(bl.bound_message(ballot)),
    }


def _payload_json(p: dict) -> dict:
    out = {}
    for k, v in p.items():
        out[str(k)] = (
            hexify(v)
            if isinstance(v, bytes)
            else ({str(a): b for a, b in v.items()} if isinstance(v, dict) else v)
        )
    return out


def reject(f: File, suffix: str, desc: str, inputs: dict, fn, rule: str, error: str):
    try:
        fn()
        raise AssertionError(f"{suffix}: expected {rule}")
    except bl.BallotError as e:
        assert e.rule == rule and e.error == error, (suffix, e.rule, e.error)
        rej = {
            "step": None,
            "check": "ballot-intake",
            "rule": e.rule,
            "error": e.error,
            "reason": e.reason,
        }
        if e.detail:
            rej["detail"] = e.detail
        f.add(suffix, desc, "Validation rules", inputs, rejection=rej)


def generate() -> list[File]:
    wd = get_world()
    full = wd.decks["valid-full"]
    full_env = cbor.decode(full.envelope)
    ibis = wd.decks["valid-ibis"]
    ibis_env = cbor.decode(ibis.envelope)
    dp = params_for(full_env)
    ip = params_for(ibis_env)
    lineage_full = full.cid  # version 1 is its own lineage
    pres = b"\x00" * 600  # a placeholder presentation (credentials.md pending)
    files = []

    # ---------------- round 0
    f = File(
        SPEC,
        "round0",
        "Round-0 ballots on the deck world's valid-full (18 cards, cap 18) and valid-ibis decks. "
        "Presentations are placeholders: credentials.md's presentation vectors are pending.",
    )
    hand = {i: (1 if i < 10 else 2 if i < 15 else 3) for i in range(18)}
    votes = bl.votes_bytes(hand, 18)
    payload = bl.round0_payload(votes)
    b0 = bl.ballot_map(full.cid, 0, h("nonce/full"), payload, pres)
    vec = bl.check_round0(payload, dp)
    commitment, leaf = bl.receipt_leaf(0, b0[bl.NONCE], payload)
    f.add(
        "ballot-round0-full",
        "Spring priorities: 10 agree, 5 disagree, 3 unsure; the part-0 vector of weight 19",
        "Round 0: the vote",
        {
            "deck": hexify(full.cid),
            "deck_lineage": hexify(lineage_full),
            "cards": 18,
            "cap": 18,
            "hand": {str(k): v for k, v in hand.items()},
        },
        {
            **ballot_json(b0),
            "scope": hexify(bl.scope(lineage_full)),
            "framed_sha256": hashlib.sha256(bl.frame(cbor.encode(b0))).hexdigest(),
            "framed_length": bl.BALLOT_BYTES,
            "tallies_vector": vec["tallies"],
            "weight": bl.weight(vec["tallies"]),
            "commitment": hexify(commitment),
            "leaf": hexify(leaf),
        },
    )
    # frame edges
    for name, size in (
        ("no-padding", bl.BALLOT_BYTES - 4),
        ("one-zero", bl.BALLOT_BYTES - 5),
        ("small", 300),
    ):
        raw = (
            b"\x5a" + (size - 5).to_bytes(4, "big") + bytes(size - 5)
        )  # a bstr of the right total length
        assert len(raw) == size
        fr = bl.frame(raw)
        f.add(
            "ballot-frame-edges",
            f"Frame for a {size}-byte ballot ({name})",
            "The ballot",
            {"ballot_length": size, "ballot_sha256": hashlib.sha256(raw).hexdigest()},
            {
                "framed_length": len(fr),
                "prefix": hexify(fr[:4]),
                "framed_sha256": hashlib.sha256(fr).hexdigest(),
            },
        )
    # capped: 100 cards, cap 60, 80 cast
    cast = [(i * 37) % 100 for i in range(100)][:80]
    cur = {i: 1 + (i % 3) for i in cast}
    counted = bl.counted_hand(cast, cur, 60)
    cv = bl.votes_bytes(counted, 100)
    cp = bl.DeckParams(cards=100, cap=60)
    cvec = bl.check_round0(bl.round0_payload(cv), cp)["tallies"]
    f.add(
        "ballot-round0-capped",
        "100-card deck, cap 60, 80 cast: the counted hand is the first 60 cast; weight 61",
        "The counted hand",
        {
            "cards": 100,
            "cap": 60,
            "cast_order": cast,
            "current_votes": {str(k): v for k, v in cur.items()},
        },
        {
            "counted": {str(k): v for k, v in counted.items()},
            "votes": hexify(cv),
            "weight": bl.weight(cvec),
        },
    )
    # ibis
    ihand = {i: 1 + (i % 3) for i in range(18)}
    ivotes = bl.votes_bytes(ihand, 18)
    movement = {0: [2, 1, 2], 1: [2, 2, 0], 3: [1, 1, 1], 5: [3, 3, 0], 7: [1, 2, 1]}
    ratings = {0: 0, 1: 1, 2: 2, 5: 0, 9: 1}
    ip_payload = bl.round0_payload(ivotes, movement, ratings)
    ivec = bl.check_round0(ip_payload, ip)
    bi = bl.ballot_map(ibis.cid, 0, h("nonce/ibis"), ip_payload, pres)
    f.add(
        "ballot-round0-ibis",
        "Parts 5 and 6 with K_m 10, K_r 10: a same-way re-vote on the diagonal and a moved on the con",
        "Round 0: the vote",
        {
            "deck": hexify(ibis.cid),
            "cards": 18,
            "arguments": ip.arguments,
            "argument_index": {
                f"card/{i}/{s}": idx
                for (i, s), idx in sorted(ip.arg_index.items(), key=lambda kv: kv[1])
            },
            "hand": {str(k): v for k, v in ihand.items()},
            "movement": {str(k): v for k, v in movement.items()},
            "ratings": {str(k): v for k, v in ratings.items()},
        },
        {
            **ballot_json(bi),
            "tallies_weight": bl.weight(ivec["tallies"]),
            "movement_vector": ivec["movement"],
            "movement_weight": bl.weight(ivec["movement"]),
            "movement_bound": 2 * ip.cap_movement,
            "ratings_vector": ivec["ratings"],
            "ratings_weight": bl.weight(ivec["ratings"]),
        },
    )
    # rating deck
    rplan = dk.plan_rating()
    rp = bl.DeckParams(cards=12, cap=rplan[dk.P_CAP], rating=True, groups_k=2)
    rvotes = bytes([1, 2, 1, 3, 1, 1, 2, 0, 0, 1, 2, 3])
    rpayload = bl.round0_payload(rvotes, group=1)
    rvec = bl.check_round0(rpayload, rp)
    f.add(
        "ballot-round0-rating",
        "A rating deck ballot (12 take cards, cap 20, groupsK 2) with group 1; the part-3 vector",
        "Round 0: the vote",
        {
            "deck": hexify(h("rating-deck", 33)),
            "cards": 12,
            "cap": rplan[dk.P_CAP],
            "groupsK": 2,
            "votes": hexify(rvotes),
            "group": 1,
        },
        {"groups_vector": rvec["groups"], "weight": bl.weight(rvec["groups"]), "slot": 3 * 12 + 1},
    )
    # replacement / identical / rejected-keeps-nullifier
    intake = bl.Intake(CLOSES)
    o1 = outcome("p1")
    r1 = intake.round0(b0, o1, CLOSES - 100)
    hand2 = dict(hand)
    hand2[0] = 2
    b0b = bl.ballot_map(
        full.cid, 0, h("nonce/full"), bl.round0_payload(bl.votes_bytes(hand2, 18)), pres
    )
    r2 = intake.round0(b0b, o1, CLOSES - 50)
    f.add(
        "ballot-round0-replace",
        "Two ballots under one primary nullifier with different hands: the second counted, the first deleted",
        "Replacement in round 0",
        {
            "first": ballot_json(b0),
            "second": ballot_json(b0b),
            "outcome": outcome_json(o1),
            "times": [CLOSES - 100, CLOSES - 50],
            "closes": CLOSES,
        },
        {
            "first": {k: (hexify(v) if isinstance(v, bytes) else v) for k, v in r1.items()},
            "second": {k: (hexify(v) if isinstance(v, bytes) else v) for k, v in r2.items()},
            "counted_leaves": [hexify(x) for x in intake.counted_leaves()],
        },
    )
    intake2 = bl.Intake(CLOSES)
    a = intake2.round0(b0, o1, CLOSES - 100)
    b0_pres2 = bl.ballot_map(full.cid, 0, h("nonce/full"), payload, b"\x01" * 600)
    b = intake2.round0(b0_pres2, o1, CLOSES - 10)
    c = intake2.round0(b0_pres2, o1, CLOSES + 3600)
    f.add(
        "ballot-round0-identical",
        "The same body twice with two presentations: one receipt; and after closes, still the original",
        "Replacement in round 0",
        {"ballot": ballot_json(b0), "times": [CLOSES - 100, CLOSES - 10, CLOSES + 3600]},
        {
            "receipts": [hexify(a["receipt"]), hexify(b["receipt"]), hexify(c["receipt"])],
            "one_receipt": a["receipt"] == b["receipt"] == c["receipt"],
        },
    )
    intake3 = bl.Intake(CLOSES)
    bad = bl.round0_payload(votes[:17])
    try:
        bl.check_round0(bad, dp)
        raise AssertionError
    except bl.BallotError as e:
        first_err = e.rule
    ok = intake3.round0(b0, o1, CLOSES - 100)
    f.add(
        "ballot-rejected-keeps-nullifier",
        "A B4 failure followed by a valid ballot under the same nullifier is accepted (AG-8)",
        "Validation rules",
        {"first_payload": _payload_json(bad), "second": ballot_json(b0)},
        {
            "first_rule": first_err,
            "second_status": ok["status"],
            "nullifier_recorded_after_first": False,
        },
    )
    files.append(f)

    # ---------------- rounds 1-3
    f = File(
        SPEC,
        "rounds",
        "Rounds 1 to 3 on valid-full (M 18, covScale 65536) from release.md's phone computations; "
        "round1-max at M = 128.",
    )
    tallies = [(300.0 - 7 * i, 100.0 + 5 * i, 20.0 + i) for i in range(18)]
    sel, mu = rmath.sel_and_mu(tallies, dp.cov_m)
    xhand = {i: (1 if v == 1 else -1 if v == 2 else 0) for i, v in hand.items()}
    r1v = rmath.round1_vector(xhand, sel, mu, dp.cov_scale)
    cov = bl.encode_cov(r1v["entries"])
    p1 = {bl.R1_COV: cov}
    chk1 = bl.check_round1(p1, dp)
    b1 = bl.ballot_map(full.cid, 1, h("nonce/r1"), p1, pres)
    f.add(
        "ballot-round1",
        "Round 1: cov as fixed-width signed 32-bit big-endian, its integer norm, within Δ_cov",
        "Rounds 1 to 3",
        {
            "deck": hexify(full.cid),
            "tallies": tallies,
            "M": dp.cov_m,
            "covScale": dp.cov_scale,
            "hand": {str(k): v for k, v in xhand.items()},
        },
        {
            **ballot_json(b1),
            "sel": sel,
            "entries": chk1["entries"],
            "norm_squared": chk1["norm_squared"],
            "delta_cov": dp.delta_cov,
            "leaf": hexify(bl.receipt_leaf(1, b1[bl.NONCE], p1)[1]),
        },
    )
    pc1 = [0.3 if i % 2 else -0.2 for i in range(dp.cov_m)]
    pc2 = [0.1 * ((i % 5) - 2) for i in range(dp.cov_m)]
    cell = rmath.round2_cell(xhand, sel, mu, pc1, pc2, 2.0, 1.5, dp.grid)
    p2 = {bl.R2_CELL: cell["cell"]}
    b2 = bl.ballot_map(full.cid, 2, h("nonce/r2"), p2, pres)
    f.add(
        "ballot-round2",
        "Round 2: one grid cell",
        "Rounds 1 to 3",
        {"pc1": pc1, "pc2": pc2, "half_x": 2.0, "half_y": 1.5, "grid": dp.grid},
        {
            **ballot_json(b2),
            "cell": cell,
            "one_hot_weight": bl.weight(bl.check_round2(p2, dp)["map"]),
        },
    )
    dp3 = params_for(full_env, groups_k=2)
    p3 = {bl.R3_GROUP: 1, bl.R3_VOTES: votes}
    chk3 = bl.check_round3(p3, dp3, payload)
    b3 = bl.ballot_map(full.cid, 3, h("nonce/r3"), p3, pres)
    f.add(
        "ballot-round3",
        "Round 3: the group index with round 0's identical votes bytes",
        "Rounds 1 to 3",
        {"groupsK": 2, "round0_votes": hexify(votes)},
        {
            **ballot_json(b3),
            "groups_vector_weight": bl.weight(chk3["groups"]),
            "bound": dp3.cap + 1,
        },
    )
    # round1-max: M = 128
    m128 = 128
    big = bl.DeckParams(
        cards=128,
        cap=128,
        cov_m=m128,
        cov_scale=65_536,
        delta_cov=65_536 + math.ceil(math.sqrt(m128 * 129 / 2) / 2),
    )
    entries = [0] * (m128 * 129 // 2)
    entries[0] = 65_536  # u = e_0, so u uᵀ has one entry of covScale
    cov128 = bl.encode_cov(entries)
    bmax = bl.ballot_map(
        h("deck128", 33), 1, h("nonce/max"), {bl.R1_COV: cov128}, bytes(bl.PRESENTATION_MAX)
    )
    enc = cbor.encode(bmax)
    f.add(
        "ballot-round1-max",
        "M = 128 with an 8 KiB presentation: the ballot fits the frame",
        "Rounds 1 to 3",
        {"M": m128, "cov_bytes": len(cov128), "presentation_bytes": bl.PRESENTATION_MAX},
        {
            "ballot_bytes": len(enc),
            "fits": len(enc) <= bl.BALLOT_BYTES - 4,
            "norm_squared": bl.check_round1({bl.R1_COV: cov128}, big)["norm_squared"],
            "part3_layout_with_ratings": {
                "slot": 3 * 18 + 1 + 3 * ip.arguments,
                "groupsK": 2,
                "length": 2 * (3 * 18 + 1 + 3 * ip.arguments),
            },
        },
    )
    # task ids and report ids
    v2 = wd.decks["valid-v2-extend"]
    ids = {
        f"round{r}/part{p}": hexify(bl.task_id(lineage_full, r, p))
        for r in range(4)
        for p in (0, 1, 2, 3, 4, 8)
    }
    f.add(
        "ballot-task-ids",
        "taskId(round, part) over the deck lineage CID; a second version gives the same ids",
        "Phase 2",
        {"deck_lineage": hexify(lineage_full), "deck_v2": hexify(v2.cid)},
        {
            "task_ids": ids,
            "same_for_v2": True,
            "report_ids": {str(p): hexify(bl.report_id(h("nonce/full"), p)) for p in (0, 4)},
            "note": "services.md's taskId(round) hashes the deck CID and the round only; ballot.md's form is used here",
        },
    )
    files.append(f)

    # ---------------- receipts
    f = File(
        SPEC,
        "receipts",
        "Receipt leaves and a padded tree with a fixed Y_r; checking a leaf against its page.",
    )
    real = [
        bl.receipt_leaf(0, h(f"n/{i}"), bl.round0_payload(bytes([1] * 18)))[1] for i in range(50)
    ]
    plan_full = dk.to_release_plan(full_env[m.BODY][dk.PLAN], 18)
    sigma_sq = rmath.rat_decode(rmath.rat(plan_full.parts[rmath.RECEIPTS]))
    d2 = rmath.delta_squared(rmath.RECEIPTS, plan_full)
    y = rb.receipt_padding(
        sigma_sq and (d2 * sigma_sq.denominator) / (2 * sigma_sq.numerator) * 1
        if False
        else __import__("fractions").Fraction(d2 * sigma_sq.denominator, 2 * sigma_sq.numerator),
        3,
    )
    dummies = [hashlib.sha256(h(f"dummy/{i}")).digest() for i in range(y)]
    pages = receipt_pages(real + dummies)
    chk = bl.check_receipt(real[7], pages["k"], pages["pages"], pages["root"])
    absent = bl.check_receipt(
        hashlib.sha256(b"absent").digest(), pages["k"], pages["pages"], pages["root"]
    )
    f.add(
        "ballot-receipt-check",
        f"A padded tree (50 real, Y_r = {y} dummies), a leaf, its page, and the expected result",
        "Receipts",
        {
            "real_leaves": [hexify(x) for x in real],
            "dummies": [hexify(x) for x in dummies],
            "Z_r": 3,
            "sigma_sq_receipts": [sigma_sq.numerator, sigma_sq.denominator],
            "delta_squared": d2,
        },
        {
            "Y_r": y,
            "k": pages["k"],
            "root": hexify(pages["root"]),
            "page_cids": [hexify(c) for c in pages["page_cids"]],
            "root_blob": hexify(pages["root_blob"]),
            "check_present": chk,
            "check_absent": absent,
        },
    )
    from ..keys import key_from_label

    leader_keys = {
        fixtures.fixed_bytes("leader-sign-1", 8): key_from_label("leader-sign-1"),
        fixtures.fixed_bytes("leader-sign-2", 8): key_from_label("leader-sign-2"),
    }
    kids = sorted(leader_keys)
    task0 = services.task_id(lineage_full, 0, 0)
    sig = services.receipt_sign(leader_keys[kids[0]], task0, leaf)
    rcpt = services.receipt_body(leaf, sig, kids[0])
    pubs = {k: v.public for k, v in leader_keys.items()}
    assert services.verify_receipt_body(rcpt, pubs, task0)
    rcpt_other = services.receipt_body(leaf, sig, kids[1])
    assert not services.verify_receipt_body(rcpt_other, pubs, task0)
    f.add(
        "ballot-receipt-kid",
        "A receipt {0: leaf, 1: signature, 2: kid}, verified under the Leader keyset's sign key "
        "that kid names",
        "Receipts",
        {
            "leader_sign_keys": {hexify(k): hexify(v.public) for k, v in leader_keys.items()},
            "task_id": hexify(task0),
            "leaf": hexify(leaf),
            "receipt": hexify(rcpt),
        },
        {"view": {"leaf": hexify(leaf), "signature": hexify(sig), "kid": hexify(kids[0])}, "verifies": True},
    )  # fmt: skip
    f.add(
        "ballot-receipt-kid",
        "The same signature with another listed kid: verified under that key, it fails",
        "Receipts",
        {
            "leader_sign_keys": {hexify(k): hexify(v.public) for k, v in leader_keys.items()},
            "task_id": hexify(task0),
            "leaf": hexify(leaf),
            "receipt": hexify(rcpt_other),
        },
        rejection={"step": None, "check": "receipt-verify", "reason": "kid names a key that did not sign"},
    )  # fmt: skip
    disp = bl.Intake(CLOSES)
    disp.round0(b0, o1, CLOSES - 100)
    disp.round0(b0b, o1, CLOSES - 50)
    f.add(
        "ballot-receipt-check",
        "A dispute over the first ballot's missing leaf is rebutted by the later valid ballot",
        "Receipts",
        {
            "complainant_leaf": hexify(bl.receipt_leaf(0, b0[bl.NONCE], payload)[1]),
            "later_body": hexify(bl.body_bytes(b0b)),
        },
        {"counted_leaves": [hexify(x) for x in disp.counted_leaves()], "rebutted": True},
    )
    files.append(f)

    # ---------------- invalid
    f = File(
        SPEC,
        "invalid",
        "One failing case per rule sub-condition that needs no real presentation or DAP report. "
        "Pending: B2 (presentations), B3 agent-class/entry-not-vote with real cards, B9 gate disclosure, B11.",
    )
    enc0 = cbor.encode(b0)
    fr = bl.frame(enc0)
    reject(
        f,
        "ballot-invalid-B1-size",
        "48 KiB + 1",
        {"frame_length": bl.BALLOT_BYTES + 1},
        lambda: bl.unframe(fr + b"\x00"),
        "B1",
        "malformed",
    )
    tail = bytearray(fr)
    tail[-1] = 1
    reject(
        f,
        "ballot-invalid-B1-nonzero-tail",
        "a non-zero byte after the ballot",
        {"frame_sha256": hashlib.sha256(bytes(tail)).hexdigest()},
        lambda: bl.unframe(bytes(tail)),
        "B1",
        "malformed",
    )
    bigp = (bl.BALLOT_BYTES).to_bytes(4, "big") + fr[4:]
    reject(
        f,
        "ballot-invalid-B1-length-prefix",
        "a length prefix larger than the frame",
        {"prefix": hexify(bigp[:4])},
        lambda: bl.unframe(bigp),
        "B1",
        "malformed",
    )
    reject(
        f,
        "ballot-invalid-B1-presentation-9k",
        "a 9 KiB presentation: too_large, services.md intake check 1",
        {"presentation_bytes": 9216},
        lambda: bl.unframe(
            bl.frame(cbor.encode(bl.ballot_map(full.cid, 0, h("n"), payload, bytes(9216))))
        ),
        "B1",
        "too_large",
    )
    reject(
        f,
        "ballot-invalid-B1-round-4",
        "round 4",
        {},
        lambda: bl.unframe(
            bl.frame(cbor.encode(bl.ballot_map(full.cid, 4, h("n"), payload, pres)))
        ),
        "B1",
        "malformed",
    )
    reject(
        f,
        "ballot-invalid-B1-nonce-31",
        "nonce of 31 bytes",
        {},
        lambda: bl.unframe(
            bl.frame(cbor.encode(bl.ballot_map(full.cid, 0, h("n", 31), payload, pres)))
        ),
        "B1",
        "malformed",
    )
    extra = dict(b0)
    extra[6] = h("agent-sig", 64)
    reject(
        f,
        "ballot-invalid-B1-unknown-key",
        "unknown key 6 holding an agentKey signature",
        {"key": 6},
        lambda: bl.unframe(bl.frame(cbor.encode(extra))),
        "B1",
        "malformed",
    )
    reject(
        f,
        "ballot-invalid-B1-other-deck",
        "a different deck",
        {"deck": hexify(ibis.cid)},
        lambda: bl.unframe(
            bl.frame(cbor.encode(bl.ballot_map(ibis.cid, 0, h("n"), payload, pres))),
            deck_versions={full.cid, v2.cid},
        ),
        "B1",
        "malformed",
    )
    # B3 set logic
    reject(
        f,
        "ballot-invalid-B3-no-card",
        "no card proof (agents never vote)",
        {"outcome": outcome_json(bl.Outcome([], None, []))},
        lambda: bl.Intake(CLOSES).round0(b0, bl.Outcome([], None, []), CLOSES - 1),
        "B3",
        "rejected",
    )
    ag = outcome("agent", cls="agent")
    reject(
        f,
        "ballot-invalid-B3-agent-class",
        "an agent-class card",
        {"outcome": outcome_json(ag)},
        lambda: bl.Intake(CLOSES).round0(b0, ag, CLOSES - 1),
        "B3",
        "rejected",
    )
    nv = outcome("entry-only", satisfies=False)
    reject(
        f,
        "ballot-invalid-B3-entry-not-vote",
        "a presentation satisfying entry but not vote (no card satisfies a vote leaf)",
        {"outcome": outcome_json(nv)},
        lambda: bl.Intake(CLOSES).round0(b0, nv, CLOSES - 1),
        "B3",
        "rejected",
    )
    pooled_intake = bl.Intake(CLOSES)
    owner = outcome("owner")
    pooled_intake.round0(b0, owner, CLOSES - 100)
    pooled = bl.Outcome(
        [h("null/pooled/0"), owner.nullifiers[0]],
        h("null/pooled/0"),
        [{"class": "person", "issuer": h("issuer/0", 33), "satisfies": True}] * 2,
    )
    reject(
        f,
        "ballot-invalid-B3-pooled",
        "a pooled presentation whose second nullifier is already in the deck",
        {"outcome": outcome_json(pooled)},
        lambda: pooled_intake.round0(b0b, pooled, CLOSES - 50),
        "B3",
        "conflict",
    )
    # B4
    reject(
        f,
        "ballot-invalid-B4-length",
        "votes of length C − 1",
        {},
        lambda: bl.check_round0(bl.round0_payload(votes[:17]), dp),
        "B4",
        "rejected",
    )
    reject(
        f,
        "ballot-invalid-B4-byte-4",
        "a byte of 4",
        {},
        lambda: bl.check_round0(bl.round0_payload(b"\x04" + votes[1:]), dp),
        "B4",
        "rejected",
    )
    reject(
        f,
        "ballot-invalid-B4-over-cap",
        "K + 1 non-zero bytes",
        {"cap": 17},
        lambda: bl.check_round0(bl.round0_payload(votes), bl.DeckParams(cards=18, cap=17)),
        "B4",
        "rejected",
    )
    reject(
        f,
        "ballot-invalid-B4-group-vote-deck",
        "group in a vote deck",
        {},
        lambda: bl.check_round0(bl.round0_payload(votes, group=0), dp),
        "B4",
        "rejected",
    )
    reject(
        f,
        "ballot-invalid-B4-group-range",
        "group ≥ groupsK",
        {},
        lambda: bl.check_round0(bl.round0_payload(rvotes, group=2), rp),
        "B4",
        "rejected",
    )
    # B5
    reject(
        f,
        "ballot-invalid-B5-without-part",
        "movement without part 5",
        {},
        lambda: bl.check_round0(bl.round0_payload(votes, {0: [1, 1, 0]}), dp),
        "B5",
        "rejected",
    )
    many = {i: [1, 1 + (i % 3), 0] for i in range(11)}
    many = {i: [1, ihand[i], 0] for i in range(11)}
    reject(
        f,
        "ballot-invalid-B5-over-cap",
        "K_m + 1 entries",
        {},
        lambda: bl.check_round0(bl.round0_payload(ivotes, many, ratings), ip),
        "B5",
        "rejected",
    )
    reject(
        f,
        "ballot-invalid-B5-moved-no-pro",
        "moved = 1 on a card with no pro",
        {"card": 12},
        lambda: bl.check_round0(bl.round0_payload(ivotes, {12: [1, ihand[12], 1]}, ratings), ip),
        "B5",
        "rejected",
    )
    reject(
        f,
        "ballot-invalid-B5-first-0",
        "first 0",
        {},
        lambda: bl.check_round0(bl.round0_payload(ivotes, {0: [0, ihand[0], 0]}, ratings), ip),
        "B5",
        "rejected",
    )
    reject(
        f,
        "ballot-invalid-B5-second-mismatch",
        "second ≠ votes[i]",
        {},
        lambda: bl.check_round0(
            bl.round0_payload(ivotes, {0: [1, 1 + ihand[0] % 3, 0]}, ratings), ip
        ),
        "B5",
        "rejected",
    )
    # B6
    reject(
        f,
        "ballot-invalid-B6-over-cap",
        "K_r + 1 ratings",
        {},
        lambda: bl.check_round0(
            bl.round0_payload(ivotes, movement, {i: 0 for i in range(10)} | {10: 0}), ip
        ),
        "B6",
        "rejected",
    )
    reject(
        f,
        "ballot-invalid-B6-key",
        "key ≥ A",
        {},
        lambda: bl.check_round0(bl.round0_payload(ivotes, movement, {10: 0}), ip),
        "B6",
        "rejected",
    )
    reject(
        f,
        "ballot-invalid-B6-value",
        "value 3",
        {},
        lambda: bl.check_round0(bl.round0_payload(ivotes, movement, {0: 3}), ip),
        "B6",
        "rejected",
    )
    # B7
    late = bl.Intake(CLOSES)
    late.round0(b0, o1, CLOSES - 100)
    reject(
        f,
        "ballot-invalid-B7-after-closes",
        "a different body after closes",
        {},
        lambda: late.round0(b0b, o1, CLOSES + 1),
        "B7",
        "closed",
    )
    other_set = bl.Outcome([o1.nullifiers[0], h("null/other")], o1.nullifiers[0], o1.cards * 2)
    reject(
        f,
        "ballot-invalid-B7-nullifier-set",
        "a replacement with a different second nullifier",
        {},
        lambda: late.round0(b0b, other_set, CLOSES - 1),
        "B7",
        "conflict",
    )
    # B8
    never = outcome("never")
    reject(
        f,
        "ballot-invalid-B8-never-voted",
        "round 2 from a nullifier that never voted",
        {},
        lambda: late.later_round(b2, never),
        "B8",
        "forbidden",
    )
    late.later_round(b1, o1)
    b1b = bl.ballot_map(
        full.cid, 1, h("nonce/r1b"), {bl.R1_COV: bl.encode_cov([0] * len(r1v["entries"]))}, pres
    )
    reject(
        f,
        "ballot-invalid-B8-twice",
        "round 1 sent twice with different cov",
        {},
        lambda: late.later_round(b1b, o1),
        "B8",
        "conflict",
    )
    # B10
    over = list(r1v["entries"])
    over[0] = dp.cov_scale + 1
    reject(
        f,
        "ballot-invalid-B10-entry",
        "cov one entry over covScale",
        {},
        lambda: bl.check_round1({0: bl.encode_cov(over)}, dp),
        "B10",
        "rejected",
    )
    norm = [dp.cov_scale] * len(r1v["entries"])
    reject(
        f,
        "ballot-invalid-B10-norm",
        "norm over Δ_cov",
        {},
        lambda: bl.check_round1({0: bl.encode_cov(norm)}, dp),
        "B10",
        "rejected",
    )
    reject(
        f,
        "ballot-invalid-B10-length",
        "cov of the wrong length",
        {},
        lambda: bl.check_round1({0: cov[:-4]}, dp),
        "B10",
        "rejected",
    )
    reject(
        f,
        "ballot-invalid-B10-cell",
        "cell = grid²",
        {},
        lambda: bl.check_round2({0: dp.grid * dp.grid}, dp),
        "B10",
        "rejected",
    )
    reject(
        f,
        "ballot-invalid-B10-round3-votes",
        "round 3 votes differing from round 0",
        {},
        lambda: bl.check_round3({0: 1, 1: bl.votes_bytes(hand2, 18)}, dp3, payload),
        "B10",
        "rejected",
    )
    files.append(f)

    # ---------------- client side
    f = File(
        SPEC,
        "client",
        "Client-side selections: the counted hand that only grows, undo before casting, the movement selection, "
        "the ratings selection from a seed (reference expansion), the send schedule, and a re-voted card outside the counted hand.",
    )
    k = 18
    sends = []
    order = list(range(k + 5))
    for n in (10, k, k + 5):
        cast_now = order[:n]
        cur = {i: 1 + (i % 3) for i in cast_now}
        sends.append({"cast": n, "counted": sorted(bl.counted_hand(cast_now, cur, k))})
    f.add(
        "ballot-client-counted-hand",
        "A hand growing from 10 to K + 5 cast cards across three sends: no card ever leaves",
        "The counted hand",
        {"cap": k, "cast_order": order},
        {
            "sends": sends,
            "never_shrinks": all(
                set(sends[i]["counted"]) <= set(sends[i + 1]["counted"]) for i in range(2)
            ),
        },
    )
    f.add(
        "ballot-client-undo",
        "An undone swipe is not cast: the hand excludes it",
        "Casting and the hand",
        {
            "swipes": [
                {"card": 0, "vote": 1, "undone": False},
                {"card": 1, "vote": 2, "undone": True},
                {"card": 2, "vote": 3, "undone": False},
            ]
        },
        {"cast_order": [0, 2], "counted": {"0": 1, "2": 3}},
    )
    f.add(
        "ballot-client-movement-selection",
        "The first K_m re-voted cards in re-vote order",
        "The movement selection",
        {"revote_order": [5, 3, 9, 1, 0, 7, 2, 8, 4, 6, 11, 10], "cap_movement": 10},
        {"selection": bl.movement_selection([5, 3, 9, 1, 0, 7, 2, 8, 4, 6, 11, 10], 10)},
    )
    seed = h("ratings-seed")
    f.add(
        "ballot-client-ratings-selection",
        "A uniform K_r of A arguments from a fixed seed (reference expansion: SHA-256 stream, rejection sampling)",
        "The ratings selection",
        {"seed": hexify(seed), "arguments": 25, "cap_ratings": 10},
        {
            "selection": bl.ratings_selection(seed, 25, 10),
            "all_when_small": bl.ratings_selection(seed, 8, 10),
        },
    )
    edits = [
        CLOSES - 40 * 3600,
        CLOSES - 39 * 3600,
        CLOSES - 30 * 3600,
        CLOSES - 8 * 3600,
        CLOSES - 7 * 3600,
    ]
    sched = bl.send_schedule(edits, CLOSES - 48 * 3600, CLOSES, h("schedule-seed"))
    f.add(
        "ballot-client-send-schedule",
        "Sends from a sequence of hand edits with timestamps and a fixed random stream",
        "Replacement in round 0",
        {
            "first_leave": CLOSES - 48 * 3600,
            "edits": edits,
            "closes": CLOSES,
            "seed": hexify(h("schedule-seed")),
        },
        {"sends": sched},
    )
    cast_order = list(range(18))[:18]
    um_payload = bl.round0_payload(
        bl.votes_bytes(bl.counted_hand(cast_order, {i: 1 for i in range(18)}, 5), 18),
        {9: [1, 2, 0]},
    )
    f.add(
        "ballot-movement-uncounted",
        "A re-voted card outside the counted hand still appears in movement",
        "The movement selection",
        {"cap": 5, "cast_order": cast_order, "revoted_card": 9},
        {
            "payload": _payload_json(um_payload),
            "card_counted": False,
            "in_movement": 9 in um_payload[bl.P_MOVEMENT],
        },
    )
    files.append(f)
    return files
