"""The ``deck`` body: docs/specs/deck.md.

Every rule D1 to D15 runs at verification step 10 (the deck spec assigns them there), with
D1 first so that a malformed body never reaches a later rule. The plan math (σ per part,
Δ²) lives in the top-level ``release`` module; this module reads and checks plans.

Builders: ``plan``, ``card``, ``body`` and the plan shapes the vectors use. ``to_release_plan``
turns a plan map into ``release.ReleasePlan`` for σ computations.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Any

from .. import manifest as m
from .. import release as rmath
from . import (
    TypeRule,
    is_cid,
    is_rat,
    is_text,
    is_uint,
    no_unknown_keys,
    rat_value,
    require,
    require_keys,
)
from . import context as c

__all__ = [
    "GATE_OF",
    "PLAN_RATING_RHO_MAX",
    "body",
    "card",
    "cards_of",
    "effective_gate",
    "plan",
    "plan_breakdown",
    "plan_full",
    "plan_ibis",
    "plan_rating",
    "plan_tallies_only",
    "post_close_rounds",
    "rules",
    "to_release_plan",
]

# ---------------------------------------------------------------- keys

TITLE, OPENS, CLOSES, TOPICS, CARDS, PLAN, ORDER, KIND = range(8)
ALL_KEYS = set(range(8))
C_KIND, C_TOPIC, C_ORIGIN, C_EPOCH = range(4)
CARD_POSITION, CARD_BLOB, CARD_TAKE = 0, 1, 2
ORIGIN_LOCAL, ORIGIN_GLOBAL = 0, 1
KIND_VOTE, KIND_RATING = 0, 1
(
    P_RHO, P_DELTA, P_PARTS, P_CAP, P_COV_STATEMENTS, P_GRID, P_BLUR, P_MIN_VOTERS, P_GATES,
    P_ABSORB, P_ROUND_WINDOW, P_CAP_MOVEMENT, P_CAP_RATINGS, P_BREAKDOWN, P_COV_SCALE,
) = range(15)  # fmt: skip
PLAN_REQUIRED = {P_RHO, P_DELTA, P_PARTS, P_CAP, P_MIN_VOTERS}
PLAN_KEYS = set(range(15))
BD_SOURCE, BD_NAME, BD_VALUES = 0, 1, 2

TALLIES, COVARIANCE, MAP, GROUPS, COUNT, MOVEMENT, RATINGS, BREAKDOWN, RECEIPTS = range(9)
PARTS = set(range(9))
TIER = (COVARIANCE, MAP, GROUPS)
GATED = {TALLIES, COVARIANCE, MAP, GROUPS, MOVEMENT, RATINGS}
GATE_OF = {
    TALLIES: c.GATE_TALLIES,
    COVARIANCE: c.GATE_MAP,
    MAP: c.GATE_MAP,
    GROUPS: c.GATE_MAP,
    MOVEMENT: c.GATE_COMMON,
    RATINGS: c.GATE_COMMON,
    BREAKDOWN: c.GATE_CELL,
}
DEFAULT_GRID = 24
DEFAULT_ROUND_WINDOW = 259_200
DEFAULT_COV_SCALE = 65_536
DEFAULT_COUNT_RHO_MAX = Fraction(1, 200)
PUBLISH_WINDOW = 2_592_000  # deck.md D13: release.md R13's 30-day allowance for version 1
MIN_OPEN = 3600
MAX_OPEN = 31_536_000
PLAN_RATING_RHO_MAX = Fraction(1, 20)
RATING_CAP_MAX = 20
RATING_CARDS_MAX = 60
TAKE_AUTHOR, TAKE_RETIRED = 0, 7  # take.md body keys read here


# ---------------------------------------------------------------- builders


def _rat(x: Fraction) -> list[int]:
    return rmath.rat(x)


def plan(
    rho: Fraction,
    parts: dict[int, Fraction],
    cap: int,
    min_voters: int = c.MIN_VOTERS,
    *,
    delta: Fraction = c.DELTA_MAX,
    cov_statements: int | None = None,
    grid: int | None = None,
    blur: Fraction | None = None,
    gates: dict[int, int] | None = None,
    absorb: bool | None = None,
    round_window: int | None = None,
    cap_movement: int | None = None,
    cap_ratings: int | None = None,
    breakdown: tuple[list[int], str, list[int]] | None = None,
    cov_scale: int | None = None,
) -> dict[int, Any]:
    out: dict[int, Any] = {
        P_RHO: _rat(rho),
        P_DELTA: _rat(delta),
        P_PARTS: {p: _rat(r) for p, r in sorted(parts.items())},
        P_CAP: cap,
        P_MIN_VOTERS: min_voters,
    }
    for key, value in (
        (P_COV_STATEMENTS, cov_statements),
        (P_GRID, grid),
        (P_GATES, gates),
        (P_ABSORB, absorb),
        (P_ROUND_WINDOW, round_window),
        (P_CAP_MOVEMENT, cap_movement),
        (P_CAP_RATINGS, cap_ratings),
        (P_COV_SCALE, cov_scale),
    ):
        if value is not None:
            out[key] = value
    if blur is not None:
        out[P_BLUR] = _rat(blur)
    if breakdown is not None:
        source, name, values = breakdown
        out[P_BREAKDOWN] = {BD_SOURCE: list(source), BD_NAME: name, BD_VALUES: list(values)}
    return out


def _split(rho: Fraction, shares: dict[int, Fraction], extras: dict[int, Fraction]) -> dict:
    base = rho - sum(extras.values(), Fraction(0))
    parts = {p: base * s for p, s in shares.items()}
    parts.update(extras)
    assert sum(parts.values(), Fraction(0)) == rho
    return parts


DEFAULT_SHARES = {
    TALLIES: Fraction(15, 100),
    COVARIANCE: Fraction(35, 100),
    MAP: Fraction(15, 100),
    GROUPS: Fraction(35, 100),
}
IBIS_SHARES = {
    TALLIES: Fraction(13, 100),
    COVARIANCE: Fraction(30, 100),
    MAP: Fraction(13, 100),
    GROUPS: Fraction(30, 100),
    MOVEMENT: Fraction(8, 100),
    RATINGS: Fraction(6, 100),
}


def plan_full(cap: int, rho: Fraction = c.RHO_MAX, *, count: bool = True, **kw) -> dict:
    """The design-doc split plus receipts (and the daily count) at 1/200 each."""
    extras = {RECEIPTS: Fraction(1, 200)}
    if count:
        extras[COUNT] = Fraction(1, 200)
    return plan(rho, _split(rho, DEFAULT_SHARES, extras), cap, **kw)


def plan_tallies_only(cap: int, rho: Fraction = c.RHO_MAX, *, count: bool = True, **kw) -> dict:
    extras = {RECEIPTS: Fraction(1, 200)}
    if count:
        extras[COUNT] = Fraction(1, 200)
    return plan(rho, _split(rho, {TALLIES: Fraction(1)}, extras), cap, **kw)


def plan_ibis(
    cap: int, rho: Fraction = c.RHO_MAX, *, cap_movement=10, cap_ratings=10, count=False, **kw
):
    extras = {RECEIPTS: Fraction(1, 200)}
    if count:
        extras[COUNT] = Fraction(1, 200)
    return plan(
        rho,
        _split(rho, IBIS_SHARES, extras),
        cap,
        cap_movement=cap_movement,
        cap_ratings=cap_ratings,
        **kw,
    )


def plan_breakdown(cap: int, source: list[int], name: str, values: list[int], **kw) -> dict:
    rho = kw.pop("rho", c.RHO_MAX)
    shares = dict(DEFAULT_SHARES)
    shares = {p: s * Fraction(9, 10) for p, s in shares.items()}
    shares[BREAKDOWN] = Fraction(1, 10)
    extras = {RECEIPTS: Fraction(1, 200)}
    return plan(rho, _split(rho, shares, extras), cap, breakdown=(source, name, values), **kw)


def plan_rating(
    cap: int = 20, rho: Fraction = PLAN_RATING_RHO_MAX, *, min_voters: int = c.GATE_TALLIES, **kw
) -> dict:
    """Parts 0, 3 and 8: tallies 0.4 and groups 0.6 of what is left after part 8 (take.md).
    ``min_voters`` = max(GATE_TALLIES, the context's minimum); above GATE_TALLIES the plan sets
    gates[0] to the same value so D11 holds (deck.md D15, ADR 0103)."""
    extras = {RECEIPTS: Fraction(1, 400)}
    shares = {TALLIES: Fraction(2, 5), GROUPS: Fraction(3, 5)}
    if min_voters > c.GATE_TALLIES and "gates" not in kw:
        kw["gates"] = {TALLIES: min_voters}
    return plan(rho, _split(rho, shares, extras), cap, min_voters, **kw)


def card(kind: int, topic: int, origin: int = ORIGIN_LOCAL, epoch: int | None = None) -> dict:
    out = {C_KIND: kind, C_TOPIC: topic, C_ORIGIN: origin}
    if epoch is not None:
        out[C_EPOCH] = epoch
    return out


def body(
    *,
    title: str,
    opens: int,
    closes: int,
    topics: list[str],
    cards: list[dict],
    plan_: dict,
    order: int = 0,
    kind: int = KIND_VOTE,
) -> dict[int, Any]:
    return {
        TITLE: title,
        OPENS: opens,
        CLOSES: closes,
        TOPICS: list(topics),
        CARDS: list(cards),
        PLAN: plan_,
        ORDER: order,
        KIND: kind,
    }


# ---------------------------------------------------------------- reading a plan


def to_release_plan(plan_map: dict[int, Any], cards: int) -> rmath.ReleasePlan:
    """The math module's view of a plan map."""
    bd = plan_map.get(P_BREAKDOWN)
    return rmath.ReleasePlan(
        rho=rat_value(plan_map[P_RHO]),
        delta=rat_value(plan_map[P_DELTA]),
        parts={p: rat_value(r) for p, r in plan_map[P_PARTS].items()},
        cap=plan_map[P_CAP],
        min_voters=plan_map[P_MIN_VOTERS],
        cov_statements=plan_map.get(P_COV_STATEMENTS, min(60, cards)),
        grid=plan_map.get(P_GRID, DEFAULT_GRID),
        blur=rat_value(plan_map[P_BLUR]) if P_BLUR in plan_map else Fraction(1),
        gates=dict(plan_map.get(P_GATES, {})),
        absorb=plan_map.get(P_ABSORB, False),
        round_window=plan_map.get(P_ROUND_WINDOW, DEFAULT_ROUND_WINDOW),
        cap_movement=plan_map.get(P_CAP_MOVEMENT),
        cap_ratings=plan_map.get(P_CAP_RATINGS),
        breakdown=dict(bd) if bd is not None else None,
        cov_scale=plan_map.get(P_COV_SCALE, DEFAULT_COV_SCALE),
    )


def effective_gate(plan_map: dict[int, Any], part: int) -> int | None:
    g = GATE_OF.get(part)
    if g is None:
        return None
    return plan_map.get(P_GATES, {}).get(part, g)


def post_close_rounds(plan_map: dict[int, Any]) -> int:
    return 3 if COVARIANCE in plan_map[P_PARTS] else 0


def cards_of(env: dict[int, Any]) -> list[dict]:
    return env[m.BODY][CARDS]


def card_refs(refs: dict[str, bytes]) -> tuple[dict[int, bytes], dict[tuple[int, str], bytes]]:
    """``card/<i>`` by index and ``card/<i>/pro|con`` by (index, side)."""
    cards: dict[int, bytes] = {}
    sides: dict[tuple[int, str], bytes] = {}
    for name, cid in refs.items():
        if not name.startswith("card/"):
            continue
        parts = name.split("/")
        if len(parts) == 2 and _is_index(parts[1]):
            cards[int(parts[1])] = cid
        elif len(parts) == 3 and _is_index(parts[1]) and parts[2] in ("pro", "con"):
            sides[(int(parts[1]), parts[2])] = cid
    return cards, sides


def _is_index(s: str) -> bool:
    return s.isdigit() and str(int(s)) == s


# ---------------------------------------------------------------- D1: shape


def _check_plan_shape(p: Any) -> None:
    require_keys(p, PLAN_REQUIRED, "D1", "plan")
    no_unknown_keys(p, PLAN_KEYS, "D1", "plan")
    require(is_rat(p[P_RHO]), "D1", "plan.rho must be a rat in lowest terms")
    require(is_rat(p[P_DELTA]), "D1", "plan.delta must be a rat in lowest terms")
    parts = p[P_PARTS]
    require(isinstance(parts, dict) and parts, "D1", "plan.parts must be a non-empty map")
    for k, v in parts.items():
        require(is_uint(k), "D1", "plan.parts keys must be uints")
        require(is_rat(v), "D1", f"plan.parts[{k}] must be a rat in lowest terms")
    require(is_uint(p[P_CAP]), "D1", "plan.cap must be a uint")
    require(is_uint(p[P_MIN_VOTERS]), "D1", "plan.minVoters must be a uint")
    for key, what in (
        (P_COV_STATEMENTS, "covStatements"),
        (P_GRID, "grid"),
        (P_ROUND_WINDOW, "roundWindow"),
        (P_CAP_MOVEMENT, "capMovement"),
        (P_CAP_RATINGS, "capRatings"),
        (P_COV_SCALE, "covScale"),
    ):
        if key in p:
            require(is_uint(p[key]), "D1", f"plan.{what} must be a uint")
    if P_BLUR in p:
        require(is_rat(p[P_BLUR]), "D1", "plan.blur must be a rat")
    if P_GATES in p:
        g = p[P_GATES]
        require(
            isinstance(g, dict) and all(is_uint(k) and is_uint(v) for k, v in g.items()),
            "D1",
            "plan.gates must map uints to uints",
        )
    if P_ABSORB in p:
        require(isinstance(p[P_ABSORB], bool), "D1", "plan.absorb must be a bool")
    if P_BREAKDOWN in p:
        bd = p[P_BREAKDOWN]
        require(
            isinstance(bd, dict) and set(bd) == {BD_SOURCE, BD_NAME, BD_VALUES},
            "D1",
            "plan.breakdown shape",
        )
        src = bd[BD_SOURCE]
        require(
            isinstance(src, list) and len(src) == 2 and all(is_uint(x) for x in src),
            "D1",
            "plan.breakdown source shape",
        )
        require(is_text(bd[BD_NAME], 32), "D1", "plan.breakdown name")
        require(
            isinstance(bd[BD_VALUES], list) and all(is_uint(v) for v in bd[BD_VALUES]),
            "D1",
            "plan.breakdown values must be uints",
        )


def _d1(env: dict[int, Any]) -> None:
    b = env[m.BODY]
    require_keys(b, ALL_KEYS, "D1")
    no_unknown_keys(b, ALL_KEYS, "D1")
    require(is_text(b[TITLE], 120), "D1", "title")
    require(is_uint(b[OPENS]) and is_uint(b[CLOSES]), "D1", "opens and closes must be times")
    topics = b[TOPICS]
    require(isinstance(topics, list) and all(is_text(t, 32) for t in topics), "D1", "topics")
    cards = b[CARDS]
    require(isinstance(cards, list), "D1", "cards must be an array")
    for i, cd in enumerate(cards):
        require(isinstance(cd, dict), "D1", f"card {i} must be a map")
        require_keys(cd, {C_KIND, C_TOPIC, C_ORIGIN}, "D1", f"card {i}")
        no_unknown_keys(cd, {C_KIND, C_TOPIC, C_ORIGIN, C_EPOCH}, "D1", f"card {i}")
        require(all(is_uint(cd[k]) for k in cd), "D1", f"card {i} values must be uints")
        require(cd[C_KIND] in (0, 1, 2), "D1", f"card {i} kind out of range")
        require(cd[C_ORIGIN] in (0, 1), "D1", f"card {i} origin out of range")
    _check_plan_shape(b[PLAN])
    require(b[ORDER] in (0, 1), "D1", "order must be 0 or 1")
    require(b[KIND] in (0, 1), "D1", "kind must be 0 or 1")
    for name, cid in env[m.REFS].items():
        require(is_cid(cid), "D1", f"ref {name!r} is not a CID")
        parts = name.split("/")
        ok = (
            name in ("context", "source")
            or (len(parts) == 2 and parts[0] == "card" and _is_index(parts[1]))
            or (
                len(parts) == 3
                and parts[0] == "card"
                and _is_index(parts[1])
                and parts[2] in ("pro", "con")
            )
        )
        require(ok, "D1", f"unknown ref {name!r}")


# ---------------------------------------------------------------- helpers over the resolver


def _latest_state_before(view: m.Resolved, cid: bytes) -> tuple[dict | None, dict | None]:
    """(the manifest ``cid`` names, the latest version of its lineage before this deck)."""
    env = view.manifest(cid)
    if env is None:
        return None, None
    lineage = env.get(m.LINEAGE, cid)
    latest = view.latest_before(lineage, view.position)
    return env, latest if latest is not None else env


def _verifier_in_force(view: m.Resolved, authority: bytes) -> dict | None:
    best = None
    for pos, env, _ in view.all_of_type("verifier"):
        if view.position is not None and pos >= view.position:
            continue
        if env.get(m.AUTHORITY) != authority:
            continue
        if best is None or env[m.VERSION] > best[m.VERSION]:
            best = env
    return best


def _breakdown_authorities(view: m.Resolved, ctx_env: dict, source: list[int], name: str):
    """Verifier authorities a breakdown source accepts for ``name`` (trust-list.md step 2)."""
    from . import trust_list as tl

    ctx_body = ctx_env[m.BODY]
    kind, i = source
    if kind == c.SRC_ISSUER:
        issuers = ctx_body.get(c.ISSUERS, [])
        require(i < len(issuers), "D9", "breakdown source names an absent issuer")
        return [issuers[i]]
    require(kind == c.SRC_TRUST_LIST, "D9", "breakdown source kind")
    ref = ctx_env[m.REFS].get(f"tl/{i}")
    require(ref is not None, "D9", "breakdown source names an absent trust list")
    tl_env = view.manifest(ref)
    require(tl_env is not None and tl_env.get(m.TYPE) == "trust-list", "D9", "tl ref")
    out = []
    for e in tl_env[m.BODY][tl.ENTRIES]:
        attrs = e[tl.EN_ATTRIBUTES]
        if not attrs or name in attrs:
            out.append(e[tl.EN_AUTHORITY])
    return out


# ---------------------------------------------------------------- D2 to D16


def rules(view: m.Resolved) -> None:
    env, refs = view.env, view.refs
    _d1(env)
    b = env[m.BODY]
    p = b[PLAN]
    cards = b[CARDS]
    n_cards = len(cards)
    rating = b[KIND] == KIND_RATING
    # D2
    require(b[OPENS] + MIN_OPEN <= b[CLOSES], "D2", "closes must be at least an hour after opens")
    require(b[CLOSES] - b[OPENS] <= MAX_OPEN, "D2", "a deck may be open for at most one year")
    # D3
    topics = b[TOPICS]
    require(1 <= len(topics) <= c.MAX_TOPICS, "D3", f"topics must have 1..{c.MAX_TOPICS}")
    require(len(set(topics)) == len(topics), "D3", "duplicate topic")
    for i, cd in enumerate(cards):
        require(cd[C_TOPIC] < len(topics), "D3", f"card {i} topic index out of range")
    # D4
    require(1 <= n_cards <= c.MAX_CARDS, "D4", f"cards must have 1..{c.MAX_CARDS} entries")
    card_cids, side_refs = card_refs(refs)
    require(set(card_cids) == set(range(n_cards)), "D4", "card/<i> refs must be exactly 0..n-1")
    require(len(set(card_cids.values())) == n_cards, "D4", "two cards share a CID")
    for (i, _side), _cid in side_refs.items():
        require(i < n_cards, "D4", f"card/{i}/pro|con has no card {i}")
        require(cards[i][C_KIND] == CARD_POSITION, "D4", f"card/{i} argument on a non-position")
    # D5
    require("context" in refs, "D5", "context ref missing")
    ctx_env = view.manifest(refs["context"])
    require(ctx_env is not None and ctx_env.get(m.TYPE) == "context", "D5", "not a context")
    ctx_body = ctx_env[m.BODY]
    ctx_lineage = view.lineage_of(refs["context"])
    # D6
    for i, cd in enumerate(cards):
        if cd[C_ORIGIN] != ORIGIN_GLOBAL:
            continue
        require(ctx_body[c.MIX_GLOBAL], "D6", "Global card in a context with mixGlobal false")
        if cd[C_KIND] == CARD_POSITION:
            obj = view.manifest(card_cids[i])
            require(obj is not None, "D6", f"card {i} does not resolve")
            obj_ctx = obj[m.REFS].get("context")
            require(
                view.ctx.global_context is not None
                and obj_ctx is not None
                and view.lineage_of(obj_ctx) == view.ctx.global_context,
                "D6",
                f"card {i} is not a Global object",
            )
    # D7
    for i, cd in enumerate(cards):
        kind = cd[C_KIND]
        if kind == CARD_POSITION and cd[C_ORIGIN] == ORIGIN_LOCAL:
            pos_env, latest = _latest_state_before(view, card_cids[i])
            require(pos_env is not None and pos_env[m.TYPE] == "position", "D7", f"card {i}")
            obj_ctx = pos_env[m.REFS].get("context")
            require(
                obj_ctx is not None and view.lineage_of(obj_ctx) == ctx_lineage,
                "D7",
                f"card {i} is a position from another context",
            )
            require(latest[m.BODY].get(3) == 1, "D7", f"card {i} position is not active")
        elif kind == CARD_BLOB:
            sealed = ctx_body[c.SEALED]
            needs_epoch = cd[C_ORIGIN] == ORIGIN_LOCAL and sealed
            require(
                (C_EPOCH in cd) == needs_epoch,
                "D7",
                f"card {i} statement blob epoch must be present iff local and sealed",
            )
        elif kind == CARD_TAKE:
            require(rating, "D7", f"card {i} is a take in a vote deck")
    for (i, side), cid in side_refs.items():
        arg_env, latest = _latest_state_before(view, cid)
        require(arg_env is not None and arg_env[m.TYPE] == "argument", "D7", f"card/{i}/{side}")
        want = 2 if side == "pro" else 3
        require(arg_env[m.BODY].get(0) == want, "D7", f"card/{i}/{side} has the wrong kind")
        parent = arg_env[m.REFS].get("parent")
        require(
            parent is not None and parent == view.lineage_of(card_cids[i]),
            "D7",
            f"card/{i}/{side} is not under card {i}'s position",
        )
        require(latest[m.BODY].get(3) == 1, "D7", f"card/{i}/{side} argument is not active")
    # D8
    parts = {k: rat_value(v) for k, v in p[P_PARTS].items()}
    require(TALLIES in parts and RECEIPTS in parts, "D8", "parts 0 and 8 are required")
    if rating:
        require(
            set(parts) == {TALLIES, GROUPS, RECEIPTS},
            "D8",
            "a rating deck's plan has exactly parts 0, 3 and 8",
        )
    else:
        tier = [t for t in TIER if t in parts]
        require(len(tier) in (0, 3), "D8", "parts 1, 2 and 3 are all present or all absent")
    require(set(parts) <= PARTS, "D8", "unknown part id")
    require(all(r > 0 for r in parts.values()), "D8", "every part rho must be positive")
    rho = rat_value(p[P_RHO])
    require(sum(parts.values(), Fraction(0)) == rho, "D8", "parts do not sum to rho")
    # D9
    arg_count = len(side_refs)
    if p.get(P_ABSORB, False):
        require(COUNT in parts, "D9", "absorb needs part 4")
    if MOVEMENT in parts:
        require(
            P_CAP_MOVEMENT in p and arg_count >= 1,
            "D9",
            "movement needs capMovement and an argument",
        )
    if RATINGS in parts:
        require(
            P_CAP_RATINGS in p and arg_count >= 1, "D9", "ratings needs capRatings and an argument"
        )
    if BREAKDOWN in parts:
        require(P_BREAKDOWN in p, "D9", "breakdown part needs the breakdown map")
        bd = p[P_BREAKDOWN]
        values = bd[BD_VALUES]
        require(2 <= len(values) <= 64 and len(set(values)) == len(values), "D9", "2..64 values")
        authorities = _breakdown_authorities(view, ctx_env, bd[BD_SOURCE], bd[BD_NAME])
        require(authorities, "D9", "breakdown source accepts no verifier for the attribute")
        require(
            len(authorities) == 1,
            "D9",
            "breakdown source must resolve to exactly one verifier authority",
        )
        for auth in authorities:
            v_env = _verifier_in_force(view, auth)
            require(v_env is not None, "D9", "breakdown verifier not resolvable")
            attrs = {a[0]: a for a in v_env[m.BODY][8]}
            a = attrs.get(bd[BD_NAME])
            require(a is not None and a[5] == "breakdown", "D9", "attribute is not breakdown")
    # D10
    floors = c.floors_of(ctx_body)
    require(rho <= floors["rho"], "D10", "rho above the context floor")
    require(rat_value(p[P_DELTA]) <= floors["delta"], "D10", "delta above the context floor")
    require(p[P_MIN_VOTERS] >= floors["minVoters"], "D10", "minVoters below the context floor")
    if COUNT in parts:
        cnt = ctx_body.get(c.COUNT, {})
        rho_max = rat_value(cnt[c.CNT_RHO_MAX]) if c.CNT_RHO_MAX in cnt else DEFAULT_COUNT_RHO_MAX
        require(parts[COUNT] <= rho_max, "D10", "count rho above count.rhoMax")
    # D11
    gates = p.get(P_GATES, {})
    require(set(gates) <= GATED, "D11", "gates names a part that has no gate")
    for part, g in gates.items():
        require(g >= GATE_OF[part], "D11", f"gate for part {part} below the protocol gate")
    for part in parts:
        g = effective_gate(p, part)
        if rating and part == GROUPS:
            # a rating deck's part 3 is gated per group cell (GATE_CELL) in post-processing,
            # like part 7, so it is outside the minVoters test (ADR 0103, TS6)
            continue
        if part in GATED and g is not None:
            require(p[P_MIN_VOTERS] <= g, "D11", f"minVoters above the gate of part {part}")
    require(
        p.get(P_COV_STATEMENTS, min(60, n_cards)) <= min(n_cards, 128),
        "D11",
        "covStatements above min(cards, 128)",
    )
    grid = p.get(P_GRID, DEFAULT_GRID)
    require(8 <= grid <= 64, "D11", "grid out of 8..64")
    blur = rat_value(p[P_BLUR]) if P_BLUR in p else Fraction(1)
    require(0 <= blur <= grid, "D11", "blur out of 0..grid")
    scale = p.get(P_COV_SCALE, DEFAULT_COV_SCALE)
    require(scale & (scale - 1) == 0 and 2**8 <= scale <= 2**24, "D11", "covScale")
    window = p.get(P_ROUND_WINDOW, DEFAULT_ROUND_WINDOW)
    require(3600 <= window <= 2_592_000, "D11", "roundWindow out of range")
    # D12
    prev = view.prev_env
    if prev is not None:
        pb = prev[m.BODY]
        for key in (TITLE, OPENS, TOPICS, CARDS, PLAN, ORDER, KIND):
            require(b[key] == pb[key], "D12", f"body key {key} changed")
        require(refs == prev[m.REFS], "D12", "refs changed")
        require(b[CLOSES] >= pb[CLOSES], "D12", "closes moved earlier")
        require(env.get(m.EXPIRES, 0) >= prev.get(m.EXPIRES, 0), "D12", "expires lowered")
        require(
            env.get(m.EXPIRES, 0) <= prev.get(m.EXPIRES, 0) or b[CLOSES] > pb[CLOSES],
            "D12",
            "expires raised without moving closes",
        )
    # D13
    require(m.EXPIRES in env, "D13", "expires is required")
    rounds = post_close_rounds(p)
    require(
        env[m.EXPIRES] >= b[CLOSES] + (rounds + 1) * window,
        "D13",
        "expires too short for the rounds",
    )
    require(
        env[m.EXPIRES] <= b[CLOSES] + PUBLISH_WINDOW + (rounds + 1) * window,
        "D13",
        "expires beyond closes + PUBLISH_WINDOW + (R+1) roundWindows",
    )
    # D14
    require(1 <= p[P_CAP] <= c.MAX_CARDS, "D14", "cap out of 1..MAX_CARDS")
    if P_CAP_MOVEMENT in p:
        require(1 <= p[P_CAP_MOVEMENT] <= n_cards, "D14", "capMovement out of range")
    if P_CAP_RATINGS in p:
        require(1 <= p[P_CAP_RATINGS] <= arg_count, "D14", "capRatings above the argument count")
    # D15
    if rating:
        _rating_rules(view, b, p, parts, cards, card_cids, side_refs, ctx_lineage)
    else:
        require("source" not in refs, "D15", "vote deck with a source ref")
        require(all(cd[C_KIND] != CARD_TAKE for cd in cards), "D15", "take card in a vote deck")
    # D16, the clock-free half (ADR 0103 item 2): a deck version is invalid when a release
    # version that pins its lineage has a lower index in the context's ledger of record
    record = ctx_body[c.LOGS][0][c.L_LOG]
    own_lineage = env.get(m.LINEAGE, view.bundle.cid)
    for pos, rel, bnd in view.all_of_type("release"):
        if bnd.proof.log != record or (view.position is not None and pos >= view.position):
            continue
        pinned = rel[m.REFS].get("deck")
        if pinned is not None and view.lineage_of(pinned) == own_lineage:
            raise TypeRule("D16", f"a release pinning this lineage is logged earlier (index {pos})")


def log_check(env: dict[int, Any], prev_env: dict[int, Any] | None, log_now: int):
    """D16, run by the ledger and each aggregator at submission with its own clock: a version
    above 1 is refused once the previous version's ``closes`` has passed. Phones never run it
    (a logged version verifies later, at any clock). Returns ``(rule, reason)`` or None."""
    if prev_env is None:
        return None
    closes = prev_env[m.BODY][CLOSES]
    if log_now >= closes:
        return ("D16", f"previous version's closes ({closes}) has passed at {log_now}")
    return None


def _rating_rules(view, b, p, parts, cards, card_cids, side_refs, ctx_lineage) -> None:
    refs = view.refs
    require("source" in refs, "D15", "rating deck needs a source ref")
    src = view.manifest(refs["source"])
    require(src is not None and src[m.TYPE] == "release", "D15", "source is not a release")
    require(src[m.BODY].get(3) is True, "D15", "source release is not final")
    src_deck = view.manifest(src[m.REFS].get("deck", b""))
    require(src_deck is not None, "D15", "source's deck does not resolve")
    require(
        view.lineage_of(src_deck[m.REFS]["context"]) == ctx_lineage,
        "D15",
        "source release is from another context",
    )
    require(3 in src[m.BODY].get(8, []), "D15", "source release did not unlock groups")
    require(all(cd[C_KIND] == CARD_TAKE for cd in cards), "D15", "every card must be a take")
    require(not side_refs, "D15", "rating decks carry no argument refs")
    eligible = _eligible_takes(view, refs["source"])
    want = [cid for _, cid in eligible][:RATING_CARDS_MAX]
    got = [card_cids[i] for i in range(len(cards))]
    require(got == want, "D15", "cards are not exactly the eligible takes in log order")
    # parts are exactly 0, 3 and 8 by D8
    floor_min = c.floors_of(view.manifest(refs["context"])[m.BODY])["minVoters"]
    want_min = max(c.GATE_TALLIES, floor_min)
    require(
        p[P_MIN_VOTERS] == want_min,
        "D15",
        f"rating minVoters must be max(GATE_TALLIES, the context's minimum) = {want_min}",
    )
    if want_min > c.GATE_TALLIES:
        require(
            p.get(P_GATES, {}).get(TALLIES) == want_min,
            "D15",
            "a rating deck above GATE_TALLIES sets gates[0] to its minVoters",
        )
    require(rat_value(p[P_RHO]) <= PLAN_RATING_RHO_MAX, "D15", "rating rho above 1/20")
    require(p[P_CAP] <= RATING_CAP_MAX, "D15", "rating cap above 20")
    require(len(b[TOPICS]) == 1, "D15", "rating deck topics must have one entry")


def _eligible_takes(view: m.Resolved, source: bytes) -> list[tuple[int, bytes]]:
    """(position, take version CID) of eligible takes in log order (take.md, D15)."""
    by_lineage: dict[bytes, tuple[int, dict, m.Bundle]] = {}
    for pos, env, bnd in view.all_of_type("take"):
        if view.position is not None and pos >= view.position:
            continue
        lineage = env.get(m.LINEAGE, bnd.cid)
        cur = by_lineage.get(lineage)
        if cur is None or env[m.VERSION] > cur[1][m.VERSION]:
            by_lineage[lineage] = (pos, env, bnd)
    out = []
    for pos, env, bnd in by_lineage.values():
        if env[m.BODY].get(TAKE_RETIRED, False):
            continue
        pins = [v for k, v in env[m.REFS].items() if k.startswith("release/")]
        if source in pins:
            out.append((pos, bnd.cid))
    return sorted(out)


def schema(env: dict[int, Any]) -> None:
    """Step 4 holds nothing for decks: deck.md assigns D1 to step 10, where ``rules`` runs it."""
    if not isinstance(env[m.BODY], dict):
        raise TypeRule("D1", "body must be a map")


def record_log(view: m.Resolved) -> bytes | None:
    """Step 7 hook: the ledger of record of the context this deck names (the first entry of
    its ``logs``), or None when the context is not held (step 9 reports that)."""
    ctx_cid = view.env[m.REFS].get("context")
    ctx_env = view.manifest(ctx_cid) if isinstance(ctx_cid, bytes) else None
    try:
        return ctx_env[m.BODY][c.LOGS][0][c.L_LOG] if ctx_env is not None else None
    except (KeyError, IndexError, TypeError):
        return None


m.register("deck", schema=schema, rules=rules, record_log=record_log)
