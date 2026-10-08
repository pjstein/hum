"""The ``take`` body: docs/specs/take.md.

TK-5 replaces verification step 6 (the author's keyset threshold, or an ``hum/author/1``
signature by the sponsor's ``agentKey``); TK-1 to TK-4 and TK-6 to TK-9 run at step 10.
Also here: the text blob, ``query_hash``, the noise math every client uses for error bars
and "within noise" flags, the measures, and the gallery score and sort key.

seam: TK-5 signatures (``hum/author/1`` reused from issue-map.md); the rating plan budget is
``deck.md``'s and is checked there (D15).
"""

from __future__ import annotations

import hashlib
import math
from typing import Any

from .. import cbor
from .. import manifest as m
from ..keys import verify
from . import (
    LANG_RE,
    TypeRule,
    is_cid,
    is_text,
    is_uint,
    no_unknown_keys,
    require,
    require_keys,
)
from . import context as c
from . import issue_map as im

__all__ = [
    "MEASURE_TABLES",
    "Z",
    "body",
    "chart",
    "decode_text_blob",
    "difference",
    "encode_text_blob",
    "gallery_score",
    "measure",
    "pooled_sigma",
    "query",
    "query_hash",
    "rank",
    "rules",
    "schema",
    "series",
    "share",
    "signatures",
    "sort_key",
]

# ---------------------------------------------------------------- keys

AUTHOR, QUERY, CHART, SEALED, EPOCH, LANG, ASSISTED, RETIRED = range(8)
REQUIRED = {AUTHOR, QUERY, CHART, SEALED}
ALL_KEYS = set(range(8))
AUTHORITY, AGENT = 0, 3
Q_SERIES, Q_COMPARE = 0, 1
S_RELEASE, S_TABLE, S_STATEMENTS, S_GROUP, S_VALUE, S_MEASURE, S_COLUMN, S_CELL = range(8)
CH_TYPE, CH_INTERVAL, CH_FLAG, CH_SORT_BY, CH_AXIS_MIN, CH_AXIS_MAX = range(6)
TB_TITLE, TB_BYLINE, TB_LABELS, TB_PROSE = range(4)
MAX_RELEASES = 8
MAX_SERIES = 12
MAX_STATEMENTS = 256
TEXT_MEDIA = "application/hum-take+cbor"
QUERY_HASH_DOMAIN = b"hum/take-query/1"
CAP_TAKE = 4
Z = {80: 1.282, 90: 1.645, 95: 1.960}
INTERVALS = set(Z)

(
    AGREE_SHARE, DISAGREE_SHARE, UNSURE_SHARE, AGREE_MINUS_DISAGREE, COUNT, PARTICIPANTS,
    MOVED_TOWARD, MOVED_AWAY, UNCHANGED, MOVES_ME, AGAINST, CONSENSUS_SCORE, REPNESS_SCORE,
    MAP_CELL,
) = range(14)  # fmt: skip

# Which measures each table takes (take.md, "Measures and the cells they read").
MEASURE_TABLES: dict[str, set[int]] = {
    "tallies": {
        AGREE_SHARE,
        DISAGREE_SHARE,
        UNSURE_SHARE,
        AGREE_MINUS_DISAGREE,
        COUNT,
        PARTICIPANTS,
    },
    "group_tallies": {AGREE_SHARE, DISAGREE_SHARE, UNSURE_SHARE, AGREE_MINUS_DISAGREE, COUNT},
    "group_sizes": {COUNT, PARTICIPANTS},
    "breakdown": {AGREE_SHARE, DISAGREE_SHARE, UNSURE_SHARE, AGREE_MINUS_DISAGREE, COUNT},
    "movement": {MOVED_TOWARD, MOVED_AWAY, UNCHANGED, COUNT},
    "moved": {COUNT},
    "ratings": {MOVES_ME, AGAINST, COUNT},
    "group_ratings": {MOVES_ME, AGAINST, COUNT},
    "consensus": {CONSENSUS_SCORE},
    "repness": {REPNESS_SCORE},
    "map": {MAP_CELL},
}
GROUP_TABLES = {"group_tallies", "group_sizes", "group_ratings", "repness"}
STATEMENT_TABLES = {
    "tallies", "group_tallies", "breakdown", "movement", "moved", "ratings", "group_ratings",
    "consensus", "repness",
}  # fmt: skip
TOWARD = {(1, 0), (2, 0), (1, 2)}
AWAY = {(0, 1), (0, 2), (2, 1)}


# ---------------------------------------------------------------- builders


def series(
    release: int,
    table: str,
    measure_: int,
    *,
    statements: list[bytes] | None = None,
    group: int | None = None,
    value: int | None = None,
    column: str | None = None,
    cell: list[int] | None = None,
) -> dict[int, Any]:
    out: dict[int, Any] = {
        S_RELEASE: release,
        S_TABLE: table,
        S_STATEMENTS: list(statements or []),
        S_MEASURE: measure_,
    }
    for k, v in ((S_GROUP, group), (S_VALUE, value), (S_COLUMN, column), (S_CELL, cell)):
        if v is not None:
            out[k] = v
    return out


def query(series_: list[dict], compare: int = 0) -> dict[int, Any]:
    return {Q_SERIES: list(series_), Q_COMPARE: compare}


def chart(
    type_: int = 0,
    interval: int = 90,
    flag: bool = True,
    sort_by: int = 0,
    axis_min: int | None = None,
    axis_max: int | None = None,
) -> dict[int, Any]:
    out = {CH_TYPE: type_, CH_INTERVAL: interval, CH_FLAG: flag, CH_SORT_BY: sort_by}
    if axis_min is not None:
        out[CH_AXIS_MIN] = axis_min
    if axis_max is not None:
        out[CH_AXIS_MAX] = axis_max
    return out


def body(
    *,
    author: int,
    query_: dict,
    chart_: dict,
    sealed: bool,
    epoch: int | None = None,
    lang: str | None = None,
    assisted: bool | None = None,
    retired: bool | None = None,
) -> dict[int, Any]:
    out: dict[int, Any] = {AUTHOR: author, QUERY: query_, CHART: chart_, SEALED: sealed}
    for k, v in ((EPOCH, epoch), (LANG, lang), (ASSISTED, assisted), (RETIRED, retired)):
        if v is not None:
            out[k] = v
    return out


def encode_text_blob(title: str, byline: str, labels: list[str], prose: str) -> bytes:
    return cbor.encode(
        {TB_TITLE: title, TB_BYLINE: byline, TB_LABELS: list(labels), TB_PROSE: prose}
    )


def decode_text_blob(data: bytes) -> dict[str, Any]:
    """The text blob map with its limits (TK-2)."""
    try:
        item = cbor.decode(data)
    except cbor.CborError as e:
        raise TypeRule("TK-2", f"text blob is not deterministic CBOR: {e}") from e
    require_keys(item, {TB_TITLE, TB_BYLINE, TB_LABELS, TB_PROSE}, "TK-2", "text blob")
    no_unknown_keys(item, {TB_TITLE, TB_BYLINE, TB_LABELS, TB_PROSE}, "TK-2", "text blob")
    require(is_text(item[TB_TITLE], 240), "TK-2", "title over 240 bytes or malformed")
    require(is_text(item[TB_BYLINE], 80), "TK-2", "byline over 80 bytes or malformed")
    labels = item[TB_LABELS]
    require(isinstance(labels, list) and all(is_text(x, 80) for x in labels), "TK-2", "labels")
    require(is_text(item[TB_PROSE], 16_000), "TK-2", "prose over 16,000 bytes or malformed")
    return {
        "title": item[TB_TITLE],
        "byline": item[TB_BYLINE],
        "labels": labels,
        "prose": item[TB_PROSE],
    }


def query_hash(query_: dict, chart_: dict) -> bytes:
    """``SHA-256("hum/take-query/1" ‖ CBOR [query, chart])``."""
    return hashlib.sha256(QUERY_HASH_DOMAIN + cbor.encode([query_, chart_])).digest()


# ---------------------------------------------------------------- step 4: shapes


def _check_series(s: Any, i: int) -> None:
    require(isinstance(s, dict), "TK-4", f"series {i} must be a map")
    no_unknown_keys(s, set(range(8)), "TK-4", f"series {i}")
    require_keys(s, {S_RELEASE, S_TABLE, S_MEASURE}, "TK-4", f"series {i}")
    require(is_uint(s[S_RELEASE]), "TK-4", f"series {i} release index")
    require(isinstance(s[S_TABLE], str), "TK-4", f"series {i} table")
    require(is_uint(s[S_MEASURE]), "TK-4", f"series {i} measure")
    stmts = s.get(S_STATEMENTS, [])
    require(isinstance(stmts, list) and all(is_cid(x) for x in stmts), "TK-4", "statements")
    if S_GROUP in s:
        require(is_uint(s[S_GROUP]), "TK-4", f"series {i} group")
    if S_VALUE in s:
        require(is_uint(s[S_VALUE]), "TK-4", f"series {i} value")
    if S_COLUMN in s:
        require(isinstance(s[S_COLUMN], str), "TK-4", f"series {i} column")
    if S_CELL in s:
        cell = s[S_CELL]
        require(
            isinstance(cell, list) and len(cell) == 2 and all(is_uint(x) for x in cell),
            "TK-4",
            f"series {i} cell",
        )


def schema(env: dict[int, Any]) -> None:
    b = env[m.BODY]
    require_keys(b, REQUIRED, "TK-2")
    require(b[AUTHOR] in (AUTHORITY, AGENT), "TK-5", "author must be 0 or 3")
    require(isinstance(b[SEALED], bool), "TK-2", "sealed must be a bool")
    if EPOCH in b:
        require(is_uint(b[EPOCH]), "TK-2", "epoch")
    if LANG in b:
        require(is_text(b[LANG], 16, pattern=LANG_RE), "TK-2", "lang")
    if ASSISTED in b:
        require(isinstance(b[ASSISTED], bool), "TK-2", "assisted")
    if RETIRED in b:
        require(isinstance(b[RETIRED], bool), "TK-2", "retired")
    q = b[QUERY]
    require(isinstance(q, dict), "TK-4", "query must be a map")
    no_unknown_keys(q, {Q_SERIES, Q_COMPARE}, "TK-4", "query")
    require_keys(q, {Q_SERIES, Q_COMPARE}, "TK-4", "query")
    require(isinstance(q[Q_SERIES], list), "TK-4", "series must be a list")
    for i, s in enumerate(q[Q_SERIES]):
        _check_series(s, i)
    require(is_uint(q[Q_COMPARE], 0, 4), "TK-4", "compare")
    ch = b[CHART]
    require(isinstance(ch, dict), "TK-7", "chart must be a map")
    no_unknown_keys(ch, set(range(6)), "TK-7", "chart")
    require_keys(ch, {CH_TYPE, CH_INTERVAL, CH_FLAG, CH_SORT_BY}, "TK-7", "chart")
    require(
        is_uint(ch[CH_TYPE]) and is_uint(ch[CH_INTERVAL]) and is_uint(ch[CH_SORT_BY]),
        "TK-7",
        "chart",
    )
    require(isinstance(ch[CH_FLAG], bool), "TK-7", "flagWithinNoise must be a bool")
    for k in (CH_AXIS_MIN, CH_AXIS_MAX):
        if k in ch:
            require(isinstance(ch[k], int) and not isinstance(ch[k], bool), "TK-7", "axis")


# ---------------------------------------------------------------- step 6: TK-5


def _sponsor_env(view: m.Resolved) -> dict[int, Any]:
    refs = view.refs
    require("sponsor" in refs, "TK-6", "agent take without a sponsor ref")
    sp = view.manifest(refs["sponsor"])
    require(
        sp is not None and sp.get(m.TYPE) == "agent-sponsor",
        "TK-5",
        "sponsor is not an agent-sponsor",
    )
    require(sp.get(m.AUTHORITY) == view.env[m.AUTHORITY], "TK-5", "sponsor authority differs")
    require(m.EXPIRES in sp and view.env[m.ISSUED] < sp[m.EXPIRES], "TK-5", "sponsor expired")
    lineage = sp.get(m.LINEAGE, refs["sponsor"])
    latest = view.latest_before(lineage, view.position) or sp
    require(not latest[m.BODY].get(im.SP_RETIRED, False), "TK-5", "sponsor lineage retired")
    require(not sp[m.BODY].get(im.SP_RETIRED, False), "TK-5", "sponsor version retired")
    require(CAP_TAKE in sp[m.BODY].get(im.SP_CAPABILITIES, []), "TK-5", "sponsor lacks take")
    return sp


def signatures(view: m.Resolved, sigs, keyset_body: dict[int, Any], revoked) -> None:
    b = view.body
    cid = view.bundle.cid
    if b[AUTHOR] == AUTHORITY:
        require(sigs is not None, "TK-5", "an authority take carries COSE signatures")
        require(view.bundle.authorship is None, "TK-5", "authority take with an authorship field")
        need = keyset_body[m.KS_THRESHOLDS][m.ROLE_SIGN]
        have = m.count_valid_signatures(keyset_body, m.ROLE_SIGN, sigs, cid, revoked, view.position)
        require(have >= need, "TK-5", f"{have} valid sign signatures, threshold {need}")
        return
    require(sigs is None, "TK-5", "agent take with COSE signatures")
    require(view.bundle.authorship is not None, "TK-5", "agent take without authorship")
    a = im.Authorship.decode(view.bundle.authorship)
    require(a.form == im.AGENT, "TK-5", "authorship form must be 3")
    sp = _sponsor_env(view)
    agent_key = sp[m.BODY][im.SP_AGENT_KEY]
    require(verify(agent_key, im.bound_message(cid), a.sig), "TK-5", "hum/author/1 signature")


# ---------------------------------------------------------------- step 10: TK-1..TK-4, TK-6..TK-9


def _release_refs(refs: dict[str, bytes]) -> list[bytes]:
    names = sorted(k for k in refs if k.startswith("release/"))
    expected = [f"release/{n}" for n in range(len(names))]
    require(names == expected, "TK-1", "release/<n> refs must be contiguous from 0")
    require(1 <= len(names) <= MAX_RELEASES, "TK-1", "1 to 8 releases")
    return [refs[n] for n in expected]


def _deck_and_context(view: m.Resolved, release_cid: bytes) -> tuple[dict, dict, bytes]:
    rel = view.manifest(release_cid)
    require(
        rel is not None and rel.get(m.TYPE) == "release", "TK-1", "a release ref is not a release"
    )
    deck = view.manifest(rel[m.REFS].get("deck", b""))
    require(
        deck is not None and deck.get(m.TYPE) == "deck",
        "TK-1",
        "the release's deck does not resolve",
    )
    ctx_cid = deck[m.REFS].get("context", b"")
    ctx = view.manifest(ctx_cid)
    require(
        ctx is not None and ctx.get(m.TYPE) == "context",
        "TK-1",
        "the deck's context does not resolve",
    )
    return deck, ctx, view.lineage_of(ctx_cid)


def _pinned_statements(deck: dict) -> set[bytes]:
    return {v for k, v in deck[m.REFS].items() if k.startswith("card/")}


def rules(view: m.Resolved) -> None:
    env, refs, b = view.env, view.refs, view.body
    # TK-2 shape (the blob half runs below when the blob is held)
    no_unknown_keys(b, ALL_KEYS, "TK-2")
    require("text" in refs, "TK-2", "text ref missing")
    require((EPOCH in b) == b[SEALED], "TK-2", "sealed iff epoch present")
    # TK-1
    releases = _release_refs(refs)
    decks: list[dict] = []
    contexts: list[dict] = []
    lineages: list[bytes] = []
    for rc in releases:
        deck, ctx, lineage = _deck_and_context(view, rc)
        decks.append(deck)
        contexts.append(ctx)
        lineages.append(lineage)
    # TK-3
    any_sealed = any(ctx[m.BODY][c.PERMS][c.P_RESULTS] != 0 for ctx in contexts)
    require(b[SEALED] == any_sealed, "TK-3", "sealed must follow the pinned releases' contexts")
    if b[SEALED]:
        require(len(set(lineages)) == 1, "TK-3", "a sealed take pins releases of one context")
    # TK-4
    series_ = b[QUERY][Q_SERIES]
    require(1 <= len(series_) <= MAX_SERIES, "TK-4", "1 to 12 series")
    for i, s in enumerate(series_):
        require(s[S_RELEASE] < len(releases), "TK-4", f"series {i} release index out of range")
        table = s[S_TABLE]
        require(table in MEASURE_TABLES, "TK-4", f"series {i} unknown table {table!r}")
        require(
            s[S_MEASURE] in MEASURE_TABLES[table],
            "TK-4",
            f"series {i} measure not allowed for {table}",
        )
        require(
            (S_GROUP in s) <= (table in GROUP_TABLES),
            "TK-4",
            f"series {i} group on a table without groups",
        )
        require((S_VALUE in s) == (table == "breakdown"), "TK-4", f"series {i} value iff breakdown")
        require(
            (S_COLUMN in s) == (s[S_MEASURE] == COUNT),
            "TK-4",
            f"series {i} column iff measure count",
        )
        require(
            (S_CELL in s) == (s[S_MEASURE] == MAP_CELL),
            "TK-4",
            f"series {i} cell iff measure mapCell",
        )
        stmts = s.get(S_STATEMENTS, [])
        require(len(stmts) <= MAX_STATEMENTS, "TK-4", f"series {i} over 256 statements")
        require(not stmts or table in STATEMENT_TABLES, "TK-4", f"series {i} statements on {table}")
        pinned = _pinned_statements(decks[s[S_RELEASE]])
        for st in stmts:
            require(st in pinned, "TK-4", f"series {i} statement not pinned by the release's deck")
    all_pinned: set[bytes] = set()
    for d in decks:
        all_pinned |= _pinned_statements(d)
    for name, cid in refs.items():
        if name.startswith("statement/"):
            require(cid in all_pinned, "TK-4", f"{name} not pinned by a pinned release's deck")
    # TK-2, blob half
    blob = view.blob(refs["text"])
    if blob is not None:
        if b[SEALED]:
            require(blob[:1] == b"\x02", "TK-2", "sealed text blob must be keyring form (0x02)")
        else:
            tb = decode_text_blob(blob)
            require(
                len(tb["labels"]) == len(series_), "TK-2", "labels must have one entry per series"
            )
    # TK-6
    require(("sponsor" in refs) == (b[AUTHOR] == AGENT), "TK-6", "sponsor present iff author is 3")
    # TK-7
    ch = b[CHART]
    require(ch[CH_TYPE] in range(5), "TK-7", "unknown chart type")
    require(ch[CH_SORT_BY] in range(3), "TK-7", "unknown sortBy")
    require(ch[CH_INTERVAL] in INTERVALS, "TK-7", "interval must be 80, 90 or 95")
    if CH_AXIS_MIN in ch and CH_AXIS_MAX in ch:
        require(ch[CH_AXIS_MIN] < ch[CH_AXIS_MAX], "TK-7", "axisMin must be below axisMax")
    # TK-9
    if "forkOf" in refs:
        parent = view.manifest(refs["forkOf"])
        require(parent is not None and parent.get(m.TYPE) == "take", "TK-9", "forkOf is not a take")
        own_lineage = env.get(m.LINEAGE, view.bundle.cid)
        require(view.lineage_of(refs["forkOf"]) != own_lineage, "TK-9", "a take cannot fork itself")
        if parent[m.BODY][SEALED]:
            require(b[SEALED], "TK-9", "a fork of a sealed take must be sealed")
            parent_rel = _release_refs(parent[m.REFS])
            _, _, parent_lineage = _deck_and_context(view, parent_rel[0])
            require(parent_lineage in lineages, "TK-9", "a sealed fork must pin the same context")
    # TK-8
    prev = view.prev_env
    if prev is not None:
        pb = prev[m.BODY]
        require(pb[AUTHOR] == b[AUTHOR], "TK-8", "author changed")
        require(pb[SEALED] == b[SEALED], "TK-8", "sealed changed")
        require(prev[m.REFS].get("forkOf") == refs.get("forkOf"), "TK-8", "forkOf changed")
        require(not pb.get(RETIRED, False), "TK-8", "a version follows a retired one")


# ---------------------------------------------------------------- noise math (binary64)


def share(counts: list[float], sigma: float, m_: int | None = None) -> dict[str, Any]:
    """Steps 1 to 3: gap test, share with σ_p, display clamp. ``counts[0]`` is the numerator."""
    m_ = len(counts) if m_ is None else m_
    n = sum(counts)
    if n < 10 * sigma or n <= 0:
        return {"too_few": True, "N": n}
    p = counts[0] / n
    sigma_p = (sigma / n) * math.sqrt((1 - p) ** 2 + (m_ - 1) * p**2)
    return {"too_few": False, "N": n, "p": p, "sigma_p": sigma_p, "display": min(max(p, 0.0), 1.0)}


def difference(agree: float, disagree: float, unsure: float, sigma: float) -> dict[str, Any]:
    """``agreeMinusDisagree`` with its σ_d."""
    n = agree + disagree + unsure
    if n < 10 * sigma or n <= 0:
        return {"too_few": True, "N": n}
    d = (agree - disagree) / n
    sigma_d = (sigma / n) * math.sqrt((1 - d) ** 2 + (1 + d) ** 2 + d**2)
    return {"too_few": False, "N": n, "d": d, "sigma_d": sigma_d, "display": min(max(d, -1.0), 1.0)}


def interval(p: float, sigma_p: float, pct: int = 90) -> tuple[float, float]:
    z = Z[pct]
    return (min(max(p - z * sigma_p, 0.0), 1.0), min(max(p + z * sigma_p, 0.0), 1.0))


def within_noise(p1: float, s1: float, p2: float, s2: float, pct: int = 90) -> bool:
    return abs(p1 - p2) < Z[pct] * math.sqrt(s1 * s1 + s2 * s2)


def pooled_sigma(sigmas: list[float]) -> float:
    return math.sqrt(sum(s * s for s in sigmas))


def measure(
    measure_: int,
    rows: list[dict[str, Any]],
    sigma: float,
    *,
    n_hat: int | None = None,
    column: str | None = None,
    cell: list[int] | None = None,
) -> dict[str, Any]:
    """Apply a measure to table rows (dicts keyed by release.md column names)."""
    if measure_ in (AGREE_SHARE, DISAGREE_SHARE, UNSURE_SHARE):
        r = rows[0]
        order = {AGREE_SHARE: "agree", DISAGREE_SHARE: "disagree", UNSURE_SHARE: "unsure"}[measure_]
        others = [k for k in ("agree", "disagree", "unsure") if k != order]
        return share([r[order], r[others[0]], r[others[1]]], sigma, 3)
    if measure_ == AGREE_MINUS_DISAGREE:
        r = rows[0]
        return difference(r["agree"], r["disagree"], r["unsure"], sigma)
    if measure_ == COUNT:
        return {"value": rows[0][column], "sigma": sigma}
    if measure_ == PARTICIPANTS:
        return {"value": n_hat if n_hat is not None else rows[0]["n"], "sigma": sigma}
    if measure_ in (MOVED_TOWARD, MOVED_AWAY, UNCHANGED):
        toward = sum(r["n"] for r in rows if (r["first"], r["second"]) in TOWARD)
        away = sum(r["n"] for r in rows if (r["first"], r["second"]) in AWAY)
        same = sum(r["n"] for r in rows if r["first"] == r["second"])
        buckets = {MOVED_TOWARD: toward, MOVED_AWAY: away, UNCHANGED: same}
        first = buckets[measure_]
        rest = [v for k, v in buckets.items() if k != measure_]
        return share([first, *rest], sigma * math.sqrt(3), 3)
    if measure_ in (MOVES_ME, AGAINST):
        r = rows[0]
        if measure_ == MOVES_ME:
            return share([r["moves"], r["neutral"], r["against"]], sigma, 3)
        return share([r["against"], r["moves"], r["neutral"]], sigma, 3)
    if measure_ == CONSENSUS_SCORE:
        return {"value": rows[0]["score"]}
    if measure_ == REPNESS_SCORE:
        return {"value": rows[0]["metric"], "significant": rows[0]["significant"]}
    if measure_ == MAP_CELL:
        x, y = cell
        for r in rows:
            if r["x"] == x and r["y"] == y:
                return {"value": r["n"], "sigma": sigma}
        raise ValueError("cell not in the map table")
    raise ValueError(f"unknown measure {measure_}")


# ---------------------------------------------------------------- gallery ranking


def fair_share(fair: float, misleading: float, sigma: float) -> dict[str, Any] | None:
    """f = fair / (fair + misleading) with m = 2; None when the gap test fails."""
    r = share([fair, misleading], sigma, 2)
    if r["too_few"]:
        return None
    return {"f": r["p"], "sigma_f": r["sigma_p"], "f_low": r["p"] - Z[90] * r["sigma_p"]}


def gallery_score(
    group_cells: list[tuple[float, float, float, float]],
    overall: tuple[float, float, float] | None,
) -> dict[str, Any]:
    """``group_cells`` are (fair, misleading, sigma, group size); ``overall`` is (fair,
    misleading, sigma). Returns rated, hasGroupScore and score."""
    lows = []
    for fair, misleading, sigma, size in group_cells:
        if size < c.GATE_CELL:
            continue
        r = fair_share(fair, misleading, sigma)
        if r is not None:
            lows.append(r["f_low"])
    if lows:
        return {"rated": True, "hasGroupScore": True, "score": min(lows)}
    if overall is not None:
        r = fair_share(*overall)
        if r is not None:
            return {"rated": True, "hasGroupScore": False, "score": r["f_low"]}
    return {"rated": False, "hasGroupScore": False, "score": None}


def sort_key(rated: bool, has_group: bool, score: float | None, fork_count: int, log_index: int):
    """take.md's sort key ``(rated, hasGroupScore, score rounded to six decimals, forkCount,
    logIndex)``, every element compared descending; ``logIndex`` is the take's version 1 leaf
    index in the log of record, so among ties the most recently logged take comes first."""
    return (
        1 if rated else 0,
        1 if has_group else 0,
        round(score, 6) if score is not None else float("-inf"),
        fork_count,
        log_index,
    )


def rank(takes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Order takes (dicts with rated, hasGroupScore, score, forkCount, logIndex) descending."""
    return sorted(
        takes,
        key=lambda t: sort_key(
            t["rated"], t["hasGroupScore"], t["score"], t["forkCount"], t["logIndex"]
        ),
        reverse=True,
    )


m.register("take", schema=schema, rules=rules, signatures=signatures)
