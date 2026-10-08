"""The ``trust-list`` body: docs/specs/trust-list.md.

Rules 1 to 9 run at verification step 4; rule 10 (the 64 KiB envelope) is manifest step 1
and is not repeated; rules 11 to 13 run at step 10 against the previous version.
``resolve_rows`` and ``credential_satisfies`` implement "How a context uses trust lists".
"""

from __future__ import annotations

from typing import Any

from .. import cbor
from .. import manifest as m
from . import LANG_RE, NAME_RE, is_cid, is_text, is_uint, no_unknown_keys, require, require_keys
from . import verifier as vf

__all__ = [
    "REASONS",
    "body",
    "credential_satisfies",
    "entry",
    "removal",
    "resolve_rows",
    "rows_for_source",
    "rules",
    "schema",
]

NAME, PUBLISHER, LANG, SCOPE, ENTRIES, REMOVED, MIN_ASSURANCE, REVIEW_PERIOD = range(8)
REQUIRED = {NAME, PUBLISHER, LANG, SCOPE, ENTRIES, MIN_ASSURANCE}
ALL_KEYS = set(range(8))
SC_KIND, SC_AREA, SC_CLASSES = range(3)
EN_AUTHORITY, EN_ATTRIBUTES, EN_MIN_ASSURANCE, EN_MIN_VERSION, EN_ATTESTED, EN_NOTE = range(6)
RM_AUTHORITY, RM_REASON, RM_NOTE = range(3)
KINDS = ("core", "federation", "community")
CLASSES = ("person", "agent")
REASONS = ("retired", "scope", "assurance", "conduct", "compromise")


# ---------------------------------------------------------------- builders


def entry(
    authority: bytes,
    attributes: list[str] | None = None,
    min_assurance: int | None = None,
    min_version: int | None = None,
    attested: list[bytes] | None = None,
    note: str | None = None,
) -> dict:
    out: dict[int, Any] = {EN_AUTHORITY: authority, EN_ATTRIBUTES: list(attributes or [])}
    for k, v in ((EN_MIN_ASSURANCE, min_assurance), (EN_MIN_VERSION, min_version),
                 (EN_ATTESTED, attested), (EN_NOTE, note)):  # fmt: skip
        if v is not None:
            out[k] = v
    return out


def removal(authority: bytes, reason: str, note: str | None = None) -> dict:
    out = {RM_AUTHORITY: authority, RM_REASON: reason}
    if note is not None:
        out[RM_NOTE] = note
    return out


def body(
    *,
    name: str,
    publisher: str,
    kind: str,
    entries: list[dict],
    min_assurance: int,
    classes: list[str] | None = None,
    area: str | None = None,
    removed: list[dict] | None = None,
    review_period: int | None = None,
    lang: str = "en",
) -> dict[int, Any]:
    scope: dict[int, Any] = {
        SC_KIND: kind,
        SC_CLASSES: classes if classes is not None else ["person"],
    }
    if area is not None:
        scope[SC_AREA] = area
    out: dict[int, Any] = {
        NAME: name,
        PUBLISHER: publisher,
        LANG: lang,
        SCOPE: scope,
        ENTRIES: entries,
        MIN_ASSURANCE: min_assurance,
    }
    if removed is not None:
        out[REMOVED] = removed
    if review_period is not None:
        out[REVIEW_PERIOD] = review_period
    return out


# ---------------------------------------------------------------- step 4: rules 1 to 9


def schema(env: dict[int, Any]) -> None:
    b = env[m.BODY]
    require_keys(b, REQUIRED, "2")
    no_unknown_keys(b, ALL_KEYS, "2")
    sc = b[SCOPE]
    require_keys(sc, {SC_KIND, SC_CLASSES}, "1", "scope")
    no_unknown_keys(sc, {SC_KIND, SC_AREA, SC_CLASSES}, "2", "scope")
    require(sc[SC_KIND] in KINDS, "1", "scope.kind")
    cl = sc[SC_CLASSES]
    require(
        isinstance(cl, list) and cl and set(cl) <= set(CLASSES) and len(set(cl)) == len(cl),
        "1",
        "scope.classes",
    )
    require(is_text(b[LANG], 16, pattern=LANG_RE), "1", "lang pattern")
    require(is_text(b[NAME], 64), "2", "name")
    require(is_text(b[PUBLISHER], 64), "2", "publisher")
    if SC_AREA in sc:
        require(is_text(sc[SC_AREA], 64), "2", "scope.area")
    entries = b[ENTRIES]
    require(isinstance(entries, list) and len(entries) <= 256, "2", "entries at most 256")
    removed = b.get(REMOVED, [])
    require(isinstance(removed, list) and len(removed) <= 256, "2", "removed at most 256")
    require(is_uint(b[MIN_ASSURANCE], 0, 3), "3", "minAssurance 0..3")
    if REVIEW_PERIOD in b:
        require(is_uint(b[REVIEW_PERIOD]), "2", "reviewPeriod")
    authorities = []
    for e in entries:
        require_keys(e, {EN_AUTHORITY, EN_ATTRIBUTES}, "2", "entry")
        no_unknown_keys(e, set(range(6)), "2", "entry")
        require(is_cid(e[EN_AUTHORITY]) and e[EN_AUTHORITY][0] == 0x01, "5", "entry authority CID")
        authorities.append(e[EN_AUTHORITY])
        at = e[EN_ATTRIBUTES]
        require(isinstance(at, list) and len(at) <= 32, "2", "entry attributes at most 32")
        require(all(is_text(x, 32, pattern=NAME_RE) for x in at), "6", "attribute name pattern")
        require(len(set(at)) == len(at), "6", "duplicate attribute in entry")
        if EN_MIN_ASSURANCE in e:
            require(is_uint(e[EN_MIN_ASSURANCE], 0, 3), "3", "entry minAssurance 0..3")
            require(
                e[EN_MIN_ASSURANCE] >= b[MIN_ASSURANCE],
                "3",
                "entry minAssurance below the list floor",
            )
        if EN_MIN_VERSION in e:
            require(is_uint(e[EN_MIN_VERSION], 1), "9", "minVersion at least 1")
        if EN_ATTESTED in e:
            att = e[EN_ATTESTED]
            require(
                isinstance(att, list) and len(att) <= 8 and all(is_cid(c) for c in att),
                "2",
                "attested",
            )
            require(len(set(att)) == len(att), "8", "duplicate attested CID")
        if EN_NOTE in e:
            require(is_text(e[EN_NOTE], 140), "2", "entry note")
    require(len(set(authorities)) == len(authorities), "4", "duplicate entry authority")
    removed_auth = []
    for r in removed:
        require_keys(r, {RM_AUTHORITY, RM_REASON}, "7", "removal")
        no_unknown_keys(r, {RM_AUTHORITY, RM_REASON, RM_NOTE}, "2", "removal")
        require(
            is_cid(r[RM_AUTHORITY]) and r[RM_AUTHORITY][0] == 0x01, "5", "removal authority CID"
        )
        require(r[RM_REASON] in REASONS, "7", "unknown removal reason")
        if RM_NOTE in r:
            require(is_text(r[RM_NOTE], 140), "2", "removal note")
        removed_auth.append(r[RM_AUTHORITY])
    require(len(set(removed_auth)) == len(removed_auth), "7", "duplicate removal")
    require(not set(removed_auth) & set(authorities), "7", "removed authority also in entries")


# ---------------------------------------------------------------- step 10: rules 11 to 13


def rules(view: m.Resolved) -> None:
    prev = view.prev_env
    if prev is None:
        return
    b, pb = view.body, prev[m.BODY]
    require(b[SCOPE][SC_KIND] == pb[SCOPE][SC_KIND], "11", "scope.kind changed")
    old = {e[EN_AUTHORITY] for e in pb[ENTRIES]}
    new = {e[EN_AUTHORITY] for e in b[ENTRIES]}
    removed = {r[RM_AUTHORITY] for r in b.get(REMOVED, [])}
    for a in old - new:
        require(a in removed, "12", "an entry was dropped without a removed row")
    for a in removed:
        require(a in old, "13", "a removal names an authority that was not an entry")


# ---------------------------------------------------------------- resolution


def rows_for_source(
    source: list[int], ctx_body: dict[int, Any], trust_lists: list[dict[int, Any]]
) -> list[list]:
    """Rows ``[authority, filter, minAssurance, minVersion, classes]`` for one policy source.

    ``trust_lists[i]`` is the body of the trust list pinned at ``tl/<i>``; ``ctx_body`` is the
    context body (its ``issuers`` are key 4). Rows come back sorted bytewise on their canonical
    CBOR encoding.
    """
    from . import context as c

    kind, i = source
    rows: list[list] = []
    if kind == c.SRC_ISSUER:
        rows.append([ctx_body[c.ISSUERS][i], "*", 0, 1, ["person", "agent"]])
    elif kind == c.SRC_TRUST_LIST:
        tl = trust_lists[i]
        floor = tl[MIN_ASSURANCE]
        classes = list(tl[SCOPE][SC_CLASSES])
        for e in tl[ENTRIES]:
            min_a = max(floor, e.get(EN_MIN_ASSURANCE, 0))
            min_v = e.get(EN_MIN_VERSION, 1)
            filters = e[EN_ATTRIBUTES] or ["*"]
            for f in filters:
                rows.append([e[EN_AUTHORITY], f, min_a, min_v, classes])
    else:
        raise ValueError("unknown source kind")
    return sorted(rows, key=cbor.encode)


def resolve_rows(
    ctx_body: dict[int, Any], trust_lists: list[dict[int, Any]]
) -> dict[str, list[list]]:
    """Rows for every source the context's policies could name: ``tl/<i>`` and ``issuers/<i>``."""
    from . import context as c

    out = {}
    for i in range(len(trust_lists)):
        out[f"tl/{i}"] = rows_for_source([c.SRC_TRUST_LIST, i], ctx_body, trust_lists)
    for i in range(len(ctx_body.get(c.ISSUERS, []))):
        out[f"issuers/{i}"] = rows_for_source([c.SRC_ISSUER, i], ctx_body, trust_lists)
    return out


def credential_satisfies(
    rows: list[list],
    attribute: str,
    *,
    verifier_authority: bytes,
    verifier_env: dict[int, Any] | None,
    kid: bytes,
    use: str = "gate",
    policy: str = "entry",
) -> bool:
    """Step 4 of "How a context uses trust lists", plus rules 5 and 6.

    ``verifier_env`` is the verifier version in force at the presentation's log position, or
    ``None`` when the lineage is retired (rule 6). ``use`` is ``gate`` or ``breakdown``;
    ``policy`` is ``entry`` or ``vote`` (rule 5).
    """
    if verifier_env is None:
        return False
    vb = verifier_env[m.BODY]
    attrs = {a[vf.AT_NAME]: a for a in vb[vf.ATTRIBUTES]}
    a = attrs.get(attribute)
    if a is None:
        return False
    since = None
    for k in vb[vf.ISSUER_KEYS]:
        if k[vf.IK_KID] == kid:
            since = k[vf.IK_SINCE]
    if since is None:
        return False
    if use == "breakdown" and a[vf.AT_EXPOSURE] != "breakdown":
        return False
    if policy == "vote" and vb[vf.CLASS] == "agent":
        return False
    for authority, flt, min_a, min_v, classes in rows:
        if authority != verifier_authority:
            continue
        if flt not in ("*", attribute):
            continue
        if vb[vf.ASSURANCE] < min_a or since < min_v or vb[vf.CLASS] not in classes:
            continue
        return True
    return False


m.register("trust-list", schema=schema, rules=rules)
