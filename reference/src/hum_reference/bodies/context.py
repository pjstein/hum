"""The ``context`` body: docs/specs/context.md.

Protocol constants, the body schema (C1, C2, C5 shape, C9, C12 shape, C15 shape run at step
4), the step-10 rules C1 to C16, policy evaluation, the results key derivation and the
daily-count bucketing.
"""

from __future__ import annotations

import hashlib
import hmac
from fractions import Fraction
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .. import manifest as m
from . import (
    NAME_RE,
    TypeRule,
    check_cid,
    check_rat,
    check_text,
    is_bytes,
    is_cid,
    is_text,
    is_uint,
    no_unknown_keys,
    rat_value,
    require,
    require_keys,
)

__all__ = [
    "AGENT_SPONSOR_ATTR",
    "CONSTANTS",
    "Policy",
    "body",
    "count_buckets",
    "evaluate_policy",
    "floors_of",
    "results_key",
    "rules",
    "schema",
]

# ---------------------------------------------------------------- protocol constants

RHO_MAX = Fraction(127, 500)
DELTA_MAX = Fraction(1, 10**6)
MIN_VOTERS = 100
RELEASES_PER_DECK = 1
SHIELD_YEAR_EPS = Fraction(20)
MIN_WITNESSES = 2
COUNT_RHO_MAX = Fraction(1, 50)
AUTHOR_WINDOW = 86_400
GATE_TALLIES, GATE_COMMON, GATE_MAP, GATE_CELL, GATE_CHECKS = 100, 300, 800, 300, 5000
MAX_CARDS = 256
MAX_TOPICS = 32
MAX_POLICY_LEAVES = 32
MAX_POLICY_DEPTH = 4
CONSTANTS = {
    "RHO_MAX": RHO_MAX,
    "DELTA_MAX": DELTA_MAX,
    "MIN_VOTERS": MIN_VOTERS,
    "RELEASES_PER_DECK": RELEASES_PER_DECK,
    "SHIELD_YEAR": SHIELD_YEAR_EPS,
    "MIN_WITNESSES": MIN_WITNESSES,
    "COUNT_RHO_MAX": COUNT_RHO_MAX,
    "AUTHOR_WINDOW": AUTHOR_WINDOW,
    "GATE_TALLIES": GATE_TALLIES,
    "GATE_COMMON": GATE_COMMON,
    "GATE_MAP": GATE_MAP,
    "GATE_CELL": GATE_CELL,
    "GATE_CHECKS": GATE_CHECKS,
    "MAX_CARDS": MAX_CARDS,
    "MAX_TOPICS": MAX_TOPICS,
    "MAX_POLICY_LEAVES": MAX_POLICY_LEAVES,
    "MAX_POLICY_DEPTH": MAX_POLICY_DEPTH,
}

# ---------------------------------------------------------------- body keys

(
    NAME, SEALED, ENTRY, VOTE, ISSUERS, PERMS, FLOORS, LOGS, AGGREGATORS, STORES, STORAGE, CHAT,
    MIX_GLOBAL, RESULTS_KEY, RESULTS_EPOCH, COUNT, MAP, AGENTS, ABOUT_EPOCH, NULLIFIER,
) = range(20)  # fmt: skip
REQUIRED = {
    NAME,
    SEALED,
    ENTRY,
    PERMS,
    FLOORS,
    LOGS,
    AGGREGATORS,
    STORES,
    STORAGE,
    CHAT,
    MIX_GLOBAL,
    NULLIFIER,
}
ALL_KEYS = set(range(20))

P_CARDS, P_RESULTS, P_MEMBER_LIST = 0, 1, 2
F_RHO, F_DELTA, F_MIN_VOTERS, F_RELEASES, F_RHO_YEAR, F_MIN_WITNESSES = range(6)
L_LOG, L_WITNESSES = 0, 1
S_RETENTION, S_MAX_BLOB, S_HISTORY, S_QUOTA, S_KEYRING_HISTORY, S_SENSITIVE_MAX = range(6)
RETENTION_KINDS = {0, 1, 2, 3, 4}
CH_ALL, CH_ORGANIZERS, CH_DELIVERY, CH_GREETING, CH_ISSUER_KEYS = range(5)
CNT_RHO_MAX = 0
MAP_UNSIGNED, MAP_SIGNED, MAP_AGENT = 1, 2, 3
AG_ANY, AG_SPONSORS, AG_ADD_ROLE = 0, 1, 2
AGENT_SPONSOR_ATTR = "agent-sponsor"

NODE_TRUE, NODE_ALL, NODE_ANY, NODE_ATTR = 0, 1, 2, 3
SRC_TRUST_LIST, SRC_ISSUER = 0, 1
PRED_PRESENT, PRED_SET, PRED_RANGE = 0, 1, 2


# ---------------------------------------------------------------- builders


def floors(
    rho: Fraction = RHO_MAX,
    delta: Fraction = DELTA_MAX,
    min_voters: int = MIN_VOTERS,
    releases_per_deck: int = 1,
    min_witnesses: int = MIN_WITNESSES,
    rho_year: Fraction | None = None,
) -> dict[int, Any]:
    out = {
        F_RHO: [rho.numerator, rho.denominator],
        F_DELTA: [delta.numerator, delta.denominator],
        F_MIN_VOTERS: min_voters,
        F_RELEASES: releases_per_deck,
        F_MIN_WITNESSES: min_witnesses,
    }
    if rho_year is not None:
        out[F_RHO_YEAR] = [rho_year.numerator, rho_year.denominator]
    return out


def storage_policy(
    retention: dict[int, int] | None = None,
    max_blob: int = 268_435_456,
    history: int = 1,
    quota: int = 53_687_091_200,
    keyring_history: int = 0,
    sensitive_max: int = 268_435_456,
) -> dict[int, Any]:
    return {
        S_RETENTION: retention
        if retention is not None
        else {0: 7_776_000, 1: 0, 2: 31_536_000, 3: 0, 4: 0},
        S_MAX_BLOB: max_blob,
        S_HISTORY: history,
        S_QUOTA: quota,
        S_KEYRING_HISTORY: keyring_history,
        S_SENSITIVE_MAX: sensitive_max,
    }


def chat_ids(
    all_members: bytes,
    organizers: bytes,
    delivery: bytes,
    greeting: bytes,
    issuer_keys: tuple[bytes, bytes],
) -> dict[int, Any]:
    return {
        CH_ALL: all_members,
        CH_ORGANIZERS: organizers,
        CH_DELIVERY: delivery,
        CH_GREETING: greeting,
        CH_ISSUER_KEYS: {0: issuer_keys[0], 1: issuer_keys[1]},
    }


def attr(source: list[int], name: str, pred: list) -> list:
    return [NODE_ATTR, source, name, pred]


def body(
    *,
    name: str,
    sealed: bool,
    entry: list,
    nullifier: list,
    perms: dict[int, int],
    floors_: dict[int, Any],
    logs: list[dict[int, Any]],
    aggregators: list[bytes],
    stores: list[bytes],
    storage: dict[int, Any],
    chat: dict[int, Any],
    mix_global: bool,
    vote: list | None = None,
    issuers: list[bytes] | None = None,
    results_key: bytes | None = None,
    results_epoch: int | None = None,
    count: dict[int, Any] | None = None,
    map_limits: dict[int, Any] | None = None,
    agents: dict[int, Any] | None = None,
    about_epoch: int | None = None,
) -> dict[int, Any]:
    out: dict[int, Any] = {
        NAME: name,
        SEALED: sealed,
        ENTRY: entry,
        PERMS: perms,
        FLOORS: floors_,
        LOGS: logs,
        AGGREGATORS: aggregators,
        STORES: stores,
        STORAGE: storage,
        CHAT: chat,
        MIX_GLOBAL: mix_global,
        NULLIFIER: nullifier,
    }
    for key, value in (
        (VOTE, vote),
        (ISSUERS, issuers),
        (RESULTS_KEY, results_key),
        (RESULTS_EPOCH, results_epoch),
        (COUNT, count),
        (MAP, map_limits),
        (AGENTS, agents),
        (ABOUT_EPOCH, about_epoch),
    ):
        if value is not None:
            out[key] = value
    return out


# ---------------------------------------------------------------- policy trees


class Policy:
    """Checks and walks a policy tree (context.md, "Entry policy")."""

    def __init__(self, node: Any, trust_lists: int, issuers: int) -> None:
        self.root = node
        self.trust_lists = trust_lists
        self.issuers = issuers
        self.leaves: list[list] = []
        self._check(node, 1)

    def _check(self, node: Any, depth: int) -> None:
        require(depth <= MAX_POLICY_DEPTH, "C5", f"policy depth exceeds {MAX_POLICY_DEPTH}")
        require(isinstance(node, list) and node and is_uint(node[0]), "C5", "policy node shape")
        kind = node[0]
        if kind == NODE_TRUE:
            require(len(node) == 1, "C5", "true node takes no arguments")
        elif kind in (NODE_ALL, NODE_ANY):
            require(len(node) == 2 and isinstance(node[1], list), "C5", "all/any need a child list")
            require(1 <= len(node[1]) <= 32, "C5", "all/any need 1..32 children")
            for child in node[1]:
                self._check(child, depth + 1)
            if kind == NODE_ANY:
                seen: set[tuple] = set()
                for child in node[1]:
                    if (
                        isinstance(child, list)
                        and child
                        and child[0] == NODE_ATTR
                        and len(child) == 4
                    ):
                        key = (tuple(child[1]) if isinstance(child[1], list) else None, child[2])
                        require(key not in seen, "C5", "any with two leaves on one (source, name)")
                        seen.add(key)
        elif kind == NODE_ATTR:
            require(len(node) == 4, "C5", "attr node needs source, name, pred")
            source, name, pred = node[1], node[2], node[3]
            require(
                isinstance(source, list)
                and len(source) == 2
                and is_uint(source[0])
                and is_uint(source[1]),
                "C5",
                "source shape",
            )
            if source[0] == SRC_TRUST_LIST:
                require(
                    source[1] < self.trust_lists,
                    "C5",
                    f"source names tl/{source[1]} which is not in refs",
                )
            elif source[0] == SRC_ISSUER:
                require(
                    source[1] < self.issuers,
                    "C5",
                    f"source names issuers[{source[1]}] which is absent",
                )
            else:
                raise TypeRule("C5", "unknown source kind")
            require(is_text(name, 32, pattern=NAME_RE), "C5", "attribute name pattern")
            require(isinstance(pred, list) and pred and is_uint(pred[0]), "C5", "predicate shape")
            if pred[0] == PRED_PRESENT:
                require(len(pred) == 1, "C5", "present predicate takes no arguments")
            elif pred[0] == PRED_SET:
                require(
                    len(pred) == 2 and isinstance(pred[1], list) and 1 <= len(pred[1]) <= 64,
                    "C5",
                    "set predicate needs 1..64 values",
                )
                require(all(is_uint(v) for v in pred[1]), "C5", "set values must be uints")
                require(len(set(pred[1])) == len(pred[1]), "C5", "duplicate set values")
                require(len(pred[1]) == 1, "C5", "draft 0.1: a set predicate has exactly one value")
            elif pred[0] == PRED_RANGE:
                require(
                    len(pred) == 3 and is_uint(pred[1]) and is_uint(pred[2]), "C5", "range shape"
                )
                require(pred[1] <= pred[2], "C5", "range lo > hi")
                require(pred[1] == pred[2], "C5", "draft 0.1: a range predicate has lo = hi")
            else:
                raise TypeRule("C5", "unknown predicate kind")
            self.leaves.append(node)
            require(
                len(self.leaves) <= MAX_POLICY_LEAVES, "C5", f"more than {MAX_POLICY_LEAVES} leaves"
            )
        else:
            raise TypeRule("C5", f"unknown node kind {kind}")

    def sources_used(self) -> set[tuple[int, int]]:
        return {(leaf[1][0], leaf[1][1]) for leaf in self.leaves}

    def has_any(self) -> bool:
        def walk(node):
            if node[0] == NODE_ANY:
                return True
            if node[0] == NODE_ALL:
                return any(walk(c) for c in node[1])
            return False

        return walk(self.root)

    def has_true(self) -> bool:
        def walk(node):
            if node[0] == NODE_TRUE:
                return True
            if node[0] in (NODE_ALL, NODE_ANY):
                return any(walk(c) for c in node[1])
            return False

        return walk(self.root)

    def leaf_reachable_through_all(self, source: list[int], name: str) -> bool:
        """An attr leaf with this source and name reachable from the root via ``all`` nodes only."""

        def walk(node):
            if node[0] == NODE_ATTR:
                return node[1] == source and node[2] == name
            if node[0] == NODE_ALL:
                return any(walk(c) for c in node[1])
            return False

        return walk(self.root)

    def names_attribute(self, name: str) -> bool:
        return any(leaf[2] == name for leaf in self.leaves)


def evaluate_policy(node: Any, held: list[tuple[tuple[int, int], str, int]]) -> bool:
    """Evaluate a policy against credentials the prover holds, as (source, attribute, value).

    ``source`` is the resolved source id ``(kind, index)``; row resolution across trust lists
    is trust-list.md's business and happens before this call. Children of ``all`` may be met
    by different credentials; ``any`` needs one child met.
    """
    kind = node[0]
    if kind == NODE_TRUE:
        return True
    if kind == NODE_ALL:
        return all(evaluate_policy(c, held) for c in node[1])
    if kind == NODE_ANY:
        return any(evaluate_policy(c, held) for c in node[1])
    source, name, pred = tuple(node[1]), node[2], node[3]
    for src, attr_name, value in held:
        if src != source or attr_name != name:
            continue
        if pred[0] == PRED_PRESENT:
            return True
        if pred[0] == PRED_SET and value in pred[1]:
            return True
        if pred[0] == PRED_RANGE and pred[1] <= value <= pred[2]:
            return True
    return False


# ------------------------------------------------ step 4: schema (C1, C2, C5, C9, C12, C15 shapes)


def _check_floors(f: Any) -> None:
    require_keys(f, {F_RHO, F_DELTA, F_MIN_VOTERS, F_RELEASES, F_MIN_WITNESSES}, "C1", "floors")
    no_unknown_keys(f, set(range(6)), "C1", "floors")
    check_rat(f[F_RHO], "C1", "floors.rho")
    check_rat(f[F_DELTA], "C1", "floors.delta")
    require(is_uint(f[F_MIN_VOTERS]), "C1", "floors.minVoters")
    require(is_uint(f[F_RELEASES]), "C1", "floors.releasesPerDeck")
    require(is_uint(f[F_MIN_WITNESSES]), "C1", "floors.minWitnesses")
    if F_RHO_YEAR in f:
        check_rat(f[F_RHO_YEAR], "C1", "floors.rhoYear")


def schema(env: dict[int, Any]) -> None:
    b = env[m.BODY]
    require_keys(b, REQUIRED, "C1")
    no_unknown_keys(b, ALL_KEYS, "C1")
    check_text(b[NAME], 120, "C2", "name", min_bytes=1)
    require(isinstance(b[SEALED], bool), "C1", "sealed must be a bool")
    require(isinstance(b[MIX_GLOBAL], bool), "C1", "mixGlobal must be a bool")
    # perms
    perms = b[PERMS]
    require_keys(perms, {P_CARDS, P_RESULTS, P_MEMBER_LIST}, "C1", "perms")
    no_unknown_keys(perms, {P_CARDS, P_RESULTS, P_MEMBER_LIST}, "C1", "perms")
    require(is_uint(perms[P_CARDS], 0, 2), "C1", "perms.cards")
    require(is_uint(perms[P_RESULTS]), "C1", "perms.results")
    require(is_uint(perms[P_MEMBER_LIST], 0, 2), "C1", "perms.memberList")
    _check_floors(b[FLOORS])
    # logs
    logs = b[LOGS]
    require(isinstance(logs, list) and 1 <= len(logs) <= 8, "C1", "logs must have 1..8 entries")
    for entry in logs:
        require_keys(entry, {L_LOG, L_WITNESSES}, "C1", "log entry")
        no_unknown_keys(entry, {L_LOG, L_WITNESSES}, "C1", "log entry")
        check_cid(entry[L_LOG], "C1", "log")
        w = entry[L_WITNESSES]
        require(isinstance(w, list) and all(is_bytes(k, 32) for k in w), "C1", "witness keys")
    aggs = b[AGGREGATORS]
    require(
        isinstance(aggs, list) and len(aggs) == 2 and all(is_cid(a) for a in aggs),
        "C1",
        "aggregators",
    )
    stores = b[STORES]
    require(
        isinstance(stores, list) and 1 <= len(stores) <= 8 and all(is_cid(s) for s in stores),
        "C1",
        "stores",
    )
    # storage (C1 shape, C9 values)
    st = b[STORAGE]
    require_keys(st, set(range(6)), "C1", "storage")
    no_unknown_keys(st, set(range(6)), "C1", "storage")
    ret = st[S_RETENTION]
    require(
        isinstance(ret, dict) and all(is_uint(k) and is_uint(v) for k, v in ret.items()),
        "C1",
        "storage.retention",
    )
    for k in (S_MAX_BLOB, S_HISTORY, S_QUOTA, S_KEYRING_HISTORY, S_SENSITIVE_MAX):
        require(is_uint(st[k]), "C1", f"storage key {k}")
    # chat
    ch = b[CHAT]
    require_keys(
        ch, {CH_ALL, CH_ORGANIZERS, CH_DELIVERY, CH_GREETING, CH_ISSUER_KEYS}, "C11", "chat"
    )
    no_unknown_keys(ch, set(range(5)), "C1", "chat")
    require(is_bytes(ch[CH_ALL], 32) and is_bytes(ch[CH_ORGANIZERS], 32), "C1", "chat group ids")
    check_cid(ch[CH_DELIVERY], "C1", "chat.delivery")
    require(is_bytes(ch[CH_GREETING], 32), "C11", "chat.greeting must be 32 bytes")
    ik = ch[CH_ISSUER_KEYS]
    require(
        isinstance(ik, dict) and set(ik) == {0, 1} and all(is_bytes(v) and v for v in ik.values()),
        "C11",
        "chat.issuerKeys needs both entries",
    )
    # optional fields
    if ISSUERS in b:
        iss = b[ISSUERS]
        require(
            isinstance(iss, list) and len(iss) <= 64 and all(is_cid(a) for a in iss),
            "C1",
            "issuers",
        )
    if RESULTS_KEY in b:
        require(is_bytes(b[RESULTS_KEY], 32), "C1", "resultsKey must be 32 bytes")
    if RESULTS_EPOCH in b:
        require(is_uint(b[RESULTS_EPOCH]), "C1", "resultsEpoch")
    if COUNT in b:
        require(isinstance(b[COUNT], dict) and set(b[COUNT]) <= {CNT_RHO_MAX}, "C1", "count")
        if CNT_RHO_MAX in b[COUNT]:
            check_rat(b[COUNT][CNT_RHO_MAX], "C1", "count.rhoMax")
    if MAP in b:
        mp = b[MAP]
        require(
            isinstance(mp, dict) and set(mp) <= {MAP_UNSIGNED, MAP_SIGNED, MAP_AGENT}, "C1", "map"
        )
        require(all(is_uint(v) for v in mp.values()), "C1", "map values")
    if AGENTS in b:
        ag = b[AGENTS]
        require(
            isinstance(ag, dict) and set(ag) <= {AG_ANY, AG_SPONSORS, AG_ADD_ROLE}, "C1", "agents"
        )
        if AG_ANY in ag:
            require(isinstance(ag[AG_ANY], bool), "C1", "agents.anySponsor")
        if AG_SPONSORS in ag:
            sp = ag[AG_SPONSORS]
            require(
                isinstance(sp, list) and len(sp) <= 64 and all(is_cid(a) for a in sp),
                "C1",
                "agents.sponsors",
            )
        if AG_ADD_ROLE in ag:
            require(is_uint(ag[AG_ADD_ROLE]), "C1", "agents.addRole")
    if ABOUT_EPOCH in b:
        require(is_uint(b[ABOUT_EPOCH]), "C1", "aboutEpoch")
    nul = b[NULLIFIER]
    require(
        isinstance(nul, list)
        and len(nul) == 2
        and isinstance(nul[0], list)
        and is_text(nul[1], 32, pattern=NAME_RE),
        "C1",
        "nullifier shape",
    )
    # refs shape
    refs = env[m.REFS]
    for name in refs:
        require(
            name == "parent" or name == "about" or name.startswith("tl/"),
            "C1",
            f"unknown ref {name!r}",
        )
    # policies (C5 shape)
    tl_count = _trust_list_count(refs)
    Policy(b[ENTRY], tl_count, len(b.get(ISSUERS, [])))
    if VOTE in b:
        Policy(b[VOTE], tl_count, len(b.get(ISSUERS, [])))


def _trust_list_count(refs: dict[str, bytes]) -> int:
    """Number of ``tl/<i>`` refs when contiguous from 0; C7 rejects gaps at step 10."""
    indices = []
    for name in refs:
        if name.startswith("tl/"):
            tail = name[3:]
            if tail.isdigit() and str(int(tail)) == tail:
                indices.append(int(tail))
    return max(indices) + 1 if indices else 0


# ---------------------------------------------------------------- step 10: C3 to C15


def floors_of(b: dict[int, Any]) -> dict[str, Any]:
    f = b[FLOORS]
    return {
        "rho": rat_value(f[F_RHO]),
        "delta": rat_value(f[F_DELTA]),
        "minVoters": f[F_MIN_VOTERS],
        "releasesPerDeck": f[F_RELEASES],
        "minWitnesses": f[F_MIN_WITNESSES],
        "rhoYear": rat_value(f[F_RHO_YEAR]) if F_RHO_YEAR in f else None,
    }


def rules(view: m.Resolved) -> None:
    b = view.body
    refs = view.refs
    f = floors_of(b)
    # C3
    require(0 < f["rho"] <= RHO_MAX, "C3", "floors.rho out of range")
    require(0 < f["delta"] <= DELTA_MAX, "C3", "floors.delta out of range")
    require(f["minVoters"] >= MIN_VOTERS, "C3", "floors.minVoters below MIN_VOTERS")
    require(f["releasesPerDeck"] == 1, "C3", "floors.releasesPerDeck must be 1")
    require(f["minWitnesses"] >= MIN_WITNESSES, "C3", "floors.minWitnesses below MIN_WITNESSES")
    # C4
    if f["rhoYear"] is not None:
        require(f["rhoYear"] >= f["rho"], "C4", "rhoYear below rho")
    # C5 already shape-checked; C6
    tl_count = _trust_list_count(refs)
    issuers = b.get(ISSUERS, [])
    entry = Policy(b[ENTRY], tl_count, len(issuers))
    vote = Policy(b[VOTE], tl_count, len(issuers)) if VOTE in b else None
    src, name = b[NULLIFIER]
    require(
        isinstance(src, list) and len(src) == 2 and src[0] in (SRC_TRUST_LIST, SRC_ISSUER),
        "C6",
        "nullifier source kind",
    )
    exists = (src[0] == SRC_TRUST_LIST and src[1] < tl_count) or (
        src[0] == SRC_ISSUER and src[1] < len(issuers)
    )
    require(exists, "C6", "nullifier names a source that does not exist")
    effective = [NODE_ALL, [b[ENTRY], b[VOTE]]] if VOTE in b else b[ENTRY]
    eff = Policy(effective, tl_count, len(issuers))
    require(
        eff.leaf_reachable_through_all(src, name),
        "C6",
        "nullifier leaf not reachable through all nodes only",
    )
    # C7
    tl_names = sorted(n for n in refs if n.startswith("tl/"))
    expected = [f"tl/{i}" for i in range(len(tl_names))]
    require(tl_names == expected, "C7", "tl/<i> refs are not contiguous from 0")
    used = entry.sources_used() | (vote.sources_used() if vote else set())
    for i in range(len(tl_names)):
        require((SRC_TRUST_LIST, i) in used, "C7", f"tl/{i} is unused by both policies")
    aggs = b[AGGREGATORS]
    require(aggs[0] != aggs[1], "C7", "aggregators must differ")
    require(len(set(b[STORES])) == len(b[STORES]), "C7", "duplicate store")
    log_ids = [e[L_LOG] for e in b[LOGS]]
    require(len(set(log_ids)) == len(log_ids), "C7", "duplicate log")
    require(len(set(issuers)) == len(issuers), "C7", "duplicate issuer")
    # C8
    for entry_ in b[LOGS]:
        w = entry_[L_WITNESSES]
        require(2 <= len(w) <= 16, "C8", "log entry needs 2..16 witness keys")
        require(len(set(w)) == len(w), "C8", "duplicate witness key")
        require(f["minWitnesses"] <= len(w), "C8", "minWitnesses exceeds a log entry's witnesses")
    # C9
    st = b[STORAGE]
    require(set(st[S_RETENTION]) == RETENTION_KINDS, "C9", "retention must list all five kinds")
    require(st[S_MAX_BLOB] >= 65_536, "C9", "maxBlob below 65536")
    require(st[S_HISTORY] in (0, 1, 2), "C9", "history out of range")
    require(st[S_KEYRING_HISTORY] in (0, 1), "C9", "keyringHistory out of range")
    require(st[S_SENSITIVE_MAX] >= 1_048_576, "C9", "sensitiveMax below 1 MiB")
    # C10, C11
    prev = view.prev_env
    if prev is not None:
        pf = floors_of(prev[m.BODY])
        require(f["rho"] <= pf["rho"], "C10", "rho raised")
        require(f["delta"] <= pf["delta"], "C10", "delta raised")
        require(f["minVoters"] >= pf["minVoters"], "C10", "minVoters lowered")
        require(f["minWitnesses"] >= pf["minWitnesses"], "C10", "minWitnesses lowered")
        if pf["rhoYear"] is not None:
            require(
                f["rhoYear"] is not None and f["rhoYear"] <= pf["rhoYear"],
                "C10",
                "rhoYear dropped or raised",
            )
        pb = prev[m.BODY]
        require(b[SEALED] == pb[SEALED], "C11", "sealed changed")
        require(b[CHAT][CH_ALL] == pb[CHAT][CH_ALL], "C11", "chat.allMembers changed")
    # C12
    results = b[PERMS][P_RESULTS]
    require(results in (0, 1), "C12", "perms.results must be 0 or 1")
    if results == 1:
        require(
            RESULTS_KEY in b and RESULTS_EPOCH in b,
            "C12",
            "results 1 needs resultsKey and resultsEpoch",
        )
    else:
        require(
            RESULTS_KEY not in b and RESULTS_EPOCH not in b, "C12", "results 0 forbids resultsKey"
        )
    sealed_about = b[SEALED] and "about" in refs
    require(
        (ABOUT_EPOCH in b) == sealed_about,
        "C12",
        "aboutEpoch present iff sealed and about ref present",
    )
    # C13
    if "parent" in refs:
        parent = view.manifest(refs["parent"])
        require(
            parent is not None and parent.get(m.TYPE) == "context", "C13", "parent is not a context"
        )
        pf = floors_of(parent[m.BODY])
        require(pf["rho"] >= f["rho"], "C13", "parent rho stricter than child")
        require(pf["delta"] >= f["delta"], "C13", "parent delta stricter than child")
        require(pf["minVoters"] <= f["minVoters"], "C13", "parent minVoters stricter than child")
        require(
            pf["minWitnesses"] <= f["minWitnesses"],
            "C13",
            "parent minWitnesses stricter than child",
        )
        own_lineage = view.env.get(m.LINEAGE, view.bundle.cid)
        require(view.lineage_of(refs["parent"]) != own_lineage, "C13", "parent is in this lineage")
    # C14
    if COUNT in b and CNT_RHO_MAX in b[COUNT]:
        require(
            rat_value(b[COUNT][CNT_RHO_MAX]) <= COUNT_RHO_MAX,
            "C14",
            "count.rhoMax above COUNT_RHO_MAX",
        )
    # C15
    require(not entry.names_attribute(AGENT_SPONSOR_ATTR), "C15", "entry names agent-sponsor")
    if vote is not None:
        require(not vote.names_attribute(AGENT_SPONSOR_ATTR), "C15", "vote names agent-sponsor")
    mp = b.get(MAP, {})
    if MAP_UNSIGNED in mp:
        require(1 <= mp[MAP_UNSIGNED] <= 20, "C15", "map.unsignedPerWindow out of 1..20")
    if MAP_SIGNED in mp:
        require(1 <= mp[MAP_SIGNED] <= 60, "C15", "map.signedPerWindow out of 1..60")
    if MAP_AGENT in mp:
        require(mp[MAP_AGENT] >= 1, "C15", "map.agentObjects below 1")
    ag = b.get(AGENTS, {})
    sponsors = ag.get(AG_SPONSORS, [])
    if ag.get(AG_ANY, False):
        require(not sponsors, "C15", "sponsors must be empty when anySponsor")
    require(len(set(sponsors)) == len(sponsors), "C15", "duplicate sponsor")
    require(ag.get(AG_ADD_ROLE, 0) in (0, 1, 2), "C15", "agents.addRole out of range")
    # C5, the half that needs step 9: [0] only on a bool attribute
    trust_lists = [view.manifest(refs[f"tl/{i}"]) for i in range(tl_count)]
    policies = [entry] + ([vote] if vote is not None else [])
    for pol in policies:
        for leaf in pol.leaves:
            if leaf[3][0] == PRED_PRESENT:
                for authority in _leaf_authorities(leaf, b, trust_lists):
                    ver = _verifier_in_force(view, authority)
                    if ver is None:
                        continue
                    attr_type = _attribute_type(ver, leaf[2])
                    require(
                        attr_type in (None, "bool"),
                        "C5",
                        f"[0] on attribute {leaf[2]!r} of type {attr_type}",
                    )
    # C16: one cell per context (ADR 0100)
    for pol in policies:
        require(not pol.has_any(), "C16", "an any node in entry or vote")
        for leaf in pol.leaves:
            if leaf[1][0] != SRC_TRUST_LIST:
                continue
            tl_env = trust_lists[leaf[1][1]]
            require(tl_env is not None, "C16", f"tl/{leaf[1][1]} does not resolve")
            accepting = _accepting_entries(tl_env, leaf[2])
            require(
                len(accepting) == 1,
                "C16",
                f"tl/{leaf[1][1]} accepts {leaf[2]!r} from {len(accepting)} authorities",
            )


def _accepting_entries(tl_env: dict[int, Any], name: str) -> list[bytes]:
    """Authorities of the trust-list entries that accept ``name`` (listed, or empty attributes)."""
    from . import trust_list as tl

    out = []
    for e in tl_env[m.BODY][tl.ENTRIES]:
        attrs = e[tl.EN_ATTRIBUTES]
        if not attrs or name in attrs:
            out.append(e[tl.EN_AUTHORITY])
    return out


def _leaf_authorities(leaf: list, b: dict[int, Any], trust_lists: list) -> list[bytes]:
    kind, i = leaf[1]
    if kind == SRC_ISSUER:
        return [b[ISSUERS][i]]
    tl_env = trust_lists[i]
    return _accepting_entries(tl_env, leaf[2]) if tl_env is not None else []


def _verifier_in_force(view: m.Resolved, authority: bytes) -> dict[int, Any] | None:
    """The latest verifier version of ``authority`` logged before this context, if any."""
    best = None
    for pos, env, _ in view.all_of_type("verifier"):
        if env.get(m.AUTHORITY) != authority:
            continue
        if view.position is not None and pos >= view.position:
            continue
        if best is None or env[m.VERSION] > best[m.VERSION]:
            best = env
    return best


def _attribute_type(ver_env: dict[int, Any], name: str) -> str | None:
    from . import verifier as vf

    for a in ver_env[m.BODY][vf.ATTRIBUTES]:
        if a[vf.AT_NAME] == name:
            return a[vf.AT_TYPE]
    return None


# ---------------------------------------------------------------- derived values


def results_key(secret_k: bytes) -> tuple[bytes, bytes]:
    """(private scalar, public key) per context.md "The results key"."""
    prk = hmac.new(bytes(32), secret_k, hashlib.sha256).digest()  # HKDF-Extract with empty salt
    seed = hmac.new(prk, b"hum/results-key/1" + b"\x01", hashlib.sha256).digest()[:32]
    clamped = bytearray(seed)
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    private = bytes(clamped)
    public = X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()
    return private, public


def count_buckets(
    receipt_times: list[int], opens: int, closes: int, noise: list[int]
) -> dict[str, Any]:
    """Daily-count buckets: bucket d = floor((t - opens) / 86400); the bucket holding ``closes``
    is the last. ``noise`` supplies one integer draw per bucket (noise is an input, never drawn
    here). Returns increments, noised increments and the running total."""
    last = (closes - opens) // 86_400
    counts = [0] * (last + 1)
    for t in receipt_times:
        if opens <= t <= closes:
            counts[(t - opens) // 86_400] += 1
    require(len(noise) == len(counts), "count", "one noise draw per bucket")
    noised = [c + z for c, z in zip(counts, noise, strict=True)]
    totals = []
    run = 0
    for v in noised:
        run += v
        totals.append(run)
    return {"buckets": list(range(last + 1)), "counts": counts, "noised": noised, "running": totals}


m.register("context", schema=schema, rules=rules)
