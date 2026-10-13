"""The ``release`` body: docs/specs/release.md.

R1 to R8 and R10 to R14 run at step 10; R9 replaces step 6 (both aggregator keysets). R15
reads opened Parquet tables. The standalone ``parquet_tables`` validator now covers
explicit trusted contracts; this world still uses opaque table blobs, so end-to-end R15
remains pending. The keybox generator now uses real HPKE; its ``info``/``aad`` byte
layout is here. Noise is never drawn: receipt padding takes ``Z_r`` as an input.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Any

from .. import manifest as m
from .. import release as rmath
from . import (
    TypeRule,
    is_bytes,
    is_cid,
    is_rat,
    is_uint,
    no_unknown_keys,
    rat_value,
    require,
    require_keys,
)
from . import context as c
from . import deck as dk

__all__ = [
    "TABLES_OF",
    "body",
    "canonical_unlocked",
    "ceil_sigma",
    "log_of_record",
    "keybox_info",
    "part_record",
    "receipt_padding",
    "required_tables",
    "rules",
    "schema",
    "sigma_of_part",
    "signatures",
]

# ---------------------------------------------------------------- keys

(
    MECHANISM, HELPER, STAGE, FINAL, RHO, DELTA, PARTS, N_HAT, UNLOCKED, RECEIPTS, ASSURANCE,
    SEALED, RESULTS_EPOCH, ROUND_DEADLINE, GROUPS_K, ABSORBED,
) = range(16)  # fmt: skip
REQUIRED = {
    MECHANISM,
    HELPER,
    STAGE,
    FINAL,
    RHO,
    DELTA,
    PARTS,
    UNLOCKED,
    RECEIPTS,
    ASSURANCE,
    SEALED,
    ABSORBED,
}
ALL_KEYS = set(range(16))
PR_RHO, PR_SIGMA, PR_N = 0, 1, 2
PARTS_WITH_N = {dk.TALLIES, dk.COVARIANCE, dk.MAP, dk.GROUPS}
STAGE_PART = {2: dk.COVARIANCE, 3: dk.MAP, 4: dk.GROUPS}
THIRTY_DAYS = 30 * 86_400
YEAR = 365 * 86_400
KEYBOX_INFO = b"hum/results-keybox/1"

# Tables each part publishes (release.md, "Tables"); the conditional ones are added in
# ``required_tables``.
TABLES_OF: dict[int, tuple[str, ...]] = {
    dk.TALLIES: ("tallies",),
    dk.COVARIANCE: ("covariance", "axes"),
    dk.MAP: ("map",),
    dk.GROUPS: ("group_tallies", "group_sizes"),
    dk.COUNT: ("count",),
    dk.MOVEMENT: ("movement", "moved"),
    dk.RATINGS: ("ratings",),
    dk.BREAKDOWN: ("breakdown", "breakdown_cells"),
    dk.RECEIPTS: (),
}
CONDITIONAL = {"consensus", "centroids", "group_ratings", "repness"}
ALL_TABLES = {t for ts in TABLES_OF.values() for t in ts} | CONDITIONAL


# ---------------------------------------------------------------- builders


def part_record(rho: Fraction, sigma_micro: int, n: int | None = None) -> dict[int, Any]:
    out = {PR_RHO: rmath.rat(rho), PR_SIGMA: sigma_micro}
    if n is not None:
        out[PR_N] = n
    return out


def body(
    *,
    helper: bytes,
    stage: int,
    final: bool,
    rho: Fraction,
    delta: Fraction,
    parts: dict[int, dict],
    unlocked: list[int],
    receipts: dict[int, bytes],
    assurance: list[tuple[bytes, int]],
    sealed: bool,
    absorbed: bool = False,
    n_hat: int | None = None,
    results_epoch: int | None = None,
    round_deadline: int | None = None,
    groups_k: int | None = None,
    mechanism: int = 0,
) -> dict[int, Any]:
    out: dict[int, Any] = {
        MECHANISM: mechanism,
        HELPER: helper,
        STAGE: stage,
        FINAL: final,
        RHO: rmath.rat(rho),
        DELTA: rmath.rat(delta),
        PARTS: {p: parts[p] for p in sorted(parts)},
        UNLOCKED: sorted(unlocked),
        RECEIPTS: {r: receipts[r] for r in sorted(receipts)},
        ASSURANCE: [[a, lvl] for a, lvl in sorted(assurance, key=lambda t: t[0])],
        SEALED: sealed,
        ABSORBED: absorbed,
    }
    for key, value in (
        (N_HAT, n_hat),
        (RESULTS_EPOCH, results_epoch),
        (ROUND_DEADLINE, round_deadline),
        (GROUPS_K, groups_k),
    ):
        if value is not None:
            out[key] = value
    return out


# ---------------------------------------------------------------- derived values


def sigma_of_part(plan: dict[int, Any], cards: int, part: int, rho_part: Fraction) -> int:
    """``sigma`` for ``part`` under ``plan`` (R4): round(σ_r × 10⁶) with σ_r = n/2²⁰ from the
    exact rational σ²; covariance divided by ``covScale``."""
    rp = dk.to_release_plan(plan, cards)
    d2 = rmath.delta_squared(part, rp, cards)
    scale = rp.cov_scale if part == rmath.COVARIANCE else 1
    return rmath.sigma_micro(d2, rho_part, scale)


def ceil_sigma(sigma_sq: Fraction) -> int:
    """⌈σ⌉ in integers: the least m with m²·q ≥ p for σ² = p/q (no square root)."""
    p, q = sigma_sq.numerator, sigma_sq.denominator
    m_ = 0
    while m_ * m_ * q < p:
        m_ += 1
    return m_


def receipt_padding(sigma_sq_receipts: Fraction, z_r: int) -> int:
    """``Y_r = 6·⌈σ_8⌉ + Z_r`` clamped at 0; ``Z_r`` is the sampler's draw, an input here."""
    return max(6 * ceil_sigma(sigma_sq_receipts) + z_r, 0)


def keybox_info(deck_cid: bytes) -> tuple[bytes, bytes]:
    """Keybox info/AAD; the HPKE seal is implemented in ``hum_reference.hpke``."""
    return KEYBOX_INFO + deck_cid, deck_cid


def canonical_unlocked(
    plan: dict[int, Any],
    parts: dict[int, dict],
    n_hat: int | None,
    stage: int,
    rating: bool = False,
) -> list[int]:
    """R6: the parts whose tables are published at this stage.

    In a rating deck part 3 is unlocked with part 0 (its group cells are filtered in
    post-processing at GATE_CELL; see release_tables.rating_group_rows).
    """
    planned = set(plan[dk.P_PARTS])
    out: set[int] = set()
    if n_hat is None or n_hat < plan[dk.P_MIN_VOTERS]:
        return []
    out.add(dk.TALLIES)
    out.add(dk.RECEIPTS)
    if dk.COUNT in planned:
        out.add(dk.COUNT)
    if rating and dk.GROUPS in planned:
        out.add(dk.GROUPS)
    for p in (dk.MOVEMENT, dk.RATINGS):
        if p in planned and n_hat >= dk.effective_gate(plan, p):
            out.add(p)
    if dk.BREAKDOWN in planned and n_hat >= c.GATE_CELL:
        out.add(dk.BREAKDOWN)
    gate1 = dk.effective_gate(plan, dk.COVARIANCE)
    for p in dk.TIER:
        rec = parts.get(p)
        if p in planned and rec is not None and PR_N in rec and rec[PR_N] >= gate1:
            out.add(p)
    return sorted(out)


def required_tables(
    plan: dict[int, Any],
    unlocked: list[int],
    n_hat: int | None,
    stage: int,
    final: bool,
    rating: bool = False,
) -> tuple[set[str], set[str]]:
    """(tables that must be in refs, tables that may be in refs) for R7. A rating release's
    tables are exactly those of its unlocked parts (tallies, group_tallies, group_sizes);
    consensus and repness are never present (release.md R7)."""
    must: set[str] = set()
    for p in unlocked:
        must.update(TABLES_OF[p])
    may = set(must)
    if rating:
        return must, may
    common = n_hat is not None and n_hat >= c.GATE_COMMON
    if dk.TALLIES in unlocked and common:
        if (stage == 1 and final) or stage == 4:
            must.add("consensus")
        may.add("consensus")
    if dk.MAP in unlocked:
        if not final:
            must.add("centroids")
        may.add("centroids")
    if dk.GROUPS in unlocked:
        if stage == 4:  # R7: repness at stage 4; a rating release publishes no repness
            must.add("repness")
        if dk.RATINGS in plan[dk.P_PARTS]:
            must.add("group_ratings")
        may |= {"repness", "group_ratings"}
    return must, may


# ---------------------------------------------------------------- R1: shape


def _r1(env: dict[int, Any]) -> None:
    b = env[m.BODY]
    require_keys(b, REQUIRED, "R1")
    no_unknown_keys(b, ALL_KEYS, "R1")
    require(is_uint(b[MECHANISM]), "R1", "mechanism must be a uint")
    require(is_cid(b[HELPER]), "R1", "helper must be an authority CID")
    require(is_uint(b[STAGE], 1, 4), "R1", "stage must be 1..4")
    require(b[STAGE] == env[m.VERSION], "R1", "stage must equal version")
    require(isinstance(b[FINAL], bool), "R1", "final must be a bool")
    require(is_rat(b[RHO]) and is_rat(b[DELTA]), "R1", "rho and delta must be rats")
    parts = b[PARTS]
    require(isinstance(parts, dict), "R1", "parts must be a map")
    for p, rec in parts.items():
        require(is_uint(p, 0, 8), "R1", "part id")
        require(isinstance(rec, dict), "R1", f"part {p} record must be a map")
        require_keys(rec, {PR_RHO, PR_SIGMA}, "R1", f"part {p}")
        no_unknown_keys(rec, {PR_RHO, PR_SIGMA, PR_N}, "R1", f"part {p}")
        require(is_rat(rec[PR_RHO]), "R1", f"part {p} rho")
        require(is_uint(rec[PR_SIGMA]), "R1", f"part {p} sigma must be a uint")
        if N_HAT in b and p in PARTS_WITH_N:
            require(PR_N in rec, "R1", f"part {p} requires n when nHat is present")
        if PR_N in rec:
            require(
                isinstance(rec[PR_N], int) and not isinstance(rec[PR_N], bool),
                "R1",
                f"part {p} n must be an int",
            )
            require(p in PARTS_WITH_N, "R1", f"part {p} carries no n")
    if N_HAT in b:
        require(isinstance(b[N_HAT], int) and not isinstance(b[N_HAT], bool), "R1", "nHat")
    unl = b[UNLOCKED]
    require(isinstance(unl, list) and all(is_uint(x, 0, 8) for x in unl), "R1", "unlocked")
    require(unl == sorted(set(unl)), "R1", "unlocked must be ascending without repeats")
    rec_ = b[RECEIPTS]
    require(
        isinstance(rec_, dict) and all(is_uint(k) and is_bytes(v, 32) for k, v in rec_.items()),
        "R1",
        "receipts must map rounds to 32-byte roots",
    )
    asr = b[ASSURANCE]
    ok = isinstance(asr, list) and all(
        isinstance(e, list) and len(e) == 2 and is_cid(e[0]) and is_uint(e[1], 0, 3) for e in asr
    )
    require(ok, "R1", "assurance entries")
    require([e[0] for e in asr] == sorted(e[0] for e in asr), "R1", "assurance unsorted")
    require(len({e[0] for e in asr}) == len(asr), "R1", "assurance lists an authority twice")
    require(isinstance(b[SEALED], bool) and isinstance(b[ABSORBED], bool), "R1", "bools")
    if RESULTS_EPOCH in b:
        require(is_uint(b[RESULTS_EPOCH]), "R1", "resultsEpoch")
    if ROUND_DEADLINE in b:
        require(is_uint(b[ROUND_DEADLINE]), "R1", "roundDeadline")
    if GROUPS_K in b:
        require(is_uint(b[GROUPS_K], 2, 5), "R1", "groupsK must be 2..5")
    for name, cid in env[m.REFS].items():
        require(is_cid(cid), "R1", f"ref {name!r} is not a CID")
        ok = (
            name in ("deck", "keybox")
            or (name.startswith("t/") and name[2:] in ALL_TABLES)
            or (name.startswith("receipts/") and name[9:].isdigit())
        )
        require(ok, "R1", f"unknown ref {name!r}")


def schema(env: dict[int, Any]) -> None:
    if not isinstance(env[m.BODY], dict):
        raise TypeRule("R1", "body must be a map")


# ---------------------------------------------------------------- step 6: R9


def signatures(view: m.Resolved, sigs, leader_keyset: dict[int, Any], revoked) -> None:
    """Both aggregator keysets' ``sign`` thresholds (release.md, "Who signs")."""
    require(sigs is not None, "R9", "a release carries COSE signatures")
    b = view.body
    require(is_cid(b.get(HELPER)), "R9", "helper must be an authority CID")
    cid = view.bundle.cid
    need = leader_keyset[m.KS_THRESHOLDS][m.ROLE_SIGN]
    have = m.count_valid_signatures(leader_keyset, m.ROLE_SIGN, sigs, cid, revoked, view.position)
    require(have >= need, "R9", f"Leader: {have} valid signatures, threshold {need}")
    try:
        helper_keyset, helper_revoked = m.keyset_in_force(view.ctx, b[HELPER], view.position)
    except m.Rejection as e:
        raise TypeRule("R9", f"Helper keyset: {e.reason}") from e
    need_h = helper_keyset[m.KS_THRESHOLDS][m.ROLE_SIGN]
    have_h = m.count_valid_signatures(
        helper_keyset, m.ROLE_SIGN, sigs, cid, helper_revoked, view.position
    )
    require(have_h >= need_h, "R9", f"Helper: {have_h} valid signatures, threshold {need_h}")


# ---------------------------------------------------------------- step 10: R1 to R14


def _keyset_public_keys(view: m.Resolved, authority: bytes) -> set[bytes]:
    try:
        ks, _ = m.keyset_in_force(view.ctx, authority, view.position)
    except m.Rejection:
        return set()
    return {k[m.KEY_PUBLIC] for k in ks[m.KS_KEYS]}


def _accepted_assurance(view: m.Resolved, ctx_env: dict, deck_position: int | None):
    """R12: (authority, assurance level) for every verifier the vote policy accepts."""
    from . import trust_list as tl

    ctx_body = ctx_env[m.BODY]
    policy = ctx_body.get(c.VOTE, ctx_body[c.ENTRY])
    leaves = c.Policy(
        policy, c._trust_list_count(ctx_env[m.REFS]), len(ctx_body.get(c.ISSUERS, []))
    ).leaves
    authorities: set[bytes] = set()
    for leaf in leaves:
        (kind, i), name = leaf[1], leaf[2]
        if kind == c.SRC_ISSUER:
            authorities.add(ctx_body[c.ISSUERS][i])
        else:
            tl_env = view.manifest(ctx_env[m.REFS][f"tl/{i}"])
            for e in tl_env[m.BODY][tl.ENTRIES]:
                attrs = e[tl.EN_ATTRIBUTES]
                if not attrs or name in attrs:
                    authorities.add(e[tl.EN_AUTHORITY])
    out = []
    for auth in sorted(authorities):
        best = None
        for pos, env, _ in view.all_of_type("verifier"):
            if deck_position is not None and pos >= deck_position:
                continue
            if env.get(m.AUTHORITY) == auth and (best is None or env[m.VERSION] > best[m.VERSION]):
                best = env
        require(best is not None, "R12", "an accepted verifier is not resolvable")
        out.append([auth, best[m.BODY][14]])
    return out


def rules(view: m.Resolved) -> None:
    env, refs = view.env, view.refs
    _r1(env)
    b = env[m.BODY]
    stage = b[STAGE]
    final = b[FINAL]
    parts = b[PARTS]
    # R2
    deck_env = view.manifest(refs.get("deck", b""))
    require(deck_env is not None and deck_env[m.TYPE] == "deck", "R2", "deck ref is not a deck")
    deck_lineage = view.lineage_of(refs["deck"])
    # "logged before deck.closes": the log carries no clock, so the reference reads this as
    # logged before release version 1 (R8 then freezes the ref; D16 keeps a legitimate
    # extension before closes, so the two agree for an honest log).
    pin_at = view.position
    if env[m.VERSION] > 1 and view.position is not None:
        pin_at = view.position_of(env[m.LINEAGE])
    highest = view.latest_before(deck_lineage, pin_at)
    require(
        highest is not None and highest[m.VERSION] == deck_env[m.VERSION],
        "R2",
        "deck ref is not the highest version of its lineage logged before release version 1",
    )
    deck_body = deck_env[m.BODY]
    plan = deck_body[dk.PLAN]
    rating_deck = deck_body[dk.KIND] == dk.KIND_RATING
    cards = len(deck_body[dk.CARDS])
    ctx_env = view.manifest(deck_env[m.REFS]["context"])
    require(ctx_env is not None, "R2", "the deck's context does not resolve")
    ctx_body = ctx_env[m.BODY]
    leader = env[m.AUTHORITY]
    require(
        ctx_body[c.AGGREGATORS] == [leader, b[HELPER]],
        "R2",
        "aggregators are not the context's [leader, helper]",
    )
    shared = _keyset_public_keys(view, leader) & _keyset_public_keys(view, b[HELPER])
    require(not shared, "R2", "a public key appears in both aggregator keysets")
    # R3
    require(b[MECHANISM] == 0, "R3", "mechanism must be 0 in draft 0.1")
    # R4
    plan_parts = {p: rat_value(r) for p, r in plan[dk.P_PARTS].items()}
    require(rat_value(b[DELTA]) == rat_value(plan[dk.P_DELTA]), "R4", "delta differs from the plan")
    absorbed = b[ABSORBED]
    if absorbed:
        require(plan.get(dk.P_ABSORB, False), "R4", "absorbed without plan.absorb")
        require(not any(p in parts for p in dk.TIER), "R4", "absorbed release lists a tier part")
    total = Fraction(0)
    for p, rec in parts.items():
        require(p in plan_parts, "R4", f"part {p} is not in the plan")
        rho_p = rat_value(rec[PR_RHO])
        expected = plan_parts[p]
        if p == dk.TALLIES and absorbed:
            expected = sum(
                (plan_parts.get(q, Fraction(0)) for q in (dk.TALLIES, *dk.TIER)), Fraction(0)
            )
        require(rho_p == expected, "R4", f"part {p} rho differs from the plan")
        require(
            rec[PR_SIGMA] == sigma_of_part(plan, cards, p, rho_p),
            "R4",
            f"part {p} sigma is not the rounding of the exact rational",
        )
        total += rho_p
    require(rat_value(b[RHO]) == total, "R4", "rho is not the sum of the parts")
    require(total <= rat_value(plan[dk.P_RHO]), "R4", "rho above the plan's")
    # R5 (the part lists apply when unlocked is not empty; below the minimum R6 fixes parts)
    n_hat = b.get(N_HAT)
    gate1 = dk.effective_gate(plan, dk.COVARIANCE)
    above_minimum = bool(b[UNLOCKED])
    if stage == 1:
        require(dk.TALLIES in parts, "R5", "version 1 must record part 0")
        for p in (dk.COUNT, dk.MOVEMENT, dk.RATINGS, dk.BREAKDOWN):
            if p in plan_parts and above_minimum:
                require(p in parts, "R5", f"version 1 must record planned part {p}")
        should_final = (
            dk.COVARIANCE not in plan_parts
            or absorbed
            or n_hat is None
            or n_hat < gate1
            or not b[UNLOCKED]
        )
        require(final == should_final, "R5", "final at stage 1 does not follow the rule")
    else:
        prev = view.prev_env
        require(prev is not None, "R5", "no previous version")
        require(prev[m.BODY][FINAL] is False, "R5", "a version follows a final one")
        require(prev[m.BODY][STAGE] == stage - 1, "R5", "stage does not follow prev")
        new_part = STAGE_PART[stage]
        require(new_part in parts, "R5", f"stage {stage} must add part {new_part}")
        if stage == 4:
            require(final, "R5", "stage 4 must be final")
        else:
            n_part = parts[new_part].get(PR_N)
            require(n_part is not None, "R5", f"part {new_part} needs n")
            require(final == (n_part < gate1), "R5", f"final at stage {stage} does not follow n")
    if rating_deck:
        if above_minimum:
            require(
                set(parts) == {dk.TALLIES, dk.GROUPS, dk.RECEIPTS},
                "R5",
                "a rating release records exactly parts 0, 3 and 8",
            )
        require(final, "R5", "a rating release is final")
        source = view.manifest(deck_env[m.REFS].get("source", b""))
        # R5's lists apply when unlocked is not empty; below the minimum there is no groupsK
        # (R7), so the equality is tested only when part 0 is unlocked.
        if dk.TALLIES in b[UNLOCKED]:
            require(
                source is not None and b.get(GROUPS_K) == source[m.BODY].get(GROUPS_K),
                "R5",
                "groupsK differs from the source release's",
            )
    # R6
    expected_unlocked = canonical_unlocked(plan, parts, n_hat, stage, rating=rating_deck)
    require(b[UNLOCKED] == expected_unlocked, "R6", f"unlocked should be {expected_unlocked}")
    require((N_HAT in b) == (dk.TALLIES in b[UNLOCKED]), "R6", "nHat present iff part 0 unlocked")
    tables_in_refs = {k[2:] for k in refs if k.startswith("t/")}
    if N_HAT not in b:
        require(final, "R6", "below the floor the version is final")
        require(not tables_in_refs, "R6", "below the floor no tables are published")
        # ADR 0103: only parts 0 and 4 are noised below the floor; part 8's noise is not drawn
        expected_parts = {dk.TALLIES} | ({dk.COUNT} if dk.COUNT in plan_parts else set())
        require(
            set(parts) == expected_parts,
            "R6",
            "below the floor parts records parts 0 and 4 (when planned) only",
        )
        require(all(PR_N not in rec for rec in parts.values()), "R6", "no n below the floor")
    # R7
    must, may = required_tables(plan, b[UNLOCKED], n_hat, stage, final, rating_deck)
    missing = must - tables_in_refs
    extra = tables_in_refs - may
    require(not missing, "R7", f"missing tables {sorted(missing)}")
    require(not extra, "R7", f"tables of parts not unlocked {sorted(extra)}")
    # R7's "stage >= 3 and not final at 2" read as: groups exist from stage 3 on, except
    # when stage 3 is final through a dropout (map published, no centroids, no groups).
    # Rating decks: groupsK iff part 0 is unlocked (below the minimum there is no group table
    # and no groupsK).
    groups_expected = (
        (dk.TALLIES in b[UNLOCKED]) if rating_deck else (stage >= 3 and not (stage == 3 and final))
    )
    require((GROUPS_K in b) == groups_expected, "R7", "groupsK presence")
    # R8
    prev = view.prev_env
    if prev is not None:
        pb = prev[m.BODY]
        require(rat_value(b[RHO]) >= rat_value(pb[RHO]), "R8", "rho lowered")
        for key in (MECHANISM, HELPER, DELTA, N_HAT, ASSURANCE, SEALED, RESULTS_EPOCH, ABSORBED):
            require(b.get(key) == pb.get(key), "R8", f"body key {key} changed")
        require(refs["deck"] == prev[m.REFS]["deck"], "R8", "deck ref changed")
        for p, rec in pb[PARTS].items():
            require(parts.get(p) == rec, "R8", f"part {p} record changed or dropped")
        require(set(pb[UNLOCKED]) <= set(b[UNLOCKED]), "R8", "an unlocked part was dropped")
        for r, root in pb[RECEIPTS].items():
            require(b[RECEIPTS].get(r) == root, "R8", f"receipt root {r} changed")
        for name, cid in prev[m.REFS].items():
            if name.startswith("t/") or name.startswith("receipts/"):
                require(refs.get(name) == cid, "R8", f"ref {name!r} changed or dropped")
    # R10, in the context's ledger of record (the first entry of ctx.logs, ADR 0103): a release
    # must be in that log; one that is only in another listed log is invalid
    record = log_of_record(ctx_body)
    require(
        view.bundle.proof is None or view.bundle.proof.log == record,
        "R10",
        "the release is not in the context's ledger of record",
    )
    own_lineage = env.get(m.LINEAGE, view.bundle.cid)
    for pos, other, bnd in _in_log(view.all_of_type("release"), record):
        if view.position is not None and pos >= view.position:
            continue
        if other.get(m.LINEAGE, bnd.cid) == own_lineage:
            continue
        other_deck = other[m.REFS].get("deck")
        if other_deck is not None and view.lineage_of(other_deck) == deck_lineage:
            raise TypeRule("R10", "another release lineage for this deck was logged earlier")
    # R10, rating decks: fewer than two other rating releases with the same source whose
    # version 1 was issued within 365 days before this version 1
    if rating_deck and env[m.VERSION] == 1:
        source = deck_env[m.REFS].get("source")
        earlier = 0
        for pos, other, bnd in _in_log(view.all_of_type("release"), record):
            if view.position is not None and pos >= view.position:
                continue
            if other[m.VERSION] != 1 or other.get(m.LINEAGE, bnd.cid) == own_lineage:
                continue
            odeck = view.manifest(other[m.REFS].get("deck", b""))
            if odeck is None or odeck[m.BODY].get(dk.KIND) != dk.KIND_RATING:
                continue
            if odeck[m.REFS].get("source") != source:
                continue
            if 0 <= env[m.ISSUED] - other[m.ISSUED] <= 365 * 86_400:
                earlier += 1
        require(earlier < 2, "R10", "third rating release for this source within a year")
    # R11
    results = ctx_body[c.PERMS][c.P_RESULTS]
    require(b[SEALED] == (results != 0), "R11", "sealed must follow perms.results")
    require(("keybox" in refs) == b[SEALED], "R11", "keybox present iff sealed")
    if b[SEALED]:
        require(b.get(RESULTS_EPOCH) == ctx_body.get(c.RESULTS_EPOCH), "R11", "resultsEpoch")
    else:
        require(RESULTS_EPOCH not in b, "R11", "resultsEpoch on a public release")
        # "every t/* is a public blob": a public table is a plain blob, so a fetched one must
        # not start with a sealed format byte followed by a GCM chunk; pending Parquet, the
        # reference accepts any fetched bytes here.
    # R12
    deck_position = view.position_of(refs["deck"])
    require(b[ASSURANCE] == _accepted_assurance(view, ctx_env, deck_position), "R12", "assurance")
    # R13 (below the minimum nothing is published, a padded leaf count included: ADR 0103)
    rounds = set(range(stage)) if above_minimum else set()
    which = "rounds 0..stage-1" if above_minimum else "nothing below the minimum"
    require(set(b[RECEIPTS]) == rounds, "R13", f"receipts must cover {which}")
    root_refs = {int(k[9:]) for k in refs if k.startswith("receipts/")}
    require(root_refs == rounds, "R13", f"receipts/<n> refs must cover {which}")
    window = plan.get(dk.P_ROUND_WINDOW, dk.DEFAULT_ROUND_WINDOW)
    if final:
        require(ROUND_DEADLINE not in b, "R13", "roundDeadline on a final version")
    else:
        require(b.get(ROUND_DEADLINE) == env[m.ISSUED] + window, "R13", "roundDeadline")
    if stage == 1:
        closes = deck_body[dk.CLOSES]
        require(closes <= env[m.ISSUED] <= closes + THIRTY_DAYS, "R13", "issued window")
    # Every version is issued by E, the expires of the deck version this release pins (R8
    # freezes refs["deck"], so a later deck version never moves E).
    expires_e = deck_env[m.EXPIRES]
    require(env[m.ISSUED] <= expires_e, "R13", "issued after the pinned deck version's expires")
    if not final:
        remaining = dk.post_close_rounds(plan) - stage + 1
        require(
            env[m.ISSUED] + remaining * window <= expires_e,
            "R13",
            "no room before expires for the rounds still to run",
        )
    # R14, counted in the ledger of record as R10
    floors = c.floors_of(ctx_body)
    if stage == 1 and floors["rhoYear"] is not None:
        ctx_lineage = view.lineage_of(deck_env[m.REFS]["context"])
        spent = rat_value(plan[dk.P_RHO])
        for pos, other, bnd in _in_log(view.all_of_type("release"), record):
            if view.position is not None and pos >= view.position:
                continue
            if other[m.VERSION] != 1 or bnd.cid == view.bundle.cid:
                continue
            other_deck = view.manifest(other[m.REFS].get("deck", b""))
            if other_deck is None:
                continue
            if view.lineage_of(other_deck[m.REFS]["context"]) != ctx_lineage:
                continue
            if env[m.ISSUED] - YEAR <= other[m.ISSUED] <= env[m.ISSUED]:
                spent += rat_value(other_deck[m.BODY][dk.PLAN][dk.P_RHO])
        require(spent <= floors["rhoYear"], "R14", "yearly rho floor exceeded")
    # R15: world integration pending; parquet_tables validates opened files
    # against a trusted contract.


def record_log(view: m.Resolved) -> bytes | None:
    """Step 7 hook: the ledger of record of the context the pinned deck names, or None when
    the deck or context is not held (step 9 reports that)."""
    deck_cid = view.env[m.REFS].get("deck")
    deck_env = view.manifest(deck_cid) if isinstance(deck_cid, bytes) else None
    if deck_env is None or not isinstance(deck_env.get(m.REFS), dict):
        return None
    ctx_cid = deck_env[m.REFS].get("context")
    ctx_env = view.manifest(ctx_cid) if isinstance(ctx_cid, bytes) else None
    try:
        return log_of_record(ctx_env[m.BODY]) if ctx_env is not None else None
    except (KeyError, IndexError, TypeError):
        return None


def log_of_record(ctx_body: dict[int, Any]) -> bytes:
    """The context's ledger of record: the first entry of ``logs`` (ADR 0103; services.md,
    "Step 10 at the log"). R10, R14 and deck.md D16's clock-free half are decided there."""
    return ctx_body[c.LOGS][0][c.L_LOG]


def _in_log(entries, record: bytes):
    """The entries of ``all_of_type`` whose bundle is logged in ``record``."""
    return [(pos, env, bnd) for pos, env, bnd in entries if bnd.proof.log == record]


def log_check(env: dict[int, Any], deck_env: dict[int, Any], log_now: int):
    """R13's clock half, run by the ledger at submission: any release version is refused when
    the ledger's own clock is past ``E``, the ``expires`` of the deck version in
    ``refs["deck"]`` (a Leader and Helper run by one party could back-date ``issued``). The
    ``issued`` halves of R13 stay in ``rules``. Returns ``(rule, reason)`` or None."""
    expires_e = deck_env[m.EXPIRES]
    if log_now > expires_e:
        return ("R13", f"the ledger's clock ({log_now}) is past the deck's expires ({expires_e})")
    return None


m.register("release", schema=schema, rules=rules, signatures=signatures, record_log=record_log)
