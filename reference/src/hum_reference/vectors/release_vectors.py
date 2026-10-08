"""Vectors for release math, written to docs/specs/deck.md, docs/specs/release.md and
docs/specs/context.md as far as they concern numbers: accounting, σ per part, plans against
floors, context floors, caps, gates, shields, the phone-side round computations, the
noise-aware rankings and the sampler harness. Whole release manifests and tables are left
for the second run (see conformance.md).

Floats are IEEE doubles printed with Python's shortest round-trip repr; conformance.md
gives the tolerance. Values a manifest carries (σ in micro-units, rats) are exact.
"""

from __future__ import annotations

import math
import random
from fractions import Fraction

from .. import release as r
from ..bodies import release as rb
from . import File

SPEC = "release"
S_ACC = "release.md Noise"
S_PLAN = "deck.md The release plan"
S_FLOORS = "context.md Floors"
S_PHONE = "release.md What a phone computes"


def frac(x: Fraction) -> dict:
    return {"num": x.numerator, "den": x.denominator, "rat": r.rat(x)}


def plan_json(p: r.ReleasePlan) -> dict:
    out = {
        "rho": frac(p.rho),
        "delta": frac(p.delta),
        "parts": {str(k): frac(v) for k, v in p.parts.items()},
        "cap": p.cap,
        "minVoters": p.min_voters,
        "grid": p.grid,
        "absorb": p.absorb,
        "roundWindow": p.round_window,
        "covScale": p.cov_scale,
    }
    for name, v in (
        ("covStatements", p.cov_statements),
        ("capMovement", p.cap_movement),
        ("capRatings", p.cap_ratings),
    ):
        if v is not None:
            out[name] = v
    if p.gates:
        out["gates"] = {str(k): v for k, v in p.gates.items()}
    if p.breakdown is not None:
        out["breakdown"] = p.breakdown
    return out


def floors_json(fl: r.Floors) -> dict:
    out = {
        "rho": frac(fl.rho),
        "delta": frac(fl.delta),
        "minVoters": fl.min_voters,
        "releasesPerDeck": fl.releases_per_deck,
        "minWitnesses": fl.min_witnesses,
    }
    if fl.rho_year is not None:
        out["rhoYear"] = frac(fl.rho_year)
    return out


# ---------------------------------------------------------------- plans used throughout

CARDS = 18
PLAN_FULL = r.ReleasePlan.default(r.RHO_MAX, cap=60)
PLAN_TALLIES_ONLY = r.ReleasePlan(
    r.RHO_MAX,
    r.DELTA_MAX,
    {
        r.TALLIES: r.RHO_MAX - Fraction(2, 200),
        r.COUNT: Fraction(1, 200),
        r.RECEIPTS: Fraction(1, 200),
    },
    cap=30,
    min_voters=100,
)
_IBIS_BASE = r.RHO_MAX - Fraction(1, 200)
PLAN_IBIS = r.ReleasePlan(
    r.RHO_MAX,
    r.DELTA_MAX,
    {
        r.TALLIES: _IBIS_BASE * Fraction(13, 100),
        r.COVARIANCE: _IBIS_BASE * Fraction(30, 100),
        r.MAP: _IBIS_BASE * Fraction(13, 100),
        r.GROUPS: _IBIS_BASE * Fraction(30, 100),
        r.MOVEMENT: _IBIS_BASE * Fraction(8, 100),
        r.RATINGS: _IBIS_BASE * Fraction(6, 100),
        r.RECEIPTS: Fraction(1, 200),
    },
    cap=60,
    min_voters=100,
    cap_movement=10,
    cap_ratings=10,
)
PLANS = {"full": PLAN_FULL, "tallies-only": PLAN_TALLIES_ONLY, "ibis": PLAN_IBIS}


def accounting_file() -> File:
    f = File(
        SPEC,
        "accounting",
        "ε ↔ ρ under zCDP with δ = 1e-6: ε = ρ + 2√(ρ ln(1/δ)); √ρ = √(L + ε) − √L, L = ln(1/δ). "
        "RHO_MAX is 127/500: ε 4.00054 at δ 1e-6 in binary64.",
    )
    for eps in [0.5, 1, 2, 4, 8, 16, 20]:
        rho = r.eps_to_rho(eps)
        f.add(
            "eps-to-rho",
            f"ρ for ε {eps}",
            S_ACC,
            {"eps": eps, "delta": r.DELTA},
            {"rho": rho, "eps_round_trip": r.rho_to_eps(rho)},
        )
    for num, den in [(127, 500), (91, 100), (1, 100), (1, 10), (1, 1), (1, 200)]:
        rho = Fraction(num, den)
        f.add(
            "rho-to-eps",
            f"ε for ρ {num}/{den}",
            S_ACC,
            {"rho": frac(rho), "delta": r.DELTA},
            {"eps": r.rho_to_eps(float(rho))},
        )
    f.add(
        "compose",
        "Four releases at RHO_MAX compose to ρ 1.016, about ε 8.5, not 16",
        S_ACC,
        {"rhos": [frac(r.RHO_MAX)] * 4},
        {"rho_total": frac(4 * r.RHO_MAX), "eps_total": r.rho_to_eps(float(4 * r.RHO_MAX))},
    )
    for d2, rho in [
        (1, Fraction(1, 200)),
        (61, Fraction(381, 10000)),
        (31, r.RHO_MAX - Fraction(1, 100)),
        (4, Fraction(1, 200)),
    ]:
        f.add(
            "sigma",
            f"σ for Δ² = {d2}, ρ = {rho}: exact σ², σ_r = n/2²⁰, the real value and the "
            "micro-unit integer round(σ_r × 10⁶) (ties to even)",
            S_ACC,
            {"delta_squared": d2, "rho": frac(rho)},
            sigma_view(d2, rho),
        )
    return f


def sigma_view(d2: int, rho: Fraction, cov_scale: int = 1) -> dict:
    s2 = r.sigma_squared(d2, rho)
    n = r.sigma_r_numerator(s2)
    out = {
        "sigma_squared": frac(s2),
        "n": n,
        "sigma_r": frac(Fraction(n, 2**r.SIGMA_R_BITS)),
        "sigma": r.gauss_sigma(math.sqrt(d2), float(rho)),
        "sigma_micro": r.sigma_micro(d2, rho, cov_scale),
    }
    if cov_scale != 1:
        out["cov_scale"] = cov_scale
    return out


def sigmas_file() -> File:
    f = File(
        SPEC,
        "sigmas",
        "σ per part for the three valid plans (deck.md Vectors): Δ² per part from the Parts table, "
        "Δ_cov = covScale + ⌈√(M(M+1)/2) / 2⌉ (release.md Round 1), σ² = Δ²·den/(2·num) in lowest "
        "terms, σ_r = n/2²⁰ with n the least integer such that n²·q ≥ p·2⁴⁰ (the rational the "
        "sampler is called with), and `sigma` = round(σ_r × 10⁶) ties to even (covariance: "
        "round(σ_r / covScale × 10⁶)). A sampler called with σ, or with a binary64 value, is "
        "non-conformant. The boundary cases show σ² a perfect square of a dyadic (n exactly at "
        "the bound), σ² one unit of 2⁻⁴⁰ below that square (n rounds up to the same value), "
        "and σ within 2⁻²⁰ below an integer, where ⌈σ_8⌉ over σ² (release.md Receipts) and "
        "⌈σ_r⌉ are both shown.",
    )
    for name, plan in PLANS.items():
        sig = r.part_sigmas(plan, CARDS)
        f.add(
            "plan",
            f"σ per part for plan {name} on an {CARDS}-card deck",
            S_PLAN,
            {"plan": plan_json(plan), "cards": CARDS},
            {
                str(p): {
                    "name": r.PART_NAMES[p],
                    "delta_squared": e["delta_squared"],
                    "rho": frac(e["rho"]),
                    "sigma_squared": frac(e["sigma_squared"]),
                    "n": e["sigma_r"].numerator,
                    "sigma_r": frac(e["sigma_r"]),
                    "sigma": e["sigma"],
                    "sigma_micro": e["sigma_micro"],
                    **(
                        {"sigma_real_units": e["sigma_real_units"]}
                        if "sigma_real_units" in e
                        else {}
                    ),
                }
                for p, e in sig.items()
            },
        )
    full_count = r.ReleasePlan.default(r.RHO_MAX, cap=60, count=True, absorb=True)
    tier_rho = sum(full_count.parts[p] for p in (r.TALLIES, r.COVARIANCE, r.MAP, r.GROUPS))
    f.add(
        "absorbed",
        "Full plan with count and absorb whose tier stayed locked: tallies noised with "
        "ρ_tallies + ρ_cov + ρ_map + ρ_groups",
        "release.md Noise",
        {"plan": plan_json(full_count)},
        {"tallies_rho": frac(tier_rho), **sigma_view(61, tier_rho)},
    )
    example = r.ReleasePlan(
        r.RHO_MAX,
        r.DELTA_MAX,
        {
            r.TALLIES: Fraction(281, 10000),
            r.COVARIANCE: Fraction(889, 10000),
            r.MAP: Fraction(381, 10000),
            r.GROUPS: Fraction(889, 10000),
            r.COUNT: Fraction(1, 200),
            r.RECEIPTS: Fraction(1, 200),
        },
        18,
        100,
    )
    sig = r.part_sigmas(example, 18)
    f.add(
        "example",
        "σ_r and `sigma` per part for release.md's example plan (cap 18, 18 cards, covScale 2¹⁶, "
        "Δ_cov 65543): tallies 18386906, covariance 2371813, map 3622619, groups 10337391, count "
        "10000000 and receipts 20000000 (perfect squares)",
        "release.md Noise",
        {"plan": plan_json(example), "cards": 18},
        {
            str(p): {
                "name": r.PART_NAMES[p],
                **sigma_view(
                    e["delta_squared"], e["rho"], example.cov_scale if p == r.COVARIANCE else 1
                ),
            }
            for p, e in sig.items()
        },  # fmt: skip
    )
    for suffix, desc, d2, rho in (
        ("square", "σ² = 100, a perfect square: n = 10·2²⁰ exactly at the bound, σ_r = σ = 10",
         1, Fraction(1, 200)),
        ("dyadic-square", "σ² = 25/16, the square of the dyadic 5/4: n exactly at the bound, σ_r = σ",
         25, Fraction(8, 1)),
        ("one-below-square", "σ² = (10·2²⁰)² − 1 over 2⁴⁰, one unit below a dyadic square: n rounds "
         "up to 10·2²⁰ and σ_r = 10 (the (n−1)² test fails by one)",
         (10 * 2**20) ** 2 - 1, Fraction(2**40, 2)),
        ("below-integer", "σ within 2⁻²⁰ below 20 (σ² = 400 − 2⁻³⁰): σ_r = 20; ⌈σ_8⌉ over σ² is 20 "
         "and ⌈σ_r⌉ is 20, the same",
         1, Fraction(2**29, 400 * 2**30 - 1)),
    ):  # fmt: skip
        s2 = r.sigma_squared(d2, rho)
        s_r = r.sigma_rational(d2, rho)
        f.add(
            f"boundary-{suffix}",
            desc,
            "release.md Noise, Receipts",
            {"delta_squared": d2, "rho": frac(rho)},
            {
                **sigma_view(d2, rho),
                "ceil_sigma_over_sigma_squared": rb.ceil_sigma(s2),
                "ceil_sigma_r": -(-s_r.numerator // s_r.denominator),
            },
        )
    return f


def plans_file() -> File:
    f = File(
        SPEC,
        "plans",
        "deck.md rules D8, D9 (data part), D10, D11 and D14: plans checked against a context's floors. "
        "Rules that need resolved refs (D5-D7, D9's argument refs, D15) are not here.",
    )
    P = r.PROTOCOL
    stricter = r.Floors(Fraction(1, 10), Fraction(1, 10**7), 300, 1, 3, Fraction(1, 2))
    valid = [
        ("full", PLAN_FULL, P, 0),
        ("tallies-only", PLAN_TALLIES_ONLY, P, 0),
        ("ibis", PLAN_IBIS, P, 12),
        (
            "under-stricter-context",
            r.ReleasePlan(
                Fraction(1, 10),
                Fraction(1, 10**7),
                {
                    **{
                        p: (Fraction(1, 10) - Fraction(1, 200)) * s
                        for p, s in r.DEFAULT_SPLIT.items()
                    },
                    r.RECEIPTS: Fraction(1, 200),
                },
                60,
                300,
                gates={r.TALLIES: 300},
            ),
            stricter,
            0,
        ),
    ]
    for name, plan, fl, args in valid:
        v = r.check_plan(plan, fl, CARDS, argument_refs=args)
        assert not v, (name, v)
        f.add(
            "plan",
            f"Plan {name} satisfies the floors",
            S_PLAN,
            {
                "plan": plan_json(plan),
                "floors": floors_json(fl),
                "cards": CARDS,
                "argument_refs": args,
            },
            {"violations": []},
        )
    rho = r.RHO_MAX

    def pl(parts, **kw):
        base = {"cap": 60, "min_voters": 100}
        base.update(kw)
        return r.ReleasePlan(kw.pop("rho", rho), kw.pop("delta", r.DELTA_MAX), parts, **base)

    invalid = [
        ("D8-no-tallies", r.ReleasePlan(rho, r.DELTA_MAX, {r.MAP: rho - Fraction(1, 200), r.RECEIPTS: Fraction(1, 200)}, 60, 100), P, 0),
        ("D8-no-receipts", r.ReleasePlan(rho, r.DELTA_MAX, {r.TALLIES: rho}, 60, 100), P, 0),
        ("D8-partial-tier", r.ReleasePlan(rho, r.DELTA_MAX, {r.TALLIES: rho / 2, r.MAP: rho / 2}, 60, 100), P, 0),
        ("D8-sum-below-rho", r.ReleasePlan(rho, r.DELTA_MAX, {r.TALLIES: rho / 2}, 60, 100), P, 0),
        ("D8-zero-part", r.ReleasePlan(rho, r.DELTA_MAX, {r.TALLIES: rho, r.COUNT: Fraction(0)}, 60, 100), P, 0),
        ("D9-absorb-without-count", r.ReleasePlan(rho, r.DELTA_MAX, {r.TALLIES: rho}, 60, 100, absorb=True), P, 0),
        ("D9-movement-no-arguments", r.ReleasePlan(rho, r.DELTA_MAX, {r.TALLIES: rho / 2, r.MOVEMENT: rho / 2}, 60, 100, cap_movement=10), P, 0),
        ("D10-rho-over-floor", r.ReleasePlan.default(Fraction(3, 10), 60), P, 0),
        ("D10-rho-over-context", r.ReleasePlan.default(Fraction(2, 10), 60, 300), stricter, 0),
        ("D10-delta-over-floor", r.ReleasePlan(rho, Fraction(1, 10**5), dict(PLAN_FULL.parts), 60, 100), P, 0),
        ("D10-minvoters-below-floor", r.ReleasePlan.default(rho, 60, 50), P, 0),
        ("D10-count-over-rhomax", r.ReleasePlan(rho, r.DELTA_MAX, {r.TALLIES: rho - Fraction(1, 100), r.COUNT: Fraction(1, 100)}, 60, 100), P, 0),
        ("D11-gate-below-protocol", r.ReleasePlan.default(rho, 60, gates={r.TALLIES: 50}), P, 0),
        ("D11-minvoters-above-gate", r.ReleasePlan.default(rho, 60, 150), P, 0),
        ("D11-covstatements-over-cards", r.ReleasePlan.default(rho, 60, cov_statements=CARDS + 1), P, 0),
        ("D11-grid-out-of-range", r.ReleasePlan.default(rho, 60, grid=7), P, 0),
        ("D11-covscale-not-power-of-two", r.ReleasePlan.default(rho, 60, cov_scale=1000), P, 0),
        ("D11-roundwindow-too-short", r.ReleasePlan.default(rho, 60, round_window=600), P, 0),
        ("D14-cap-zero", r.ReleasePlan.default(rho, 0), P, 0),
        ("D14-capmovement-over-cards", r.ReleasePlan(rho, r.DELTA_MAX, {r.TALLIES: rho / 2, r.MOVEMENT: rho / 2}, 60, 100, cap_movement=CARDS + 1), P, 4),
    ]  # fmt: skip
    for name, plan, fl, args in invalid:
        v = r.check_plan(plan, fl, CARDS, argument_refs=args)
        assert v, name
        rule = name.split("-")[0]
        assert any(x.startswith(rule) for x in v), (name, v)
        f.add(
            "reject",
            f"Plan breaks {name}",
            S_PLAN,
            {
                "plan": plan_json(plan),
                "floors": floors_json(fl),
                "cards": CARDS,
                "argument_refs": args,
            },
            rejection={"step": 10, "check": "deck-plan", "reason": rule, "violations": v},
        )
    return f


def floors_file() -> File:
    f = File(
        SPEC,
        "floors",
        "context.md: protocol constants, rules C3 and C4 on a context's floors, and C10 on tightening "
        "between versions.",
    )
    P = r.PROTOCOL
    f.add(
        "protocol",
        "Draft 0.1 protocol constants",
        "context.md Protocol constants",
        {},
        {
            "floors": floors_json(P),
            "shieldYearEps": frac(r.SHIELD_YEAR_EPS),
            "gates": {
                "tallies": r.GATE_TALLIES,
                "common": r.GATE_COMMON,
                "map": r.GATE_MAP,
                "cell": r.GATE_CELL,
                "checks": r.GATE_CHECKS,
            },
            "maxCards": r.MAX_CARDS,
            "countRhoMaxDefault": frac(r.COUNT_RHO_MAX_DEFAULT),
        },
    )
    stricter = r.Floors(Fraction(1, 10), Fraction(1, 10**7), 300, 1, 3, Fraction(1, 2))
    for name, fl in [("equal-to-protocol", P), ("stricter", stricter)]:
        assert not r.check_context_floors(fl)
        f.add(
            "context",
            f"Context floors {name} are accepted",
            S_FLOORS,
            {"floors": floors_json(fl)},
            {"violations": []},
        )
    looser = [
        ("C3-rho", r.Floors(Fraction(3, 10), P.delta, P.min_voters)),
        ("C3-delta", r.Floors(P.rho, Fraction(1, 10**5), P.min_voters)),
        ("C3-minvoters", r.Floors(P.rho, P.delta, 50)),
        ("C3-releases", r.Floors(P.rho, P.delta, P.min_voters, releases_per_deck=2)),
        ("C3-minwitnesses", r.Floors(P.rho, P.delta, P.min_voters, min_witnesses=1)),
        ("C4-rhoyear", r.Floors(P.rho, P.delta, P.min_voters, rho_year=Fraction(1, 10))),
    ]
    for name, fl in looser:
        v = r.check_context_floors(fl)
        assert v, name
        f.add(
            "reject",
            f"Context floors break {name}",
            S_FLOORS,
            {"floors": floors_json(fl)},
            rejection={
                "step": 10,
                "check": "context-floors",
                "reason": name.split("-")[0],
                "violations": v,
            },
        )
    v2_ok = r.Floors(Fraction(1, 5), P.delta, 300, 1, 2, Fraction(1))
    prev = r.Floors(P.rho, P.delta, 100, 1, 2, Fraction(2))
    assert not r.check_context_tightening(v2_ok, prev)
    f.add(
        "tighten",
        "Version 2 lowers rho to 1/5, raises minVoters to 300 and lowers rhoYear (C10)",
        S_FLOORS,
        {"prev": floors_json(prev), "new": floors_json(v2_ok)},
        {"violations": []},
    )
    for name, new in [
        ("C10-rho-raised", r.Floors(P.rho, P.delta, 100, 1, 2, Fraction(2))),
        ("C10-minvoters-lowered", r.Floors(Fraction(1, 5), P.delta, 50, 1, 2, Fraction(2))),
        ("C10-rhoyear-dropped", r.Floors(Fraction(1, 5), P.delta, 300, 1, 2, None)),
    ]:
        prev_i = (
            prev
            if "rho-raised" not in name
            else r.Floors(Fraction(1, 5), P.delta, 100, 1, 2, Fraction(2))
        )
        v = r.check_context_tightening(new, prev_i)
        assert v, name
        f.add(
            "reject",
            f"Version 2 breaks {name}",
            S_FLOORS,
            {"prev": floors_json(prev_i), "new": floors_json(new)},
            rejection={"step": 10, "check": "context-tightening", "reason": "C10", "violations": v},
        )
    return f


def cap_file() -> File:
    f = File(
        SPEC,
        "cap",
        "Contribution capping on the phone: a later vote replaces an earlier one on the same card, "
        "then at most K votes are kept (this reference keeps the first K in cast order; ballot.md "
        "says a uniformly random K). The tallies contribution has squared L2 norm at most K + 1.",
    )
    cases = [
        ("under-cap", [(0, 1), (1, -1), (2, 0)], 5, 6),
        ("at-cap", [(0, 1), (1, -1), (2, 0), (3, 1), (4, 1)], 5, 6),
        ("over-cap", [(i, 1 if i % 2 == 0 else -1) for i in range(8)], 5, 10),
        ("revote-replaces", [(0, 1), (1, -1), (0, -1), (2, 0)], 2, 4),
        ("cap-1", [(3, 0), (1, 1)], 1, 4),
        ("empty", [], 60, 3),
    ]
    for name, votes, cap, cards in cases:
        c = r.contribution(votes, cap, cards)
        f.add(
            "contribution",
            f"Contribution for {name}",
            S_PLAN,
            {"votes": [{"card": s, "vote": v} for s, v in votes], "cap": cap, "cards": cards},
            {
                "kept": [{"card": s, "vote": v} for s, v in c["kept"]],
                "agree": c["agree"],
                "disagree": c["disagree"],
                "unsure": c["unsure"],
                "participant": 1,
                "norm_squared": c["norm_squared"],
                "max_norm_squared": cap + 1,
            },
        )
    f.add(
        "reject",
        "A vote outside {1, -1, 0} is invalid",
        S_PLAN,
        {"votes": [{"card": 0, "vote": 2}], "cap": 5, "cards": 1},
        rejection={"step": None, "check": "contribution", "reason": "invalid-vote"},
    )
    return f


def gates_file() -> File:
    f = File(SPEC, "gates", "Size gates: which features a noised voter count unlocks.")
    for n in [0, 99, 100, 101, 299, 300, 799, 800, 4999, 5000, 100000]:
        f.add(
            "unlock",
            f"Features unlocked at {n} noised voters",
            "context.md Protocol constants",
            {"noised_voters": n, "gates": r.FEATURE_GATES},
            {"unlocked": r.unlocked(n), "publishable": n >= r.GATE_TALLIES},
        )
    f.add(
        "unlock",
        "A noised count of -3 (raw nHat may be negative) publishes nothing",
        "release.md Body fields",
        {"noised_voters": -3, "gates": r.FEATURE_GATES},
        {"unlocked": [], "publishable": False},
    )
    return f


def shield_file() -> File:
    f = File(
        SPEC,
        "shield",
        "A phone charges its yearly shield (ε 20 → ρ) with each plan's full ρ before voting, and "
        "sits a deck out when the total would exceed it.",
    )
    q = r.RHO_MAX
    cases = [
        ("first-deck", [], q, Fraction(20)),
        ("fourth-deck", [q, q, q], q, Fraction(20)),
        ("seventeenth-deck", [q] * 16, q, Fraction(20)),
        ("eighteenth-deck", [q] * 17, q, Fraction(20)),
        ("stricter-personal-shield", [q, q], q, Fraction(8)),
        ("stricter-personal-shield-fits", [q], q, Fraction(8)),
    ]
    for name, spent, planned, shield in cases:
        out = r.shield_check(spent, planned, shield)
        f.add(
            "charge",
            f"Shield check: {name}",
            "context.md Floors",
            {
                "spent_rho": [frac(s) for s in spent],
                "planned_rho": frac(planned),
                "shield_eps_year": frac(shield),
            },
            out,
        )
    return f


def phone_file() -> File:
    f = File(
        SPEC,
        "phone",
        "What a phone computes in rounds 1 to 3 from published tables (release.md): sel and mu from "
        "tallies, the round-1 integer vector and its norm, the round-2 cell, the round-3 group.",
    )
    rng = random.Random(20261006)
    cards = 12
    tallies = []
    for _j in range(cards):
        n = rng.choice([40, 120, 300, 300, 450, 600, 20, 300, 800, 90, 150, 300])
        a = rng.random()
        tallies.append(
            (
                round(n * a + rng.uniform(-8, 8), 2),
                round(n * (1 - a) * 0.8 + rng.uniform(-8, 8), 2),
                round(n * (1 - a) * 0.2 + rng.uniform(-8, 8), 2),
            )
        )
    tallies[3] = (-4.0, 2.0, 1.0)  # a negative noised count, clamped at 0
    m_ = 8
    sel, mu = r.sel_and_mu(tallies, m_)
    f.add(
        "sel-mu",
        f"sel (M = {m_}, ties to the lower index) and mu from a noised tallies table with a negative count",
        S_PHONE,
        {
            "tallies": [
                {"card": j, "agree": t[0], "disagree": t[1], "unsure": t[2]}
                for j, t in enumerate(tallies)
            ],
            "M": m_,
        },
        {"sel": sel, "mu": mu},
    )
    hands = {
        "full": {j: rng.choice([1, -1, 0]) for j in range(cards)},
        "sparse": {0: 1, 5: -1},
        "one-vote": {sel[0]: 1},
        "no-sel-votes": {j: 1 for j in range(cards) if j not in sel},
    }
    cov_scale = 65_536
    for name, hand in hands.items():
        v = r.round1_vector(hand, sel, mu, cov_scale)
        f.add(
            "round1",
            f"Round 1 vector for hand {name}",
            S_PHONE,
            {
                "hand": {str(k): val for k, val in hand.items()},
                "sel": sel,
                "mu": mu,
                "covScale": cov_scale,
            },
            {
                "contributes": v is not None,
                **(
                    {}
                    if v is None
                    else {
                        "z": v["z"],
                        "entries": v["entries"],
                        "norm_squared": v["norm_squared"],
                        "delta_cov": v["delta_cov"],
                        "within_sensitivity": v["within_sensitivity"],
                    }
                ),
            },
        )
    # axes: fixed unit vectors (what the aggregator publishes), not derived here
    pc1 = [0.5, -0.3, 0.4, 0.2, -0.45, 0.1, 0.35, -0.25]
    n1 = math.sqrt(sum(x * x for x in pc1))
    pc1 = [x / n1 for x in pc1]
    pc2 = [0.1, 0.5, 0.2, -0.4, 0.3, -0.5, 0.15, 0.4]
    d = sum(a * b for a, b in zip(pc1, pc2, strict=True))
    pc2 = [b - d * a for a, b in zip(pc1, pc2, strict=True)]
    n2 = math.sqrt(sum(x * x for x in pc2))
    pc2 = [x / n2 for x in pc2]
    half_x, half_y, grid = 2.4, 1.9, 24
    axes_in = {
        "sel": sel,
        "mu": mu,
        "pc1": pc1,
        "pc2": pc2,
        "half_x": half_x,
        "half_y": half_y,
        "grid": grid,
    }
    for name, hand in hands.items():
        c = r.round2_cell(hand, sel, mu, pc1, pc2, half_x, half_y, grid)
        f.add(
            "round2",
            f"Round 2 cell for hand {name}",
            S_PHONE,
            {"hand": {str(k): val for k, val in hand.items()}, **axes_in},
            {"contributes": c is not None, **({} if c is None else c)},
        )
    # a hand projected far outside the box clips to the edge cell
    far = {j: (1 if pc1[i] > 0 else -1) for i, j in enumerate(sel)}
    c = r.round2_cell(far, sel, mu, pc1, pc2, 0.3, 0.3, grid)
    f.add(
        "round2",
        "Round 2 cell for a hand far outside a small box: clipped to an edge cell",
        S_PHONE,
        {
            "hand": {str(k): val for k, val in far.items()},
            **{**axes_in, "half_x": 0.3, "half_y": 0.3},
        },
        {"contributes": True, **c},
    )
    centroids = [(-0.8, 0.2), (0.9, -0.1), (0.1, 1.1)]
    for name, hand in hands.items():
        g = r.round3_group(hand, sel, mu, pc1, pc2, centroids)
        f.add(
            "round3",
            f"Round 3 group for hand {name}",
            S_PHONE,
            {
                "hand": {str(k): val for k, val in hand.items()},
                "sel": sel,
                "mu": mu,
                "pc1": pc1,
                "pc2": pc2,
                "centroids": centroids,
            },
            {"contributes": g is not None, **({} if g is None else g)},
        )
    # equidistant: centroids symmetric about the projection's x
    hand = hands["full"]
    p = r._project(hand, sel, mu, pc1, pc2)
    sym = [(p[0] - 0.5, p[1]), (p[0] + 0.5, p[1])]
    g = r.round3_group(hand, sel, mu, pc1, pc2, sym)
    assert g["group"] == 0
    f.add(
        "round3",
        "Round 3 with two centroids at equal distance: the lower index wins",
        S_PHONE,
        {
            "hand": {str(k): val for k, val in hand.items()},
            "sel": sel,
            "mu": mu,
            "pc1": pc1,
            "pc2": pc2,
            "centroids": sym,
        },
        g,
    )
    return f


def ranking_file() -> File:
    f = File(
        SPEC,
        "ranking",
        "Noise-aware representative statements (repness) and common ground (consensus) from fixed "
        "noised group tallies, with noise_sd = the groups part's σ (release.md, after round 3). "
        "Ported from the oracle; the rankings are normative.",
    )
    rng = random.Random(20261006)
    c = 12
    k = 3

    def counts(agree_rate, n):
        na = [round(a * t + rng.uniform(-3, 3), 3) for a, t in zip(agree_rate, n, strict=True)]
        nd = [
            round((1 - a) * t * 0.8 + rng.uniform(-3, 3), 3)
            for a, t in zip(agree_rate, n, strict=True)
        ]
        nu = [
            round((1 - a) * t * 0.2 + rng.uniform(-3, 3), 3)
            for a, t in zip(agree_rate, n, strict=True)
        ]
        return [[max(x, 0.0) for x in na], [max(x, 0.0) for x in nd], [max(x, 0.0) for x in nu]]

    rates = [
        [0.9, 0.2, 0.5, 0.95, 0.1, 0.6, 0.85, 0.3, 0.5, 0.7, 0.4, 0.9],
        [0.2, 0.9, 0.5, 0.9, 0.15, 0.4, 0.3, 0.8, 0.5, 0.7, 0.6, 0.85],
        [0.5, 0.5, 0.9, 0.92, 0.1, 0.5, 0.5, 0.5, 0.2, 0.75, 0.5, 0.88],
    ]
    sizes = [[300.0] * c, [220.0] * c, [40.0] * c]
    groups = [counts(rates[g], sizes[g]) for g in range(k)]
    sigma_groups = r.part_sigmas(PLAN_FULL, CARDS)[r.GROUPS]["sigma"]
    for noise_sd in (0.0, sigma_groups):
        f.add(
            "repness",
            f"Representative statements, noise_sd {noise_sd}",
            "release.md After round 3",
            {"group_counts": groups, "noise_sd": noise_sd, "top": 5},
            {
                "ranked": [
                    [{"card": j, "direction": d} for j, d in g]
                    for g in r.repness(groups, 5, noise_sd)
                ]
            },
        )
        f.add(
            "consensus",
            f"Common ground, noise_sd {noise_sd}",
            "release.md After round 3",
            {"group_counts": groups, "noise_sd": noise_sd, "top": 5},
            {"ranked": r.consensus(groups, 5, noise_sd)},
        )
    lucky = [[[200.0, 3.0], [20.0, 0.0], [10.0, 0.0]], [[150.0, 0.0], [60.0, 0.0], [10.0, 0.0]]]
    f.add(
        "consensus",
        "Naive ranking (noise_sd 0) prefers a 3-vote statement over a 230-vote one",
        "design.md Rankings must know the noise",
        {"group_counts": lucky, "noise_sd": 0.0, "top": 1},
        {"ranked": r.consensus(lucky, 1, 0.0)},
    )
    f.add(
        "consensus",
        f"Noise-aware ranking (noise_sd {sigma_groups:.2f}) does not",
        "design.md Rankings must know the noise",
        {"group_counts": lucky, "noise_sd": sigma_groups, "top": 1},
        {"ranked": r.consensus(lucky, 1, sigma_groups)},
    )
    return f


def sampler_file() -> File:
    f = File(
        SPEC,
        "sampler",
        "Statistical harness for Gaussian samplers: mean, variance and tail fractions within z = 4 "
        "standard errors. The draws here come from Box–Muller over a Mersenne Twister stream so the "
        "file is reproducible; a real (discrete) sampler is checked the same way over its own draws.",
    )
    sigma = 2.5

    def draws(seed: int, n: int) -> list[float]:
        rng = random.Random(seed)
        out = []
        while len(out) < n:
            u1 = 1.0 - rng.random()
            u2 = rng.random()
            mag = math.sqrt(-2.0 * math.log(u1))
            out.append(round(sigma * mag * math.cos(2 * math.pi * u2), 6))
            out.append(round(sigma * mag * math.sin(2 * math.pi * u2), 6))
        return out[:n]

    good = draws(1, 4000)
    res = r.sampler_check(good, sigma)
    assert res["pass"]
    f.add(
        "check",
        "4000 Gaussian draws at σ 2.5 pass",
        "release.md Noise",
        {"sigma": sigma, "z": 4.0, "draws": good},
        res,
    )
    base = "the draws of the first case"
    doubled = [d * 2 for d in good]
    res = r.sampler_check(doubled, sigma)
    assert not res["pass"]
    f.add(
        "check",
        "The same draws at twice the scale fail the variance and tail checks",
        "release.md Noise",
        {"sigma": sigma, "z": 4.0, "draws_rule": f"each of {base} times 2"},
        res,
    )
    shifted = [d + 0.5 for d in good]
    res = r.sampler_check(shifted, sigma)
    assert not res["checks"]["mean"]
    f.add(
        "check",
        "Draws shifted by 0.5 fail the mean check",
        "release.md Noise",
        {"sigma": sigma, "z": 4.0, "draws_rule": f"each of {base} plus 0.5"},
        res,
    )
    clipped = [max(min(d, 2 * sigma), -2 * sigma) for d in good]
    res = r.sampler_check(clipped, sigma)
    assert not res["checks"]["tail_2sigma"]
    f.add(
        "check",
        "Draws clipped at 2σ fail the 2σ tail check (4000 draws give the 3σ check little power; "
        "use 20,000 or more for a real sampler)",
        "release.md Noise",
        {"sigma": sigma, "z": 4.0, "draws_rule": f"each of {base} clipped to [-5, 5]"},
        res,
    )
    rounded = [float(round(d)) for d in good]
    res = r.sampler_check(rounded, sigma)
    f.add(
        "check",
        "The same draws rounded to integers (a stand-in for a discrete Gaussian at σ 2.5) still pass",
        "release.md Noise",
        {"sigma": sigma, "z": 4.0, "draws_rule": f"each of {base} rounded to the nearest integer"},
        res,
    )
    return f


def generate() -> list[File]:
    return [
        accounting_file(),
        sigmas_file(),
        plans_file(),
        floors_file(),
        cap_file(),
        gates_file(),
        shield_file(),
        phone_file(),
        ranking_file(),
        sampler_file(),
    ]
