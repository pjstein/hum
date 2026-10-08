"""Release math: zCDP accounting, σ per part, contribution caps, size gates, floors, the
phone-side round computations, and the noise-aware rankings.

Sources: ``docs/specs/deck.md`` (the release plan, parts, floors), ``docs/specs/release.md``
(rounds, noise, what a phone computes), ``docs/specs/context.md`` (protocol constants,
floors), ADR 0010 (``rat`` and σ rounding), and the oracle
``docs/research/dp-polis/polis_dp.py`` for ``repness`` and ``consensus``.

Nothing here draws noise. Sampling is a seam that uses a vetted discrete sampler in the
production code; ``sampler_check`` tests any sampler's draws statistically. Everything
else is deterministic and is what the vectors fix.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from fractions import Fraction

__all__ = [
    "DEFAULT_SPLIT",
    "DELTA",
    "FEATURE_GATES",
    "GATES",
    "PART_NAMES",
    "PROTOCOL",
    "Floors",
    "ReleasePlan",
    "cap_votes",
    "check_context_floors",
    "check_context_tightening",
    "check_plan",
    "consensus",
    "contribution",
    "delta_squared",
    "eps_to_rho",
    "gauss_sigma",
    "part_sigmas",
    "rat",
    "rat_decode",
    "repness",
    "rho_to_eps",
    "round1_vector",
    "round2_cell",
    "round3_group",
    "sampler_check",
    "sel_and_mu",
    "shield_check",
    "sigma_micro",
    "sigma_micro_binary64",
    "sigma_r_numerator",
    "sigma_rational",
    "sigma_squared",
    "unlocked",
]

DELTA = 1e-6

# Part ids (deck.md, "Parts").
TALLIES, COVARIANCE, MAP, GROUPS, COUNT, MOVEMENT, RATINGS, BREAKDOWN, RECEIPTS = range(9)
PART_NAMES = {
    TALLIES: "tallies",
    COVARIANCE: "covariance",
    MAP: "map",
    GROUPS: "groups",
    COUNT: "count",
    MOVEMENT: "movement",
    RATINGS: "ratings",
    BREAKDOWN: "breakdown",
    RECEIPTS: "receipts",
}
ALWAYS_PRESENT = (TALLIES, RECEIPTS)
RECEIPTS_RHO_DEFAULT = Fraction(1, 200)
TIER = (COVARIANCE, MAP, GROUPS)

# Protocol constants (context.md).
RHO_MAX = Fraction(127, 500)
DELTA_MAX = Fraction(1, 10**6)
MIN_VOTERS = 100
RELEASES_PER_DECK = 1
SHIELD_YEAR_EPS = Fraction(20)
MIN_WITNESSES = 2
GATE_TALLIES, GATE_COMMON, GATE_MAP, GATE_CELL, GATE_CHECKS = 100, 300, 800, 300, 5000
MAX_CARDS = 256
COUNT_RHO_MAX_DEFAULT = Fraction(1, 200)

# Gate per part (deck.md "Parts"); COUNT has none.
GATES: dict[int, int | None] = {
    TALLIES: GATE_TALLIES,
    COVARIANCE: GATE_MAP,
    MAP: GATE_MAP,
    GROUPS: GATE_MAP,
    COUNT: None,
    MOVEMENT: GATE_COMMON,
    RATINGS: GATE_COMMON,
    BREAKDOWN: GATE_CELL,
    RECEIPTS: None,
}
FEATURE_GATES = {
    "tallies": GATE_TALLIES,
    "common-ground": GATE_COMMON,
    "map": GATE_MAP,
    "groups": GATE_MAP,
    "breakdown-cell": GATE_CELL,
    "real-data-checks": GATE_CHECKS,
}

DEFAULT_SPLIT: dict[int, Fraction] = {
    TALLIES: Fraction(15, 100),
    COVARIANCE: Fraction(35, 100),
    MAP: Fraction(15, 100),
    GROUPS: Fraction(35, 100),
}


# ---------------------------------------------------------------- rat (ADR 0010)


def rat(value: Fraction) -> list[int]:
    """A ``rat``: CBOR array ``[num, den]`` in lowest terms, ``den >= 1``, both below 2^64."""
    if value < 0:
        raise ValueError("rat is non-negative")
    f = Fraction(value)
    if f.numerator >= 1 << 64 or f.denominator >= 1 << 64:
        raise ValueError("rat does not fit in 64 bits")
    return [f.numerator, f.denominator]


def rat_decode(item: object) -> Fraction:
    """Parse a ``rat``; a value not in lowest terms fails the schema check (step 4)."""
    if not (isinstance(item, list) and len(item) == 2 and all(isinstance(x, int) for x in item)):
        raise ValueError("rat must be [num, den]")
    num, den = item
    if num < 0 or den < 1:
        raise ValueError("rat must be non-negative with den >= 1")
    if math.gcd(num, den) != 1:
        raise ValueError("rat not in lowest terms (schema failure, step 4)")
    return Fraction(num, den)


# ---------------------------------------------------------------- accounting


def rho_to_eps(rho: float, delta: float = DELTA) -> float:
    """ε such that ρ-zCDP implies (ε, δ)-DP: ε = ρ + 2√(ρ ln(1/δ))."""
    return rho + 2 * math.sqrt(rho * math.log(1 / delta))


def eps_to_rho(eps: float, delta: float = DELTA) -> float:
    """Largest ρ with ρ-zCDP implying (ε, δ)-DP: √ρ = √(L + ε) − √L, L = ln(1/δ)."""
    if math.isinf(eps):
        return math.inf
    big_l = math.log(1 / delta)
    s = math.sqrt(big_l + eps) - math.sqrt(big_l)
    return s * s


def gauss_sigma(l2_sensitivity: float, rho: float) -> float:
    """Gaussian noise scale for ρ-zCDP: σ = Δ₂ / √(2ρ)."""
    if math.isinf(rho):
        return 0.0
    if rho <= 0:
        raise ValueError("rho must be positive")
    return l2_sensitivity / math.sqrt(2 * rho)


SIGMA_R_BITS = 20
"""σ_r = n / 2²⁰ (release.md Noise, accepted by the owner 2026-10-07)."""


def sigma_squared(delta_sq: int, rho: Fraction) -> Fraction:
    """σ² = Δ²·den / (2·num) in lowest terms, in integer units."""
    if rho <= 0:
        raise ValueError("rho must be positive")
    return Fraction(delta_sq * rho.denominator, 2 * rho.numerator)


def sigma_r_numerator(sigma_sq: Fraction) -> int:
    """``n``: the least integer with n²·q ≥ p·2⁴⁰ for σ² = p/q, in integer arithmetic."""
    p, q = sigma_sq.numerator, sigma_sq.denominator
    target = p << (2 * SIGMA_R_BITS)
    n = math.isqrt((target + q - 1) // q)
    while n * n * q < target:
        n += 1
    while n > 0 and (n - 1) * (n - 1) * q >= target:
        n -= 1
    return n


def sigma_rational(delta_sq: int, rho: Fraction) -> Fraction:
    """σ_r = n / 2²⁰, the rational upper bound on σ every sampler is called with."""
    return Fraction(sigma_r_numerator(sigma_squared(delta_sq, rho)), 1 << SIGMA_R_BITS)


def sigma_micro(delta_sq: int, rho: Fraction, cov_scale: int = 1) -> int:
    """``sigma`` as a part record carries it: round(σ_r × 10⁶), ties to even.

    For covariance the published value is round(σ_r / ``covScale`` × 10⁶). Display only: a
    sampler takes the rational σ_r itself, never this value and never σ.
    """
    return round(sigma_rational(delta_sq, rho) / cov_scale * 10**6)


def sigma_micro_binary64(delta_sq: int, rho: Fraction, cov_scale: int = 1) -> int:
    """round(σ × 10⁶) from binary64 σ, the non-conformant value an R4 case shows."""
    value = math.sqrt(delta_sq * rho.denominator / (2 * rho.numerator)) / cov_scale * 1e6
    return round(value)


# ---------------------------------------------------------------- the plan (deck.md key 5)


@dataclass(frozen=True)
class ReleasePlan:
    rho: Fraction
    delta: Fraction
    parts: dict[int, Fraction]
    cap: int | None
    min_voters: int
    cov_statements: int | None = None  # default min(60, cards)
    grid: int = 24
    blur: Fraction = Fraction(1)
    gates: dict[int, int] = field(default_factory=dict)
    absorb: bool = False
    round_window: int = 259_200
    cap_movement: int | None = None
    cap_ratings: int | None = None
    breakdown: dict | None = None
    cov_scale: int = 65_536

    @classmethod
    def default(
        cls, rho: Fraction, cap: int, min_voters: int = MIN_VOTERS, count: bool = False, **kw
    ) -> ReleasePlan:
        """The four-tier-part plan with the default split plus receipts (and the daily count
        when asked), each at 1/200, every share summing exactly to ``rho``."""
        extras = {RECEIPTS: RECEIPTS_RHO_DEFAULT}
        if count:
            extras[COUNT] = COUNT_RHO_MAX_DEFAULT
        base = rho - sum(extras.values(), Fraction(0))
        parts = {p: base * s for p, s in DEFAULT_SPLIT.items()}
        parts.update(extras)
        return cls(rho, DELTA_MAX, parts, cap, min_voters, **kw)

    @property
    def post_close_rounds(self) -> int:
        """R: 3 when the map tier is planned, else 0."""
        return 3 if COVARIANCE in self.parts else 0

    def cov_m(self, cards: int) -> int:
        return self.cov_statements if self.cov_statements is not None else min(60, cards)


def delta_squared(part: int, plan: ReleasePlan, cards: int | None = None) -> int:
    """Integer squared L2 sensitivity per person for ``part``.

    deck.md "Parts" for every part but covariance; release.md "Round 1" for ``Δ_cov``.
    """
    k = plan.cap
    if k is None:
        raise ValueError("a plan must declare its contribution cap")
    if part in (TALLIES, BREAKDOWN):
        return k + 1
    if part == COVARIANCE:
        if cards is None:
            raise ValueError("covariance sensitivity needs the card count")
        m = plan.cov_m(cards)
        d_cov = plan.cov_scale + math.ceil(math.sqrt(m * (m + 1) / 2) / 2)
        return d_cov * d_cov
    if part in (MAP, COUNT):
        return 1
    if part == GROUPS:
        return k + 1 + (plan.cap_ratings if RATINGS in plan.parts else 0)
    if part == MOVEMENT:
        if plan.cap_movement is None:
            raise ValueError("movement needs capMovement")
        return 2 * plan.cap_movement
    if part == RECEIPTS:
        return plan.post_close_rounds + 1
    if part == RATINGS:
        if plan.cap_ratings is None:
            raise ValueError("ratings needs capRatings")
        return plan.cap_ratings
    raise ValueError(f"unknown part {part}")


def part_sigmas(plan: ReleasePlan, cards: int | None = None) -> dict[int, dict]:
    """σ per part: the exact σ², the rational σ_r = n/2²⁰ the sampler takes, the real σ,
    and the micro-unit integer a release carries.

    For covariance, σ² and σ_r are in integer (fixed-point) units; the published ``sigma``
    divides σ_r by ``covScale`` (release.md, "Noise").
    """
    out = {}
    for part, rho_p in plan.parts.items():
        d2 = delta_squared(part, plan, cards)
        scale = plan.cov_scale if part == COVARIANCE else 1
        s2 = sigma_squared(d2, rho_p)
        s_r = sigma_rational(d2, rho_p)
        real = gauss_sigma(math.sqrt(d2), float(rho_p))
        entry = {
            "delta_squared": d2,
            "rho": rho_p,
            "sigma_squared": s2,
            "sigma_r": s_r,
            "sigma": real,
            "sigma_micro": sigma_micro(d2, rho_p, scale),
        }
        if part == COVARIANCE:
            entry["sigma_real_units"] = real / plan.cov_scale
        out[part] = entry
    return out


# ---------------------------------------------------------------- floors


@dataclass(frozen=True)
class Floors:
    """``context.md`` ``floors`` (key 6)."""

    rho: Fraction
    delta: Fraction
    min_voters: int
    releases_per_deck: int = 1
    min_witnesses: int = MIN_WITNESSES
    rho_year: Fraction | None = None


PROTOCOL = Floors(RHO_MAX, DELTA_MAX, MIN_VOTERS, RELEASES_PER_DECK, MIN_WITNESSES)


def check_context_floors(f: Floors) -> list[str]:
    """context.md rules C3 and C4 (the data-only part)."""
    out = []
    if f.rho > RHO_MAX:
        out.append("C3: floors.rho above RHO_MAX")
    if f.rho <= 0:
        out.append("C3: floors.rho must be positive")
    if f.delta > DELTA_MAX:
        out.append("C3: floors.delta above DELTA_MAX")
    if f.delta <= 0:
        out.append("C3: floors.delta must be positive")
    if f.min_voters < MIN_VOTERS:
        out.append("C3: floors.minVoters below MIN_VOTERS")
    if f.releases_per_deck != 1:
        out.append("C3: floors.releasesPerDeck must be 1")
    if f.min_witnesses < MIN_WITNESSES:
        out.append("C3: floors.minWitnesses below MIN_WITNESSES")
    if f.rho_year is not None and f.rho_year < f.rho:
        out.append("C4: rhoYear below rho")
    return out


def check_context_tightening(new: Floors, prev: Floors) -> list[str]:
    """context.md rule C10: a later version may only tighten."""
    out = []
    if new.rho > prev.rho:
        out.append("C10: rho raised")
    if new.delta > prev.delta:
        out.append("C10: delta raised")
    if new.min_voters < prev.min_voters:
        out.append("C10: minVoters lowered")
    if new.min_witnesses < prev.min_witnesses:
        out.append("C10: minWitnesses lowered")
    if prev.rho_year is not None and (new.rho_year is None or new.rho_year > prev.rho_year):
        out.append("C10: rhoYear raised or dropped")
    return out


def check_plan(
    plan: ReleasePlan,
    floors: Floors,
    cards: int,
    count_rho_max: Fraction = COUNT_RHO_MAX_DEFAULT,
    argument_refs: int = 0,
) -> list[str]:
    """deck.md rules D8, D9 (the data part), D10, D11 and D14 for a plan under ``floors``."""
    out = []
    parts = plan.parts
    for p in ALWAYS_PRESENT:
        if p not in parts:
            out.append(f"D8: part {p} missing")
    present_tier = [p for p in TIER if p in parts]
    if present_tier and len(present_tier) != len(TIER):
        out.append("D8: parts 1, 2 and 3 must be all present or all absent")
    if any(p not in PART_NAMES for p in parts):
        out.append("D8: unknown part id")
    if any(r <= 0 for r in parts.values()):
        out.append("D8: every part rho must be positive")
    if sum(parts.values(), Fraction(0)) != plan.rho:
        out.append("D8: parts do not sum to rho")
    if plan.absorb and COUNT not in parts:
        out.append("D9: absorb needs part 4")
    if MOVEMENT in parts and (plan.cap_movement is None or argument_refs < 1):
        out.append("D9: movement needs capMovement and an argument ref")
    if RATINGS in parts and (plan.cap_ratings is None or argument_refs < 1):
        out.append("D9: ratings needs capRatings and an argument ref")
    if BREAKDOWN in parts and plan.breakdown is None:
        out.append("D9: breakdown needs the breakdown map")
    if plan.rho > floors.rho:
        out.append("D10: rho above the context floor")
    if plan.delta > floors.delta:
        out.append("D10: delta above the context floor")
    if plan.min_voters < floors.min_voters:
        out.append("D10: minVoters below the context floor")
    if COUNT in parts and parts[COUNT] > count_rho_max:
        out.append("D10: count rho above count.rhoMax")
    for p, g in plan.gates.items():
        protocol_gate = GATES.get(p)
        if protocol_gate is None or g < protocol_gate:
            out.append(f"D11: gate for part {p} below the protocol gate")
    effective = {p: plan.gates.get(p, GATES[p]) for p in parts if GATES.get(p) is not None}
    if any(plan.min_voters > g for g in effective.values()):
        out.append("D11: minVoters above a gate")
    if plan.cov_m(cards) > cards:
        out.append("D11: covStatements above the card count")
    if not 8 <= plan.grid <= 64:
        out.append("D11: grid out of range")
    if not (plan.cov_scale & (plan.cov_scale - 1) == 0 and 2**8 <= plan.cov_scale <= 2**24):
        out.append("D11: covScale not a power of two in 2^8..2^24")
    if not 3600 <= plan.round_window <= 2_592_000:
        out.append("D11: roundWindow out of range")
    if plan.cap is None or plan.cap < 1:
        out.append("D14: cap must be at least 1")
    if plan.cap_movement is not None and plan.cap_movement > cards:
        out.append("D14: capMovement above the card count")
    if plan.cap_ratings is not None and plan.cap_ratings > argument_refs:
        out.append("D14: capRatings above the argument refs")
    return out


def unlocked(noised_voters: float) -> list[str]:
    """Which release features the noised voter count unlocks (design doc table)."""
    return [name for name, gate in FEATURE_GATES.items() if noised_voters >= gate]


def shield_check(spent_rho: list[Fraction], planned_rho: Fraction, shield_eps_year: Fraction):
    """Charge the plan's full ρ against a yearly shield expressed in ε. Returns a dict."""
    budget_rho = eps_to_rho(float(shield_eps_year))
    total = float(sum(spent_rho, Fraction(0)) + planned_rho)
    return {
        "budget_rho": budget_rho,
        "total_rho_after": total,
        "eps_after": rho_to_eps(total),
        "allowed": total <= budget_rho,
    }


# ---------------------------------------------------------------- contribution cap


def cap_votes(votes: list[tuple[int, int]], cap: int) -> list[tuple[int, int]]:
    """Keep at most ``cap`` votes per person.

    ``votes`` is a list of (card index, vote) with vote in {1, -1, 0}; a later vote on the
    same card replaces the earlier one. The phone keeps a uniformly random ``cap`` of its
    votes (ballot.md); this reference keeps the first ``cap`` in cast order, so a vector can
    fix the result. Only the bound matters for the sums.
    """
    latest: dict[int, int] = {}
    for card, v in votes:
        if v not in (1, -1, 0):
            raise ValueError("vote must be 1, -1 or 0")
        latest.pop(card, None)
        latest[card] = v
    return list(latest.items())[:cap]


def contribution(votes: list[tuple[int, int]], cap: int, cards: int) -> dict[str, object]:
    """A person's tallies contribution: agree, disagree, unsure per card plus a participant
    coordinate. Its squared L2 norm is at most cap + 1."""
    kept = cap_votes(votes, cap)
    agree = [0] * cards
    disagree = [0] * cards
    unsure = [0] * cards
    for card, v in kept:
        if not 0 <= card < cards:
            raise ValueError("card index out of range")
        (agree if v == 1 else disagree if v == -1 else unsure)[card] = 1
    norm_sq = len(kept) + 1
    return {
        "kept": kept,
        "agree": agree,
        "disagree": disagree,
        "unsure": unsure,
        "participant": 1,
        "norm_squared": norm_sq,
        "within_sensitivity": norm_sq <= cap + 1,
    }


# ---------------------------------------------------------------- what a phone computes


def sel_and_mu(tallies: list[tuple[float, float, float]], m: int) -> tuple[list[int], list[float]]:
    """Round 1 inputs from the ``tallies`` table (release.md, "What a phone computes").

    ``sel`` is the M cards with the largest ns, ties to the lower index, in ascending order;
    ``mu`` is per card.
    """
    ns = []
    mu = []
    for na, nd, nu in tallies:
        na, nd, nu = max(na, 0.0), max(nd, 0.0), max(nu, 0.0)
        total = max(na + nd + nu, 1.0)
        ns.append(total)
        mu.append(min(max((na - nd) / total, -1.0), 1.0))
    order = sorted(range(len(ns)), key=lambda j: (-ns[j], j))
    sel = sorted(order[:m])
    return sel, mu


def round1_vector(
    hand: dict[int, int], sel: list[int], mu: list[float], cov_scale: int
) -> dict[str, object] | None:
    """Round 1: the upper triangle of ``u uᵀ`` scaled and rounded, or ``None`` if ‖z‖ = 0."""
    z = [(hand[j] - mu[j]) if j in hand else 0.0 for j in sel]
    norm = math.sqrt(sum(v * v for v in z))
    if norm == 0:
        return None
    u = [v / norm for v in z]
    m = len(sel)
    entries = []
    for i in range(m):
        for j in range(i, m):
            entries.append(round(u[i] * u[j] * cov_scale))
    d_cov = cov_scale + math.ceil(math.sqrt(m * (m + 1) / 2) / 2)
    norm_sq = sum(e * e for e in entries)
    return {
        "z": z,
        "u": u,
        "entries": entries,
        "norm_squared": norm_sq,
        "delta_cov": d_cov,
        "within_sensitivity": norm_sq <= d_cov * d_cov,
    }


def _project(
    hand: dict[int, int], sel: list[int], mu: list[float], pc1: list[float], pc2: list[float]
) -> tuple[float, float] | None:
    z = [(hand[j] - mu[j]) if j in hand else 0.0 for j in sel]
    nv = sum(1 for j in sel if j in hand)
    if nv == 0:
        return None
    scale = math.sqrt(len(sel) / nv)
    px = sum(a * b for a, b in zip(z, pc1, strict=True)) * scale
    py = sum(a * b for a, b in zip(z, pc2, strict=True)) * scale
    return px, py


def round2_cell(
    hand: dict[int, int],
    sel: list[int],
    mu: list[float],
    pc1: list[float],
    pc2: list[float],
    half_x: float,
    half_y: float,
    grid: int,
) -> dict[str, object] | None:
    """Round 2: the phone's map cell, ``cx * grid + cy``."""
    p = _project(hand, sel, mu, pc1, pc2)
    if p is None:
        return None
    px, py = p
    cx = min(max(math.floor((px + half_x) * grid / (2 * half_x)), 0), grid - 1)
    cy = min(max(math.floor((py + half_y) * grid / (2 * half_y)), 0), grid - 1)
    return {"projection": [px, py], "cx": cx, "cy": cy, "cell": cx * grid + cy}


def round3_group(
    hand: dict[int, int],
    sel: list[int],
    mu: list[float],
    pc1: list[float],
    pc2: list[float],
    centroids: list[tuple[float, float]],
) -> dict[str, object] | None:
    """Round 3: the nearest centroid by Euclidean distance, ties to the lower group index."""
    p = _project(hand, sel, mu, pc1, pc2)
    if p is None:
        return None
    px, py = p
    dists = [math.hypot(px - cx, py - cy) for cx, cy in centroids]
    best = min(range(len(centroids)), key=lambda g: (dists[g], g))
    return {"projection": [px, py], "distances": dists, "group": best}


# ---------------------------------------------------------------- post-processing (oracle port)


def _z_pair(p, po, s, o, ns, os_, ne_in, ne_out):
    pt = 2 * math.sqrt(ne_in + 1) * (p - 0.5)
    pp = (s + o + 1) / (ns + os_ + 2)
    rt = (p - po) / math.sqrt(max(pp * (1 - pp) * (1 / (ne_in + 1) + 1 / (ne_out + 1)), 1e-12))
    return pt, rt


def repness(
    group_counts: list[list[list[float]]], top: int = 5, noise_sd: float = 0.0
) -> list[list[tuple[int, str]]]:
    """Representative statements per group, Polis-style and noise-aware (oracle ``repness``).

    ``group_counts[g] = [agree[], disagree[], unsure[]]``. Returns, per group, the top
    ``3 * top`` statements as (index, "A" or "D"): significant ones first, then by the
    representativeness metric, ties by index.
    """
    k = len(group_counts)
    c = len(group_counts[0][0])
    tot = [[sum(g[i][j] for g in group_counts) for j in range(c)] for i in range(3)]
    lam_in = max(1.0, noise_sd)
    lam_out = max(1.0, noise_sd * math.sqrt(max(k - 1, 1)))
    out = []
    for na, nd, npass in group_counts:
        rows = []
        for j in range(c):
            ns = na[j] + nd[j] + npass[j]
            oa, od = tot[0][j] - na[j], tot[1][j] - nd[j]
            os_ = (tot[0][j] + tot[1][j] + tot[2][j]) - ns
            if noise_sd:
                ne_in = ns**2 / max(ns + 3 * noise_sd**2, 1e-9)
                ne_out = os_**2 / max(os_ + 3 * (k - 1) * noise_sd**2, 1e-9)
            else:
                ne_in, ne_out = ns, os_
            res = {}
            for direction, s, o in (("A", na[j], oa), ("D", nd[j], od)):
                p = (s + lam_in) / (ns + 2 * lam_in)
                po = (o + lam_out) / (os_ + 2 * lam_out)
                r = p / po
                pt, rt = _z_pair(p, po, s, o, ns, os_, ne_in, ne_out)
                res[direction] = (r * rt * p * pt, pt, rt)
            use = "A" if res["A"][0] >= res["D"][0] else "D"
            metric, pt, rt = res[use]
            sig = pt > 1.2816 and rt > 1.2816
            rows.append((0 if sig else 1, -metric, j, use))
        rows.sort()
        out.append([(j, use) for _, _, j, use in rows[: 3 * top]])
    return out


def consensus(
    group_counts: list[list[list[float]]], top: int = 5, noise_sd: float = 0.0
) -> list[int]:
    """Common ground: statements ranked by the product over groups of smoothed agree rates."""
    lam = max(1.0, noise_sd)
    c = len(group_counts[0][0])
    gic = []
    for j in range(c):
        v = 1.0
        for na, nd, npass in group_counts:
            v *= (na[j] + lam) / (na[j] + nd[j] + npass[j] + 2 * lam)
        gic.append(v)
    order = sorted(range(c), key=lambda j: (-gic[j], j))
    return order[: 3 * top]


# ---------------------------------------------------------------- sampler harness


def sampler_check(draws: list[float], sigma: float, mean: float = 0.0, z: float = 4.0) -> dict:
    """Mean, variance and tail checks for Gaussian draws at scale ``sigma``.

    Each statistic must sit within ``z`` standard errors of its expectation. With z = 4 a
    correct sampler fails each check with probability about 6e-5. The same checks apply to
    a discrete Gaussian; for σ below about 2 its variance is measurably below σ², and the
    caller passes the square root of the exact variance instead.
    """
    n = len(draws)
    if n < 100:
        raise ValueError("need at least 100 draws")
    m = sum(draws) / n
    var = sum((d - mean) ** 2 for d in draws) / n
    tails = {}
    checks = {}
    se_mean = sigma / math.sqrt(n)
    checks["mean"] = abs(m - mean) <= z * se_mean
    # Var(x²) for a Gaussian is 2σ⁴, so the standard error of the variance estimate is σ²√(2/n).
    checks["variance"] = abs(var - sigma**2) <= z * sigma**2 * math.sqrt(2 / n)
    for k, p in (
        (1.0, 0.3173105078629141),
        (2.0, 0.04550026389635842),
        (3.0, 0.002699796063260207),
    ):
        frac = sum(1 for d in draws if abs(d - mean) > k * sigma) / n
        se = math.sqrt(p * (1 - p) / n)
        tails[f"{k:g}"] = frac
        checks[f"tail_{k:g}sigma"] = abs(frac - p) <= z * se
    return {
        "n": n,
        "mean": m,
        "variance": var,
        "tails": tails,
        "checks": checks,
        "pass": all(checks.values()),
    }
