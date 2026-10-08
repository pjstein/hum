import importlib.util
import math
import random
import sys
import types
from fractions import Fraction
from pathlib import Path

import pytest

from hum_reference import cbor
from hum_reference import release as r

ORACLE = Path(__file__).resolve().parents[2] / "docs" / "research" / "dp-polis" / "polis_dp.py"


def load_oracle():
    """Import polis_dp.py with its heavy dependencies stubbed; only the ranking functions run."""
    np = pytest.importorskip("numpy")
    for name in [
        "pandas",
        "scipy",
        "scipy.optimize",
        "scipy.ndimage",
        "sklearn",
        "sklearn.cluster",
        "sklearn.metrics",
    ]:
        if name not in sys.modules:
            mod = types.ModuleType(name)
            for attr in [
                "linear_sum_assignment",
                "gaussian_filter",
                "KMeans",
                "silhouette_score",
                "adjusted_rand_score",
            ]:
                setattr(mod, attr, None)
            sys.modules[name] = mod
    spec = importlib.util.spec_from_file_location("polis_dp_oracle", ORACLE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod, np


def test_rat_round_trip_and_lowest_terms():
    assert r.rat(Fraction(254, 1000)) == [127, 500]
    assert cbor.encode(r.rat(r.RHO_MAX)) == bytes.fromhex("82187f1901f4")
    assert r.rat_decode([127, 500]) == Fraction(127, 500)
    with pytest.raises(ValueError):
        r.rat_decode([254, 1000])
    with pytest.raises(ValueError):
        r.rat_decode([1, 0])


def test_accounting_matches_design_numbers():
    assert math.isclose(r.eps_to_rho(4), 0.254, abs_tol=2e-4)
    assert math.isclose(r.eps_to_rho(8), 0.91, abs_tol=1e-3)
    assert math.isclose(r.rho_to_eps(r.eps_to_rho(4)), 4.0)
    # context.md says ε 4.0007 at RHO_MAX; the exact value is 4.00054 (noted in conformance.md)
    assert math.isclose(r.rho_to_eps(float(r.RHO_MAX)), 4.00054, abs_tol=1e-5)
    assert math.isclose(r.rho_to_eps(4 * r.eps_to_rho(4)), 8.5, abs_tol=0.01)
    assert r.eps_to_rho(math.inf) == math.inf
    assert r.gauss_sigma(1.0, math.inf) == 0.0


def test_accounting_matches_oracle():
    oracle, _ = load_oracle()
    for eps in [0.5, 1, 2, 4, 8, 16]:
        assert math.isclose(r.eps_to_rho(eps), oracle.eps_to_rho(eps), rel_tol=1e-12)
        assert math.isclose(r.rho_to_eps(eps / 10), oracle.rho_to_eps(eps / 10), rel_tol=1e-12)
    assert math.isclose(
        r.gauss_sigma(math.sqrt(61), 0.0381), oracle.gauss_sigma(math.sqrt(61), 0.0381)
    )


def test_sigma_r_is_the_least_dyadic_upper_bound():
    rho = Fraction(15, 100) * r.RHO_MAX
    s2 = r.sigma_squared(61, rho)
    n = r.sigma_r_numerator(s2)
    assert n * n * s2.denominator >= s2.numerator * 2**40
    assert (n - 1) ** 2 * s2.denominator < s2.numerator * 2**40
    s_r = r.sigma_rational(61, rho)
    assert s_r == Fraction(n, 2**20) and s_r * s_r >= s2 and s_r - 2 ** Fraction(-20) < 1e9
    assert float(s_r) - math.sqrt(float(s2)) < 2**-20
    assert r.sigma_micro(61, rho) == round(s_r * 10**6)
    assert isinstance(r.sigma_micro(61, rho), int)
    # the daily count: σ = 1/√(2 · 1/200) = 10, a perfect square: σ_r = σ
    assert r.sigma_rational(1, Fraction(1, 200)) == 10
    assert r.sigma_micro(1, Fraction(1, 200)) == 10_000_000
    # release.md's example plan (W0-01's values, 2026-10-07)
    assert r.sigma_micro(19, Fraction(281, 10000)) == 18_386_906
    assert r.sigma_micro(65_543**2, Fraction(889, 10000), 2**16) == 2_371_813
    assert r.sigma_micro(1, Fraction(381, 10000)) == 3_622_619
    assert r.sigma_micro(19, Fraction(889, 10000)) == 10_337_391
    assert r.sigma_micro(4, Fraction(1, 200)) == 20_000_000
    assert r.sigma_micro_binary64(19, Fraction(281, 10000)) == 18_386_905 < 18_386_906


def test_part_sigmas_follow_split_and_sensitivity():
    plan = r.ReleasePlan.default(r.RHO_MAX, cap=60)
    assert sum(plan.parts.values()) == r.RHO_MAX and plan.parts[r.RECEIPTS] == Fraction(1, 200)
    s = r.part_sigmas(plan, cards=18)
    rho = float(r.RHO_MAX - Fraction(1, 200))
    assert math.isclose(s[r.TALLIES]["sigma"], math.sqrt(61) / math.sqrt(2 * rho * 0.15))
    assert math.isclose(s[r.MAP]["sigma"], 1 / math.sqrt(2 * rho * 0.15))
    assert math.isclose(s[r.GROUPS]["sigma"], math.sqrt(61) / math.sqrt(2 * rho * 0.35))
    assert s[r.RECEIPTS]["delta_squared"] == 4  # R = 3 post-close rounds
    assert (
        r.delta_squared(
            r.RECEIPTS, r.ReleasePlan(r.RHO_MAX, r.DELTA_MAX, {r.TALLIES: r.RHO_MAX}, 60, 100)
        )
        == 1
    )
    d_cov = 65_536 + math.ceil(math.sqrt(18 * 19 / 2) / 2)
    assert s[r.COVARIANCE]["delta_squared"] == d_cov * d_cov
    assert math.isclose(
        s[r.COVARIANCE]["sigma_real_units"], d_cov / 65_536 / math.sqrt(2 * rho * 0.35)
    )
    ibis = r.ReleasePlan(
        r.RHO_MAX,
        r.DELTA_MAX,
        {r.TALLIES: r.RHO_MAX / 2, r.GROUPS: r.RHO_MAX / 4, r.RATINGS: r.RHO_MAX / 4},
        60,
        100,
        cap_ratings=10,
    )
    assert r.delta_squared(r.GROUPS, ibis) == 71
    assert r.delta_squared(r.RATINGS, ibis) == 10
    moving = r.ReleasePlan(r.RHO_MAX, r.DELTA_MAX, {r.TALLIES: r.RHO_MAX}, 60, 100, cap_movement=10)
    assert r.delta_squared(r.MOVEMENT, moving) == 20
    with pytest.raises(ValueError):
        r.part_sigmas(
            r.ReleasePlan(Fraction(1, 10), r.DELTA_MAX, {r.TALLIES: Fraction(1, 10)}, None, 100)
        )


def test_cap_and_contribution():
    votes = [(i, 1) for i in range(10)]
    assert len(r.cap_votes(votes, 4)) == 4
    assert r.cap_votes([(0, 1), (0, -1)], 5) == [(0, -1)]
    c = r.contribution(votes, 4, 10)
    assert c["norm_squared"] == 5 and c["within_sensitivity"]
    assert sum(c["agree"]) == 4
    with pytest.raises(ValueError):
        r.contribution([(0, 2)], 4, 1)


def test_gates():
    assert r.unlocked(99) == []
    assert r.unlocked(100) == ["tallies"]
    assert set(r.unlocked(800)) == {"tallies", "common-ground", "map", "groups", "breakdown-cell"}
    assert "real-data-checks" in r.unlocked(5000)


def test_context_floors():
    P = r.PROTOCOL
    assert r.check_context_floors(P) == []
    assert r.check_context_floors(r.Floors(Fraction(3, 10), P.delta, 300))
    assert r.check_context_floors(r.Floors(P.rho, P.delta, 50))
    assert r.check_context_floors(r.Floors(P.rho, P.delta, 100, releases_per_deck=2))
    assert r.check_context_floors(r.Floors(P.rho, P.delta, 100, min_witnesses=1))
    assert r.check_context_floors(r.Floors(P.rho, P.delta, 100, rho_year=Fraction(1, 10)))
    prev = r.Floors(P.rho, P.delta, 100, 1, 2, Fraction(2))
    assert (
        r.check_context_tightening(r.Floors(Fraction(1, 5), P.delta, 300, 1, 2, Fraction(1)), prev)
        == []
    )
    assert r.check_context_tightening(r.Floors(P.rho, P.delta, 50, 1, 2, Fraction(2)), prev)
    assert r.check_context_tightening(r.Floors(P.rho, P.delta, 100, 1, 2, None), prev)


def test_plan_rules():
    P = r.PROTOCOL
    assert r.check_plan(r.ReleasePlan.default(r.RHO_MAX, 60), P, 18) == []
    rho = r.RHO_MAX
    bad = {
        "D8": r.ReleasePlan(rho, r.DELTA_MAX, {r.TALLIES: rho / 2}, 60, 100),
        "D9": r.ReleasePlan(rho, r.DELTA_MAX, {r.TALLIES: rho}, 60, 100, absorb=True),
        "D10": r.ReleasePlan.default(Fraction(3, 10), 60),
        "D11": r.ReleasePlan.default(rho, 60, gates={r.TALLIES: 50}),
        "D14": r.ReleasePlan.default(rho, 0),
    }
    for rule, plan in bad.items():
        v = r.check_plan(plan, P, 18)
        assert any(x.startswith(rule) for x in v), (rule, v)


def test_shield():
    q = r.RHO_MAX
    assert r.shield_check([], q, Fraction(20))["allowed"]
    assert r.shield_check([q] * 16, q, Fraction(20))["allowed"]
    assert not r.shield_check([q] * 17, q, Fraction(20))["allowed"]


def test_phone_computations():
    tallies = [(50.0, 10.0, 5.0), (-3.0, 2.0, 1.0), (30.0, 30.0, 0.0), (80.0, 5.0, 5.0)]
    sel, mu = r.sel_and_mu(tallies, 3)
    assert sel == [0, 2, 3]
    assert mu[1] == -2 / 3 and mu[2] == 0.0
    v = r.round1_vector({0: 1, 3: -1}, sel, mu, 65_536)
    assert v["within_sensitivity"] and len(v["entries"]) == 6
    assert r.round1_vector({1: 1}, sel, mu, 65_536) is None
    pc1, pc2 = [1.0, 0.0, 0.0], [0.0, 1.0, 0.0]
    cell = r.round2_cell({0: 1}, sel, mu, pc1, pc2, 2.0, 2.0, 24)
    assert 0 <= cell["cell"] < 576 and cell["cx"] >= 12
    g = r.round3_group({0: 1}, sel, mu, pc1, pc2, [(5.0, 0.0), (0.5, 0.0), (0.5, 0.0)])
    assert g["group"] == 1


def random_groups(rng, k, c):
    out = []
    for _ in range(k):
        n = [rng.uniform(20, 400) for _ in range(c)]
        a = [rng.random() for _ in range(c)]
        na = [max(0.0, x * t + rng.gauss(0, 5)) for x, t in zip(a, n, strict=True)]
        nd = [max(0.0, (1 - x) * t * 0.7 + rng.gauss(0, 5)) for x, t in zip(a, n, strict=True)]
        nu = [max(0.0, (1 - x) * t * 0.3 + rng.gauss(0, 5)) for x, t in zip(a, n, strict=True)]
        out.append([na, nd, nu])
    return out


@pytest.mark.parametrize("seed", [1, 2, 3])
@pytest.mark.parametrize("noise_sd", [0.0, 7.5, 18.37])
def test_rankings_match_oracle(seed, noise_sd):
    oracle, np = load_oracle()
    rng = random.Random(seed)
    groups = random_groups(rng, k=3, c=25)
    np_groups = [tuple(np.array(x) for x in g) for g in groups]
    ours = r.repness(groups, 5, noise_sd)
    theirs = oracle.repness(np_groups, 5, noise_sd)
    for g in range(3):
        assert [(j, d) for j, d in ours[g]] == [(int(j), d) for j, d in theirs[g]]
    assert r.consensus(groups, 5, noise_sd) == [
        int(j) for j in oracle.consensus(np_groups, 5, noise_sd)
    ]


def test_sampler_check_accepts_good_and_rejects_bad():
    rng = random.Random(7)
    draws = [rng.gauss(0, 3) for _ in range(20000)]
    assert r.sampler_check(draws, 3.0)["pass"]
    assert not r.sampler_check([d * 1.2 for d in draws], 3.0)["pass"]
    assert not r.sampler_check([d + 0.3 for d in draws], 3.0)["pass"]
    assert not r.sampler_check([max(min(d, 7.0), -7.0) for d in draws], 3.0)["checks"][
        "tail_3sigma"
    ]
    with pytest.raises(ValueError):
        r.sampler_check([0.0] * 10, 1.0)
