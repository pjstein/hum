from fractions import Fraction

import pytest

from hum_reference import cbor, fixtures
from hum_reference import manifest as m
from hum_reference.bodies import context as c
from hum_reference.bodies import deck as dk
from hum_reference.vectors import deck_vectors as dv


@pytest.fixture(scope="module")
def wd():
    return dv.get_world()


def test_plan_builders_sum_to_rho():
    for p in (dk.plan_full(18), dk.plan_tallies_only(18), dk.plan_ibis(18), dk.plan_rating()):
        total = sum((Fraction(r[0], r[1]) for r in p[dk.P_PARTS].values()), Fraction(0))
        assert total == Fraction(*p[dk.P_RHO])
        assert dk.TALLIES in p[dk.P_PARTS] and dk.RECEIPTS in p[dk.P_PARTS]
    assert set(dk.plan_rating()[dk.P_PARTS]) == {0, 3, 8}


def test_to_release_plan_defaults():
    rp = dk.to_release_plan(dk.plan_full(18), 18)
    assert rp.cov_statements == 18 and rp.grid == 24 and rp.cov_scale == 65_536
    assert dk.effective_gate(dk.plan_full(18, gates={0: 150}), 0) == 150
    assert dk.effective_gate(dk.plan_full(18), 4) is None
    assert dk.post_close_rounds(dk.plan_full(18)) == 3
    assert dk.post_close_rounds(dk.plan_tallies_only(18)) == 0


def test_valid_decks_verify(wd):
    for name in dv.VALID_DECKS:
        ctx = wd.w.context(now=fixtures.NOW)
        env = m.verify_bundle(ctx, wd.decks[name])
        assert env[m.TYPE] == "deck"
    env = cbor.decode(wd.decks["valid-expires-max"].envelope)
    assert env[m.EXPIRES] == dv.CLOSES + dk.PUBLISH_WINDOW + 4 * dv.WINDOW


def test_d16_is_a_submission_rule(wd):
    env2 = cbor.decode(wd.d16_v2.envelope)
    prev = cbor.decode(wd.named["deck-lineage-D16-v1"].envelope)
    assert dk.log_check(env2, prev, dv.CLOSES - 1) is None
    assert dk.log_check(env2, prev, dv.CLOSES + 1)[0] == "D16"
    assert dk.log_check(env2, None, dv.CLOSES + 1) is None
    # a phone verifying the logged version later never runs D16
    for now in (dv.CLOSES - 1, dv.CLOSES + 1, dv.EXPIRES_FULL):
        assert m.verify_bundle(wd.w.context(now=now), wd.d16_v2)[m.VERSION] == 2


def test_new_rule_cases_present(wd):
    names = {f"{rule}-{name}" for rule, name, _d, _b in wd.invalid_decks}
    for want in ("D9-breakdown-source-two-verifiers", "D12-expires-raised-closes-unchanged",
                 "D13-expires-far"):  # fmt: skip
        assert want in names, want


def test_every_invalid_deck_names_its_rule(wd):
    seen = set()
    for rule, name, _desc, b in wd.invalid_decks:
        ctx = wd.w.context(now=fixtures.NOW)
        with pytest.raises(m.Rejection) as e:
            m.verify_bundle(ctx, b)
        assert (e.value.step, e.value.rule) == (10, rule), (rule, name, str(e.value))
        seen.add(rule)
    assert seen == {f"D{i}" for i in range(1, 16)}


def test_deck_references_positions_in_its_context(wd):
    env = cbor.decode(wd.decks["valid-full"].envelope)
    assert env[m.REFS]["context"] == wd.ctx.cid
    assert env[m.BODY][dk.CARDS][16][dk.C_ORIGIN] == dk.ORIGIN_GLOBAL
    assert c.floors_of(cbor.decode(wd.ctx.envelope)[m.BODY])["rho"] == c.RHO_MAX


def test_d16_clock_free_half_rejects_a_version_after_a_release(wd):
    cases = {s: (r, b) for s, _d, r, b in wd.releases.deck_cases}
    rule, b = cases["deck-invalid-D16-after-release"]
    assert rule == "D16"
    with pytest.raises(m.Rejection) as e:
        m.verify_bundle(wd.w.context(now=fixtures.NOW), b)
    assert (e.value.step, e.value.rule) == (10, "D16")


def test_plan_rating_raises_gates0_with_min_voters():
    assert dk.P_GATES not in dk.plan_rating()
    p = dk.plan_rating(min_voters=300)
    assert p[dk.P_MIN_VOTERS] == 300 and p[dk.P_GATES] == {0: 300}
