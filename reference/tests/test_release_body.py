from fractions import Fraction

import pytest

from hum_reference import cbor, fixtures
from hum_reference import manifest as m
from hum_reference.bodies import deck as dk
from hum_reference.bodies import release as rb
from hum_reference.vectors import deck_vectors as dv


@pytest.fixture(scope="module")
def wd():
    return dv.get_world()


def test_ceil_sigma_and_padding():
    assert rb.ceil_sigma(Fraction(400)) == 20  # σ² = 4·200/2 = 400, σ = 20
    assert rb.ceil_sigma(Fraction(401)) == 21
    assert rb.ceil_sigma(Fraction(1, 2)) == 1
    assert rb.receipt_padding(Fraction(400), 0) == 120
    assert rb.receipt_padding(Fraction(400), -121) == 0
    assert rb.receipt_padding(Fraction(400), 7) == 127


def test_keybox_info_layout():
    info, aad = rb.keybox_info(b"\x01" + bytes(32))
    assert info.startswith(b"hum/results-keybox/1") and aad == b"\x01" + bytes(32)


def test_canonical_unlocked_follows_gates():
    plan = dk.plan_full(18)
    parts = {0: rb.part_record(Fraction(1, 100), 1, 500), 8: rb.part_record(Fraction(1, 200), 1)}
    assert rb.canonical_unlocked(plan, parts, 500, 1) == [0, 4, 8]
    assert rb.canonical_unlocked(plan, parts, 90, 1) == []
    parts[1] = rb.part_record(Fraction(1, 100), 1, 900)
    assert rb.canonical_unlocked(plan, parts, 500, 2) == [0, 1, 4, 8]
    parts[1] = rb.part_record(Fraction(1, 100), 1, 700)
    assert rb.canonical_unlocked(plan, parts, 500, 2) == [0, 4, 8]


def test_required_tables():
    plan = dk.plan_tallies_only(18)
    must, may = rb.required_tables(plan, [0, 4, 8], 400, 1, True)
    assert must == {"tallies", "count", "consensus"}
    must, _ = rb.required_tables(plan, [0, 4, 8], 200, 1, True)
    assert "consensus" not in must
    full = dk.plan_full(18)
    must, _ = rb.required_tables(full, [0, 1, 2, 4, 8], 1243, 3, True)
    assert "map" in must and "centroids" not in must
    rating = dk.plan_rating()
    must, may = rb.required_tables(rating, [0, 3, 8], 400, 1, True, rating=True)
    assert must == may == {"tallies", "group_tallies", "group_sizes"}


def test_release_cases_match_expected(wd):
    rules = set()
    for name, _desc, rule, b in wd.releases.cases:
        ctx = wd.w.context(now=fixtures.NOW)
        if rule is None:
            assert m.verify_bundle(ctx, b)[m.TYPE] == "release", name
            continue
        with pytest.raises(m.Rejection) as e:
            m.verify_bundle(ctx, b)
        step = 6 if rule == "R9" else 10
        assert (e.value.step, e.value.rule) == (step, rule), (name, str(e.value))
        rules.add(rule)
    assert rules == {f"R{i}" for i in range(1, 15)}


def test_r13_expires_cases(wd):
    names = {name: rule for name, _d, rule, _b in wd.releases.cases}
    for want in ("issued-after-expires", "no-room-for-rounds", "v2-after-pinned-expires"):
        assert names[f"invalid-R13-{want}"] == "R13"
    assert names["valid-R13-final-at-expires"] is None
    final = wd.named["release-valid-R13-final-at-expires"]
    env = cbor.decode(final.envelope)
    deck_env = cbor.decode(wd.w.bundles[env[m.REFS]["deck"]].envelope)
    assert env[m.ISSUED] == deck_env[m.EXPIRES]
    # the ledger's clock half is a submission check, never a phone-side rule
    log_names = {n for n, _d, _b, _t in wd.releases.log_cases}
    assert log_names == {"invalid-R13-ledger-clock-after-expires",
                         "valid-R13-ledger-clock-at-expires"}  # fmt: skip
    clock = wd.named["release-valid-R13-ledger-clock"]
    env = cbor.decode(clock.envelope)
    deck_env = cbor.decode(wd.w.bundles[env[m.REFS]["deck"]].envelope)
    e = deck_env[m.EXPIRES]
    assert rb.log_check(env, deck_env, e) is None
    assert rb.log_check(env, deck_env, e + 1)[0] == "R13"
    assert m.verify_bundle(wd.w.context(now=e + 1), clock)[m.TYPE] == "release"


def test_four_stage_release_body(wd):
    v4 = wd.named["release-valid-four-stages-v4"]
    env = cbor.decode(v4.envelope)
    body = env[m.BODY]
    assert body[rb.STAGE] == 4 and body[rb.FINAL] is True and body[rb.GROUPS_K] == 2
    assert body[rb.UNLOCKED] == [0, 1, 2, 3, 4, 8]
    assert set(body[rb.RECEIPTS]) == {0, 1, 2, 3}
    assert "keybox" in env[m.REFS] and "t/repness" in env[m.REFS]
    assert body[rb.PARTS][4][rb.PR_SIGMA] == 10_000_000  # σ = 1/√(2·1/200) = 10
