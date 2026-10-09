import copy
import json
import tempfile
from pathlib import Path

import pytest

from hum_reference import cbor, fixtures
from hum_reference import manifest as m
from hum_reference.bodies import TypeRule
from hum_reference.bodies import context as c
from hum_reference.bodies import trust_list as tl
from hum_reference.bodies import verifier as vf
from hum_reference.vectors import trust_list_vectors as tlv
from hum_reference.vectors import verifier_vectors as vv


@pytest.fixture(scope="module")
def world():
    return vv.World()


def env_for(w, body, refs):
    return m.envelope("verifier", body, authority=w.authority, issued=fixtures.ISSUED, refs=refs)


def test_profile_bodies_pass_schema(world):
    for fn, profile, ds in vv.PROFILE_BUILDERS.values():
        vf.schema(env_for(world, fn(world), world.refs(profile, ds)))
    vf.schema(env_for(world, vv.district(world), world.refs("district", ["wards"])))


@pytest.mark.parametrize(
    ("rule", "mutate"),
    [
        ("1", lambda b: b.__setitem__(vf.PROFILE, "x")),
        (
            "3",
            lambda b: b.__setitem__(
                vf.ISSUER_KEYS, [vv.issuer("a"), vv.issuer("b"), vv.issuer("c")]
            ),
        ),
        ("7a", lambda b: b[vf.ATTRIBUTES][1].__setitem__(vf.AT_VALUES, vf.enum_values(["one"]))),
        (
            "9",
            lambda b: b[vf.ATTRIBUTES][0].__setitem__(
                vf.AT_VALUES, vf.enum_values([str(i) for i in range(65)])
            ),
        ),
        ("12", lambda b: b[vf.EVIDENCE][0].__setitem__(vf.EV_KEPT, 1)),
        (
            "16",
            lambda b: b.update({vf.VALIDITY: 86_400}),
        ),
        ("20a", lambda b: b[vf.ATTRIBUTES].pop(1)),
        ("29", lambda b: b[vf.ATTRIBUTES][1].pop(vf.AT_FROM_EPOCH)),
        ("29", lambda b: b[vf.ATTRIBUTES][0].__setitem__(vf.AT_FROM_EPOCH, 3)),
        ("29", lambda b: b[vf.ATTRIBUTES][0].__setitem__(vf.AT_FROM_EPOCH, "0")),
    ],
)
def test_schema_rules_name_their_rule(world, rule, mutate):
    body = vv.district(world)
    mutate(body)
    with pytest.raises(TypeRule) as e:
        vf.schema(env_for(world, body, world.refs("district", ["wards"])))
    assert e.value.rule == rule


def test_lineage_rules(world):
    fx = world.fx
    ctx = fx.world.context(now=fixtures.NOW)
    d1 = world.append(
        "t-d1", world.envelope(vv.district(world, 1), world.refs("district", ["wards"]))
    )
    good = world.envelope(
        vv.district(world, 2),
        world.refs("district", ["wards"]),
        version=2,
        lineage=d1.cid,
        prev=d1.cid,
    )
    bad = copy.deepcopy(good)
    bad[m.BODY][vf.ISSUER_KEYS][0][vf.IK_SINCE] = 2  # rule 27
    view = m.Resolved(ctx, m.Bundle(cbor.encode(good), None, b"", None), good, None)
    ctx.resolver[d1.cid] = d1
    vf.rules(view)
    with pytest.raises(TypeRule) as e:
        vf.rules(m.Resolved(ctx, m.Bundle(cbor.encode(bad), None, b"", None), bad, None))
    assert e.value.rule == "27"
    moved = copy.deepcopy(good)
    for a in moved[m.BODY][vf.ATTRIBUTES]:
        a[vf.AT_FROM_EPOCH] = 2  # rule 29: an existing attribute's fromEpoch is frozen
    with pytest.raises(TypeRule) as e:
        vf.rules(m.Resolved(ctx, m.Bundle(cbor.encode(moved), None, b"", None), moved, None))
    assert e.value.rule == "29"


def test_rule_31_one_lineage_per_authority(world):
    w, built = vv.build()
    ctx = vv.blob_context(w.fx)
    d1 = w.named["valid-district-v1"]
    dup = built["dup31"]
    assert cbor.decode(dup.envelope)[m.AUTHORITY] == w.authority
    with pytest.raises(m.Rejection) as e:
        m.verify_bundle(ctx, dup)
    assert (e.value.step, e.value.rule) == (10, "31")
    view = m.Resolved(ctx, d1, cbor.decode(d1.envelope), d1.proof.position)
    assert m.envelope_cid(vf.verifier_of_authority(view, w.authority)) == d1.cid
    # every other lineage has its own authority and verifies
    for name in ("valid-custom", "lineage-29-from-epoch-changed-v1", "valid-district-v1"):
        m.verify_bundle(vv.blob_context(w.fx), w.named[name])
    assert len({cbor.decode(b.envelope)[m.AUTHORITY] for b in w.named.values()}) > 10


def test_rule_30_log_check(world):
    w = world
    body = vv.district(w, 1)
    assert vf.epoch_periods(body[vf.VALIDITY]) == 6
    e_now, hand = vf.epoch_now(fixtures.NOW, body[vf.VALIDITY])
    assert (e_now, hand) == (123, False)
    v1 = env_for(w, body, w.refs("district", ["wards"]))

    def v2_with(from_epoch):
        b = vv.district(w, 1)
        b[vf.ATTRIBUTES].append(vf.attribute("tier", "bool", "gate", "Tier", from_epoch=from_epoch))
        return m.envelope(
            "verifier",
            b,
            authority=w.authority,
            version=2,
            lineage=b"\x01" * 34,
            prev=b"\x01" * 34,
            issued=fixtures.ISSUED,
            refs=w.refs("district", ["wards"]),
        )

    assert vf.log_check(v1, None, fixtures.NOW) is None
    assert vf.log_check(v2_with(e_now), v1, fixtures.NOW)[0] == "30"
    assert vf.log_check(v2_with(e_now + 1), v1, fixtures.NOW) is None
    assert vf.log_check(v2_with(e_now + 2), v1, fixtures.NOW) is None
    assert vf.log_check(v2_with(e_now + 3), v1, fixtures.NOW)[0] == "30"
    # handover: the last two periods of an epoch; V = 6, so periods 4 and 5 of the epoch
    in_handover = (e_now * 6 + 4) * vf.PERIOD
    assert vf.epoch_now(in_handover, body[vf.VALIDITY]) == (e_now, True)
    assert vf.log_check(v2_with(e_now + 1), v1, in_handover)[0] == "30"
    assert vf.log_check(v2_with(e_now + 2), v1, in_handover) is None
    far = vv.district(w, 1)
    far[vf.ATTRIBUTES].append(vf.attribute("tier", "bool", "gate", "Tier", from_epoch=500))
    assert (
        vf.log_check(env_for(w, far, w.refs("district", ["wards"])), None, fixtures.NOW)[0] == "30"
    )


def test_message_count_from_one_version(world):
    body = vv.district(world, 1)
    body[vf.ATTRIBUTES].append(
        vf.attribute("tier", "enum", "gate", "Tier", vf.enum_values(["A", "B"]), from_epoch=5)
    )
    assert vf.message_count(body, 4) == 4
    assert vf.message_count(body, 5) == 5
    assert all(a[vf.AT_FROM_EPOCH] == 0 for a in vv.district(world, 1)[vf.ATTRIBUTES])
    assert vf.TOOLCHAIN == "rustc 1.99.0, target wasm32-wasip2"
    assert vf.code(b"\x00" * 32)[vf.CD_TOOLCHAIN] == vf.TOOLCHAIN


def test_key_of_epoch_and_epoch_periods(world):
    body = vv.district(world, 2)
    assert vf.key_of_epoch(body, 0)[vf.IK_SINCE] == 1
    assert vf.key_of_epoch(body, 3)[vf.IK_SINCE] == 1
    assert vf.key_of_epoch(body, 4)[vf.IK_SINCE] == 2
    assert vf.key_of_epoch(body, 9)[vf.IK_SINCE] == 2
    assert vf.epoch_periods(15_552_000) == 6


def test_disclosure_summary_matches_spec_shape(world):
    env = env_for(world, vv.district(world), world.refs("district", ["wards"]))
    s = vf.disclosure_summary(env)
    assert set(s) == {"who", "proves", "asks", "links", "expires", "code", "datasets"}
    assert s["proves"][0]["values"] == ["Ward 1", "Ward 2", "Ward 3"]
    assert s["proves"][0]["canBreakdown"] is True
    assert s["asks"][0]["keptSeconds"] == 0 and s["links"][0]["method"] == "evidence"
    assert s["code"]["profile"] == s["code"]["cid"]
    assert s["expires"] == {"validitySeconds": 15_552_000, "epochPeriods": 6, "renewal": "reissue"}


def test_trust_list_schema_and_rules():
    env = m.envelope("trust-list", tlv.core(3), authority=tlv.DISTRICT, issued=1)
    tl.schema(env)
    bad = copy.deepcopy(env)
    bad[m.BODY][tl.ENTRIES][0][tl.EN_MIN_ASSURANCE] = 1
    with pytest.raises(TypeRule) as e:
        tl.schema(bad)
    assert e.value.rule == "3"


def test_resolution_rows_and_satisfies():
    vw = vv.World()
    ctx_body = fixtures.context_body(vw.fx, vw.authority)
    ctx_body[c.ISSUERS] = [tlv.auth("approved-list")]
    rows = tl.resolve_rows(ctx_body, [tlv.core(3)])
    assert rows["issuers/0"] == [[tlv.auth("approved-list"), "*", 0, 1, ["person", "agent"]]]
    tl_rows = rows["tl/0"]
    assert [r for r in tl_rows if r[0] == tlv.UNIQUE][0][2:4] == [3, 2]
    assert tl_rows == sorted(tl_rows, key=cbor.encode)
    d2 = m.envelope("verifier", vv.district(vw, 2), authority=tlv.DISTRICT, issued=1)
    kid2 = vv.issuer("district-2", since=2)[vf.IK_KID]
    assert tl.credential_satisfies(
        tl_rows, "ward", verifier_authority=tlv.DISTRICT, verifier_env=d2, kid=kid2
    )
    assert not tl.credential_satisfies(
        tl_rows, "ward", verifier_authority=tlv.DISTRICT, verifier_env=None, kid=kid2
    )
    agent_env = m.envelope("verifier", vv.agent_class(vw), authority=tlv.AGENT, issued=1)
    agent_rows = tl.rows_for_source([c.SRC_TRUST_LIST, 0], ctx_body, [tlv.agent_list()])
    kid = vv.issuer("agent")[vf.IK_KID]
    assert tl.credential_satisfies(
        agent_rows, "agent-sponsor", verifier_authority=tlv.AGENT, verifier_env=agent_env, kid=kid
    )
    assert not tl.credential_satisfies(
        agent_rows,
        "agent-sponsor",
        verifier_authority=tlv.AGENT,
        verifier_env=agent_env,
        kid=kid,
        policy="vote",
    )


def _tree(gen) -> dict[str, bytes]:
    out = Path(tempfile.mkdtemp())
    for f in gen():
        f.write(out)
    return {str(p.relative_to(out)): p.read_bytes() for p in out.rglob("*.json")}


def test_generators_are_deterministic_and_well_formed():
    for gen in (vv.generate, tlv.generate):
        a, b = _tree(gen), _tree(gen)
        assert a == b and a
        for data in a.values():
            doc = json.loads(data)
            for case in doc["cases"]:
                assert ("expected" in case) != ("rejection" in case)


def test_key_tail_retirement_timing():
    from hum_reference.bodies import verifier as vf

    assert vf.KEY_TAIL == 44_928_000
    validity = 15_552_000  # 180 days: V = 6, one epoch = 14,515,200 s
    assert vf.epoch_seconds(validity) == 6 * vf.PERIOD
    assert vf.earliest_retirement(3, validity) == 4 * 6 * vf.PERIOD + vf.KEY_TAIL
    body = vf.body(
        name="t",
        operator="o",
        profile="district",
        issuer_keys=[
            vf.issuer_key(b"kid-0001", bytes(96), 0, 1),
            vf.issuer_key(b"kid-0002", bytes(96), 4, 2),
        ],
        host_keys=[vf.host_key(b"hkid-001", bytes(32))],
        attributes=[],
        evidence_=[],
        dedup_=[],
        code_=vf.code(bytes(32), vf.TOOLCHAIN),
        assurance=2,
        validity=validity,
        datasets=[],
    )
    assert vf.last_epoch_of_key(body, b"kid-0001") == 3
    assert vf.last_epoch_of_key(body, b"kid-0002") is None
