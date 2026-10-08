import math

import pytest

from hum_reference import cbor, fixtures
from hum_reference import manifest as m
from hum_reference.bodies import issue_map as im
from hum_reference.keys import key_from_label
from hum_reference.vectors import issue_map_vectors as v


@pytest.fixture(scope="module")
def world():
    return v.World()


def test_every_valid_object_verifies_and_every_bad_one_names_its_rule(world):
    seen = set()
    for name, b in world.named.items():
        env = cbor.decode(b.envelope)
        if env[m.TYPE] not in im.TYPES:
            continue
        ctx = world.w.context(now=v.VERIFY_AT.get(name, v.NOW))
        if name in v.EXPECTED_REJECTIONS:
            with pytest.raises(m.Rejection) as e:
                m.verify_bundle(ctx, b)
            assert (e.value.step, e.value.rule) == v.EXPECTED_REJECTIONS[name], name
            seen.add(e.value.rule)
        else:
            m.verify_bundle(ctx, b)
    assert {f"IM-{i}" for i in range(1, 16) if i != 4} | {"IM-4a", "IM-4b"} <= seen
    for name in ("im-ok-verified-next-epoch", "im-ok-kid-removed-after"):
        assert name in world.named and name not in v.EXPECTED_REJECTIONS


def test_membership_proof_rules(world):
    b = world.named["im-ok-issue"]
    a = im.Authorship.decode(b.authorship)
    from hum_reference import credentials as cr

    pres = cr.Presentation.decode(a.proof)
    assert pres.context == world.ctx_open.cid and pres.branches == []
    assert a.nullifier == cr.nullifier(pres.creds[0].pseudonym)
    env = cbor.decode(b.envelope)
    v_of = {world.verifier_cid: v.V}
    assert im.log_submission_check(b.authorship, env[m.ISSUED], env[m.ISSUED] + 3600, v_of) is None
    assert im.log_submission_check(b.authorship, env[m.ISSUED], v.LOG_SKEW_T, v_of) is not None
    rejected = {name for name, (step, rule) in v.EXPECTED_REJECTIONS.items() if step == 6}
    assert {"im-bad-proof-epoch-mismatch", "im-bad-kid-removed-before"} <= rejected
    assert v.EXPECTED_REJECTIONS["im-bad-rebuilt-after-logged"] == (6, "IM-7")


def test_log_of_record_and_retry(world):
    two = world.named["im-ok-two-logs"]
    ctx_body = cbor.decode(world.ctx_two_logs.envelope)[m.BODY]
    assert im.log_of_record(ctx_body) == two.proof.log == world.w.log_authority
    assert world.in_second_log.cid == two.cid
    assert world.in_second_log.proof.log == world.w2.log_authority != two.proof.log
    with pytest.raises(m.Rejection):
        m.verify_bundle(world.w.context(now=v.NOW), world.in_second_log)
    assert im.rebuild_decision(True) == "keep"
    assert im.rebuild_decision(False) == "rebuild"
    assert im.rebuild_decision(False, refused_im7=True) == "first-logged-next-slot"


def test_authorship_round_trip_and_shapes():
    key = key_from_label("chat-alice")
    a = im.Authorship(1, key=key.public, sig=bytes(64), nullifier=bytes(32), proof=b"p")
    assert im.Authorship.decode(a.encode()).to_item() == a.to_item()
    with pytest.raises(im.TypeRule):
        im.Authorship.decode(cbor.encode({0: 1, 1: key.public}))  # member form without sig
    with pytest.raises(im.TypeRule):
        im.Authorship.decode(cbor.encode({0: 2, 3: 1, 4: bytes(32), 5: b"p", 1: key.public}))


def test_scopes_and_bound_message_layout():
    cid = b"\x01" + bytes(32)
    assert im.bound_message(cid) == b"hum/author/1" + cid
    assert im.once_scope(cid) == b"hum/author-once/1" + cid
    s = im.slot_scope(cid, 20733, 2)
    assert s == b"hum/author-slot/1" + cid + (20733).to_bytes(8, "big") + (2).to_bytes(2, "big")


def test_edit_key_is_derived_from_the_stripped_v1_envelope(world):
    v1 = cbor.decode(world.named["revisable-v1"].envelope)
    root = world.edit_root
    k = im.derive_edit_key(root, v1)
    assert k.public == v1[m.BODY][im.EDIT_KEY]
    other = dict(v1)
    other[m.BODY] = {**v1[m.BODY], im.EDIT_KEY: bytes(32)}
    assert im.derive_edit_key(root, other).public == k.public  # key 2 is stripped before hashing
    assert im.derive_edit_key(fixtures.fixed_bytes("other-root"), v1).public != k.public


def test_annotation_labels():
    st, sg = 18.0, 10.0
    assert (
        im.annotate((900.0, 80.0, 60.0), st, [(500.0, 40.0, 30.0), (400.0, 40.0, 30.0)], sg)[
            "label"
        ]
        == "Common ground"
    )
    assert (
        im.annotate((520.0, 480.0, 40.0), st, [(480.0, 60.0, 20.0), (40.0, 420.0, 20.0)], sg)[
            "label"
        ]
        == "Divides"
    )
    assert im.annotate((420.0, 580.0, 40.0), st)["label"] == "Leans no"
    assert im.annotate((60.0, 50.0, 10.0), st)["label"] is None  # N < 10 sigma
    r = im.annotate((600.0, 300.0, 100.0), st)
    p = 0.6
    assert math.isclose(r["sigma"], (st / 1000) * math.sqrt((1 - p) ** 2 + 2 * p * p))


def test_duplicate_ratio():
    assert im.duplicate_ratio("Fix the boiler.", "fix THE boiler!") == 1.0
    assert im.duplicate_ratio("a b c d", "a b c e") == 0.6
