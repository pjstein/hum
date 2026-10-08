import hashlib

import pytest

from hum_reference import cbor, fixtures
from hum_reference import manifest as m
from hum_reference.bodies import agent_sponsor as sp
from hum_reference.keys import key_from_label
from hum_reference.vectors import agent_sponsor_vectors as v


@pytest.fixture(scope="module")
def world():
    return v.World()


def test_sponsor_manifests(world):
    rules = set()
    for name, b in world.named.items():
        env = cbor.decode(b.envelope)
        if env[m.TYPE] != "agent-sponsor":
            continue
        ctx = world.w.context(now=v.VERIFY_AT.get(name, v.NOW))
        if name in v.EXPECTED:
            with pytest.raises(m.Rejection) as e:
                m.verify_bundle(ctx, b)
            assert (e.value.step, e.value.rule) == (10, v.EXPECTED[name]), name
            rules.add(e.value.rule)
        else:
            m.verify_bundle(ctx, b)
    assert {"AS-1", "AS-2a", "AS-3", "AS-4", "AS-5", "AS-6", "AS-7", "AS-8", "AS-9"} <= rules
    assert "as-ok-proof-after-epoch" in world.named and "as-bad-proof-epoch-mismatch" in v.EXPECTED


def test_report_binding(world):
    body = world.enclave_body
    assert sp.check_report(world.report, body, world.auth) == []
    agent = body[sp.AGENT_KEY]
    assert (
        sp.report_data(agent, world.auth)
        == hashlib.sha256(b"hum/attest/1" + agent + world.auth).digest()
    )
    bad = sp.synthetic_report(
        0,
        body[sp.ATTESTATION][sp.AT_MEASUREMENT],
        sp.report_data(key_from_label("x").public, world.auth),
    )
    assert sp.check_report(bad, body, world.auth) == [
        "report data is not bound to agentKey and the sponsor authority"
    ]
    assert sp.check_report(b"\xff", body, world.auth) == ["report is not deterministic CBOR"]


def test_sponsor_proof_structure(world):
    from hum_reference import credentials as cr

    proof = world.proof_of(world.vauth, "shape")
    pres = cr.Presentation.decode(proof)
    assert pres.context is None and pres.branches == [] and len(pres.creds) == 1
    assert pres.creds[0].issuer == world.vauth and pres.creds[0].disclosed == {0: v.AGENT_EPOCH}
    assert sp.log_submission_check(proof, v.ISSUED, v.ISSUED + 1800, 1) is None
    assert sp.log_submission_check(proof, v.ISSUED, v.LOG_SKEW_T, 1) is not None
    assert fixtures.ISSUED < v.ISSUED


def test_log_of_record_is_the_proof_log(world):
    b = world.named["as-ok-with-proof"]
    assert sp.log_of_record(b) == world.w.log_authority
    other = fixtures.fixed_bytes("another log keyset cid", 33)
    assert sp.context_accepts_log([other, world.w.log_authority], b)
    assert not sp.context_accepts_log([other], b)
    assert sp.log_of_record(m.Bundle(b.envelope, b.signatures, b.cid)) is None
