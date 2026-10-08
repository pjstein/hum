import copy

import pytest

from hum_reference import cbor, cose, fixtures
from hum_reference import manifest as m
from hum_reference.cid import cid


@pytest.fixture(scope="module")
def fx():
    return fixtures.build()


def verify(fx, bundle, **kw):
    ctx = fx.world.context(now=kw.pop("now", fixtures.NOW), held_size=kw.pop("held_size", 0))
    return m.verify_bundle(ctx, bundle, **kw)


def rejected_at(fx, bundle, step, **kw):
    with pytest.raises(m.Rejection) as e:
        verify(fx, bundle, **kw)
    assert e.value.step == step, str(e.value)
    return e.value


def test_good_bundles_verify(fx):
    for name in [
        "keyset_log",
        "keyset_a1",
        "context_v1",
        "deck_v1",
        "deck_v2",
        "keyset_a2",
        "deck_v3",
        "keyset_b1",
        "keyset_d1",
        "chain_16",
    ]:
        env = verify(fx, fx.named[name])
        assert env[m.SPEC] == 1


def test_cid_is_over_unsigned_envelope_only(fx):
    assert fx.deck_v1.cid == cid(fx.deck_v1.envelope)
    env = cbor.decode(fx.deck_v1.envelope)
    assert cid(cbor.encode(env)) == fx.deck_v1.cid


def test_every_step_has_a_rejection(fx):
    deck_env = cbor.decode(fx.deck_v1.envelope)

    def resign(env, signers):
        data = cbor.encode(env)
        c = cid(data)
        sigs = [cose.sign_cid(fx.keys[s], s.encode(), c) for s in signers]
        return m.Bundle(data, cose.encode_cose_sign(sigs), c, copy.deepcopy(fx.deck_v1.proof))

    big = copy.deepcopy(deck_env)
    big[m.BODY][7] = bytes(m.MAX_ENVELOPE_BYTES)
    rejected_at(fx, resign(big, ["a1", "a2"]), 1)
    raw = fx.deck_v1.envelope[:1] + b"\x18\x00" + fx.deck_v1.envelope[2:]
    rejected_at(
        fx, m.Bundle(raw, fx.deck_v1.signatures, cid(raw), copy.deepcopy(fx.deck_v1.proof)), 2
    )
    rejected_at(
        fx,
        m.Bundle(
            fx.deck_v1.envelope,
            fx.deck_v1.signatures,
            fx.deck_v2.cid,
            copy.deepcopy(fx.deck_v1.proof),
        ),
        3,
    )
    bad_type = copy.deepcopy(deck_env)
    bad_type[m.TYPE] = "poll"
    rejected_at(fx, resign(bad_type, ["a1", "a2"]), 4)
    no_auth = copy.deepcopy(deck_env)
    no_auth[m.AUTHORITY] = cid(b"nobody")
    rejected_at(fx, resign(no_auth, ["a1", "a2"]), 5)
    rejected_at(fx, resign(deck_env, ["a1"]), 6)
    rejected_at(fx, fx.deck_x, 6)  # revoked key
    noproof = m.Bundle(fx.deck_v3.envelope, fx.deck_v3.signatures, fx.deck_v3.cid, None)
    rejected_at(fx, noproof, 7)
    other_log = copy.deepcopy(fx.deck_v1)
    other_log.proof.log = cid(b"another log")
    rejected_at(fx, other_log, 7)
    rejected_at(fx, fx.deck_v2_fork, 8)
    rejected_at(fx, fx.deck_orphan, 8)
    rejected_at(fx, fx.deck_skip, 8)
    rejected_at(fx, fx.deck_hijack, 8)
    rejected_at(fx, fx.deck_dangling, 9)
    rejected_at(fx, fx.deck_bad_ref, 9)
    rejected_at(fx, fx.chain_17, 9)
    rejected_at(fx, fx.keyset_d2_broken_commitment, 10)
    rejected_at(fx, fx.keyset_e_threshold, 10)
    rejected_at(fx, fx.deck_v3, 11, now=fixtures.EXPIRES)
    verify(fx, fx.deck_v3, now=fixtures.EXPIRES, for_action=False)


def test_witness_threshold_counts_listed_keys_only(fx):
    ctx = fx.world.context(now=fixtures.NOW)
    ctx.witness_keys = ctx.witness_keys[:1]
    with pytest.raises(m.Rejection) as e:
        m.verify_bundle(ctx, fx.deck_v1)
    assert e.value.step == 7
    ctx = fx.world.context(now=fixtures.NOW)
    ctx.min_witnesses = 1
    ctx.witness_keys = ctx.witness_keys[:1]
    m.verify_bundle(ctx, fx.deck_v1)


def test_held_checkpoint_consistency(fx):
    fx3 = fixtures.build(held_size=3)
    ctx = fx3.world.context(now=fixtures.NOW, held_size=3)
    m.verify_bundle(ctx, fx3.deck_v3)
    assert ctx.held_checkpoint == (len(fx3.world.leaves), fx3.world.checkpoint().root)
    # the main world's bundles carry no consistency proofs; the top-level one must supply it
    bad = copy.deepcopy(fx.deck_v3)
    ctx = fx.world.context(now=fixtures.NOW, held_size=3)
    with pytest.raises(m.Rejection) as e:
        m.verify_bundle(ctx, bad)
    assert e.value.step == 7
    ctx = fx.world.context(now=fixtures.NOW, held_size=3)
    ctx.held_checkpoint = (3, bytes(32))
    with pytest.raises(m.Rejection) as e:
        m.verify_bundle(ctx, fx3.deck_v3)
    assert e.value.step == 7


def test_rotation_keyset_in_force_follows_log_order(fx):
    verify(fx, fx.deck_v1)  # a1 + a3 under keyset v1, before the revocation position
    verify(fx, fx.deck_v3)  # b keys, which only keyset v2 lists
    env = cbor.decode(fx.deck_v3.envelope)
    data = cbor.encode(env)
    sigs = [cose.sign_cid(fx.keys[s], s.encode(), cid(data)) for s in ("a1", "a2")]
    b = m.Bundle(data, cose.encode_cose_sign(sigs), cid(data), copy.deepcopy(fx.deck_v3.proof))
    rejected_at(fx, b, 6)


def test_bundle_wire_round_trip(fx):
    wire = m.encode_bundle(fx.deck_v3, ["https://resolver.example/"])
    item = cbor.decode(wire)
    assert set(item) == {0, 1, 2, 3}
    assert item[2][0][0] == fx.world.log_authority
    back = m.decode_bundle(wire)
    assert back.envelope == fx.deck_v3.envelope and back.cid == fx.deck_v3.cid
    assert back.proof.position == fx.deck_v3.proof.position
    verify(fx, back)
    with pytest.raises(ValueError):
        m.decode_bundle(cbor.encode({0: b"", 1: [b""], 2: [], 3: ["x" * 100_000]}))


def test_next_commitment_is_order_independent(fx):
    keys = [fixtures.kk(n, fx.keys[n], "sign") for n in ("b1", "b2", "b3")]
    assert m.next_commitment(keys) == m.next_commitment(list(reversed(keys)))


def test_world_is_deterministic():
    a, b = fixtures.build(), fixtures.build()
    assert a.world.leaves == b.world.leaves
    assert a.world.note().text() == b.world.note().text()
    assert all(a.named[n].signatures == b.named[n].signatures for n in a.named)
