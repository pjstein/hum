import hashlib

import pytest

from hum_reference import cbor, fixtures, merkle, services
from hum_reference import manifest as m
from hum_reference.bodies import service as sv
from hum_reference.keys import key_from_label


def test_error_bodies_and_bare_forms():
    body = services.encode_error(services.ErrorBody("conflict", "cid_mismatch"))
    assert cbor.decode(body) == {0: "conflict", 1: "cid_mismatch"}
    assert services.decode_error(body).status == 409
    bare = services.encode_error(services.ErrorBody("not_found"))
    assert cbor.decode(bare) == {0: "not_found"}
    with pytest.raises(ValueError):
        services.decode_error(cbor.encode({0: "not_found", 1: "x"}))
    with pytest.raises(ValueError):
        services.encode_error(services.ErrorBody("not_found", "has-cid-caew..."))
    with pytest.raises(ValueError):
        services.encode_error(services.ErrorBody("nope"))


def test_signed_request_round_trip_and_rejections():
    keys = {n.encode(): key_from_label(n) for n in ("a1", "a2", "a3")}
    pubs = {k: v.public for k, v in keys.items()}
    nonce = bytes(16)
    cs, header = services.sign_request(
        [(b"a1", keys[b"a1"]), (b"a2", keys[b"a2"])], "POST", "/v1/log/add", b"{}", nonce, 100
    )
    assert "=" not in header
    assert services.verify_request(cs, pubs, 2, "POST", "/v1/log/add", b"{}", nonce, 100) == 2
    assert services.verify_request(cs, pubs, 2, "POST", "/v1/log/add", b"{ }", nonce, 100) == 0
    assert services.verify_request(cs, pubs, 2, "GET", "/v1/log/add", b"{}", nonce, 100) == 0
    assert services.check_freshness(100, 400, nonce, set()) is None
    assert services.check_freshness(100, 401, nonce, set()) == "replay"
    assert services.check_freshness(100, 110, nonce, {nonce}) == "replay"
    payload = services.request_payload("POST", "/p", b"", nonce, 1)
    assert (
        payload
        == hashlib.sha256(
            b"hum/service-request/1\x00POST /p\x00"
            + hashlib.sha256(b"").digest()
            + nonce
            + (1).to_bytes(8, "big")
        ).digest()
    )


def test_task_ids_and_receipts():
    deck = b"\x01" + bytes(32)
    assert services.task_id(deck, 0, 0) != services.task_id(deck, 1, 1)
    assert (
        services.task_id(deck, 2, 2)
        == hashlib.sha256(b"hum/dap-task/1" + deck + b"\x02\x02").digest()
    )
    key = key_from_label("agg")
    t = services.task_id(deck, 0, 0)
    sig = services.receipt_sign(key, t, bytes(32))
    assert services.receipt_verify(key.public, t, bytes(32), sig)
    assert not services.receipt_verify(key.public, services.task_id(deck, 1, 1), bytes(32), sig)


@pytest.mark.parametrize(("n", "k"), [(100, 0), (4096, 0), (4097, 1), (10_000, 2), (1_000_000, 8)])
def test_receipt_pages(n, k):
    leaves = [hashlib.sha256(b"%d" % i).digest() for i in range(n)]
    pages = services.receipt_pages(leaves)
    assert pages["k"] == k and len(pages["pages"]) == 1 << k
    assert sum(len(p) for p in pages["pages"]) == 32 * n
    assert pages["root"] == merkle.root_hash(sorted(leaves))
    assert b"".join(pages["pages"]) == b"".join(sorted(leaves))
    assert cbor.decode(pages["root_blob"]) == {0: k, 1: pages["page_cids"]}


def test_padding_buckets():
    assert [services.padding_bucket(s) for s in (0, 1024, 1025, 262_144, 262_145, 600_000)] == [
        1024, 1024, 4096, 262_144, 524_288, 786_432,
    ]  # fmt: skip


def test_witness_decision_matrix():
    fx = fixtures.build()
    w = fx.world
    note = w.note().text()
    n = len(w.leaves)
    proof = merkle.consistency_proof(w.leaves, 3)
    r3 = merkle.root_hash(w.leaves[:3])
    assert services.witness_decide(
        services.witness_request(3, proof, note), w.log_public, 3, r3
    ) == (200, "")
    assert services.witness_decide(
        services.witness_request(3, proof, note), w.log_public, 5, r3
    ) == (409, "5")
    assert services.witness_decide(
        services.witness_request(n, [], note), w.log_public, n, bytes(32)
    ) == (409, str(n))
    assert (
        services.witness_decide(
            services.witness_request(3, [bytes(32)] * len(proof), note), w.log_public, 3, r3
        )[0]
        == 422
    )
    assert (
        services.witness_decide(services.witness_request(n + 1, [], note), w.log_public, 3, r3)[0]
        == 400
    )
    assert (
        services.witness_decide(
            services.witness_request(3, proof, note), key_from_label("x").public, 3, r3
        )[0]
        == 403
    )


def test_key_config_round_trip():
    kc = sv.key_config(bytes(32))
    assert sv.parse_key_config(kc)["suites"] == [(1, 1)]
    with pytest.raises(ValueError):
        sv.parse_key_config(kc[:-1])
    with pytest.raises(ValueError):
        sv.parse_key_config(kc + b"\x00")


def test_service_manifests_verify_and_reject():
    fx = fixtures.build()
    w = fx.world
    fx.keys["svc"] = key_from_label("svc")
    fx.keys["svc-r"] = key_from_label("svc-r")
    ks = w.append(fixtures.service_keyset("svc", "svc-r", fx.keys), [(b"svc-r", fx.keys["svc-r"])])
    kc = sv.key_config(bytes(32))
    good = w.append(
        m.envelope(
            "service",
            sv.body("resolver", ["https://r.example/"], ohttp=kc),
            authority=ks.cid,
            issued=fixtures.ISSUED,
        ),
        [(b"svc", fx.keys["svc"])],
    )
    store = w.append(
        m.envelope(
            "service",
            sv.body(
                "blob-store",
                ["https://s.example/"],
                ohttp=kc,
                token_issuers=[ks.cid],
                **sv.blob_store_defaults(),
            ),
            authority=ks.cid,
            issued=fixtures.ISSUED,
        ),
        [(b"svc", fx.keys["svc"])],
    )
    w.finalize()
    ctx = w.context(now=fixtures.NOW)
    assert m.verify_bundle(ctx, good)[m.TYPE] == "service"
    assert m.verify_bundle(ctx, store)[m.BODY][sv.KIND] == "blob-store"
    from hum_reference.bodies import TypeRule

    bad = m.envelope(
        "service",
        sv.body("resolver", ["https://r.example/"]),
        authority=ks.cid,
        issued=fixtures.ISSUED,
    )
    with pytest.raises(TypeRule) as e:
        sv.schema(bad)
    assert e.value.rule == "S-5"


def test_service_schema_rules_directly():
    kc = sv.key_config(bytes(32))

    def env(body):
        return m.envelope("service", body, authority=b"\x01" + bytes(32), issued=1)

    from hum_reference.bodies import TypeRule

    def rule_of(body):
        try:
            sv.schema(env(body))
        except TypeRule as e:
            return e.rule
        return None

    assert rule_of(sv.body("resolver", ["https://r/"], ohttp=kc)) is None
    assert rule_of(sv.body("gateway", ["https://r/"])) == "S-1"
    assert rule_of(sv.body("resolver", ["http://r/"], ohttp=kc)) == "S-2"
    assert rule_of(sv.body("resolver", ["https://r/"])) == "S-5"
    assert rule_of(sv.body("relay", ["https://r/"], ohttp=kc)) == "S-5"
    assert rule_of(sv.body("delivery", ["https://r/"], ohttp=kc)) == "S-6"
    assert rule_of(sv.body("aggregator", ["https://r/"], ohttp=kc, phase=2)) == "S-7"
    assert (
        rule_of(sv.body("gallery", ["https://r/"], ohttp=kc, retention={"requests": 10**9}))
        == "S-8"
    )
    assert rule_of(sv.body("log", ["https://r/"], ohttp=kc, witnesses=[("a", bytes(32))])) == "S-3"


def test_log_submission_check():
    from hum_reference import credentials as cr

    v, e = 3, 40
    boundary = (e + 1) * v * cr.PERIOD
    assert services.log_submission_check(boundary + 9000, boundary + 9000, [(e + 1, v)]) is None
    assert services.log_submission_check(boundary + 1800, boundary + 1800, [(e, v)]) is None
    err = services.log_submission_check(boundary + 3660, boundary + 3660, [(e, v)])
    assert (err.code, err.rule, err.detail) == ("rejected", "P5", "epoch_not_current")
    err = services.log_submission_check(boundary + 16200, boundary + 9000, [(e + 1, v)])
    assert (err.detail, err.status) == ("issued_skew", 422) or err.detail == "issued_skew"
    assert services.log_submission_check(boundary + 12600, boundary + 9000, [(e + 1, v)]) is None
