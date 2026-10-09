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


def test_body_keys_round_trip_and_provisional_rows():
    c = b"\x01" + bytes(32)
    named = {"root": bytes(32), "k": 1, "pages": [c, c]}
    data = services.encode_body("agg-receipts", named)
    assert cbor.decode(data) == {0: bytes(32), 1: 1, 2: [c, c]}
    assert services.decode_body("agg-receipts", data) == named
    with pytest.raises(ValueError):
        services.encode_body("agg-receipts", {**named, "count": 812})
    with pytest.raises(ValueError):
        services.encode_body("agg-receipts", {"root": bytes(32), "k": 1})
    nested = services.encode_body(
        "agg-daily", {"sigma": [10, 1], "buckets": [{"bucket": 0, "increment": 2}], "total": 2}
    )
    assert cbor.decode(nested) == {0: [10, 1], 1: [{0: 0, 1: 2}], 2: 2}
    assert services.decode_body(
        "gallery-take-forks", services.encode_body("gallery-take-forks", {"takes": [c]})
    ) == {"takes": [c]}
    assert set(services.BODIES) >= services.PROVISIONAL_BODIES
    assert len(services.PROVISIONAL_BODIES) == 6


def test_receipt_body_kid_and_404_below_minimum():
    deck = b"\x01" + bytes(32)
    k1, k2 = key_from_label("l1"), key_from_label("l2")
    pubs = {b"kid-1": k1.public, b"kid-2": k2.public}
    t = services.task_id(deck, 0, 0)
    leaf = bytes(32)
    sig = services.receipt_sign(k1, t, leaf)
    good = services.receipt_body(leaf, sig, b"kid-1")
    assert cbor.decode(good) == {0: leaf, 1: sig, 2: b"kid-1"}
    assert services.verify_receipt_body(good, pubs, t)
    assert not services.verify_receipt_body(services.receipt_body(leaf, sig, b"kid-2"), pubs, t)
    assert not services.verify_receipt_body(services.receipt_body(leaf, sig, b"kid-9"), pubs, t)
    status, body = services.receipts_response(True)
    assert status == 404 and cbor.decode(body) == {0: "not_found"}
    status, body = services.receipts_response(False, bytes(32), 0, [deck])
    assert status == 200 and cbor.decode(body) == {0: bytes(32), 1: 0, 2: [deck]}
    blob = cbor.encode({0: 0, 1: [deck]})
    assert services.check_receipts_response(body, bytes(32), blob) is None
    assert services.check_receipts_response(body, bytes([1]) * 32, blob) == "root_mismatch"
    assert (
        services.check_receipts_response(body, bytes(32), cbor.encode({0: 1, 1: [deck]}))
        == "k_mismatch"
    )
    assert (
        services.check_receipts_response(body, bytes(32), cbor.encode({0: 0, 1: []}))
        == "pages_mismatch"
    )


def test_evidence_strings_and_structural_open():
    auth = b"\x01" + bytes(32)
    sid = bytes(16)
    req, req2 = b"request-a", b"request-b"
    info = services.evidence_info(auth, "match")
    assert info == b"hum/evidence/1" + auth + b"match"
    aad = services.evidence_aad(sid, req)
    assert aad == sid + hashlib.sha256(req).digest() and len(aad) == 48
    sealed = {"info": info, "aad": aad, "ciphertext": b"x"}
    assert services.open_evidence_structural(sealed, auth, "match", sid, req) is None
    assert services.open_evidence_structural(sealed, auth, "match", sid, req2) == "other_request"
    assert (
        services.open_evidence_structural(sealed, auth, "match", bytes([1]) * 16, req)
        == "other_session"
    )
    assert services.open_evidence_structural(sealed, auth, "address", sid, req) == "other_item_name"
    other = b"\x01" + bytes([7]) * 32
    assert services.open_evidence_structural(sealed, other, "match", sid, req) == "other_verifier"
    with pytest.raises(ValueError):
        services.evidence_aad(bytes(15), req)
    err = services.evidence_rejection()
    assert (err.status, err.code, err.rule) == (422, "rejected", "V-4")
    assert services.host_rejection(0).rule == "vr-0"
    assert cbor.decode(services.encode_error(services.host_rejection(2))) == {
        0: "rejected",
        3: "vr-2",
    }


def test_host_sessions_v2():
    host = services.HostSessions(b"secret")
    s1, s2, s3 = bytes([1]) * 16, bytes([2]) * 16, bytes([3]) * 16
    status, resp, why = host.issue(s1, b"req-a", b"row")
    assert status == 200 and why == "issued"
    assert host.issue(s1, b"req-a", b"row") == (200, resp, "identical_retry")
    st, err, why = host.issue(s1, b"req-b", b"row")
    assert (st, err.code, why) == (409, "conflict", "conflict_in_session")
    assert host.issue(s2, b"req-a", b"row") == (200, resp, "identical_retry_new_session")
    st, err, why = host.issue(s3, b"req-b", b"row")
    assert (st, err.code, err.rule, why) == (422, "rejected", "vr-0", "duplicate_masked")
    assert host.issue(s3, b"req-b", b"row")[2] == "identical_retry"


def test_host_sessions_v4_evidence_binding():
    auth = b"\x01" + bytes(32)
    host = services.HostSessions(b"secret", auth)
    s1, s2, s3 = bytes([1]) * 16, bytes([2]) * 16, bytes([3]) * 16
    info = services.evidence_info(auth, "match")

    def sealed(sess, req):
        return {"info": info, "aad": services.evidence_aad(sess, req), "ciphertext": b"x"}

    host.submit_evidence(s1, "match", sealed(s1, b"req-a"))
    status, resp, why = host.issue(s1, b"req-a", b"row")
    assert status == 200 and why == "issued"
    # a different request beside evidence sealed for req-a, in a fresh session
    host.submit_evidence(s2, "match", sealed(s2, b"req-a"))
    st, err, why = host.issue(s2, b"req-b", b"row-2")
    assert (st, err.code, err.rule, why) == (422, "rejected", "V-4", "evidence_other_request")
    assert host.issue(s2, b"req-a", b"row-2")[2] == "session_ended"
    # session ID replaced in transit
    host.submit_evidence(s3, "match", sealed(s1, b"req-c"))
    assert host.issue(s3, b"req-c", b"row-3")[2] == "evidence_other_session"
    # lost response: same request, evidence re-sealed under the new session, identical response
    s4 = bytes([4]) * 16
    host.submit_evidence(s4, "match", sealed(s4, b"req-a"))
    assert host.issue(s4, b"req-a", b"row") == (200, resp, "identical_retry_new_session")


def test_gallery_score_and_element():
    assert services.gallery_score(0.4123454) == 412_345
    assert services.gallery_score(1 / 128) == 7812  # 0.0078125: tie, half to even
    assert services.gallery_score(-0.25) == -250_000
    e = services.gallery_takes_element(b"c", 9, 1, None, True)
    assert e == {"cid": b"c", "logIndex": 9, "rated": False, "hasGroupScore": False, "forkCount": 1}
    data = services.encode_body("gallery-takes", {"takes": [e], "ratings": []})
    assert cbor.decode(data) == {0: [{0: b"c", 1: 9, 2: False, 3: False, 5: 1}], 1: []}


def test_relay_set_and_picker_o6():
    shipped = [b"s1", b"s2"]
    assert services.relay_set("delivery", shipped, [b"a"]) == [b"s1", b"s2", b"a"]
    for kind in ("ballot", "deck-status", "log-submit", "store-put-authored-text", "no-context"):
        assert services.relay_set(kind, shipped, [b"a"]) == shipped
    assert services.relay_set("store", shipped, [b"a"]) == [b"s1", b"s2", b"a"]
    assert services.relay_set("delivery", shipped, None) == shipped
    with pytest.raises(ValueError):
        services.relay_set("teleport", shipped, None)
    p = services.RelayPicker(b"seed")
    first = p.pick([b"s1", b"s2", b"a"])
    assert first in {b"s1", b"s2", b"a"}
    assert p.pick([b"s1", b"s2", b"a"], failed=[first]) != first
    assert p.pick([b"s1"], failed=[b"s1"]) is None
    assert services.RelayPicker(b"seed").pick([b"s1", b"s2", b"a"]) == first


def test_aggregator_log_line_l5_and_gateway_config():
    cid = "01" + "ab" * 32
    ok = {
        "service": "aggregator",
        "day": 1,
        "deck": cid,
        "round": 0,
        "code": "malformed",
        "rejected_count": 1,
        "n_hat": 812,
    }
    assert services.check_aggregator_log_line(ok) is None
    assert (
        services.check_aggregator_log_line({"service": "aggregator", "day": 1, "rejected_count": 4})
        is None
    )
    assert services.check_aggregator_log_line({"deck": cid, "accepted": 807}) == "L-5"
    assert services.check_aggregator_log_line({"deck": cid, "accepted_bucket_50": 800}) == "L-5"
    assert services.check_aggregator_log_line({"deck": cid, "minute": 60}) == "L-5"
    for code in ("conflict", "closed"):
        assert (
            services.check_aggregator_log_line({"deck": cid, "code": code, "rejected_count": 1})
            == "L-5"
        )
        assert services.check_aggregator_log_line({"code": code, "rejected_count": 1}) == "L-5"
    assert services.check_aggregator_log_line({"deck": cid, "relay_connection": 4}) == "L-6"
    assert services.check_aggregator_log_line({"deck": cid, "round": 9}) == "L-6"
    assert services.check_aggregator_log_line({"deck": "not-a-cid"}) == "L-6"
    assert services.check_gateway_log_line({"path": "/v1/log/entry", "count": 3}) is None
    assert services.check_gateway_log_line({"count": 10}) is None
    assert services.check_gateway_log_line({"path": "/v1/agg/decks/c/rounds/0/ballots"}) == "L-5"
    assert services.check_gateway_log_line({"ballot_intake_daily": 807}) == "L-5"
    assert services.check_gateway_log_line({"client_ip": "x"}) == "L-6"
    assert services.check_log_line("resolver", {"cid": cid, "count": 2}) is None
    assert services.check_log_line("resolver", {"cid": cid, "count": 2, "size": 1}) == "L-6"
    host = {
        "session_id": "00" * 16,
        "authority": cid,
        "version": 1,
        "day": 1,
        "outcome": "issued",
        "memory_bucket": 0,
        "fuel_bucket": 0,
    }
    assert services.check_log_line("host", host) is None
    assert services.check_log_line("host", {**host, "outcome": 999}) is None
    for line in (
        {**host, "outcome": 1000},
        {**host, "session_id": "z" * 32},
        {"session_id": "00" * 16},
    ):
        assert services.check_log_line("host", line) == "L-6"
    for line in ({"cid": "01" + "g" * 64}, {"day": "2025-02-29"}, {"type": []}):
        assert services.check_log_line("log", line) == "L-6"
    assert services.check_log_line("aggregator", {"state": []}) == "L-6"
    assert services.check_log_line("resolver", {"count": 2}) == "L-6"
    assert services.check_log_line("host", {"session_id": "00" * 15, "outcome": "issued"}) == "L-6"
    with pytest.raises(ValueError):
        services.check_log_line("nobody", {})
    assert services.gateway_accepts_config(1, [1, 2], 2)["accepted"]
    assert not services.gateway_accepts_config(0, [1, 2], 2)["accepted"]
