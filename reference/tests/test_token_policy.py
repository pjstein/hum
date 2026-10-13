import hashlib
import hmac
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from hum_reference import cbor
from hum_reference.privacy_pass import rfc_fixtures
from hum_reference.privacy_pass_adapter import bridge, channel_issuer, channel_seed
from hum_reference.token_policy import (
    FetchSessions,
    IssuerBinding,
    NonceLedger,
    authenticate_channel_request,
    redeem,
)


@pytest.mark.parametrize("case", rfc_fixtures()["cases"][:5])
def test_private_actual_issuance_and_finalization(case):
    args = dict(
        secret_key=case["skI"],
        challenge=case["token_challenge"],
        nonce=case["nonce"],
        blind=case["blind"],
        pinned_public=case["pkI"],
    )
    for extra in ({}, {"response": case["token_response"]}):
        result = bridge("private_issue", **args, **extra)
        assert result["request"] == case["token_request"]
        assert result["token"] == case["token"]
    assert bridge("verify", secret_key=case["skI"], token=case["token"])["nonce"] == case["nonce"]
    with pytest.raises(ValueError):
        bridge("private_issue", **args, response=bytes(len(bytes.fromhex(case["token_response"]))))


@pytest.mark.parametrize("index", range(5, 10))
def test_public_actual_blind_issuance(index):
    result = bridge("public_fixture", index=index)
    case = rfc_fixtures()["cases"][index]
    for field in ("request", "response", "token"):
        assert result[field] == case["token_" + field if field != "token" else "token"]


def setup_policy(tmp_path):
    group = b"g" * 32
    issuer = channel_issuer(b"s" * 32, group)
    challenge = bridge("challenge", token_type=1, issuer_name="delivery.example")
    token = bytes.fromhex(
        bridge(
            "private_issue",
            seed=issuer["seed"],
            info=group,
            challenge=challenge["challenge"],
            nonce=b"n" * 32,
            blind=bytes.fromhex(rfc_fixtures()["cases"][0]["blind"]),
            pinned_public=issuer["public_key"],
        )["token"]
    )
    binding = IssuerBinding(
        group, b"authority", "delivery.example", issuer["public_key"], issuer["seed"], group
    )
    return token, dict(
        binding=binding,
        context=group,
        accepted_issuers={b"authority"},
        issuance_connection=b"issue",
        spend_connection=b"spend",
        ledger=NonceLedger(tmp_path / "nonces.sqlite"),
    )


def test_atomic_persistent_redemption(tmp_path):
    token, policy = setup_policy(tmp_path)

    def attempt(_):
        try:
            redeem(token, **policy)
            return "ok"
        except ValueError as error:
            return str(error)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(16)))
    assert results.count("ok") == 1
    assert results.count("token_spent") == 15
    policy["ledger"] = NonceLedger(tmp_path / "nonces.sqlite")
    with pytest.raises(ValueError, match="token_spent"):
        redeem(token, **policy)


def test_rejections_do_not_consume_nonce(tmp_path):
    token, policy = setup_policy(tmp_path)
    for changes in (
        {"context": b"other"},
        {"accepted_issuers": set()},
        {"spend_connection": b"issue"},
        {"binding": replace(policy["binding"], issuer_name="other.example")},
        {"binding": replace(policy["binding"], public_key=b"wrong")},
    ):
        with pytest.raises(ValueError):
            redeem(token, **{**policy, **changes})
    for invalid in (token + b"x", token[:-1] + bytes([token[-1] ^ 1])):
        with pytest.raises(ValueError):
            redeem(invalid, **policy)
    redeem(token, **policy)


def test_seed_and_response_pinning(tmp_path):
    token, policy = setup_policy(tmp_path)
    assert len(token) > 32
    assert channel_seed(b"s" * 32, b"g" * 32) != channel_seed(b"s" * 32, b"h" * 32)
    other = channel_issuer(b"t" * 32, b"g" * 32)
    with pytest.raises(ValueError):
        bridge(
            "private_issue",
            seed=other["seed"],
            info=b"g" * 32,
            pinned_public=policy["binding"].public_key,
            nonce=b"n" * 32,
            challenge=bridge("challenge", token_type=1, issuer_name="delivery.example")[
                "challenge"
            ],
            blind=rfc_fixtures()["cases"][0]["blind"],
        )


def test_channel_any_held_secret_and_cookie_deadline(tmp_path):
    request = {
        0: 1,
        1: b"g" * 32,
        2: 900,
        3: [bytes.fromhex(rfc_fixtures()["cases"][0]["token_request"])],
    }
    request[4] = hmac.digest(
        b"old" * 10 + b"!!", b"hum/token-request/1" + cbor.dumps(request), hashlib.sha256
    )
    assert authenticate_channel_request(request, (b"new" * 10 + b"!!", b"old" * 10 + b"!!"), 2) == 1
    with pytest.raises(ValueError):
        authenticate_channel_request({**request, 2: 901}, (b"old" * 10 + b"!!",), 2)
    token, policy = setup_policy(tmp_path)
    sessions = FetchSessions()
    cookie = sessions.redeem_and_open(token, now=100, **policy)
    assert len(cookie) == 16
    sessions.authorize_fetch(cookie, context=policy["context"], now=999.999)
    for now in (99, 1000, 1001):
        with pytest.raises(ValueError):
            sessions.authorize_fetch(cookie, context=policy["context"], now=now)
    with pytest.raises(ValueError):
        sessions.authorize_fetch(cookie, context=b"other", now=200)


def test_public_general_issue_and_policy(tmp_path):
    case = rfc_fixtures()["cases"][5]
    challenge = bridge("challenge", token_type=2, issuer_name="store.example")["challenge"]
    actual = bridge("public_issue", **{**case, "token_challenge": challenge})
    token = bytes.fromhex(actual["token"])
    binding = IssuerBinding(
        b"context", b"authority", "store.example", bytes.fromhex(case["pkI"]), b"", b"", 2
    )
    policy = dict(
        binding=binding,
        context=b"context",
        accepted_issuers={b"authority"},
        issuance_connection=b"issue",
        spend_connection=b"spend",
        ledger=NonceLedger(tmp_path / "public.sqlite"),
    )
    with pytest.raises(ValueError):
        redeem(token, **{**policy, "binding": replace(binding, issuer_name="wrong.example")})
    redeem(token, **policy)
    with pytest.raises(ValueError, match="token_spent"):
        redeem(token, **policy)


def test_directory_binding_and_malformed_requests(tmp_path):
    from hum_reference.token_policy import finalize_channel_token

    _, policy = setup_policy(tmp_path)
    binding = policy["binding"]
    args = dict(
        binding=binding,
        group_id=binding.context,
        directory_key=binding.public_key,
        nonce=b"x" * 32,
        blind=bytes.fromhex(rfc_fixtures()["cases"][0]["blind"]),
    )
    assert finalize_channel_token(**args)["token"]
    for changes in ({"group_id": b"other"}, {"directory_key": b"wrong"}):
        with pytest.raises(ValueError, match="directory_issuer_binding"):
            finalize_channel_token(**{**args, **changes})
    valid = {
        0: 1,
        1: b"g" * 32,
        2: 0,
        3: [bytes.fromhex(rfc_fixtures()["cases"][0]["token_request"])],
    }
    for changes in ({0: True}, {2: 2**64}, {3: [b"bad"]}, {3: [b"\x00\x01" + bytes(50)]}):
        request = {**valid, **changes}
        request[4] = bytes(32)  # Shape/point validation precedes MAC verification.
        with pytest.raises(ValueError):
            authenticate_channel_request(request, (b"s" * 32,), 2)


def test_cookie_forgetting_idle_and_no_resurrection(tmp_path):
    token, policy = setup_policy(tmp_path)
    sessions = FetchSessions()
    cookie = sessions.redeem_and_open(token, now=100, **policy)
    # A second independent cookie models a later, already-redeemed session.
    fresh = b"fresh-cookie-0001"
    sessions._sessions[fresh] = (policy["context"], 500)
    assert sessions.expire(now=999.999) == 0
    assert sessions.expire(now=1000) == 1
    assert cookie not in sessions._sessions
    assert fresh in sessions._sessions
    for now in (1000, 200):
        with pytest.raises(ValueError, match="fetch_session_expired"):
            sessions.authorize_fetch(cookie, context=policy["context"], now=now)
    # No fetch of fresh is needed for periodic service cleanup to forget it.
    assert sessions.expire(now=1400) == 1
    assert not sessions._sessions


def test_cookie_clock_validation_and_request_time_cleanup(tmp_path):
    token, policy = setup_policy(tmp_path)
    sessions = FetchSessions()
    for now in (True, "100", 10**1000, float("nan"), float("inf"), -float("inf")):
        with pytest.raises(ValueError, match="session clock"):
            sessions.redeem_and_open(token, now=now, **policy)
        with pytest.raises(ValueError, match="session clock"):
            sessions.authorize_fetch(b"missing", context=policy["context"], now=now)
    # Invalid clocks did not spend the valid token. Opening also purges idle cookies.
    sessions._sessions[b"expired"] = (policy["context"], 0)
    cookie = sessions.redeem_and_open(token, now=900, **policy)
    assert b"expired" not in sessions._sessions
    with pytest.raises(ValueError, match="fetch_session_expired"):
        sessions.authorize_fetch(cookie, context=policy["context"], now=1800)
    assert cookie not in sessions._sessions
