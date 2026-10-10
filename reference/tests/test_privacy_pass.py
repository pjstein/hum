import hashlib

import pytest

from hum_reference.privacy_pass import Token, rfc_fixtures, verify_public_token


@pytest.mark.parametrize("case", rfc_fixtures()["cases"], ids=lambda c: str(c["id"]))
def test_rfc_token_framing(case):
    raw = bytes.fromhex(case["token"])
    token = Token.decode(raw)
    assert token.nonce == bytes.fromhex(case["nonce"])
    assert token.challenge_digest == hashlib.sha256(bytes.fromhex(case["token_challenge"])).digest()
    assert token.key_id == hashlib.sha256(bytes.fromhex(case["pkI"])).digest()
    assert token.authenticator_input() + token.authenticator == raw
    for malformed in (raw[:-1], raw + b"\x00", b"\x00\x03" + raw[2:]):
        with pytest.raises(ValueError):
            Token.decode(malformed)


@pytest.mark.parametrize("case", rfc_fixtures()["cases"][5:], ids=lambda c: str(c["id"]))
def test_rfc_public_tokens_verify_and_bind_all_fields(case):
    raw, challenge, key = (bytes.fromhex(case[n]) for n in ("token", "token_challenge", "pkI"))
    assert verify_public_token(raw, challenge, key)
    for at in (2, 34, 66, 98, len(raw) - 1):
        changed = bytearray(raw)
        changed[at] ^= 1
        assert not verify_public_token(bytes(changed), challenge, key)
    assert not verify_public_token(raw, challenge + b"x", key)
    assert not verify_public_token(raw, challenge, b"invalid DER")


def test_type1_is_not_falsely_verified_as_public_token():
    c = rfc_fixtures()["cases"][0]
    assert not verify_public_token(
        *(bytes.fromhex(c[n]) for n in ("token", "token_challenge", "pkI"))
    )
