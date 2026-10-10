"""Known-answer tests from CFRG's RFC 9180 fixture corpus, plus Hum bindings."""

import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from pyhpke import AEADId
from pyhpke.exceptions import PyHPKEError

from hum_reference import hpke

FIXTURES = json.loads((Path(__file__).parent / "fixtures/rfc9180-base.json").read_text())
SK = bytes(range(32))
EPHEMERAL = bytes(range(32, 64))
CID = b"\x01" + bytes(32)
SESSION = bytes(16)


@pytest.mark.parametrize("v", FIXTURES, ids=["AES128", "ChaCha20"])
def test_rfc9180_known_answers(v):
    h = bytes.fromhex
    enc, sender = hpke.sender(
        h(v["pkRm"]), h(v["info"]), aead=AEADId(v["aead_id"]), ephemeral_private=h(v["skEm"])
    )
    assert enc == h(v["enc"])
    suite = hpke.suite(AEADId(v["aead_id"]))
    recipient = suite.create_recipient_context(
        enc, suite.kem.deserialize_private_key(h(v["skRm"])), h(v["info"])
    )
    for encryption in v["encryptions"]:
        plaintext, aad, ciphertext = (h(encryption[k]) for k in ("pt", "aad", "ct"))
        assert sender.seal(plaintext, aad) == ciphertext
        assert recipient.open(ciphertext, aad) == plaintext
    for export in v["exports"]:
        for context in (sender, recipient):
            assert context.export(h(export["exporter_context"]), export["L"]) == h(
                export["exported_value"]
            )


def test_issue_response_export_binding():
    sealed, sender = hpke.seal_issue(
        hpke.public_key(SK), CID, b"request", ephemeral_private=EPHEMERAL
    )
    request, recipient = hpke.open_issue(SK, CID, sealed)
    assert request == b"request"
    assert hpke.response_material(sender) == hpke.response_material(recipient)
    response = hpke.seal_response(recipient, SESSION, b"response")
    assert hpke.open_response(sender, SESSION, response) == b"response"
    with pytest.raises(InvalidTag):
        hpke.open_response(sender, bytes([1]) * 16, response)


@pytest.mark.parametrize("field", ["authority", "name", "session", "request", "ciphertext", "key"])
def test_evidence_rejects_substitution(field):
    args = dict(private_key=SK, authority=CID, name="address", session=SESSION, request=b"request")
    sealed = hpke.seal_evidence(
        hpke.public_key(SK),
        CID,
        "address",
        SESSION,
        b"request",
        b"evidence",
        ephemeral_private=EPHEMERAL,
    )
    assert hpke.open_evidence(**args, sealed=sealed) == b"evidence"
    if field == "ciphertext":
        sealed = sealed[:-1] + bytes([sealed[-1] ^ 1])
    else:
        key = "private_key" if field == "key" else field
        args[key] = {
            "authority": b"\x01" + bytes([1]) * 32,
            "name": "other",
            "session": bytes([1]) * 16,
            "request": b"other",
            "key": EPHEMERAL,
        }[field]
    with pytest.raises((PyHPKEError, ValueError)):
        hpke.open_evidence(**args, sealed=sealed)


def test_keybox_and_ticket_domains():
    pk = hpke.public_key(SK)
    box = hpke.seal_keybox(pk, CID, b"references", ephemeral_private=EPHEMERAL)
    assert hpke.open_keybox(SK, CID, box) == b"references"
    with pytest.raises(ValueError):
        hpke.open_keybox(SK, CID, b"\x02" + box[1:])
    with pytest.raises(PyHPKEError):
        hpke.open_keybox(SK, b"\x01" + bytes([1]) * 32, box)
    ticket = hpke.seal_ticket(pk, CID, bytes(4096), ephemeral_private=EPHEMERAL)
    assert len(ticket) == 4144
    assert hpke.open_ticket(SK, CID, ticket) == bytes(4096)
    with pytest.raises(ValueError):
        hpke.seal_ticket(pk, CID, bytes(4095))
    with pytest.raises(PyHPKEError):
        hpke.open_ticket(SK, b"\x01" + bytes([1]) * 32, ticket)


def test_backup_wrap():
    phrase = b"abandon " * 11 + b"about"
    key = hpke.backup_private_key(phrase, bytes(16))
    wrap = hpke.wrap_backup_key(hpke.public_key(key), bytes(range(16)), ephemeral_private=EPHEMERAL)
    assert hpke.unwrap_backup_key(key, wrap) == bytes(range(16))
    with pytest.raises(PyHPKEError):
        hpke.unwrap_backup_key(hpke.backup_private_key(phrase + b" wrong", bytes(16)), wrap)
