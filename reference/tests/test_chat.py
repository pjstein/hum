import hashlib

import pytest

from hum_reference import cbor, chat, fixtures, storage
from hum_reference.cid import cid
from hum_reference.keys import key_from_label


def test_content_round_trip_and_generic_rejections():
    body = {0: 1, 1: cid(b"log"), 2: 5, 3: bytes(32)}
    data = chat.encode("checkpoint", body)
    assert chat.decode("checkpoint", data) == body
    with pytest.raises(chat.ChatError):
        chat.decode("checkpoint", cbor.encode({**body, 0: 2}))
    with pytest.raises(chat.ChatError):
        chat.decode("checkpoint", cbor.encode({k: v for k, v in body.items() if k != 3}))
    with pytest.raises(chat.ChatError):
        chat.decode("checkpoint", cbor.encode({**body, 9: 1}))
    with pytest.raises(chat.ChatError):
        chat.decode("checkpoint", data[:1] + b"\x18\x00" + data[2:])
    with pytest.raises(chat.ChatError):
        chat.decode("join-request", cbor.encode({0: 1, 1: bytes(32), 2: [b"h"] * 9}))


def test_file_op_external_part_count():
    body = {0: 1, 1: 1, 2: bytes(16), 3: "a.txt", 4: []}
    with pytest.raises(chat.ChatError):
        chat.decode("file-op", cbor.encode(body), external_parts=0)
    chat.decode("file-op", cbor.encode(body), external_parts=1)
    with pytest.raises(chat.ChatError):
        chat.decode("file-op", cbor.encode({0: 1, 1: 5, 2: bytes(16)}), external_parts=1)
    with pytest.raises(chat.ChatError):
        chat.decode(
            "file-op", cbor.encode({0: 1, 1: 2, 2: bytes(16)}), external_parts=0
        )  # rename needs name


def test_roles_signature():
    keys = {n: key_from_label(n) for n in ("a1", "a2", "a3")}
    body = {0: 1, 1: cid(b"ctx"), 2: 1, 3: [[bytes(32), 1]], 6: {bytes(32): b"\x02" * 49}}
    signed = chat.roles_sign(body, [(b"a1", keys["a1"]), (b"a2", keys["a2"])])
    pubs = {n.encode(): k.public for n, k in keys.items()}
    assert chat.roles_verify(signed, pubs) == 2
    assert chat.roles_verify({**signed, 2: 2}, pubs) == 0
    assert chat.roles_payload(signed).startswith(b"hum/chat-roles/1")
    chat.decode("roles", cbor.encode(signed))


def test_message_id_layout():
    key, group, salt = bytes(32), bytes(32), bytes(16)
    mid = chat.message_id(key, group, b"msg", salt)
    s = chat.sender_uri(key).encode()
    r = chat.room_uri(group).encode()
    assert s.startswith(b"hum:member:") and r.startswith(b"hum:channel:")
    expected = hashlib.sha256(
        len(s).to_bytes(2, "big") + s + len(r).to_bytes(2, "big") + r + b"msg" + salt
    ).digest()[:31]
    assert chat.uri_length(len(s)) == len(s).to_bytes(2, "big")
    with pytest.raises(ValueError):
        chat.uri_length(65536)
    assert mid == b"\x01" + expected and len(mid) == 32


def test_padding_and_authenticated_data():
    assert chat.mls_bucket(100) == 512 and chat.mls_bucket(513) == 1024
    assert chat.mls_bucket(65537) is None and chat.mls_bucket(65537, commit=True) == 131072
    assert chat.mls_bucket(1_048_577, commit=True) is None
    assert chat.authenticated_data(None) == b"\x00"
    ad = chat.authenticated_data(bytes(32))
    assert len(ad) == 33 and chat.check_authenticated_data(ad, True)
    assert not chat.check_authenticated_data(bytes(32), True)


def test_safety_code():
    code, groups = chat.safety_code(bytes(32))
    assert code == hashlib.sha512(b"hum/safety/1" + bytes(32)).digest()
    parts = groups.split(" ")
    assert len(parts) == 12 and all(len(p) == 5 and p.isdigit() for p in parts)
    assert int(parts[0]) == int.from_bytes(code[:5], "big") % 100000


def test_external_part_mapping_and_reverse_rule():
    ref, _ = storage.SealedReference.direct(
        b"hello", bytes(16), "image/png", "p.png", 5, description="d"
    )
    part = chat.external_part_from_reference(ref)
    assert len(part) == chat.EP_LEN == 15 and part[:3] == [1, "", 2]
    assert part[4] == "hum:blob:" + __import__("hum_reference.cid", fromlist=["cid_text"]).cid_text(
        ref.cid
    )
    back = chat.external_part_to_reference(part)
    assert back.cid == ref.cid and back.digest == ref.digest and back.name == "p.png"
    for idx, value in (
        (2, 1),
        (1, "not a tag!"),
        (7, 2),
        (11, 2),
        (8, bytes(15)),
        (9, b"\x00"),
        (10, b"\x00"),
        (12, bytes(31)),
        (4, "https://x/"),
    ):
        bad = list(part)
        bad[idx] = value
        with pytest.raises(chat.ChatError):
            chat.external_part_to_reference(bad)
    _ = fixtures  # keep the fixture import meaningful for determinism checks elsewhere
