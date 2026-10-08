import hashlib

import pytest

from hum_reference import cbor, cose
from hum_reference.cid import cid, cid_from_text, cid_text, parse_cid
from hum_reference.keys import key_from_label, verify


def test_cid_is_algorithm_byte_plus_sha256():
    c = cid(b"hello")
    assert c[0] == 1 and c[1:] == hashlib.sha256(b"hello").digest()
    assert parse_cid(c) == (1, c[1:])


def test_cid_text_round_trip_and_shape():
    c = cid(b"hello")
    t = cid_text(c)
    assert t.startswith("c") and t == t.lower() and "=" not in t
    assert len(t) == 1 + 53  # 33 bytes -> 53 base32 chars without padding
    assert cid_from_text(t) == c


@pytest.mark.parametrize("bad", ["C" + "a" * 53, "c" + "A" * 53, "c" + "a" * 20, "x" + "a" * 53])
def test_cid_text_rejects(bad):
    with pytest.raises(ValueError):
        cid_from_text(bad)


def test_cose_sign_structure_contains_domain_string():
    key = key_from_label("t")
    c = cid(b"m")
    sig = cose.sign_cid(key, b"k", c)
    structure = cbor.decode(cose.sig_structure(sig.protected, c))
    assert structure == ["Signature", b"", sig.protected, b"hum/manifest/1", c]
    assert cbor.decode(sig.protected) == {1: -8, 4: b"k"}
    assert verify(key.public, cose.sig_structure(sig.protected, c), sig.signature)


def test_cose_sign_round_trip_and_verify():
    key = key_from_label("t")
    c = cid(b"m")
    sig = cose.sign_cid(key, b"k", c)
    data = cose.encode_cose_sign([sig])
    item = cbor.decode(data)
    assert isinstance(item, cbor.Tag) and item.tag == 98
    assert item.value[2] is None  # detached payload
    assert cose.decode_cose_sign(data) == [sig]
    assert cose.verify_signature(key.public, sig, c)
    assert not cose.verify_signature(key.public, sig, cid(b"other"))
    assert not cose.verify_signature(key_from_label("u").public, sig, c)


def test_signature_without_domain_does_not_verify():
    key = key_from_label("t")
    c = cid(b"m")
    protected = cose.protected_header(b"k")
    raw = key.sign(cose.sig_structure(protected, c, external_aad=b""))
    assert not cose.verify_signature(key.public, cose.Signature(protected, b"k", -8, raw), c)


@pytest.mark.parametrize(
    "item",
    [
        [b"", {}, None, []],  # untagged
        cbor.Tag(98, [b"", {}, None, []]),  # no signatures
        cbor.Tag(98, [b"", {}, b"payload", [[b"", {}, b""]]]),  # attached payload
        cbor.Tag(98, [b"", {}, None, [[cbor.encode({1: -8}), {}, b""]]]),  # no kid
    ],
)
def test_decode_rejects_malformed(item):
    with pytest.raises(ValueError):
        cose.decode_cose_sign(cbor.encode(item))
