import pytest

from hum_reference import cbor


@pytest.mark.parametrize(
    ("value", "hexs"),
    [
        (0, "00"),
        (23, "17"),
        (24, "1818"),
        (255, "18ff"),
        (256, "190100"),
        (65535, "19ffff"),
        (65536, "1a00010000"),
        (1 << 32, "1b0000000100000000"),
        ((1 << 64) - 1, "1bffffffffffffffff"),
        (-1, "20"),
        (-24, "37"),
        (-25, "3818"),
        (-(1 << 64), "3bffffffffffffffff"),
        (b"", "40"),
        (b"\x01\x02", "420102"),
        ("", "60"),
        ("a", "6161"),
        ("ü", "62c3bc"),
        ([], "80"),
        ([1, [2]], "82018102"),
        ({}, "a0"),
        (False, "f4"),
        (True, "f5"),
        (None, "f6"),
        (cbor.Tag(98, []), "d86280"),
    ],
)
def test_encode_known_values(value, hexs):
    assert cbor.encode(value).hex() == hexs
    assert cbor.decode(bytes.fromhex(hexs)) == value


def test_map_keys_sorted_bytewise_not_length_first():
    # RFC 8949: bytewise order of the encoded keys. 0x0a (10) < 0x19 0x01 0x00 (256); "aa" < "b".
    assert cbor.encode({256: 0, 10: 0, 1: 0}).hex() == "a3 0100 0a00 19010000".replace(" ", "")
    assert cbor.encode({"aa": 0, "b": 0}).hex() == "a2 6162 00 626161 00".replace(" ", "")


def test_mixed_key_types_order_by_encoding():
    enc = cbor.encode({"a": 0, 1: 0, -1: 0, b"\x00": 0})
    # uint (0x01) < negint (0x20) < bytes (0x41..) < text (0x61..)
    assert enc.hex() == "a4 0100 2000 410000 616100".replace(" ", "")


@pytest.mark.parametrize(
    "hexs",
    [
        "1800",  # non-shortest int
        "190018",
        "1a0000ffff",
        "1b00000000ffffffff",
        "a2010000 00".replace(" ", ""),  # unsorted keys
        "a201000100",  # duplicate key
        "9f0102ff",  # indefinite array
        "5f4101ff",
        "bf0100ff",
        "f93c00",  # floats
        "fb3ff0000000000000",
        "0100",  # trailing
        "a2010002",  # truncated
        "61ff",  # bad utf-8
        "f7",  # undefined
        "a1800100",  # array key
        "1c",  # reserved additional info
    ],
)
def test_reject_non_canonical(hexs):
    with pytest.raises(cbor.CborError):
        cbor.decode(bytes.fromhex(hexs))
    assert not cbor.is_canonical(bytes.fromhex(hexs))


def test_encode_rejects_floats_and_duplicates():
    with pytest.raises(cbor.CborError):
        cbor.encode(1.5)
    with pytest.raises(cbor.CborError):
        cbor.encode(1 << 64)


def test_round_trip_nested():
    v = {0: 1, 1: "deck", 8: {"context": b"\x01" + bytes(32)}, 9: {0: [1, -2, b"x", None]}}
    assert cbor.decode(cbor.encode(v)) == v
    assert cbor.is_canonical(cbor.encode(v))
