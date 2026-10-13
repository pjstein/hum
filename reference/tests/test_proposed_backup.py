import copy
import json
from pathlib import Path

import pytest

from hum_reference import cbor, hpke, storage
from hum_reference import proposed_backup as backup

PHRASE = "abandon " * 11 + "about"
SALT = bytes(range(16))
KEY = bytes(range(16, 32))
EPHEMERAL = bytes(range(32, 64))
PRIVATE = bytes(range(64, 96))
LIMIT = 1_000_000  # this test receiver's local resource policy, not a protocol cap
FIXTURES = json.loads((Path(__file__).parent / "fixtures/bip39-english-128.json").read_text())


def full():
    return {
        0: 1,
        1: bytes(32),
        2: bytes([1]) * 32,
        3: [],
        4: [{0: b"\x01" + bytes(32), 1: 100}],
        5: 200,
    }


def chat():
    return {0: 1, 1: bytes(32), 2: bytes([1]) * 32}


@pytest.mark.parametrize("fixture", FIXTURES)
def test_independent_bip39_entropy_and_phrase_vectors(fixture):
    assert backup.phrase_from_entropy(bytes.fromhex(fixture["entropy"])) == fixture["mnemonic"]
    assert backup.canonical_phrase(fixture["mnemonic"]) == fixture["mnemonic"].encode("ascii")


def test_normalization_is_exact_proposal():
    assert (
        backup.canonical_phrase("\t" + PHRASE.upper().replace(" ", "\r\n\t") + "  ")
        == PHRASE.encode()
    )
    # NFKD fullwidth Latin is ASCII after normalization; no locale case-folding.
    fullwidth = "".join(chr(ord(c) + 0xFEE0) if c != " " else " " for c in PHRASE)
    assert backup.canonical_phrase(fullwidth) == PHRASE.encode()


@pytest.mark.parametrize(
    "phrase",
    [
        "abandon " * 12,
        "abandon " * 11,
        "abandon " * 13,
        "abandon " * 24,
        PHRASE + ".",
        PHRASE + "\0",
        "\ufeff" + PHRASE,
        PHRASE.replace("about", "abo"),
        PHRASE.replace("about", "ábout"),
        PHRASE.replace("about", "notaword"),
    ],
)
def test_phrase_rejections(phrase):
    with pytest.raises(backup.BackupError):
        backup.canonical_phrase(phrase)


@pytest.fixture(scope="module")
def packed():
    return backup.pack_backup(
        full(), PHRASE, salt=SALT, content_key=KEY, ephemeral_private=EPHEMERAL
    )


def test_complete_file_roundtrips_and_receive_limit(packed):
    assert backup.unpack_backup(packed, PHRASE, max_envelope_bytes=LIMIT) == full()
    envelope = cbor.decode(packed)
    assert set(envelope) == {0, 1, 2, 3, 4}
    assert len(envelope[3]) == 64 and envelope[4][0] == 1
    exported = backup.pack_chat_export(
        chat(), hpke.public_key(PRIVATE), content_key=KEY, ephemeral_private=EPHEMERAL
    )
    assert backup.unpack_chat_export(exported, PRIVATE, max_envelope_bytes=LIMIT) == chat()
    assert set(cbor.decode(exported)) == {0, 1, 3, 4}
    with pytest.raises(backup.BackupError, match="receive policy"):
        backup.unpack_backup(packed, PHRASE, max_envelope_bytes=len(packed) - 1)


@pytest.mark.parametrize(
    "key,value",
    [
        (0, 2),
        (0, True),
        (1, 3),
        (1, True),
        (2, bytes(15)),
        (3, bytes(63)),
        (3, "not bytes"),
        (4, b"\x02invalid"),
        (8, b"unknown"),
    ],
)
def test_envelope_shape_before_decryption(packed, key, value):
    envelope = cbor.decode(packed)
    envelope[key] = value
    with pytest.raises(backup.BackupError):
        backup.unpack_backup(cbor.encode(envelope), PHRASE, max_envelope_bytes=LIMIT)


def test_noncanonical_trailing_and_duplicate_keys(packed):
    for bad in (packed + b"\x00", packed[:1] + b"\x18\x00" + packed[2:], b"\xa2\x00\x01\x00\x01"):
        with pytest.raises(backup.BackupError):
            backup.unpack_backup(bad, PHRASE, max_envelope_bytes=LIMIT)


def test_authentication_failure_never_returns_partial_state(packed):
    before = copy.deepcopy(full())
    with pytest.raises(backup.BackupError):
        backup.unpack_backup(packed, FIXTURES[1]["mnemonic"], max_envelope_bytes=LIMIT)
    for key in (2, 3, 4):
        envelope = cbor.decode(packed)
        raw = envelope[key]
        envelope[key] = raw[:-1] + bytes([raw[-1] ^ 1])
        with pytest.raises(backup.BackupError):
            backup.unpack_backup(cbor.encode(envelope), PHRASE, max_envelope_bytes=LIMIT)
    assert full() == before


def raw_authenticated(value, mode=1):
    private = hpke.backup_private_key(PHRASE.encode(), SALT)
    outer = {
        0: 1,
        1: mode,
        3: hpke.wrap_backup_key(hpke.public_key(private), KEY, ephemeral_private=EPHEMERAL),
        4: storage.seal(cbor.encode(value), KEY),
    }
    if mode == 1:
        outer[2] = SALT
    return cbor.encode(outer), private


@pytest.mark.parametrize("key", ["hand", "shield", "receipt", "order", "selection", 6])
def test_writer_and_reader_reject_forbidden_plaintext(key):
    value = full()
    value[key] = b"not portable"
    with pytest.raises(backup.BackupError):
        backup.pack_backup(value, PHRASE)
    encoded, _ = raw_authenticated(value)
    with pytest.raises(backup.BackupError):
        backup.unpack_backup(encoded, PHRASE, max_envelope_bytes=LIMIT)


def test_full_backup_cannot_be_reinterpreted_as_chat_export():
    encoded, private = raw_authenticated(full(), 2)
    with pytest.raises(backup.BackupError):
        backup.unpack_chat_export(encoded, private, max_envelope_bytes=LIMIT)
    encoded, _ = raw_authenticated(chat(), 1)
    with pytest.raises(backup.BackupError):
        backup.unpack_backup(encoded, PHRASE, max_envelope_bytes=LIMIT)


def test_proposed_e1_card_layout_requires_blind_and_strict_nested_fields():
    # Serialization only: opaque signature is deliberately NOT claimed valid BBS.
    value = full()
    card = {
        0: b"\x01" + bytes(32),
        1: b"test-kid",
        2: 3,
        3: [bytes(8)],
        4: bytes(80),
        5: (1).to_bytes(32, "big"),
        6: (2).to_bytes(32, "big"),
    }
    value[3] = [card]
    backup.validate_plaintext(value, 1)
    for bad in (
        {k: v for k, v in card.items() if k != 6},
        {**card, 7: b"extra"},
        {**card, 2: 2},
        {**card, 5: bytes(32)},
        {**card, 6: bytes([255]) * 32},
    ):
        malformed = copy.deepcopy(value)
        malformed[3] = [bad]
        with pytest.raises(backup.BackupError):
            backup.validate_plaintext(malformed, 1)
    value[4][0][2] = b"shield"
    with pytest.raises(backup.BackupError):
        backup.validate_plaintext(value, 1)
