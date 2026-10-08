import hashlib
import hmac
import os

import pytest

from hum_reference import cbor, storage
from hum_reference.cid import cid


@pytest.mark.parametrize(
    ("n", "padded"),
    [
        (0, 0),
        (1, 1),
        (2, 2),
        (3, 3),
        (7, 7),
        (9, 10),
        (15, 16),
        (17, 18),
        (100, 104),
        (1000, 1024),
        (65536, 65536),
        (65537, 67584),
        (1_000_000, 1_015_808),
    ],
)
def test_padme_matches_the_spec_table(n, padded):
    assert storage.padme(n) == padded


def test_padme_overhead_bound():
    for n in [10, 100, 1000, 12345, 10**6, 10**7, 2**40 + 1]:
        p = storage.padme(n)
        assert n <= p <= n * 1.12 + 1


@pytest.mark.parametrize("n", [0, 1, 7, 100, 65535, 65536, 65537, 200_000])
def test_pad_is_self_delimiting(n):
    pt = os.urandom(n)
    padded = storage.pad(pt)
    assert len(padded) == storage.padme(n + 1)
    assert padded[n] == 0x80
    assert storage.unpad(padded) == pt


def test_unpad_rejects_bad_padding():
    with pytest.raises(storage.SealedError) as e:
        storage.unpad(bytes(16))
    assert e.value.reason == "bad-padding"
    with pytest.raises(storage.SealedError):
        storage.unpad(b"abc\x80\x00\x00\x00\x00\x00")  # 9 bytes, padme(4) is 4


@pytest.mark.parametrize("n", [0, 1, 100, 65535, 65536, 65537, 140_000])
def test_seal_round_trip_format_1(n):
    key = os.urandom(16)
    pt = os.urandom(n)
    ct = storage.seal(pt, key)
    assert ct[0] == 0x01
    padded = storage.padme(n + 1)
    chunks = -(-padded // storage.CHUNK)
    assert len(ct) == 1 + padded + 16 * chunks
    assert storage.open_sealed(ct, key) == pt
    assert storage.open_sealed(ct, key, size=n) == pt


def test_seal_round_trip_format_2_and_salt_binding():
    secret = os.urandom(16)
    salt = os.urandom(16)
    pt = os.urandom(1000)
    ct = storage.seal_keyring(pt, secret, salt)
    assert ct[:17] == b"\x02" + salt
    assert storage.open_sealed(ct, epoch_secret=secret) == pt
    other_salt = ct[:1] + os.urandom(16) + ct[17:]
    with pytest.raises(storage.SealedError) as e:
        storage.open_sealed(other_salt, epoch_secret=secret)
    assert e.value.reason == "bad-tag"


def test_seal_detects_truncation_reorder_tamper_and_trailing():
    key = bytes(16)
    pt = bytes(range(256)) * 300  # 76,800 bytes: two chunks
    ct = storage.seal(pt, key)
    end0 = 1 + storage.CHUNK + 16

    def reason(data, **kw):
        with pytest.raises(storage.SealedError) as e:
            storage.open_sealed(data, key, **kw)
        return e.value.reason

    assert reason(ct[:end0]) == "bad-tag"
    assert reason(ct[:1] + ct[end0:] + ct[1:end0]) == "bad-tag"
    assert reason(ct[:10] + bytes([ct[10] ^ 1]) + ct[11:]) == "bad-tag"
    assert reason(ct + bytes(16), size=len(pt)) == "trailing-data"
    assert reason(ct + bytes(16)) == "bad-tag"
    assert reason(b"\x03" + ct[1:]) == "bad-format"
    assert reason(ct, expected_format=2) == "bad-format"
    with pytest.raises(storage.SealedError):
        storage.open_sealed(ct, os.urandom(16))


def test_nonce_and_aad_layout():
    assert storage.chunk_nonce(0, False) == bytes(12)
    assert storage.chunk_nonce(1, True) == bytes(3) + b"\x01" + (1).to_bytes(8, "big")
    assert storage.chunk_aad(b"\x01") == b"hum/sealed/1\x01"
    assert len(storage.chunk_aad(b"\x02" + bytes(16))) == 29


def test_range_chunk_decrypts_alone():
    key = os.urandom(16)
    pt = os.urandom(150_000)
    ct = storage.seal(pt, key)
    off = 1 + storage.CHUNK + 16
    chunk1 = ct[off : off + storage.CHUNK + 16]
    assert (
        storage.open_chunk(chunk1, 1, False, key, ct[:1])
        == storage.pad(pt)[storage.CHUNK : 2 * storage.CHUNK]
    )
    with pytest.raises(storage.SealedError):
        storage.open_chunk(chunk1, 0, False, key, ct[:1])


def test_reference_forms_and_opening():
    key = os.urandom(16)
    ref, ct = storage.SealedReference.direct(b"hello", key, "text/plain", "h.txt", 5)
    assert ref.cid == cid(ct) and ref.digest == cid(b"hello")
    assert storage.SealedReference.decode(ref.encode()) == ref
    assert ref.open(ct) == b"hello"
    secret, salt = os.urandom(16), os.urandom(16)
    kref, kct = storage.SealedReference.keyring(b"hello", secret, 4, salt, "text/plain")
    assert kref.key is None and kref.size is None and kref.epoch == 4
    assert storage.SealedReference.decode(kref.encode()) == kref
    assert kref.open(kct, epoch_secret=secret) == b"hello"
    for reason, blob in (
        ("cid-mismatch", storage.seal(b"hellp", key)),
        ("digest-mismatch", None),
    ):
        if blob is None:
            bad = storage.SealedReference(ref.cid, 1, ref.media, key, 5, None, b"\x01" + bytes(32))
            with pytest.raises(storage.SealedError) as e:
                bad.open(ct)
        else:
            with pytest.raises(storage.SealedError) as e:
                ref.open(blob)
        assert e.value.reason == reason


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.__setitem__(storage.REF_EPOCH, 1),  # both forms
        lambda d: d.pop(storage.REF_KEY),  # neither form
        lambda d: d.__setitem__(storage.REF_FORMAT, 2),  # direct form with format 2
        lambda d: d.__setitem__(storage.REF_NAME, "a/b"),  # slash in name
        lambda d: d.__setitem__(storage.REF_MEDIA, "x" * 128),  # media too long
        lambda d: d.__setitem__(storage.REF_KEY, bytes(15)),  # key length
        lambda d: d.__setitem__(11, 1),  # unknown key
    ],
)
def test_reference_rejects_malformed(mutate):
    ref, _ = storage.SealedReference.direct(b"hello", bytes(16), "text/plain", "h.txt")
    item = ref.to_item()
    mutate(item)
    with pytest.raises(storage.SealedError) as e:
        storage.SealedReference.decode(cbor.encode(item))
    assert e.value.reason == "bad-reference"


def test_keyring_blob_key_is_hkdf_extract_then_expand():
    secret, salt = os.urandom(16), os.urandom(16)
    prk = hmac.new(salt, secret, hashlib.sha256).digest()
    expected = hmac.new(prk, b"hum/keyring-blob/1" + b"\x01", hashlib.sha256).digest()[:16]
    assert storage.blob_key_from_keyring(secret, salt) == expected
    assert storage.blob_key_from_keyring(secret, os.urandom(16)) != expected


def test_mls_exporter_matches_hand_computation():
    secret = bytes(range(32))

    def hkdf_expand(prk, info, length):
        out, block, i = b"", b"", 1
        while len(out) < length:
            block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
            out += block
            i += 1
        return out[:length]

    def label(length, lab, ctx):
        lab = b"MLS 1.0 " + lab
        return length.to_bytes(2, "big") + bytes([len(lab)]) + lab + bytes([len(ctx)]) + ctx

    derived = hkdf_expand(secret, label(32, b"hum/keyring/1", b""), 32)
    ctx_hash = hashlib.sha256(b"").digest()
    assert storage.keyring_secret(secret) == hkdf_expand(
        derived, label(16, b"exported", ctx_hash), 16
    )


def test_keyring_share_sorted_and_delete_commitment():
    payload = storage.keyring_share([(2, 9, bytes(16)), (1, 3, bytes(16))])
    assert cbor.decode(payload) == {0: [[1, 3, bytes(16)], [2, 9, bytes(16)]]}
    s = os.urandom(32)
    assert storage.delete_commitment(s) == hashlib.sha256(b"hum/delete/1" + s).digest()
