"""Checks against the pinned primary draft, not Rust-produced fixtures."""

import re
from pathlib import Path

import pytest

from hum_reference import bbs

FIXTURES = Path(__file__).parent / "fixtures" / "bbs"
BASE = (FIXTURES / "draft-irtf-cfrg-bbs-signatures-12.txt").read_text()
BASE = "\n".join(
    line for line in BASE.splitlines() if not line.startswith(("Looker,", "Internet-Draft"))
)


def section(label, following):
    # rsplit ignores the table of contents.
    return BASE.rsplit(label, 1)[1].split(following, 1)[0]


def hex_field(text, name):
    match = re.search(r"(?m)^" + re.escape(name) + r" = (?:h|0x)'([\da-f\s]*)'", text)
    assert match is not None, name
    return bytes.fromhex("".join(match[1].split()))


def messages(text):
    return [
        bytes.fromhex("".join(m.split())) for m in re.findall(r"(?m)^m_\d+ = h'([\da-f\s]*)'", text)
    ]


@pytest.mark.parametrize("number,end", [("1", "8.4.4.2."), ("2", "8.4.5.")])
def test_published_signatures(number, end):
    text = section("8.4.4." + number + ".", end)
    sk = int.from_bytes(hex_field(text, "SK"), "big")
    pk = hex_field(text, "PK")
    header = hex_field(text, "header") if "header = h'" in text else b""
    sig = hex_field(text, "signature")
    msgs = messages(text)
    if not msgs:
        msgs = messages(section("8.4.5.2.", "8.4.5.3."))
    assert bbs.public_key(sk) == pk
    assert bbs.sign(sk, msgs, header) == sig
    assert bbs.verify(pk, sig, msgs, header)
    assert not bbs.verify(pk, sig, msgs, header + b"x")


@pytest.mark.parametrize("number,end", [("1", "8.4.5.2."), ("2", "8.4.5.3."), ("3", "9.  ")])
def test_published_proofs(number, end):
    text = section("8.4.5." + number + ".", end)
    msgs = messages(text)
    pk, sig = hex_field(text, "public_key"), hex_field(text, "signature")
    header = hex_field(text, "header") if "header = h'" in text else b""
    ph = hex_field(text, "presentation_header") if "presentation_header = h'" in text else b""
    indexes = [int(i) for i in re.search(r"revealed_indexes = \[([^]]*)\]", text)[1].split(",")]
    proof = hex_field(text, "proof")
    randomness = bbs.mock_random_scalars(5 + len(msgs) - len(indexes))
    assert bbs.proof_gen(pk, sig, msgs, indexes, randomness, header, ph) == proof
    disclosed = [msgs[i] for i in indexes]
    assert bbs.proof_verify(pk, proof, disclosed, indexes, header, ph)
    assert not bbs.proof_verify(pk, proof, disclosed, indexes, header, ph + b"x")


def test_malformed_points_and_proofs():
    text = section("8.4.5.1.", "8.4.5.2.")
    pk, proof = hex_field(text, "public_key"), hex_field(text, "proof")
    msgs = messages(text)
    header, ph = hex_field(text, "header"), hex_field(text, "presentation_header")
    for invalid in [
        b"",
        proof[:-1],
        proof + b"\0",
        bytes(48) + proof[48:],
        proof[:144] + bbs.i2osp(bbs.ORDER) + proof[176:],
    ]:
        assert not bbs.proof_verify(pk, invalid, msgs, [0], header, ph)
    assert not bbs.proof_verify(bytes(96), proof, msgs, [0], header, ph)
    assert not bbs.proof_verify(pk, proof, msgs, [1], header, ph)
    with pytest.raises(ValueError):
        bbs.decode_point(bytes.fromhex("c0" + "00" * 47))


NYM = (FIXTURES / "draft-irtf-cfrg-bbs-per-verifier-linkability-03.txt").read_text()
NYM = "\n".join(
    line for line in NYM.splitlines() if not line.startswith(("Kalos &", "Internet-Draft"))
)


def nym_section(label, following):
    return NYM.rsplit(label, 1)[1].split(following, 1)[0]


def nym_field(text, name):
    match = re.search(r"(?m)^" + re.escape(name) + r' =\s*"([a-f0-9\s]*)"', text)
    assert match is not None, name
    return bytes.fromhex("".join(match[1].split()))


@pytest.mark.parametrize("number", [1, 2])
def test_published_nym_commitments(number):
    from hum_reference import bbs_commit

    text = nym_section(f"12.1.3.{number}.", "12.1.")
    encoded = nym_field(text, "commitmentWithProof")
    assert bbs_commit.verify_commitment(encoded)
    assert not bbs_commit.verify_commitment(encoded[:-1] + bytes([encoded[-1] ^ 1]))
    assert not bbs_commit.verify_commitment(encoded, bbs.BLIND_API)


@pytest.mark.parametrize("number", range(1, 8))
def test_published_nym_proof_verification(number):
    text = nym_section(f"12.1.5.{number}.", f"12.1.5.{number + 1}." if number < 7 else "12.2.")
    known, committed = text.split("revealedMessages", 1)[1].split("revealedCommittedMessages", 1)
    committed = committed.split("Trace:", 1)[0]
    entries = re.findall(r'(?m)^(\d+): "([a-f0-9]*)"', known)
    committed_entries = re.findall(r'(?m)^(\d+): "([a-f0-9]*)"', committed)
    indexes = [int(i) for i, _ in entries] + [11 + int(i) for i, _ in committed_entries]
    msgs = [bytes.fromhex(m) for _, m in entries + committed_entries]
    gens = bbs.generators(11, bbs.NYM_API) + bbs.generators(7, b"BLIND_" + bbs.NYM_API)
    args = dict(
        pk=nym_field(text, "signerPublicKey"),
        proof=nym_field(text, "proof"),
        gens=gens,
        disclosed=bbs.messages_to_scalars(msgs, bbs.NYM_API),
        indexes=indexes,
        header=nym_field(text, "header") + bbs.i2osp(1, 8),
        ph=nym_field(text, "presentationHeader"),
        api=bbs.NYM_API,
        scope=nym_field(text, "context_id"),
        pseudonym=nym_field(text, "pseudonym"),
    )
    assert bbs.core_proof_verify(**args)
    assert not bbs.core_proof_verify(**{**args, "scope": args["scope"] + b"x"})
    assert not bbs.core_proof_verify(**{**args, "ph": args["ph"] + b"x"})
    assert not bbs.core_proof_verify(**{**args, "pseudonym": bbs.encode_point(bbs.P1)})


def test_commit_generation_and_rejection():
    from hum_reference import bbs_commit

    encoded, blind = bbs_commit.commit_scalars([123], [7, 11, 13])
    assert blind == 7
    assert bbs_commit.verify_commitment(encoded)
    for invalid in [b"", encoded[:-1], encoded + b"\0", bytes(48) + encoded[48:]]:
        assert not bbs_commit.verify_commitment(invalid)
    with pytest.raises(ValueError):
        bbs_commit.commit_scalars([123], [7, 0, 13])


def test_draft_keygen_and_generators():
    text = section("8.4.1.", "8.4.2.")
    sk = bbs.key_gen(
        hex_field(text, "key_material"), hex_field(text, "key_info"), hex_field(text, "key_dst")
    )
    assert bbs.i2osp(sk) == hex_field(text, "SK")
    assert bbs.public_key(sk) == hex_field(text, "PK")
    gens = section("8.4.3.", "8.4.4.")
    expected = [hex_field(gens, "Q_1")] + [hex_field(gens, f"H_{i}") for i in range(1, 11)]
    assert list(map(bbs.encode_point, bbs.generators(11))) == expected


def test_synthetic_nym_core_generation():
    # This is a low-level proof test, not blind issuance or a Hum resident card.
    sk, msgs = 1234567, [b"visible", b"hidden"]
    pk, api = bbs.public_key(sk), bbs.NYM_API
    header = b"synthetic" + bbs.i2osp(1, 8)
    sig = bbs.sign(sk, msgs, header, api)
    values, gens = bbs.messages_to_scalars(msgs, api), bbs.generators(3, api)
    proof, nym = bbs.core_proof_gen(
        pk, sig, gens, values, [0], [2, 3, 5, 7, 11, 13], header, b"presentation", api, b"scope"
    )
    assert bbs.core_proof_verify(
        pk, proof, gens, values[:1], [0], header, b"presentation", api, b"scope", nym
    )
    with pytest.raises(ValueError):
        bbs.core_proof_gen(
            pk, sig, gens, values, [1], [2, 3, 5, 7, 11, 13], header, b"presentation", api, b"scope"
        )


def test_reject_subgroup_and_index_errors():
    # Compressed x=0 is a curve point outside the prime-order G1 subgroup.
    with pytest.raises(ValueError):
        bbs.decode_point(bytes.fromhex("80" + "00" * 47))
    for indexes in [[0, 0], [1, 0], [-1], [2]]:
        with pytest.raises(ValueError):
            bbs.validate_indexes(indexes, 2)


def test_generated_vectors_replay():
    from hum_reference.vectors import bbs_vectors

    files = bbs_vectors.generate()
    assert len(files) == 1
    for case in files[0].cases:
        value = case["inputs"]
        if value["operation"] == "proof_verify":
            assert not bbs.proof_verify(
                bytes.fromhex(value["public_key"]),
                bytes.fromhex(value["proof"]),
                [bytes.fromhex(m) for m in value["disclosed_messages"]],
                value["disclosed_indexes"],
                bytes.fromhex(value["header"]),
                bytes.fromhex(value["presentation_header"]),
            )
