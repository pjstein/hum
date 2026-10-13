"""Unadopted E1 proposal: independently sourced generation bytes and refusals."""

import hashlib
import json
import re
from pathlib import Path

import pytest

from hum_reference import bbs, bbs_commit
from hum_reference import proposed_bbs as e1

FIXTURES = Path(__file__).parent / "fixtures/bbs/upstream-nym-sha256"


NYM = (FIXTURES.parent / "draft-irtf-cfrg-bbs-per-verifier-linkability-03.txt").read_text()
NYM = "\n".join(
    line for line in NYM.splitlines() if not line.startswith(("Kalos &", "Internet-Draft"))
)


def nym_section(label, following):
    return NYM.rsplit(label, 1)[1].split(following, 1)[0]


def nym_field(text, name):
    match = re.search(r"(?m)^" + re.escape(name) + r' =\s*"([a-f0-9\s]*)"', text)
    assert match is not None
    return bytes.fromhex("".join(match[1].split()))


def fixture(kind, number):
    return json.loads((FIXTURES / f"{kind}{number:03}.json").read_text())


def octets(data):
    return [bytes.fromhex(value) for value in data]


def integer(data):
    return int(data, 16)


def test_source_hashes():
    provenance = json.loads((FIXTURES / "provenance.json").read_text())
    for path, digest in provenance["sha256"].items():
        assert hashlib.sha256((FIXTURES / Path(path).name).read_bytes()).hexdigest() == digest


@pytest.mark.parametrize("number", [1, 2])
def test_independent_commitment_generation(number):
    f = fixture("nymCommit", number)
    published = nym_section(f"12.1.3.{number}.", "12.1.")
    expected = bytes.fromhex(f["commitmentWithProof"])
    assert expected == nym_field(published, "commitmentWithProof")
    values = bbs.messages_to_scalars(octets(f["committedMessages"]), e1.API)
    values += list(map(integer, f["proverNyms"]))
    r = f["trace"]["random_scalars"]
    randomness = [integer(f["proverBlind"]), integer(r["s_tilde"]), *map(integer, r["m_tildes"])]
    assert bbs_commit.commit_scalars(values, randomness, e1.API) == (expected, randomness[0])
    if number == 1:
        assert e1.commit(values[0], randomness) == (expected, randomness[0])


@pytest.mark.parametrize("number", range(1, 5))
def test_independent_signatures_and_finalization(number):
    f = fixture("nymSignature", number)
    published = nym_section(f"12.1.4.{number}.", "12.1.")
    signature = bytes.fromhex(f["signature"])
    assert signature == nym_field(published, "signature")
    sk, pk = (
        integer(f["signerKeyPair"]["secretKey"]),
        bytes.fromhex(f["signerKeyPair"]["publicKey"]),
    )
    commitment, header = bytes.fromhex(f["commitmentWithProof"]), bytes.fromhex(f["header"])
    entropy = integer(f["signer_nym_entropy"])
    messages, committed = octets(f["messages"]), octets(f["committedMessages"])
    assert e1._core_blind_sign(sk, commitment, entropy, messages, header) == signature
    nym = (integer(f["proverNyms"][0]) + entropy) % bbs.ORDER
    assert nym == integer(f["nym_secrets"][0])
    gens = bbs.generators(len(messages) + 1, e1.API) + bbs.generators(
        len(committed) + 2, b"BLIND_" + e1.API
    )
    values = [
        *bbs.messages_to_scalars(messages, e1.API),
        integer(f["proverBlind"]),
        *bbs.messages_to_scalars(committed, e1.API),
        nym,
    ]
    assert bbs.core_verify(pk, signature, gens, values, header + bbs.i2osp(1, 8), e1.API)
    dom = bbs.domain(pk, gens, header + bbs.i2osp(1, 8), e1.API)
    point = bbs.linear(gens, [dom, *values], bbs.P1)
    # The printed blind -03 transcript DOES NOT produce the published e.
    printed_e = bbs.hash_to_scalar(
        bbs.i2osp(sk) + bbs.encode_point(point) + bbs.i2osp(dom), e1.API + b"H2S_"
    )
    assert printed_e != integer(f["signature"][96:])


@pytest.mark.parametrize("number", range(1, 8))
def test_independent_full_proof_generation(number):
    f = fixture("nymProof", number)
    published = nym_section(f"12.1.5.{number}.", f"12.1.5.{number + 1}." if number < 7 else "12.2.")
    assert bytes.fromhex(f["proof"]) == nym_field(published, "proof")
    messages, committed = octets(f["messages"]), octets(f["committedMessages"])
    regular = bbs.generators(len(messages) + 1, e1.API)
    blind = bbs.generators(len(committed) + 2, b"BLIND_" + e1.API)
    values = [
        *bbs.messages_to_scalars(messages, e1.API),
        integer(f["proverBlind"]),
        *bbs.messages_to_scalars(committed, e1.API),
        integer(f["nym_secrets"][0]),
    ]
    indexes = list(map(int, f["revealedMessages"])) + [
        len(messages) + 1 + int(i) for i in f["revealedCommittedMessages"]
    ]
    r = f["trace"]["random_scalars"]
    randomness = [integer(r[k]) for k in ["r1", "r2", "e_Tilde", "r1_Tilde", "r3_Tilde"]] + list(
        map(integer, r["m_tilde_scalars"])
    )
    proof, nym = bbs.core_proof_gen(
        bytes.fromhex(f["signerPublicKey"]),
        bytes.fromhex(f["signature"]),
        regular + blind,
        values,
        indexes,
        randomness,
        bytes.fromhex(f["header"]) + bbs.i2osp(1, 8),
        bytes.fromhex(f["presentationHeader"]),
        e1.API,
        bytes.fromhex(f["context_id"]),
    )
    assert proof == bytes.fromhex(f["proof"])
    assert nym == bytes.fromhex(f["pseudonym"])


@pytest.fixture(scope="module")
def card():
    sk, p, blind, entropy = 12345, 123, 7, 456
    pk, messages, header = (
        bbs.public_key(sk),
        [bbs.i2osp(42, 8), bbs.i2osp(1, 8)],
        b"synthetic-header",
    )
    commitment, returned_blind = e1.commit(p, [blind, 11, 13])
    assert returned_blind == blind
    sig = e1.blind_sign(sk, commitment, entropy, messages, header)
    nym = e1.finalize(pk, sig, p, entropy, blind, messages, header)
    return dict(
        sk=sk,
        pk=pk,
        signature=sig,
        messages=messages,
        blind=blind,
        nym=nym,
        header=header,
        commitment=commitment,
    )


@pytest.mark.parametrize("indexes", [[], [0], [0, 1]])
def test_e1_roundtrip_and_boundaries(card, indexes):
    count = len(card["messages"])

    def generate(scope):
        return e1.proof_gen(
            card["pk"],
            card["signature"],
            card["messages"],
            card["blind"],
            card["nym"],
            indexes,
            list(range(2, 2 + 5 + count + 2 - len(indexes))),
            header=card["header"],
            ph=b"presentation",
            scope=scope,
        )

    proof, nym = generate(b"scope-a")
    args = dict(
        pk=card["pk"],
        proof=proof,
        pseudonym=nym,
        signer_count=count,
        disclosed=[card["messages"][i] for i in indexes],
        indexes=indexes,
        header=card["header"],
        ph=b"presentation",
        scope=b"scope-a",
    )
    assert e1.proof_verify(**args)
    assert len(proof) == 272 + 32 * (count + 2 - len(indexes))
    _, different_nym = generate(b"scope-b")
    assert nym != different_nym
    for change in [
        dict(scope=b"scope-b"),
        dict(ph=b"changed"),
        dict(header=card["header"] + b"x"),
        dict(pk=bbs.public_key(23456)),
        dict(pseudonym=bytes(48)),
        dict(proof=proof[:-32]),
        dict(proof=proof + bbs.i2osp(1)),
        dict(signer_count=count + 1),
        dict(proof=proof[:144] + bbs.i2osp(bbs.ORDER) + proof[176:]),
    ]:
        assert not e1.proof_verify(**{**args, **change})


def test_e1_fail_closed(card):
    for invalid in [
        b"",
        card["commitment"][:-1],
        card["commitment"] + bbs.i2osp(1),
        bytes(48) + card["commitment"][48:],
        card["commitment"][:-1] + bytes([card["commitment"][-1] ^ 1]),
    ]:
        with pytest.raises(ValueError):
            e1.blind_sign(card["sk"], invalid, 456, card["messages"], card["header"])
    for p, t, s in [
        (124, 456, 7),
        (123, 457, 7),
        (123, 456, 8),
        (123, bbs.ORDER - 123, 7),
        (0, 456, 7),
        (123, bbs.ORDER, 7),
    ]:
        with pytest.raises(ValueError):
            e1.finalize(card["pk"], card["signature"], p, t, s, card["messages"], card["header"])
    for indexes in [[2], [3], [0, 0], [1, 0], [-1]]:
        with pytest.raises(ValueError):
            e1.proof_gen(
                card["pk"],
                card["signature"],
                card["messages"],
                card["blind"],
                card["nym"],
                indexes,
                list(range(2, 11)),
                scope=b"scope",
            )
    with pytest.raises(ValueError):
        e1.blind_sign(card["sk"], card["commitment"], 456, [b"bad"], card["header"])


def test_entropy_is_wide_and_deterministic():
    a = e1.signer_entropy(b"synthetic-host-secret", b"request", 42)
    assert 0 <= a < bbs.ORDER
    assert a == e1.signer_entropy(b"synthetic-host-secret", b"request", 42)
    assert a != e1.signer_entropy(b"synthetic-host-secret", b"request", 43)
    assert a != e1.signer_entropy(b"synthetic-host-secret", b"changed", 42)


def test_missing_scope_cannot_disable_nym_binding(card):
    with pytest.raises(ValueError):
        e1.proof_gen(
            card["pk"],
            card["signature"],
            card["messages"],
            card["blind"],
            card["nym"],
            [],
            list(range(2, 11)),
            scope=None,
        )
    assert not e1.proof_verify(card["pk"], bytes(400), bytes(48), 2, [], [], scope=None)


def test_experimental_proposal_vectors():
    from hum_reference.vectors import proposed_bbs_vectors

    files = proposed_bbs_vectors.generate()
    assert len(files) == 1
    assert len(files[0].cases) == 21
    for case in files[0].cases:
        x = case["inputs"]
        assert e1.proof_verify(
            bytes.fromhex(x["pk"]),
            bytes.fromhex(x["proof"]),
            bytes.fromhex(x["pseudonym"]),
            x["signer_count"],
            octets(x["disclosed"]),
            x["indexes"],
            header=bytes.fromhex(x["header"]),
            ph=bytes.fromhex(x["ph"]),
            scope=bytes.fromhex(x["scope"]),
        ) == ("expected" in case)


def test_verifier_rejects_framing_before_generator_work(monkeypatch):
    def forbidden(_):
        raise RuntimeError("malformed input reached generator derivation")

    monkeypatch.setattr(e1, "_generators", forbidden)
    for count, indexes in [
        (10**100, []),
        (2.0, []),
        (True, []),
        (2, [0.0]),
        (2, [True]),
        (2, ["0"]),
    ]:
        assert not e1.proof_verify(bytes(96), b"", bytes(48), count, [], indexes, scope=b"scope")


def test_zero_retained_blind_is_valid_draft_scalar():
    sk, p, entropy = 12345, 123, 456
    pk, messages = bbs.public_key(sk), [bbs.i2osp(42, 8)]
    commitment, blind = e1.commit(p, [0, 11, 13])
    assert blind == 0
    signature = e1.blind_sign(sk, commitment, entropy, messages)
    nym = e1.finalize(pk, signature, p, entropy, blind, messages)
    proof, pseudonym = e1.proof_gen(
        pk, signature, messages, blind, nym, [0], list(range(2, 9)), scope=b"scope"
    )
    assert e1.proof_verify(pk, proof, pseudonym, 1, messages, [0], scope=b"scope")
    for indexes in [[0.0], [True], ["0"]]:
        with pytest.raises(ValueError):
            e1.proof_gen(
                pk, signature, messages, blind, nym, indexes, list(range(2, 9)), scope=b"scope"
            )


@pytest.mark.parametrize("randomness", [[7, 0, 13], [7, 11, 0]])
def test_individual_zero_commitment_nonce_is_valid(randomness):
    encoded, blind = bbs_commit.commit_scalars([123], randomness)
    assert blind == randomness[0]
    assert bbs_commit.verify_commitment(encoded)


@pytest.mark.parametrize(
    "randomness",
    [[7, 0, 0], [0, 0, 13], [7, True, 13], [7, 0.0, 13], [7, -1, 13], [7, bbs.ORDER, 13]],
)
def test_degenerate_or_noncanonical_commitment_nonce_rejected(randomness):
    with pytest.raises(ValueError):
        bbs_commit.commit_scalars([123], randomness)


def test_zero_prover_share_with_nonzero_final_nym():
    sk, entropy = 12345, 456
    pk, messages = bbs.public_key(sk), [bbs.i2osp(42, 8)]
    commitment, blind = e1.commit(0, [7, 11, 13])
    signature = e1.blind_sign(sk, commitment, entropy, messages)
    nym = e1.finalize(pk, signature, 0, entropy, blind, messages)
    assert nym == entropy
    proof, pseudonym = e1.proof_gen(
        pk, signature, messages, blind, nym, [0], list(range(2, 9)), scope=b"scope"
    )
    assert e1.proof_verify(pk, proof, pseudonym, 1, messages, [0], scope=b"scope")
    with pytest.raises(ValueError):
        e1.commit(0, [0, 11, 13])  # identity commitment is still invalid
