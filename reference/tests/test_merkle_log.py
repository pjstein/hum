import hashlib

import pytest

from hum_reference import cbor, fixtures, log, merkle
from hum_reference import manifest as m
from hum_reference.cid import cid_text

CT_LEAVES = [
    bytes.fromhex(h)
    for h in [
        "",
        "00",
        "10",
        "2021",
        "3031",
        "40414243",
        "5051525354555657",
        "606162636465666768696a6b6c6d6e6f",
    ]
]


def test_known_roots_from_certificate_transparency():
    assert merkle.root_hash([]) == hashlib.sha256(b"").digest()
    assert merkle.root_hash(CT_LEAVES[:1]).hex() == (
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    )
    assert merkle.root_hash(CT_LEAVES[:3]).hex() == (
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77"
    )
    assert merkle.root_hash(CT_LEAVES).hex() == (
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"
    )


@pytest.mark.parametrize("n", range(1, 9))
def test_inclusion_and_consistency_all_sizes(n):
    leaves = CT_LEAVES[:n]
    root = merkle.root_hash(leaves)
    for i in range(n):
        proof = merkle.inclusion_proof(leaves, i)
        assert merkle.verify_inclusion(merkle.leaf_hash(leaves[i]), i, n, proof, root)
        assert not merkle.verify_inclusion(merkle.leaf_hash(leaves[i]), i, n, proof, bytes(32))
        if i + 1 < n:
            assert not merkle.verify_inclusion(merkle.leaf_hash(leaves[i + 1]), i, n, proof, root)
    for k in range(1, n + 1):
        proof = merkle.consistency_proof(leaves, k)
        assert merkle.verify_consistency(k, n, merkle.root_hash(leaves[:k]), root, proof)
        if k < n:
            assert not merkle.verify_consistency(k, n, bytes(32), root, proof)


def test_consistency_detects_rewritten_history():
    rewritten = CT_LEAVES[:2] + [b"x"] + CT_LEAVES[3:7]
    assert not merkle.verify_consistency(
        3,
        7,
        merkle.root_hash(CT_LEAVES[:3]),
        merkle.root_hash(rewritten),
        merkle.consistency_proof(rewritten, 3),
    )


def test_leaf_encoding_follows_services_md():
    fx = fixtures.build()
    b = fx.deck_v2
    env = cbor.decode(b.envelope)
    leaf = fx.world.leaves[b.proof.position]
    assert cbor.decode(leaf) == [b.cid, "deck", fx.authority_a, env[m.LINEAGE], 2]
    ks = cbor.decode(fx.world.leaves[1])
    assert ks == [fx.keyset_a1.cid, "keyset", fx.keyset_a1.cid, None, 1]


def test_names_come_from_authority_cids():
    fx = fixtures.build()
    w = fx.world
    assert w.origin() == "hum/log/" + cid_text(w.log_authority)
    for authority in w.witnesses:
        assert log.witness_name(authority) == "hum/witness/" + cid_text(authority)


def test_checkpoint_note_round_trip_and_signatures():
    fx = fixtures.build()
    w = fx.world
    note = w.note()
    parsed = log.parse_note(note.text())
    assert parsed.checkpoint == w.checkpoint()
    assert len(parsed.signatures) == 3
    assert parsed.signatures[0].name == w.origin()
    assert log.verify_log_signature(parsed.checkpoint, parsed.signatures[0], w.log_public)
    assert log.cosigners(parsed, w.witness_keys()) == set(w.witness_keys())
    assert len(log.cosigners(parsed, w.witness_keys()[:1])) == 1
    other = log.Checkpoint(
        parsed.checkpoint.origin, parsed.checkpoint.size + 1, parsed.checkpoint.root
    )
    assert not log.verify_log_signature(other, parsed.signatures[0], w.log_public)


def test_tampered_cosignature_timestamp_fails():
    fx = fixtures.build()
    w = fx.world
    note = w.note()
    sig = note.signatures[1]
    payload = sig.payload[:4] + (1_791_259_201).to_bytes(8, "big") + sig.payload[12:]
    note.signatures[1] = log.NoteSignature(sig.name, payload)
    assert len(log.cosigners(note, w.witness_keys())) == 1


def test_note_format_is_c2sp_shaped():
    fx = fixtures.build()
    text = fx.world.note().text()
    body, sigs = text.split("\n\n", 1)
    lines = body.split("\n")
    assert lines[0].startswith("hum/log/c")
    assert lines[1].isdigit()
    assert all(line.startswith("— ") for line in sigs.strip().split("\n"))
