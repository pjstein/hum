"""Vectors for the log: RFC 9162 trees and proofs, leaves, checkpoints, witness cosignatures,
and the bundle wire format. Sources: docs/specs/manifest.md ("Transparency logs") and
docs/specs/services.md ("The bundle", "Log and ledger", "Witness").
"""

from __future__ import annotations

from .. import cbor, fixtures, log, merkle
from .. import manifest as m
from ..keys import key_from_label
from . import File, hexify, jsonable

SPEC = "log"
S_LOG = "Log and ledger"
S_WIT = "Witness"
S_BUNDLE = "The bundle"

# The RFC 6962 / certificate-transparency-go test leaves; the size-8 root is a known answer.
RFC_LEAVES = [
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


def merkle_file() -> File:
    f = File(
        SPEC,
        "merkle",
        "RFC 9162 section 2.1 hashing. Leaves are the Certificate Transparency test leaves; "
        "the size-8 root matches the known answer "
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328.",
    )
    for n in range(0, len(RFC_LEAVES) + 1):
        f.add(
            "root",
            f"Root hash of the first {n} leaves",
            "RFC 9162 2.1",
            {"leaves": [hexify(leaf) for leaf in RFC_LEAVES[:n]]},
            {"root": hexify(merkle.root_hash(RFC_LEAVES[:n]))},
        )
    for i, leaf in enumerate(RFC_LEAVES[:3]):
        f.add(
            "leaf-hash",
            f"Leaf hash of leaf {i}",
            "RFC 9162 2.1",
            {"leaf": hexify(leaf)},
            {"leaf_hash": hexify(merkle.leaf_hash(leaf))},
        )
    return f


def inclusion_file() -> File:
    f = File(
        SPEC, "inclusion", "Inclusion proofs (RFC 9162 section 2.1.3) over the CT test leaves."
    )
    for n in (1, 2, 3, 5, 8):
        leaves = RFC_LEAVES[:n]
        root = merkle.root_hash(leaves)
        for i in range(n):
            proof = merkle.inclusion_proof(leaves, i)
            f.add(
                "prove",
                f"Leaf {i} in a tree of size {n}",
                "RFC 9162 2.1.3",
                {
                    "leaf_hash": hexify(merkle.leaf_hash(leaves[i])),
                    "index": i,
                    "size": n,
                    "root": hexify(root),
                },
                {"proof": [hexify(h) for h in proof], "valid": True},
            )
    leaves = RFC_LEAVES
    root = merkle.root_hash(leaves)
    proof = merkle.inclusion_proof(leaves, 3)
    bad = [
        ("wrong-leaf", merkle.leaf_hash(leaves[4]), 3, 8, proof, root),
        ("wrong-index", merkle.leaf_hash(leaves[3]), 4, 8, proof, root),
        ("size-too-small-for-proof", merkle.leaf_hash(leaves[3]), 3, 4, proof, root),
        ("index-past-size", merkle.leaf_hash(leaves[3]), 8, 8, proof, root),
        ("short-proof", merkle.leaf_hash(leaves[3]), 3, 8, proof[:-1], root),
        ("long-proof", merkle.leaf_hash(leaves[3]), 3, 8, proof + [bytes(32)], root),
        ("wrong-root", merkle.leaf_hash(leaves[3]), 3, 8, proof, bytes(32)),
    ]
    for name, lh, i, n, p, r in bad:
        assert not merkle.verify_inclusion(lh, i, n, p, r)
        f.add(
            "reject",
            f"Inclusion does not verify: {name}",
            "RFC 9162 2.1.3",
            {
                "leaf_hash": hexify(lh),
                "index": i,
                "size": n,
                "proof": [hexify(h) for h in p],
                "root": hexify(r),
            },
            rejection={"step": 7, "reason": name},
        )
    return f


def consistency_file() -> File:
    f = File(
        SPEC, "consistency", "Consistency proofs (RFC 9162 section 2.1.4) over the CT test leaves."
    )
    for old, new in [
        (1, 2),
        (1, 8),
        (2, 3),
        (2, 5),
        (3, 7),
        (4, 7),
        (6, 8),
        (7, 8),
        (8, 8),
        (3, 3),
    ]:
        proof = merkle.consistency_proof(RFC_LEAVES[:new], old)
        f.add(
            "prove",
            f"Tree of size {old} extended to size {new}",
            "RFC 9162 2.1.4",
            {
                "old_size": old,
                "new_size": new,
                "old_root": hexify(merkle.root_hash(RFC_LEAVES[:old])),
                "new_root": hexify(merkle.root_hash(RFC_LEAVES[:new])),
            },
            {"proof": [hexify(h) for h in proof], "valid": True},
        )
    proof = merkle.consistency_proof(RFC_LEAVES[:7], 3)
    r3, r7 = merkle.root_hash(RFC_LEAVES[:3]), merkle.root_hash(RFC_LEAVES[:7])
    rewritten = RFC_LEAVES[:2] + [b"rewritten"] + RFC_LEAVES[3:7]
    bad = [
        ("wrong-old-root", 3, 7, bytes(32), r7, proof),
        ("wrong-new-root", 3, 7, r3, bytes(32), proof),
        ("old-larger-than-new", 7, 3, r7, r3, proof),
        ("empty-proof", 3, 7, r3, r7, []),
        (
            "history-rewritten",
            3,
            7,
            r3,
            merkle.root_hash(rewritten),
            merkle.consistency_proof(rewritten, 3),
        ),
        ("equal-sizes-different-roots", 7, 7, r7, bytes(32), []),
    ]
    for name, o, n, orr, nr, p in bad:
        assert not merkle.verify_consistency(o, n, orr, nr, p)
        f.add(
            "reject",
            f"Consistency does not verify: {name}",
            "RFC 9162 2.1.4",
            {
                "old_size": o,
                "new_size": n,
                "old_root": hexify(orr),
                "new_root": hexify(nr),
                "proof": [hexify(h) for h in p],
            },
            rejection={"step": 7, "reason": name},
        )
    return f


def leaves_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "leaves",
        "Leaf bytes [cid, type, authority, lineage or null, version] and RFC 6962 leaf hashes for "
        "the test world, plus the entry bundle (uint16 length-prefixed records) of three leaves.",
    )
    w = fx.world
    names = {b.cid: n for n, b in fx.named.items()}
    for b in list(w.bundles.values())[:9]:
        env = cbor.decode(b.envelope)
        leaf = w.leaves[b.proof.position]
        f.add(
            "leaf",
            f"Leaf for {names[b.cid]} at index {b.proof.position}",
            S_LOG,
            {
                "cid": hexify(b.cid),
                "type": env[m.TYPE],
                "authority": hexify(env.get(m.AUTHORITY, b.cid)),
                "lineage": None if m.LINEAGE not in env else hexify(env[m.LINEAGE]),
                "version": env[m.VERSION],
            },
            {
                "leaf": hexify(leaf),
                "leaf_hash": hexify(merkle.leaf_hash(leaf)),
                "view": jsonable(cbor.decode(leaf)),
            },
        )
    three = w.leaves[:3]
    bundle = b"".join(len(leaf).to_bytes(2, "big") + leaf for leaf in three)
    f.add(
        "entry-bundle",
        "Entry bundle of leaves 0..2: big-endian uint16 length prefix per leaf",
        S_LOG,
        {"leaves": [hexify(leaf) for leaf in three]},
        {"entry_bundle": hexify(bundle)},
    )
    return f


def checkpoint_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "checkpoint",
        "Signed checkpoints (C2SP tlog-checkpoint note) and witness cosignatures (cosignature/v1) "
        "for the test world. Names come from authority CIDs; a phone matches cosignatures by "
        "recomputing the key id from the line's name and each listed key.",
    )
    w = fx.world
    cp = w.checkpoint()
    f.add(
        "origin",
        "Origin line hum/log/<log authority CID text>",
        S_LOG,
        {"log_authority": hexify(w.log_authority)},
        {"origin": w.origin()},
    )
    w1 = next(iter(w.witnesses))
    f.add(
        "witness-name",
        "Witness name hum/witness/<witness authority CID text>",
        S_WIT,
        {"witness_authority": hexify(w1)},
        {"name": log.witness_name(w1)},
    )
    f.add(
        "key-id",
        "Note key id (0x01) for the log key and cosignature key id (0x04) for witness 1",
        S_WIT,
        {
            "log": {"name": w.origin(), "public": hexify(w.log_public)},
            "witness": {"name": log.witness_name(w1), "public": hexify(w.witnesses[w1].public)},
        },
        {
            "log_key_id": hexify(log.note_key_id(w.origin(), w.log_public)),
            "witness_key_id": hexify(
                log.witness_key_id(log.witness_name(w1), w.witnesses[w1].public)
            ),
        },
    )
    sig = log.sign_checkpoint(cp, w.log_key)
    f.add(
        "sign",
        "The log signs its checkpoint; the key name equals the origin line",
        S_LOG,
        {
            "origin": cp.origin,
            "size": cp.size,
            "root": hexify(cp.root),
            "seed": hexify(w.log_key.seed),
        },
        {"text": cp.text(), "signature_line": sig.line(), "payload": hexify(sig.payload)},
    )
    ts = 1_791_259_200
    cosig = log.cosign_checkpoint(cp, log.witness_name(w1), w.witnesses[w1], ts)
    f.add(
        "cosign",
        "Witness 1 cosigns the checkpoint at a fixed time",
        S_WIT,
        {
            "text": cp.text(),
            "name": log.witness_name(w1),
            "seed": hexify(w.witnesses[w1].seed),
            "timestamp": ts,
        },
        {
            "signed_message": hexify(log.cosignature_message(cp, ts)),
            "signature_line": cosig.line(),
            "payload": hexify(cosig.payload),
        },
    )
    note = w.note()
    f.add(
        "note",
        "The full signed note: log signature plus two witness cosignatures",
        S_LOG,
        {"text": cp.text()},
        {"note": note.text(), "cosignatures": 2},
    )
    keys = w.witness_keys()
    f.add(
        "verify",
        "Both listed witness keys cosigned (W-1)",
        S_WIT,
        {
            "note": note.text(),
            "log_public": hexify(w.log_public),
            "witness_keys": [hexify(k) for k in keys],
        },
        {"log_signature_valid": True, "cosigners": 2, "timestamps": [ts, ts]},
    )
    f.add(
        "reject",
        "Only one listed witness key: fewer than MIN_WITNESSES (W-2)",
        S_WIT,
        {
            "note": note.text(),
            "log_public": hexify(w.log_public),
            "witness_keys": [hexify(keys[0])],
        },
        rejection={"step": 7, "reason": "W-2", "cosigners": 1},
    )
    other = key_from_label("not-a-witness")
    f.add(
        "reject",
        "A cosignature from an unlisted witness does not count",
        S_WIT,
        {
            "note": note.text(),
            "log_public": hexify(w.log_public),
            "witness_keys": [hexify(other.public), hexify(keys[0])],
        },
        rejection={"step": 7, "reason": "W-2", "cosigners": 1},
    )
    tampered = log.Note(cp, list(note.signatures))
    first = tampered.signatures[1]
    payload = first.payload[:4] + (ts + 1).to_bytes(8, "big") + first.payload[12:]
    tampered.signatures[1] = log.NoteSignature(first.name, payload)
    assert len(log.cosigners(tampered, keys)) == 1
    f.add(
        "reject",
        "A cosignature whose timestamp was changed after signing does not verify",
        S_WIT,
        {
            "note": tampered.text(),
            "log_public": hexify(w.log_public),
            "witness_keys": [hexify(k) for k in keys],
        },
        rejection={"step": 7, "reason": "W-2", "cosigners": 1},
    )
    cp2 = log.Checkpoint(cp.origin, cp.size + 1, cp.root)
    f.add(
        "reject",
        "The log signature over a different tree size does not verify",
        S_LOG,
        {"note": log.Note(cp2, note.signatures).text(), "log_public": hexify(w.log_public)},
        rejection={"step": 7, "reason": "log-signature-invalid"},
    )
    return f


def bundle_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "bundle",
        "The bundle wire format {0: envelope, 1: signatures, 2: [proofs], 3: hints, 4: authorship?}. "
        "The signatures entry is one COSE_Sign holding every signer's COSE_Signature "
        "(manifest.md and services.md agree).",
    )
    b = fx.deck_v3
    wire = m.encode_bundle(b, ["https://resolver.example/"])
    f.add(
        "encode",
        "deck v3 as a bundle with one proof and one location hint",
        S_BUNDLE,
        {
            "envelope": hexify(b.envelope),
            "signatures": hexify(b.signatures),
            "proof": {
                "log": hexify(b.proof.log),
                "index": b.proof.position,
                "checkpoint": b.proof.checkpoint_note,
                "path": [hexify(h) for h in b.proof.inclusion],
            },
            "hints": ["https://resolver.example/"],
        },
        {"bundle": hexify(wire), "bytes": len(wire), "cid": hexify(b.cid)},
    )
    pending = m.Bundle(b.envelope, b.signatures, b.cid, None)
    f.add(
        "encode",
        "The same manifest while being submitted: empty proofs",
        S_BUNDLE,
        {"envelope": hexify(b.envelope), "signatures": hexify(b.signatures)},
        {"bundle": hexify(m.encode_bundle(pending))},
    )
    big = dict(cbor.decode(wire))
    big[3] = ["x" * 70_000]
    f.add(
        "reject",
        "A bundle over 96 KiB on the wire (B-1)",
        S_BUNDLE,
        {
            "bundle_sha256": __import__("hashlib").sha256(cbor.encode(big)).hexdigest(),
            "bytes": len(cbor.encode(big)),
        },
        rejection={"step": None, "check": "decode-bundle", "reason": "too-large"},
    )
    return f


def generate() -> list[File]:
    fx = fixtures.build()
    return [
        merkle_file(),
        inclusion_file(),
        consistency_file(),
        leaves_file(fx),
        checkpoint_file(fx),
        bundle_file(fx),
    ]
