"""BBS base SHA256 cryptographic vectors from the independent Python oracle.

These exercise actual signatures and selective-disclosure proofs. They do not
replace Hum credential P4: blind issuance adapters remain a pinned-draft question.
"""

from .. import bbs
from . import File


def generate() -> list[File]:
    file = File(
        "credentials",
        "bbs-base",
        "draft-irtf-cfrg-bbs-signatures-12 SHA256, py_ecc 8.0.0 independent oracle. "
        "Base signature/proof operations only; not Hum blind-issued resident cards. "
        "All keys and proof randomness are public deterministic test data. "
        "Pinned published fixtures are verified separately by tests/test_bbs.py.",
    )
    sk = bbs.key_gen(b"Hum independent BBS reference test key material")
    pk = bbs.public_key(sk)
    msgs = [b"synthetic epoch", b"synthetic attribute", b"synthetic hidden message"]
    header, ph = b"hum/bbs/base-test/1", b"hum/bbs/base-presentation-test/1"
    signature = bbs.sign(sk, msgs, header)
    file.add(
        "sign",
        "Deterministic base BBS signature",
        "BBS draft -12 §3.5.1",
        {
            "operation": "sign",
            "secret_key": bbs.i2osp(sk).hex(),
            "public_key": pk.hex(),
            "messages": [m.hex() for m in msgs],
            "header": header.hex(),
        },
        {"signature": signature.hex()},
    )
    for indexes in [[], [0], [0, 1, 2]]:
        randomness = bbs.mock_random_scalars(5 + len(msgs) - len(indexes))
        proof = bbs.proof_gen(pk, signature, msgs, indexes, randomness, header, ph)
        disclosed = [msgs[i] for i in indexes]
        assert bbs.proof_verify(pk, proof, disclosed, indexes, header, ph)
        inputs = {
            "operation": "proof",
            "public_key": pk.hex(),
            "signature": signature.hex(),
            "messages": [m.hex() for m in msgs],
            "header": header.hex(),
            "presentation_header": ph.hex(),
            "disclosed_indexes": indexes,
            "random_scalars": [bbs.i2osp(r).hex() for r in randomness],
        }
        file.add(
            "prove",
            f"Selective disclosure at indexes {indexes}",
            "BBS draft -12 §3.5.3",
            inputs,
            {"proof": proof.hex(), "verified": True},
        )
        verify_inputs = {
            "operation": "proof_verify",
            "public_key": pk.hex(),
            "proof": proof.hex(),
            "disclosed_messages": [m.hex() for m in disclosed],
            "disclosed_indexes": indexes,
            "header": header.hex(),
            "presentation_header": ph.hex(),
        }
        for label, override in [
            ("wrong-header", {"header": (header + b"x").hex()}),
            ("wrong-presentation-header", {"presentation_header": (ph + b"x").hex()}),
            ("truncated-proof", {"proof": proof[:-1].hex()}),
            ("invalid-public-key", {"public_key": bytes(96).hex()}),
        ]:
            file.add(
                label,
                label,
                "BBS draft -12 §3.5.4",
                {**verify_inputs, **override},
                rejection={"step": "BBS", "reason": "cryptographic proof rejected"},
            )
    return [file]
