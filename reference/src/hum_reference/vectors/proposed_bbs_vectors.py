"""Experimental E1 proposal vectors, excluded from normative obligations."""

from .. import bbs
from .. import proposed_bbs as e1
from . import File


def generate():
    output = File(
        "experimental",
        "proposed-bbs",
        "UNADOPTED ADR0113 E1. Synthetic review fixtures, not Hum P4 conformance. All secrets/randomness are public test inputs.",
    )
    sk, prover, entropy = 12345, 123, 456
    pk = bbs.public_key(sk)
    messages = [bbs.i2osp(42, 8), bbs.i2osp(1, 8)]
    header, ph, scope = b"synthetic-header", b"presentation", b"scope-a"
    commitment, blind = e1.commit(prover, [7, 11, 13])
    signature = e1.blind_sign(sk, commitment, entropy, messages, header)
    nym = e1.finalize(pk, signature, prover, entropy, blind, messages, header)
    for indexes in [[], [0], [0, 1]]:
        randomness = list(range(2, 2 + 5 + len(messages) + 2 - len(indexes)))
        proof, pseudonym = e1.proof_gen(
            pk,
            signature,
            messages,
            blind,
            nym,
            indexes,
            randomness,
            header=header,
            ph=ph,
            scope=scope,
        )
        args = dict(
            pk=pk,
            proof=proof,
            pseudonym=pseudonym,
            signer_count=len(messages),
            disclosed=[messages[i] for i in indexes],
            indexes=indexes,
            header=header,
            ph=ph,
            scope=scope,
        )
        assert e1.proof_verify(**args)
        inputs = {
            k: value.hex()
            if isinstance(value, bytes)
            else [m.hex() if isinstance(m, bytes) else m for m in value]
            if isinstance(value, list)
            else value
            for k, value in args.items()
        }
        output.add(
            "roundtrip",
            "E1 blind issuance, finalization, N1 proof",
            "Proposed ADR0113 E1",
            {
                **inputs,
                "secret_key": bbs.i2osp(sk).hex(),
                "prover_nym": bbs.i2osp(prover).hex(),
                "signer_entropy": bbs.i2osp(entropy).hex(),
                "messages": [m.hex() for m in messages],
                "commit_randomness": [bbs.i2osp(r).hex() for r in [7, 11, 13]],
                "proof_randomness": [bbs.i2osp(r).hex() for r in randomness],
            },
            {
                "commitment": commitment.hex(),
                "blind": bbs.i2osp(blind).hex(),
                "signature": signature.hex(),
                "nym_secret": bbs.i2osp(nym).hex(),
                "proof": proof.hex(),
                "pseudonym": pseudonym.hex(),
                "verified": True,
            },
        )
        for name, override in [
            ("scope", dict(scope=b"wrong")),
            ("ph", dict(ph=b"wrong")),
            ("header", dict(header=b"wrong")),
            ("truncated", dict(proof=proof[:-32])),
            ("wrong-issuer", dict(pk=bbs.public_key(54321))),
            ("wrong-layout", dict(signer_count=3)),
        ]:
            assert not e1.proof_verify(**{**args, **override})
            encoded = {
                key: value.hex() if isinstance(value, bytes) else value
                for key, value in override.items()
            }
            output.add(
                name,
                "E1 rejects altered " + name,
                "Proposed ADR0113 E1",
                {**inputs, **encoded},
                rejection={"step": "E1", "reason": "experimental cryptographic proof rejected"},
            )
    return [output]
