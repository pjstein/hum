"""Executable proposal E1, NOT an adopted Hum credential implementation.

ADR 0113's hum-bbs-nym-03-errata-1: N=1, no extra committed messages.
Kept outside credentials/P4 and normative conformance until owner acceptance.
All caller-supplied randomness here is explicit for reference/fixture use; callers
must not reuse these synthetic test secrets in deployed credentials.
"""

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from py_ecc.optimized_bls12_381 import is_inf, multiply

from . import bbs, bbs_commit

PROFILE = "hum-bbs-nym-03-errata-1"
API = bbs.NYM_API


def _scalar(value, *, zero=False):
    if type(value) is not int or not (0 if zero else 1) <= value < bbs.ORDER:
        raise ValueError("noncanonical scalar")
    return value


def _messages(messages):
    if not messages or any(type(m) is not bytes or len(m) != 8 for m in messages):
        raise ValueError("E1 needs epoch and eight-byte issuer messages")


def _generators(signer_count):
    if type(signer_count) is not int or signer_count < 1:
        raise ValueError("E1 issuer message count")
    return bbs.generators(signer_count + 1, API) + bbs.generators(2, b"BLIND_" + API)


def _header(header):
    return header + bbs.i2osp(1, 8)


def signer_entropy(host_secret, request_plaintext, epoch):
    """Proposed explicit HKDF L=48 then wide scalar reduction; not adopted."""
    uniform = HKDF(
        algorithm=hashes.SHA256(),
        length=48,
        salt=b"hum/nym-share/1",
        info=hashlib.sha256(request_plaintext).digest() + bbs.i2osp(epoch, 8),
    ).derive(host_secret)
    return int.from_bytes(uniform, "big") % bbs.ORDER


def commit(prover_nym, randomness):
    """Return (144-byte commitment with proof, secret blind)."""
    return bbs_commit.commit_scalars([_scalar(prover_nym, zero=True)], randomness, API)


def _core_blind_sign(sk, commitment, entropy, messages, header):
    """N=1 draft core also used to reproduce upstream extra-message fixtures.

    Public E1 blind_sign restricts the commitment to exactly one hidden message.
    This low-level function infers the generator count from the checked proof.
    """
    _scalar(sk)
    _scalar(entropy, zero=True)
    if not bbs_commit.verify_commitment(commitment, API):
        raise ValueError("invalid commitment proof")
    count = (len(commitment) - 48) // 32 - 1
    if count < 2:
        raise ValueError("missing nym commitment")
    regular = bbs.generators(len(messages) + 1, API)
    blind = bbs.generators(count, b"BLIND_" + API)
    pk = bbs.public_key(sk)
    dom = bbs.domain(pk, regular + blind, _header(header), API)
    point = bbs.linear(
        [*regular, bbs.decode_point(commitment[:48]), blind[-1]],
        [dom, *bbs.messages_to_scalars(messages, API), 1, entropy],
        bbs.P1,
    )
    if is_inf(point):
        raise ValueError("identity signature input")
    # Explicit E1 erratum: B includes domain, no appended domain scalar.
    e = bbs.hash_to_scalar(bbs.i2osp(sk) + bbs.encode_point(point), API + b"H2S_")
    if e == 0 or (sk + e) % bbs.ORDER == 0:
        raise ValueError("invalid signature scalar")
    a = multiply(point, pow((sk + e) % bbs.ORDER, -1, bbs.ORDER))
    return bbs.encode_point(a) + bbs.i2osp(e)


def blind_sign(sk, commitment, entropy, messages, header=b""):
    _messages(messages)
    if len(commitment) != 144:
        raise ValueError("E1 requires exactly one nym commitment")
    return _core_blind_sign(sk, commitment, entropy, messages, header)


def finalize(pk, signature, prover_nym, entropy, blind, messages, header=b""):
    """Verify completed signature and return n; no signature byte unblinding."""
    _messages(messages)
    nym = (_scalar(prover_nym, zero=True) + _scalar(entropy, zero=True)) % bbs.ORDER
    _scalar(nym)
    values = [*bbs.messages_to_scalars(messages, API), _scalar(blind, zero=True), nym]
    if not bbs.core_verify(pk, signature, _generators(len(messages)), values, _header(header), API):
        raise ValueError("final signature does not verify")
    return nym


def proof_gen(
    pk, signature, messages, blind, nym, indexes, randomness, *, header=b"", ph=b"", scope
):
    _messages(messages)
    if type(scope) is not bytes:
        raise ValueError("scope must be bytes")
    if any(type(i) is not int for i in indexes):
        raise ValueError("disclosure indexes must be integers")
    bbs.validate_indexes(indexes, len(messages))  # neither blind nor nym may be disclosed
    values = [*bbs.messages_to_scalars(messages, API), _scalar(blind, zero=True), _scalar(nym)]
    return bbs.core_proof_gen(
        pk,
        signature,
        _generators(len(messages)),
        values,
        indexes,
        randomness,
        _header(header),
        ph,
        API,
        scope,
    )


def proof_verify(
    pk, proof, pseudonym, signer_count, disclosed, indexes, *, header=b"", ph=b"", scope
):
    try:
        if type(scope) is not bytes or type(pseudonym) is not bytes or len(pseudonym) != 48:
            return False
        if type(signer_count) is not int or signer_count < 1:
            return False
        if type(proof) is not bytes or any(type(i) is not int for i in indexes):
            return False
        bbs.validate_indexes(indexes, signer_count)
        if any(type(m) is not bytes or len(m) != 8 for m in disclosed):
            return False
        if len(disclosed) != len(indexes):
            return False
        if len(proof) != 272 + 32 * (signer_count + 2 - len(indexes)):
            return False
        return bbs.core_proof_verify(
            pk,
            proof,
            _generators(signer_count),
            bbs.messages_to_scalars(disclosed, API),
            indexes,
            _header(header),
            ph,
            API,
            scope,
            pseudonym,
        )
    except (ValueError, AssertionError, OverflowError):
        return False
