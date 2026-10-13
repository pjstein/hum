"""Unambiguous commitment equations shared by blind -03 and nym -03.

No BlindSignWithNym wrapper is exposed: the pinned drafts leave domain inputs and
interface adapters undefined. See the accompanying pinned-draft findings.
"""

from py_ecc.optimized_bls12_381 import is_inf

from . import bbs


def commitment_challenge(point, temporary, gens, api):
    data = bbs.i2osp(len(gens) - 1, 8)
    data += b"".join(map(bbs.encode_point, [*gens, point, temporary]))
    return bbs.hash_to_scalar(data, api + b"H2S_")


def commit_scalars(values, randomness, api=bbs.NYM_API):
    """CoreCommit §4.3.1; randomness = blind, s_tilde, message tildes."""
    if len(randomness) != len(values) + 2:
        raise ValueError("commitment randomness count")
    # Base -12 section 4.2.1 reduces every random draw modulo r; zero is
    # allowed. Identity C/T are rejected below, not every individual zero.
    if any(type(r) is not int or not 0 <= r < bbs.ORDER for r in randomness):
        raise ValueError("commitment randomness range")
    if any(type(value) is not int or not 0 <= value < bbs.ORDER for value in values):
        raise ValueError("message scalar range")
    blind, *tildes = randomness
    gens = bbs.generators(len(values) + 1, b"BLIND_" + api)
    point = bbs.linear(gens, [blind, *values])
    temporary = bbs.linear(gens, tildes)
    if is_inf(point) or is_inf(temporary):
        raise ValueError("identity commitment")
    c = commitment_challenge(point, temporary, gens, api)
    responses = [(r + c * m) % bbs.ORDER for r, m in zip(tildes, [blind, *values], strict=True)]
    # Blind -03 section 5.4.2 rejects zero serialized proof scalars.
    if c == 0 or any(value == 0 for value in responses):
        raise ValueError("zero serialized commitment proof scalar")
    return bbs.encode_point(point) + b"".join(map(bbs.i2osp, [*responses, c])), blind


def verify_commitment(encoded, api=bbs.NYM_API):
    """Validate serialized commitment using §4.3.2 group equation.

    The generator count follows the tuple (Q2, J1, ..., JM), also used by
    §4.3.1. §4.3.2's contradictory length assertion is not adopted.
    """
    try:
        if len(encoded) < 112 or (len(encoded) - 48) % 32:
            return False
        point = bbs.decode_point(encoded[:48])
        values = [bbs.scalar(encoded[i : i + 32]) for i in range(48, len(encoded), 32)]
        responses, c = values[:-1], values[-1]
        gens = bbs.generators(len(responses), b"BLIND_" + api)
        temporary = bbs.linear([*gens, point], [*responses, -c])
        return c == commitment_challenge(point, temporary, gens, api)
    except (ValueError, AssertionError, OverflowError):
        return False
