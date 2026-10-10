"""Independent BBS SHA-256 reference, draft-irtf-cfrg-bbs-signatures-12.

Protocol equations come from the pinned draft; all curve, pairing and hash-to-curve
operations come from py_ecc 8.0.0 (ADR 0110). This is a variable-time test oracle,
not a production secret-handling implementation. Randomness must be supplied explicitly.
Draft code-component license: tests/fixtures/bbs/LICENSE-CODE-COMPONENTS.txt.
The optional scope path is the N=1 low-level pseudonym equation, tested against
public -03 fixtures; callers supply the combined header. It is not a blind
issuance adapter or a claim of full pseudonym-interface implementation.
"""

from functools import lru_cache
from hashlib import sha256

from py_ecc.bls.hash import expand_message_xmd
from py_ecc.bls.hash_to_curve import hash_to_G1
from py_ecc.bls.point_compression import compress_G1, compress_G2, decompress_G1, decompress_G2
from py_ecc.optimized_bls12_381 import G2, Z1, add, curve_order, is_inf, multiply, pairing

ORDER = curve_order
SUITE = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"
API = SUITE + b"H2G_HM2S_"
NYM_API = API + b"PSEUDONYM_"
BLIND_API = SUITE + b"BLIND_H2G_HM2S_"


def i2osp(n, length=32):
    return n.to_bytes(length, "big")


def encode_point(point):
    return i2osp(int(compress_G1(point)), 48)


def decode_point(data):
    if len(data) != 48:
        raise ValueError("G1 length")
    point = decompress_G1(int.from_bytes(data, "big"))
    if is_inf(point) or not is_inf(multiply(point, ORDER)):
        raise ValueError("G1 identity or wrong subgroup")
    return point


def decode_public_key(data):
    if len(data) != 96:
        raise ValueError("G2 length")
    point = decompress_G2((int.from_bytes(data[:48], "big"), int.from_bytes(data[48:], "big")))
    if is_inf(point) or not is_inf(multiply(point, ORDER)):
        raise ValueError("G2 identity or wrong subgroup")
    return point


def scalar(data):
    value = int.from_bytes(data, "big")
    if len(data) != 32 or not 0 < value < ORDER:
        raise ValueError("noncanonical or zero scalar")
    return value


def hash_to_scalar(data, dst):
    return int.from_bytes(expand_message_xmd(data, dst, 48, sha256), "big") % ORDER


def public_key(sk):
    if not 0 < sk < ORDER:
        raise ValueError("secret key range")
    return b"".join(i2osp(int(x), 48) for x in compress_G2(multiply(G2, sk)))


def key_gen(material, info=b"", dst=SUITE + b"KEYGEN_DST_"):
    if len(material) < 32 or len(info) > 65535:
        raise ValueError("key material or info length")
    return hash_to_scalar(material + i2osp(len(info), 2) + info, dst)


@lru_cache(maxsize=128)
def generators(count, api=API):
    if not 0 <= count < 2**64:
        raise ValueError("generator count range")
    seed_dst = api + b"SIG_GENERATOR_SEED_"
    value = expand_message_xmd(api + b"MESSAGE_GENERATOR_SEED", seed_dst, 48, sha256)
    result = []
    for index in range(1, count + 1):
        value = expand_message_xmd(value + i2osp(index, 8), seed_dst, 48, sha256)
        result.append(hash_to_G1(value, api + b"SIG_GENERATOR_DST_", sha256))
    return tuple(result)


P1 = decode_point(
    bytes.fromhex(
        "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e"
        "7c59698588e70d11406d161b4e28c9"
    )
)


def messages_to_scalars(messages, api=API):
    return [hash_to_scalar(message, api + b"MAP_MSG_TO_SCALAR_AS_HASH_") for message in messages]


def domain(pk, gens, header=b"", api=API):
    data = pk + i2osp(len(gens) - 1, 8) + b"".join(map(encode_point, gens)) + api
    return hash_to_scalar(data + i2osp(len(header), 8) + header, api + b"H2S_")


def linear(points, scalars, initial=Z1):
    if len(points) != len(scalars):
        raise ValueError("point/scalar count")
    result = initial
    for point, value in zip(points, scalars, strict=True):
        result = add(result, multiply(point, value % ORDER))
    return result


def sign(sk, messages, header=b"", api=API):
    pk = public_key(sk)
    values = messages_to_scalars(messages, api)
    gens = generators(len(values) + 1, api)
    dom = domain(pk, gens, header, api)
    e = hash_to_scalar(b"".join(map(i2osp, [sk, *values, dom])), api + b"H2S_")
    b = linear(gens, [dom, *values], P1)
    a = multiply(b, pow((sk + e) % ORDER, -1, ORDER))
    if is_inf(a) or e == 0:
        raise ValueError("invalid signature")
    return encode_point(a) + i2osp(e)


def core_verify(pk, signature, gens, values, header=b"", api=API):
    try:
        if len(signature) != 80 or len(gens) != len(values) + 1:
            return False
        a, e = decode_point(signature[:48]), scalar(signature[48:])
        w = decode_public_key(pk)
        b = linear(gens, [domain(pk, gens, header, api), *values], P1)
        return pairing(add(w, multiply(G2, e)), a) == pairing(G2, b)
    except (ValueError, AssertionError, OverflowError):
        return False


def verify(pk, signature, messages, header=b"", api=API):
    return core_verify(
        pk,
        signature,
        generators(len(messages) + 1, api),
        messages_to_scalars(messages, api),
        header,
        api,
    )


def validate_indexes(indexes, total):
    if list(indexes) != sorted(set(indexes)) or any(i < 0 or i >= total for i in indexes):
        raise ValueError("disclosure indexes must be unique, sorted and in range")


def challenge(points, dom, disclosed, indexes, ph, api, nym=None):
    data = i2osp(len(indexes), 8)
    data += b"".join(i2osp(i, 8) + i2osp(m) for i, m in zip(indexes, disclosed, strict=True))
    data += b"".join(map(encode_point, points))
    if nym is not None:
        pseudonym, scope, commitment = nym
        data += encode_point(pseudonym) + encode_point(commitment)
    data += i2osp(dom) + i2osp(len(ph), 8) + ph
    if nym is not None:
        data += i2osp(len(scope), 8) + scope
    return hash_to_scalar(data, api + b"H2S_")


def core_proof_gen(
    pk, signature, gens, values, indexes, randomness, header=b"", ph=b"", api=API, scope=None
):
    validate_indexes(indexes, len(values))
    hidden = [i for i in range(len(values)) if i not in indexes]
    if len(randomness) != len(hidden) + 5 or any(not 0 < r < ORDER for r in randomness):
        raise ValueError("proof randomness count or range")
    if not core_verify(pk, signature, gens, values, header, api):
        raise ValueError("signature does not verify")
    if scope is not None and (not values or len(values) - 1 not in hidden):
        raise ValueError("nym secret must remain hidden")
    a, e = decode_point(signature[:48]), scalar(signature[48:])
    r1, r2, et, r1t, r3t, *mt = randomness
    dom = domain(pk, gens, header, api)
    b = linear(gens, [dom, *values], P1)
    d = multiply(b, r2)
    abar = multiply(a, r1 * r2 % ORDER)
    bbar = linear([d, abar], [r1, -e])
    t1 = linear([abar, d], [et, r1t])
    t2 = linear([d, *(gens[i + 1] for i in hidden)], [r3t, *mt])
    nym = None
    if scope is not None:
        op = hash_to_G1(scope, api, sha256)
        nym = (multiply(op, values[-1]), scope, multiply(op, mt[-1]))
        if is_inf(nym[0]) or is_inf(nym[2]):
            raise ValueError("identity pseudonym")
    c = challenge([abar, bbar, d, t1, t2], dom, [values[i] for i in indexes], indexes, ph, api, nym)
    responses = [et + e * c, r1t - r1 * c, r3t - pow(r2, -1, ORDER) * c]
    responses += [r + values[i] * c for i, r in zip(hidden, mt, strict=True)]
    proof = b"".join(map(encode_point, [abar, bbar, d]))
    proof += b"".join(i2osp(x % ORDER) for x in [*responses, c])
    return proof if nym is None else (proof, encode_point(nym[0]))


def core_proof_verify(
    pk, proof, gens, disclosed, indexes, header=b"", ph=b"", api=API, scope=None, pseudonym=None
):
    try:
        if len(proof) < 272 or (len(proof) - 272) % 32:
            return False
        abar, bbar, d = [decode_point(proof[i : i + 48]) for i in range(0, 144, 48)]
        eh, r1h, r3h, *tail = [scalar(proof[i : i + 32]) for i in range(144, len(proof), 32)]
        mh, c = tail[:-1], tail[-1]
        total = len(mh) + len(indexes)
        validate_indexes(indexes, total)
        if len(disclosed) != len(indexes) or len(gens) != total + 1:
            return False
        hidden = [i for i in range(total) if i not in indexes]
        dom = domain(pk, gens, header, api)
        t1 = linear([bbar, abar, d], [c, eh, r1h])
        bv = linear([gens[0], *(gens[i + 1] for i in indexes)], [dom, *disclosed], P1)
        t2 = linear([bv, d, *(gens[i + 1] for i in hidden)], [c, r3h, *mh])
        nym = None
        if scope is not None:
            if not hidden or hidden[-1] != total - 1 or pseudonym is None:
                return False
            point = decode_point(pseudonym)
            op = hash_to_G1(scope, api, sha256)
            ut = linear([op, point], [mh[-1], -c])
            if is_inf(ut):
                return False
            nym = (point, scope, ut)
        if c != challenge([abar, bbar, d, t1, t2], dom, disclosed, indexes, ph, api, nym):
            return False
        return pairing(decode_public_key(pk), abar) == pairing(G2, bbar)
    except (ValueError, AssertionError, OverflowError):
        return False


def proof_gen(pk, signature, messages, indexes, randomness, header=b"", ph=b""):
    return core_proof_gen(
        pk,
        signature,
        generators(len(messages) + 1),
        messages_to_scalars(messages),
        indexes,
        randomness,
        header,
        ph,
    )


def proof_verify(pk, proof, disclosed, indexes, header=b"", ph=b""):
    if len(proof) < 272 or (len(proof) - 272) % 32:
        return False
    total = (len(proof) - 272) // 32 + len(indexes)
    return core_proof_verify(
        pk, proof, generators(total + 1), messages_to_scalars(disclosed), indexes, header, ph
    )


def mock_random_scalars(count, api=API):
    """Draft §8.1 deterministic fixture randomness; never use with real secrets."""
    seed = b"3.141592653589793238462643383279"
    data = expand_message_xmd(seed, api + b"MOCK_RANDOM_SCALARS_DST_", 48 * count, sha256)
    return [int.from_bytes(data[i : i + 48], "big") % ORDER for i in range(0, len(data), 48)]
