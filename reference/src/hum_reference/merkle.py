"""RFC 9162 Merkle trees: root hashes, inclusion proofs and consistency proofs.

Hashing (RFC 9162 section 2.1): a leaf is ``SHA-256(0x00 || data)``, an
interior node is ``SHA-256(0x01 || left || right)``, and the empty tree is
``SHA-256("")``. Proof generation and verification follow sections 2.1.3 and
2.1.4 exactly, including the ``fn``/``sn`` walk in the verifiers.
"""

from __future__ import annotations

import hashlib

__all__ = [
    "consistency_proof",
    "inclusion_proof",
    "leaf_hash",
    "node_hash",
    "root_hash",
    "verify_consistency",
    "verify_inclusion",
]


def _sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(data: bytes) -> bytes:
    return _sha(b"\x00" + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _sha(b"\x01" + left + right)


def _largest_power_of_two_below(n: int) -> int:
    """The largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root_hash(leaves: list[bytes]) -> bytes:
    """Merkle tree hash of a list of leaf *inputs* (not yet hashed)."""
    n = len(leaves)
    if n == 0:
        return _sha(b"")
    if n == 1:
        return leaf_hash(leaves[0])
    k = _largest_power_of_two_below(n)
    return node_hash(root_hash(leaves[:k]), root_hash(leaves[k:]))


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    """Audit path for ``leaves[index]`` (RFC 9162 section 2.1.3.1)."""
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError("leaf index out of range")
    if n == 1:
        return []
    k = _largest_power_of_two_below(n)
    if index < k:
        return inclusion_proof(leaves[:k], index) + [root_hash(leaves[k:])]
    return inclusion_proof(leaves[k:], index - k) + [root_hash(leaves[:k])]


def _subproof(m: int, leaves: list[bytes], b: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if b else [root_hash(leaves)]
    k = _largest_power_of_two_below(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [root_hash(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [root_hash(leaves[:k])]


def consistency_proof(leaves: list[bytes], old_size: int) -> list[bytes]:
    """Proof that the first ``old_size`` leaves are a prefix (RFC 9162 section 2.1.4.1)."""
    n = len(leaves)
    if not 0 < old_size <= n:
        raise IndexError("old size out of range")
    if old_size == n:
        return []
    return _subproof(old_size, leaves, True)


def verify_inclusion(leaf: bytes, index: int, size: int, proof: list[bytes], root: bytes) -> bool:
    """RFC 9162 section 2.1.3.2, with ``leaf`` the already-hashed leaf."""
    if index >= size:
        return False
    fn, sn = index, size - 1
    r = leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(
    old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list[bytes]
) -> bool:
    """RFC 9162 section 2.1.4.2."""
    if old_size > new_size:
        return False
    if old_size == new_size:
        return old_root == new_root and proof == []
    if old_size == 0:
        return proof == []
    if not proof:
        return False
    path = list(proof)
    if old_size & (old_size - 1) == 0:  # power of two: the old root is the first node
        path = [old_root] + path
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root
