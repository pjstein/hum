"""verifier-runtime.md artifacts that need no WebAssembly runtime: dataset records and
their salted Merkle tree (rule 15), the build recipe (rule 16), and the duplicate-masking
rule (rule 12) as a pure function. Module instantiation and ``decide`` runs are pending a
component-model runtime; see conformance.md. When they land, the normative limit is
``DECIDE_WALL_CLOCK_SECONDS`` of wall clock per ``decide`` call including host imports;
fuel metering is the host's choice and not part of conformance (the runaway-loop vector
must be stopped under any budget). Modules are built with ``rustc`` for ``wasm32-wasip2``,
which emits a component directly; ``cargo-component`` is not used.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .. import cbor, merkle
from .. import manifest as m
from . import verifier as vf

__all__ = [
    "DECIDE_WALL_CLOCK_SECONDS",
    "RESERVED_CODES",
    "build_recipe",
    "check_build_recipe",
    "dataset_blob",
    "dataset_root",
    "inclusion_proof",
    "mask_rejection",
    "record_bytes",
    "verify_inclusion",
]

DECIDE_WALL_CLOCK_SECONDS = 10  # verifier-runtime.md "Sandbox": the normative limit

RESERVED_CODES = {
    0: "no match",
    1: "duplicate",
    2: "missing evidence",
    3: "malformed evidence",
    4: "dataset proof failed",
    5: "outside scope",
}
BINDING_KINDS = {"document", "selfie", "credential", "device"}
BR_SOURCE, BR_REPOSITORY, BR_IMAGE, BR_COMMAND, BR_OUTPUT, BR_TOOLCHAIN, BR_LANG, BR_REJECTIONS = (
    range(8)
)


# ---------------------------------------------------------------- datasets


def record_bytes(key: bytes, fields: list[tuple[str, str]]) -> bytes:
    """A record is canonical CBOR ``[key, [[name, value], ...]]``."""
    return cbor.encode([key, [[n, v] for n, v in fields]])


def _sorted_records(records: list[tuple[bytes, list[tuple[str, str]]]]) -> list[bytes]:
    keys = [k for k, _ in records]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate record key")
    return [record_bytes(k, f) for k, f in sorted(records, key=lambda r: r[0])]


def dataset_root(salt: bytes, records: list[tuple[bytes, list[tuple[str, str]]]]) -> bytes:
    """RFC 9162 tree over salted leaves: leaf = SHA-256(0x00 ‖ salt ‖ record); empty = SHA-256()."""
    recs = _sorted_records(records)
    if not recs:
        return hashlib.sha256(b"").digest()
    return merkle.root_hash([salt + r for r in recs])


def inclusion_proof(salt: bytes, records, index: int) -> list[bytes]:
    recs = _sorted_records(records)
    return merkle.inclusion_proof([salt + r for r in recs], index)


def verify_inclusion(
    salt: bytes, key: bytes, fields, index: int, size: int, proof: list[bytes], root: bytes
) -> bool:
    """What the module does with a ``dataset.lookup`` answer: rebuild the record from the key
    it asked for and the returned fields, hash the salted leaf, and verify the path."""
    leaf = merkle.leaf_hash(salt + record_bytes(key, fields))
    return merkle.verify_inclusion(leaf, index, size, proof, root)


def dataset_blob(salt: bytes, records) -> bytes:
    """A public dataset blob: canonical CBOR ``[salt, record, record, ...]``."""
    recs = _sorted_records(records)
    return cbor.encode([salt] + [cbor.decode(r) for r in recs])


def dataset_blob_root(blob: bytes) -> bytes:
    """Rule 15: recompute the root from a public dataset blob."""
    items = cbor.decode(blob)
    salt = items[0]
    recs = [cbor.encode(r) for r in items[1:]]
    if not recs:
        return hashlib.sha256(b"").digest()
    return merkle.root_hash([salt + r for r in recs])


# ---------------------------------------------------------------- build recipe


def build_recipe(
    source: bytes,
    repository: str,
    image: str,
    command: list[str],
    output: str,
    toolchain: str,
    lang: str,
    rejections: list[tuple[int, str]] | None = None,
) -> bytes:
    return cbor.encode(
        {
            BR_SOURCE: source,
            BR_REPOSITORY: repository,
            BR_IMAGE: image,
            BR_COMMAND: command,
            BR_OUTPUT: output,
            BR_TOOLCHAIN: toolchain,
            BR_LANG: lang,
            BR_REJECTIONS: [{0: c, 1: t} for c, t in (rejections or [])],
        }
    )


def check_build_recipe(recipe: bytes, verifier_env: dict[int, Any]) -> list[str]:
    """Rule 16: ``source``, ``toolchain`` and ``lang`` equal the manifest's. Returns problems."""
    r = cbor.decode(recipe)
    b = verifier_env[m.BODY]
    problems = []
    if r.get(BR_SOURCE) != b[vf.CODE][vf.CD_SOURCE]:
        problems.append("source differs from code.source")
    if r.get(BR_TOOLCHAIN) != b[vf.CODE][vf.CD_TOOLCHAIN]:
        problems.append("toolchain differs from code.toolchain")
    if r.get(BR_LANG) != b[vf.LANG]:
        problems.append("lang differs from the manifest's lang")
    for rej in r.get(BR_REJECTIONS, []):
        if not 100 <= rej[0] <= 999:
            problems.append(f"module rejection code {rej[0]} outside 100..999")
    return problems


# ---------------------------------------------------------------- rule 12


def mask_rejection(code: int, required_kinds: list[str]) -> int:
    """The code the phone sees: a duplicate (1) becomes 0 unless every required evidence item
    binds the submitter (document, selfie, credential, device)."""
    if code == 1 and not all(k in BINDING_KINDS for k in required_kinds):
        return 0
    return code
