"""Transparency log leaves, checkpoints and witness cosignatures.

Written from ``docs/specs/manifest.md`` ("Transparency logs") and
``docs/specs/services.md`` ("Log and ledger", "Witness"), which fix the bytes:

- **Leaf:** deterministic CBOR array ``[cid, type, authority, lineage or null, version]``;
  the Merkle leaf hash is RFC 6962: ``SHA-256(0x00 || leaf bytes)``.
- **Checkpoint:** a C2SP ``tlog-checkpoint`` note. The origin line is
  ``hum/log/<log authority CID, text form>``. The log signs with an Ed25519
  ``sign`` key in the note signature format; its key name equals the origin
  line and the 4-byte key ID is ``SHA-256(name || "\\n" || 0x01 || key)[:4]``.
- **Witness cosignature:** C2SP ``cosignature/v1``. The signed message is
  ``"cosignature/v1\\ntime <seconds>\\n" || checkpoint body``; the line payload is
  ``keyid(4) || timestamp(8, big-endian) || signature(64)`` with key ID
  ``SHA-256(name || "\\n" || 0x04 || key)[:4]``. Names are
  ``hum/witness/<witness authority CID, text form>``. A phone holds only keys:
  it takes the name from the line and recomputes the ID for each listed key.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field

from . import cbor, merkle
from .cid import cid_text
from .keys import SigningKey, verify

__all__ = [
    "Checkpoint",
    "Note",
    "NoteSignature",
    "cosign_checkpoint",
    "cosigners",
    "entry_bytes",
    "entry_leaf",
    "log_origin",
    "note_key_id",
    "parse_note",
    "sign_checkpoint",
    "verify_log_signature",
    "verify_witness_cosignature",
    "witness_key_id",
    "witness_name",
]

KEY_TYPE_ED25519 = 0x01
KEY_TYPE_COSIGNATURE_V1 = 0x04


def entry_bytes(
    cid: bytes, type_: str, authority: bytes, lineage: bytes | None, version: int
) -> bytes:
    """The leaf bytes: ``[cid, type, authority, lineage or null, version]``."""
    return cbor.encode([cid, type_, authority, lineage, version])


def entry_leaf(
    cid: bytes, type_: str, authority: bytes, lineage: bytes | None, version: int
) -> bytes:
    return merkle.leaf_hash(entry_bytes(cid, type_, authority, lineage, version))


def log_origin(log_authority: bytes) -> str:
    return "hum/log/" + cid_text(log_authority)


def witness_name(witness_authority: bytes) -> str:
    return "hum/witness/" + cid_text(witness_authority)


@dataclass(frozen=True)
class Checkpoint:
    origin: str
    size: int
    root: bytes

    def text(self) -> str:
        return f"{self.origin}\n{self.size}\n{base64.b64encode(self.root).decode()}\n"


@dataclass(frozen=True)
class NoteSignature:
    name: str
    payload: bytes  # key id || (timestamp ||) signature

    def line(self) -> str:
        return f"— {self.name} {base64.b64encode(self.payload).decode()}\n"


@dataclass
class Note:
    checkpoint: Checkpoint
    signatures: list[NoteSignature] = field(default_factory=list)

    def text(self) -> str:
        return self.checkpoint.text() + "\n" + "".join(s.line() for s in self.signatures)


def note_key_id(name: str, public: bytes) -> bytes:
    return hashlib.sha256(name.encode() + b"\n" + bytes([KEY_TYPE_ED25519]) + public).digest()[:4]


def witness_key_id(name: str, public: bytes) -> bytes:
    return hashlib.sha256(
        name.encode() + b"\n" + bytes([KEY_TYPE_COSIGNATURE_V1]) + public
    ).digest()[:4]


def sign_checkpoint(cp: Checkpoint, key: SigningKey) -> NoteSignature:
    """The log's own signature; the key name is the origin line."""
    sig = key.sign(cp.text().encode())
    return NoteSignature(cp.origin, note_key_id(cp.origin, key.public) + sig)


def cosignature_message(cp: Checkpoint, timestamp: int) -> bytes:
    return f"cosignature/v1\ntime {timestamp}\n".encode() + cp.text().encode()


def cosign_checkpoint(cp: Checkpoint, name: str, key: SigningKey, timestamp: int) -> NoteSignature:
    sig = key.sign(cosignature_message(cp, timestamp))
    return NoteSignature(
        name, witness_key_id(name, key.public) + timestamp.to_bytes(8, "big") + sig
    )


def verify_log_signature(cp: Checkpoint, sig: NoteSignature, public: bytes) -> bool:
    if sig.name != cp.origin or len(sig.payload) != 4 + 64:
        return False
    if sig.payload[:4] != note_key_id(cp.origin, public):
        return False
    return verify(public, cp.text().encode(), sig.payload[4:])


def verify_witness_cosignature(cp: Checkpoint, sig: NoteSignature, public: bytes) -> int | None:
    """Return the cosignature timestamp when ``sig`` is a valid cosignature by ``public``."""
    if len(sig.payload) != 4 + 8 + 64:
        return None
    if sig.payload[:4] != witness_key_id(sig.name, public):
        return None
    timestamp = int.from_bytes(sig.payload[4:12], "big")
    return (
        timestamp if verify(public, cosignature_message(cp, timestamp), sig.payload[12:]) else None
    )


def cosigners(note: Note, witness_keys: list[bytes]) -> set[bytes]:
    """The listed witness keys that validly cosigned the note's checkpoint."""
    found: set[bytes] = set()
    for sig in note.signatures:
        for key in witness_keys:
            if (
                key not in found
                and verify_witness_cosignature(note.checkpoint, sig, key) is not None
            ):
                found.add(key)
    return found


def parse_note(text: str) -> Note:
    """Parse a signed note. Raises ``ValueError`` when the text is not a checkpoint note."""
    if "\n\n" not in text:
        raise ValueError("note has no signature section")
    body, sigs = text.split("\n\n", 1)
    lines = body.split("\n")
    if len(lines) != 3:
        raise ValueError("checkpoint body must have exactly three lines")
    origin, size_s, root_b64 = lines
    if not size_s.isdigit():
        raise ValueError("tree size must be decimal digits")
    root = base64.b64decode(root_b64, validate=True)
    if len(root) != 32:
        raise ValueError("root must be 32 bytes")
    out = Note(Checkpoint(origin, int(size_s), root))
    for line in sigs.split("\n"):
        if not line:
            continue
        if not line.startswith("— "):
            raise ValueError("signature line must start with an em dash")
        _, name, payload = line.split(" ", 2)
        out.signatures.append(NoteSignature(name, base64.b64decode(payload, validate=True)))
    return out
