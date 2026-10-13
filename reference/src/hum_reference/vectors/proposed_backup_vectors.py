"""Executable B1 proposal: never a claim that ADR 0113 was accepted."""

from .. import cbor, hpke, storage
from .. import proposed_backup as backup
from ..fixtures import fixed_bytes
from . import File, jsonable


def generate():
    f = File(
        "experimental",
        "proposed-backup",
        "EXPERIMENTAL B1/E1 ADR0113 proposal only. All phrases, private keys and plaintext are public synthetic fixture material. Empty-card full backups and chat exports exercise complete file framing; this does not verify a restored BBS card or migrate old opaque cards. No normative existing backup vectors are replaced. Size limits are local receiver policy, not universal protocol constants.",
    )
    phrase = backup.phrase_from_entropy(bytes(16))
    salt = fixed_bytes("proposed-backup-salt", 16)
    key = fixed_bytes("proposed-backup-content-key", 16)
    ephemeral = fixed_bytes("proposed-backup-ephemeral")
    private = fixed_bytes("proposed-chat-recipient")
    derived = hpke.backup_private_key(backup.canonical_phrase(phrase), salt)
    chat = {0: 1, 1: fixed_bytes("synthetic-chat-secret"), 2: fixed_bytes("synthetic-edit-root")}
    full = {
        **chat,
        3: [],
        4: [{0: b"\x01" + fixed_bytes("synthetic-left-context"), 1: 100}],
        5: 200,
    }
    limit = 1_000_000
    recovery = backup.pack_backup(
        full, phrase, salt=salt, content_key=key, ephemeral_private=ephemeral
    )
    export = backup.pack_chat_export(
        chat, hpke.public_key(private), content_key=key, ephemeral_private=ephemeral
    )
    for mode, encoded, plaintext, recipient in (
        (1, recovery, full, derived),
        (2, export, chat, private),
    ):
        restored = (
            backup.unpack_backup(encoded, phrase, max_envelope_bytes=limit)
            if mode == 1
            else backup.unpack_chat_export(encoded, private, max_envelope_bytes=limit)
        )
        assert restored == plaintext
        envelope = cbor.decode(encoded)
        f.add(
            "full" if mode == 1 else "chat-only",
            "Complete proposed file roundtrip",
            "ADR0113 B1",
            {
                "profile": backup.PROFILE,
                "mode": mode,
                "phrase": phrase if mode == 1 else None,
                "salt": salt.hex() if mode == 1 else None,
                "recipient_private": recipient.hex(),
                "content_key": key.hex(),
                "ephemeral_private": ephemeral.hex(),
                "plaintext": jsonable(plaintext),
                "max_envelope_bytes": limit,
            },
            expected={
                "canonical_phrase": backup.canonical_phrase(phrase).hex() if mode == 1 else None,
                "wrapped_key": envelope[3].hex(),
                "sealed_blob": envelope[4].hex(),
                "envelope": encoded.hex(),
                "restored": jsonable(restored),
            },
        )
    outer = cbor.decode(recovery)
    candidates = [
        ("version", {**outer, 0: 2}),
        ("mode", {**outer, 1: 3}),
        ("salt-length", {**outer, 2: bytes(15)}),
        ("wrap-length", {**outer, 3: bytes(63)}),
        ("unknown-field", {**outer, 9: b"not allowed"}),
        ("sealed-format", {**outer, 4: b"\x02" + outer[4][1:]}),
        ("tampered-blob", {**outer, 4: outer[4][:-1] + bytes([outer[4][-1] ^ 1])}),
        ("tampered-wrap", {**outer, 3: outer[3][:-1] + bytes([outer[3][-1] ^ 1])}),
    ]
    for name, candidate in candidates:
        encoded = cbor.encode(candidate)
        try:
            backup.unpack_backup(encoded, phrase, max_envelope_bytes=limit)
        except backup.BackupError:
            pass
        else:
            raise AssertionError(name)
        f.add(
            name,
            "Reject malformed or unauthenticated proposed file",
            "ADR0113 B1",
            {
                "profile": backup.PROFILE,
                "envelope": encoded.hex(),
                "phrase": phrase,
                "max_envelope_bytes": limit,
            },
            rejection={"step": None, "check": "proposed-backup", "reason": name},
        )
    # Authenticated full contents under a mode-2 envelope still cannot restore as chat-only.
    substituted = cbor.encode(
        {
            0: 1,
            1: 2,
            3: hpke.wrap_backup_key(hpke.public_key(private), key, ephemeral_private=ephemeral),
            4: storage.seal(cbor.encode(full), key),
        }
    )
    try:
        backup.unpack_chat_export(substituted, private, max_envelope_bytes=limit)
    except backup.BackupError:
        pass
    else:
        raise AssertionError("full-to-chat downgrade")
    f.add(
        "full-to-chat-downgrade",
        "Authenticated full backup is not a chat export",
        "ADR0113 B1",
        {
            "profile": backup.PROFILE,
            "envelope": substituted.hex(),
            "recipient_private": private.hex(),
            "max_envelope_bytes": limit,
        },
        rejection={"step": None, "check": "proposed-backup", "reason": "wrong inner schema"},
    )
    return [f]
