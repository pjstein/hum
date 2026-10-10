"""Actual HPKE seals; fixed private keys are public test material only."""

from cryptography.exceptions import InvalidTag
from pyhpke.exceptions import PyHPKEError

from .. import cbor, credentials, hpke, storage
from ..fixtures import fixed_bytes
from . import File


def generate():
    f = File(
        "credentials",
        "hpke",
        "RFC 9180 base-mode seals via pyhpke 0.6.5. All private keys are synthetic published fixtures. The test suite separately checks both suites against the CFRG RFC 9180 known-answer corpus. Plaintexts here exercise encryption bindings, not BBS or ticket proof validity. Backup components are separate because the specs do not assign an outer backup-file framing.",
    )
    private = fixed_bytes("hpke-recipient")
    public = hpke.public_key(private)
    ephemeral = fixed_bytes("hpke-ephemeral")
    authority = b"\x01" + fixed_bytes("hpke-authority")
    session = fixed_bytes("hpke-session", 16)
    request = cbor.encode({0: 1, 1: authority, 2: b"issuer-kid", 3: [b"opaque commitment"], 4: [1]})
    response = cbor.encode({0: 1, 1: b"issuer-kid", 2: [b"opaque response"]})
    base = {
        "recipient_private": private.hex(),
        "recipient_public": public.hex(),
        "ephemeral_private": ephemeral.hex(),
    }

    def add(name, inputs, plaintext, sealed, info, aad=b"", extra=None):
        f.add(
            name,
            name.replace("-", " "),
            "HPKE",
            {**base, **inputs, "info": info.hex(), "aad": aad.hex(), "plaintext": plaintext.hex()},
            {"sealed": sealed.hex(), "opened": plaintext.hex(), **(extra or {})},
        )

    sealed, sender = hpke.seal_issue(public, authority, request, ephemeral_private=ephemeral)
    opened, recipient = hpke.open_issue(private, authority, sealed)
    assert opened == request
    encrypted_response = hpke.seal_response(recipient, session, response)
    assert hpke.open_response(sender, session, encrypted_response) == response
    key, nonce = hpke.response_material(sender)
    add(
        "issuance",
        {"authority": authority.hex(), "session": session.hex()},
        request,
        sealed,
        b"hum/issue/1" + authority,
        extra={
            "response_plaintext": response.hex(),
            "response_ciphertext": encrypted_response.hex(),
            "response_export_key": key.hex(),
            "response_export_nonce": nonce.hex(),
        },
    )
    info, aad = hpke.evidence_binding(authority, "address", session, request)
    evidence = b"synthetic evidence"
    sealed = hpke.seal_evidence(
        public, authority, "address", session, request, evidence, ephemeral_private=ephemeral
    )
    assert hpke.open_evidence(private, authority, "address", session, request, sealed) == evidence
    add(
        "evidence",
        {
            "authority": authority.hex(),
            "session": session.hex(),
            "item_name": "address",
            "request": request.hex(),
        },
        evidence,
        sealed,
        info,
        aad,
    )
    for suffix, changed_info, changed_aad, changed_key, changed_sealed in (
        ("request", info, session + fixed_bytes("wrong-request-hash"), private, sealed),
        ("session", info, fixed_bytes("wrong-session", 16) + aad[16:], private, sealed),
        ("item", info + b"wrong", aad, private, sealed),
        (
            "authority",
            b"hum/evidence/1" + b"\x01" + fixed_bytes("other-authority") + b"address",
            aad,
            private,
            sealed,
        ),
        ("recipient", info, aad, ephemeral, sealed),
        ("tag", info, aad, private, sealed[:-1] + bytes([sealed[-1] ^ 1])),
    ):
        try:
            hpke.open_seal(
                changed_key, changed_info, changed_sealed, aad=changed_aad, aead=hpke.CHACHA
            )
        except PyHPKEError:
            pass
        else:
            raise AssertionError("tampered evidence accepted")
        f.add(
            "evidence-wrong-" + suffix,
            "evidence rejects altered " + suffix,
            "Host key",
            {
                "recipient_private": changed_key.hex(),
                "info": changed_info.hex(),
                "aad": changed_aad.hex(),
                "sealed": changed_sealed.hex(),
            },
            rejection={
                "step": None,
                "check": "evidence-open",
                "rule": "V-4",
                "reason": "HPKE authentication failed",
            },
        )
    reference, blob = storage.SealedReference.direct(
        b"synthetic table", fixed_bytes("hpke-table-key", 16), "application/vnd.apache.parquet"
    )
    keybox_plain = cbor.encode([reference.to_item()])
    keybox = hpke.seal_keybox(public, authority, keybox_plain, ephemeral_private=ephemeral)
    assert hpke.open_keybox(private, authority, keybox) == keybox_plain
    add(
        "results-keybox",
        {"deck": authority.hex(), "table_blob": blob.hex()},
        keybox_plain,
        keybox,
        b"hum/results-keybox/1" + authority,
        authority,
    )
    # Fixed-size CBOR placeholder payload exercises sealing without claiming a valid membership proof.
    ticket_plain = cbor.encode({0: 1, 1: authority, 2: [], 3: b"opaque proof", 4: bytes(4036)})
    for size in range(4000, 4096):
        ticket_plain = cbor.encode({0: 1, 1: authority, 2: [], 3: b"opaque proof", 4: bytes(size)})
        if len(ticket_plain) == 4096:
            break
    ticket = hpke.seal_ticket(public, authority, ticket_plain, ephemeral_private=ephemeral)
    assert hpke.open_ticket(private, authority, ticket) == ticket_plain
    add(
        "join-ticket-seal",
        {"lineage": authority.hex()},
        ticket_plain,
        ticket,
        b"hum/join-ticket/1" + authority,
    )
    phrase = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    salt = fixed_bytes("hpke-backup-salt", 16)
    backup_private = hpke.backup_private_key(phrase, salt)
    blob_key = fixed_bytes("hpke-backup-blob-key", 16)
    for name, recipient_private in (("backup", backup_private), ("chat-only-export", private)):
        chat_key, edit_root = fixed_bytes("synthetic-chat-key"), fixed_bytes("synthetic-edit-root")
        plaintext = (
            credentials.write_backup(
                chat_key, edit_root, [], [{"lineage": authority, "left": 1}], 2
            )
            if name == "backup"
            else credentials.write_chat_export(chat_key, edit_root)
        )
        blob = storage.seal(plaintext, blob_key)
        wrap = hpke.wrap_backup_key(
            hpke.public_key(recipient_private), blob_key, ephemeral_private=ephemeral
        )
        assert (
            storage.open_sealed(blob, key=hpke.unwrap_backup_key(recipient_private, wrap))
            == plaintext
        )
        add(
            name,
            {
                "recipient_private": recipient_private.hex(),
                "recipient_public": hpke.public_key(recipient_private).hex(),
                "phrase_ascii": phrase.decode() if name == "backup" else None,
                "salt": salt.hex() if name == "backup" else None,
                "sealed_blob": blob.hex(),
                "backup_plaintext": plaintext.hex(),
            },
            blob_key,
            wrap,
            b"hum/backup/1",
        )

    def rejected(name, inputs, operation):
        try:
            operation()
        except (PyHPKEError, InvalidTag, ValueError):
            pass
        else:
            raise AssertionError(name + " unexpectedly opened")
        f.add(
            name,
            name.replace("-", " "),
            "HPKE",
            inputs,
            rejection={
                "step": None,
                "check": "hpke-open",
                "reason": "invalid framing or authentication",
            },
        )

    other = b"\x01" + fixed_bytes("hpke-other-context")
    rejected(
        "keybox-wrong-deck",
        {"recipient_private": private.hex(), "deck": other.hex(), "sealed": keybox.hex()},
        lambda: hpke.open_keybox(private, other, keybox),
    )
    rejected(
        "keybox-version",
        {
            "recipient_private": private.hex(),
            "deck": authority.hex(),
            "sealed": (b"\x02" + keybox[1:]).hex(),
        },
        lambda: hpke.open_keybox(private, authority, b"\x02" + keybox[1:]),
    )
    rejected(
        "ticket-wrong-context",
        {"recipient_private": private.hex(), "lineage": other.hex(), "sealed": ticket.hex()},
        lambda: hpke.open_ticket(private, other, ticket),
    )
    rejected(
        "ticket-truncated",
        {
            "recipient_private": private.hex(),
            "lineage": authority.hex(),
            "sealed": ticket[:-1].hex(),
        },
        lambda: hpke.open_ticket(private, authority, ticket[:-1]),
    )
    wrong_session = fixed_bytes("hpke-wrong-session", 16)
    rejected(
        "response-wrong-session",
        {
            "export_key": key.hex(),
            "export_nonce": nonce.hex(),
            "session": wrong_session.hex(),
            "ciphertext": encrypted_response.hex(),
        },
        lambda: hpke.open_response(sender, wrong_session, encrypted_response),
    )
    backup_wrap = hpke.wrap_backup_key(
        hpke.public_key(backup_private), blob_key, ephemeral_private=ephemeral
    )
    wrong_phrase = b"legal winner thank year wave sausage worth useful legal winner thank yellow"
    wrong_private = hpke.backup_private_key(wrong_phrase, salt)
    rejected(
        "backup-wrong-phrase",
        {
            "phrase_ascii": wrong_phrase.decode(),
            "salt": salt.hex(),
            "wrapped_key": backup_wrap.hex(),
        },
        lambda: hpke.unwrap_backup_key(wrong_private, backup_wrap),
    )
    corrupted = backup_wrap[:-1] + bytes([backup_wrap[-1] ^ 1])
    rejected(
        "backup-tampered-wrap",
        {"recipient_private": backup_private.hex(), "wrapped_key": corrupted.hex()},
        lambda: hpke.unwrap_backup_key(backup_private, corrupted),
    )
    return [f]
