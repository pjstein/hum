"""Vectors for docs/specs/chat.md that need no MLS state: content bodies (section 5), message ids
(5.1), padding (4.3) and authenticated data (4.2), the safety code (2.2).

Pending (need an MLS implementation driven from the reference, open for the owner):
chat/credential, chat/exporter, chat/frank, chat/stamp, chat/tokens, chat/join, chat/roles
commit matrix, chat/ignore, chat/promote flow, chat/directory replay, chat/agent-limits,
chat/history, chat/ds-api, chat/no-votes.
"""

from __future__ import annotations

from .. import cbor, chat, fixtures, storage
from ..cid import cid
from . import File, hexify, jsonable

SPEC = "chat"
PENDING = (
    "credential, exporter, frank, stamp, tokens, join, roles commit matrix, ignore, promote flow, "
    "directory replay, agent-limits, history, ds-api, no-votes: need an MLS implementation or "
    "ballot.md; which MLS stack is an open decision for the owner."
)


def _examples(fx: fixtures.Fixture) -> dict[str, tuple[dict, int]]:
    c1, c2 = cid(b"deck"), cid(b"context")
    msg = fixtures.fixed_bytes("message-id")
    key = fixtures.fixed_bytes("identity-key")
    ref, _ = storage.SealedReference.direct(
        b"file bytes", fixtures.fixed_bytes("file-key", 16), "image/png", "porch.png"
    )
    part = chat.external_part_from_reference(ref)
    return {
        "promote-proposal": (
            {
                0: 1,
                1: 1,
                2: cid(b"issue"),
                3: cid(b"issue"),
                4: "Organize a rent strike after 60 days.",
                5: msg,
            },
            0,
        ),
        "promote-confirm": ({0: 1, 1: msg, 2: 1, 3: cid(b"object")}, 0),
        "merge-proposal": ({0: 1, 1: cid(b"dup"), 2: cid(b"survivor"), 3: "Same idea."}, 0),
        "deck-dealt": (
            {
                0: 1,
                1: c1,
                2: c2,
                3: "Spring priorities",
                4: 18,
                5: [cid(b"p1")],
                6: fixtures.EXPIRES,
            },
            0,
        ),
        "release-digest": ({0: 1, 1: cid(b"release"), 2: c1, 3: "Results are in."}, 0),
        "file-op": (
            {0: 1, 1: 1, 2: fixtures.fixed_bytes("file-id", 16), 3: "porch.png", 4: ["photos"]},
            1,
        ),
        "folder-index": ({0: 1, 1: 12}, 1),
        "public-copy": ({0: cid(b"sealed"), 1: cid(b"public"), 2: "image/png"}, 0),
        "keyring-share": ({0: [[1, 4, bytes(range(16))], [2, 9, bytes(range(16, 32))]]}, 0),
        "token-key": ({0: 1, 1: cid(b"store"), 2: b"\x01\x02\x03\x04", 3: fixtures.ISSUED}, 0),
        "greeting-key": ({0: 1, 1: c2, 2: fixtures.fixed_bytes("greeting-private")}, 0),
        "agent-membership": ({0: 1, 1: 1, 2: cid(b"sponsor"), 3: 1, 4: 7, 5: key}, 0),
        "directory": (
            {
                0: 1,
                1: 3,
                2: 1,
                3: {
                    0: fixtures.fixed_bytes("group"),
                    1: "repairs",
                    2: 2,
                    5: True,
                    6: fixtures.ISSUED,
                },
            },
            0,
        ),
        "checkpoint": ({0: 1, 1: fx.world.log_authority, 2: 36, 3: fx.world.checkpoint().root}, 0),
        "history-offer": ({0: 1, 1: ref.encode(), 2: 1, 3: 400}, 0),
        "join-request": ({0: 1, 1: fixtures.fixed_bytes("group"), 2: [b"h1", b"h2"]}, 0),
    }, part


def content_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "content",
        "One valid body per Hum content type (section 5.2 to 5.16) and the generic rejections: unknown version, missing key, array over maximum, non-canonical, ExternalPart count, deck-dealt context lineage, release-digest deck mismatch. "
        + PENDING,
    )
    examples, part = _examples(fx)
    for name, (body, parts) in examples.items():
        data = chat.encode(name, body) if parts == 0 else cbor.encode(body)
        chat.decode(name, data, external_parts=parts)
        f.add(
            f"content-{name}",
            f"Valid {name}",
            "5.2",
            {"type": name, "view": jsonable(body), "external_parts": parts},
            {"content_type": chat.media_type(name), "bytes": hexify(data)},
        )
    body, _ = examples["promote-proposal"]
    bad = [
        ("content-reject-version", "promote-proposal", {**body, 0: 2}, 0, "unknown version"),
        (
            "content-reject-missing-key",
            "promote-proposal",
            {k: v for k, v in body.items() if k != 4},
            0,
            "missing required key",
        ),
        (
            "content-reject-array-max",
            "join-request",
            {0: 1, 1: fixtures.fixed_bytes("group"), 2: [b"h"] * 9},
            0,
            "array over maximum",
        ),
        (
            "content-reject-unknown-key",
            "checkpoint",
            {**examples["checkpoint"][0], 9: 1},
            0,
            "unknown key",
        ),
        (
            "content-reject-file-op-no-part",
            "file-op",
            examples["file-op"][0],
            0,
            "add without an ExternalPart",
        ),
        (
            "content-reject-file-op-extra-part",
            "file-op",
            {0: 1, 1: 2, 2: fixtures.fixed_bytes("file-id", 16), 3: "x"},
            1,
            "rename with an ExternalPart",
        ),
        (
            "content-reject-folder-index-no-part",
            "folder-index",
            examples["folder-index"][0],
            0,
            "folder-index without its ExternalPart",
        ),
    ]
    for cid_, name, b, parts, why in bad:
        data = cbor.encode(b)
        try:
            chat.decode(name, data, external_parts=parts)
            raise AssertionError(cid_)
        except chat.ChatError:
            pass
        f.add(
            cid_,
            f"Reject: {why}",
            "5.2",
            {"type": name, "bytes": hexify(data), "external_parts": parts},
            rejection={"step": None, "check": "decode-content", "reason": why},
        )
    canon = chat.encode("checkpoint", examples["checkpoint"][0])
    noncanon = canon[:1] + b"\x18\x00" + canon[2:]
    f.add(
        "content-reject-non-canonical",
        "Reject: bytes that do not re-encode to themselves",
        "5.2",
        {"type": "checkpoint", "bytes": hexify(noncanon)},
        rejection={"step": None, "check": "decode-content", "reason": "non-canonical"},
    )
    f.add(
        "content-reject-deck-dealt-foreign-context",
        "deck-dealt whose context is a version of another lineage than the group's",
        "5.6",
        {
            "type": "deck-dealt",
            "view": jsonable(examples["deck-dealt"][0]),
            "group_context_lineage": hexify(cid(b"other lineage")),
        },
        rejection={
            "step": None,
            "check": "deck-dealt-context",
            "reason": "context not in the group's lineage",
        },
    )
    f.add(
        "content-reject-release-digest-deck-mismatch",
        "release-digest whose deck is not the release's refs['deck']",
        "5.6",
        {
            "type": "release-digest",
            "view": jsonable(examples["release-digest"][0]),
            "release_refs_deck": hexify(cid(b"another deck")),
        },
        rejection={
            "step": None,
            "check": "release-digest-deck",
            "reason": "deck does not match the release",
        },
    )
    # roles
    roles = {
        0: 1,
        1: fx.context_v1.cid,
        2: 1,
        3: [[fixtures.fixed_bytes("member-1"), 1], [fixtures.fixed_bytes("member-2"), 2]],
        6: {fixtures.fixed_bytes("all-members"): b"\x02" * 49},
    }
    signed = chat.roles_sign(roles, [(b"a1", fx.keys["a1"]), (b"a2", fx.keys["a2"])])
    keys = {n.encode(): fx.keys[n].public for n in ("a1", "a2", "a3")}
    assert chat.roles_verify(signed, keys) == 2
    chat.decode("roles", cbor.encode(signed))
    f.add(
        "content-roles-signed",
        "A roles message signed by the context's a1+a2 under hum/chat-roles/1",
        "5.8",
        {"view": jsonable({k: v for k, v in signed.items() if k != 7}), "signers": ["a1", "a2"]},
        {
            "payload": hexify(chat.roles_payload(signed)),
            "bytes": hexify(cbor.encode(signed)),
            "valid_signatures": 2,
        },
    )
    forged = dict(signed)
    forged[2] = 2
    f.add(
        "content-roles-reject-bad-signature",
        "The same signature over serial 2",
        "5.8",
        {"bytes": hexify(cbor.encode(forged))},
        rejection={
            "step": None,
            "check": "roles-verify",
            "valid_signatures": chat.roles_verify(forged, keys),
        },
    )
    # external part
    f.add(
        "external-part",
        "A direct reference as a draft-ietf-mimi-content-09 ExternalPart: one flat fifteen-element nestedPart array, disposition render (1), cardinality external (2)",
        "5.1",
        {"reference": jsonable(chat.external_part_to_reference(part).to_item())},
        {"external_part": jsonable(part), "bytes": hexify(cbor.encode(part))},
    )
    return f


def derivations_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "derivations",
        "Message ids (5.1), padding buckets (4.3), authenticated data (4.2), safety code (2.2). "
        "Message-id lengths are big-endian uint16 (draft-ietf-mimi-content-09 message IDs, chat.md 5.1); the salt is in the input twice, once inside the serialized MimiContent and once appended.",
    )
    key = fixtures.fixed_bytes("identity-key")
    group = fixtures.fixed_bytes("group")
    salt = fixtures.fixed_bytes("mimi-salt", 16)
    message = cbor.encode(
        [salt, None, b"", None, None, {}, [1, "", 0, 0, "text/markdown;variant=GFM-MIMI", b"hello"]]
    )
    f.add(
        "message-id",
        "Message id for a text message",
        "5.1",
        {
            "identity_key": hexify(key),
            "group_id": hexify(group),
            "message": hexify(message),
            "salt": hexify(salt),
            "sender_uri": chat.sender_uri(key),
            "room_uri": chat.room_uri(group),
            "length_encoding": "big-endian uint16",
        },
        {"message_id": hexify(chat.message_id(key, group, message, salt))},
    )
    for size, commit in (
        (100, False),
        (512, False),
        (513, False),
        (65536, False),
        (65537, False),
        (65537, True),
        (1_048_576, True),
        (1_048_577, True),
    ):
        b = chat.mls_bucket(size, commit)
        if b is None:
            f.add(
                "padding-reject",
                f"{size} bytes exceeds every {'commit' if commit else 'application'} bucket",
                "4.3",
                {"size": size, "commit": commit},
                rejection={"step": None, "check": "mls-bucket", "reason": "not_padded"},
            )
        else:
            f.add(
                "padding",
                f"Bucket for {size} bytes ({'commit' if commit else 'application'})",
                "4.3",
                {"size": size, "commit": commit},
                {"bucket": b},
            )
    f.add(
        "padding-reject-not-bucket",
        "The DS rejects a 700-byte application message (not a bucket size)",
        "4.3",
        {"size": 700, "commit": False},
        rejection={"step": None, "check": "ds-bucket", "reason": "not_padded"},
    )
    tag = fixtures.fixed_bytes("frank-tag")
    f.add(
        "authenticated-data",
        "authenticated_data for an application message and for a commit",
        "4.2",
        {"franking_tag": hexify(tag)},
        {
            "application": hexify(chat.authenticated_data(tag)),
            "commit": hexify(chat.authenticated_data(None)),
        },
    )
    f.add(
        "authenticated-data-reject-length",
        "A 32-byte authenticated_data on an application message is dropped",
        "4.2",
        {"authenticated_data": hexify(tag)},
        rejection={"step": None, "check": "authenticated-data", "reason": "wrong length"},
    )
    code, groups = chat.safety_code(key)
    f.add(
        "safety-code",
        "Safety code: SHA-512(hum/safety/1 || identity key), 12 groups of 5 digits",
        "2.2",
        {"identity_key": hexify(key)},
        {"code": hexify(code), "groups": groups},
    )
    return f


def generate() -> list[File]:
    fx = fixtures.build()
    return [content_file(fx), derivations_file(fx)]
