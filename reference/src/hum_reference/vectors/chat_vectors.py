"""Vectors for docs/specs/chat.md that need no MLS state: content bodies (section 5), message ids
(5.1), padding (4.3) and authenticated data (4.2), the safety code (2.2), the greeter's
join-record state machine (2.5 step 4, 5.17) and the delivery service manifest rules DL-1 to
DL-5 (12.1).

Pending (need an MLS implementation driven from the reference, open for the owner):
chat/credential, chat/exporter, chat/frank, chat/stamp, chat/tokens, chat/join (the ticket's HPKE
sealing and proof; the nullifier checks are in chat/join-records), chat/roles commit matrix,
chat/ignore, chat/promote flow, chat/directory replay, chat/agent-limits, chat/history,
chat/ds-api, chat/no-votes.
"""

from __future__ import annotations

import copy

from .. import cbor, chat, fixtures, storage
from .. import manifest as m
from ..bodies import service as sv
from ..cid import cid
from ..keys import key_from_label
from . import File, hexify, jsonable
from .manifest_vectors import bundle_json

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
        "join-record": (
            {
                0: 1,
                1: sorted(
                    [fixtures.fixed_bytes("join-nul-a", 32), fixtures.fixed_bytes("join-nul-b", 32)]
                ),
                2: key,
                3: c2,
                5: 20733,
            },
            0,
        ),
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


def _nul(label: str) -> bytes:
    return fixtures.fixed_bytes(f"join-nul-{label}", 32)


def _rec_json(r: chat.JoinRecord) -> dict:
    return {
        "nullifiers": [hexify(n) for n in r.nullifiers],
        "identity": hexify(r.identity),
        "day": r.day,
        "seq": r.seq,
        "received": r.received,
    }


def join_records_file() -> File:
    f = File(
        SPEC,
        "join-records",
        "The greeter's join-record state machine (2.5 step 4, 5.17, ADR 0104, TS9, RT4, RU1, "
        "RU2): record and snapshot bodies, the ticket decision against the live records, the "
        "record-before-commit sequence with its pre-commit check (JOIN_PENDING = 3,600 s), the "
        "two-greeter race, the no-record backstop (JOIN_GRACE = 600 s) and pruning. Times are "
        "delivery-service receive times in seconds; `seq` is the delivery-service sequence "
        "number. The ticket's HPKE sealing and its membership proof stay in the pending "
        "chat/join set; here the nullifiers a proof yields are inputs.",
    )
    ctx = cid(b"context")
    ida, idb, idc, idd = (fixtures.fixed_bytes(f"identity-{x}", 32) for x in "abcd")
    n1, n2, n3, n4 = sorted(_nul(x) for x in "1234")
    t0 = 1_800_000_000
    rec_a = chat.JoinRecord((n1, n2), ida, 20700, 41, t0)
    rec_b = chat.JoinRecord((n3,), idb, 20710, 57, t0 + 864_000)
    body = rec_a.body(ctx)
    data = chat.encode("join-record", body)
    f.add(
        "join-record-valid",
        "A record: two nullifiers sorted bytewise (a two-card entry policy), identity, context, day",
        "5.17",
        {"view": jsonable(body)},
        {"content_type": chat.media_type("join-record"), "bytes": hexify(data)},
    )
    snap = chat.join_snapshot_body([rec_a, rec_b])
    data = chat.encode("join-record", snap)
    f.add(
        "join-record-snapshot-valid",
        "The snapshot a newcomer to the organizers group receives: rows [nullifiers, identity, day]",
        "5.17",
        {"view": jsonable(snap)},
        {"content_type": chat.media_type("join-record"), "bytes": hexify(data)},
    )
    for suffix, bad, why in (
        ("join-record-reject-unsorted", {**body, 1: [n2, n1]}, "nullifiers not sorted bytewise"),
        ("join-record-reject-duplicate", {**body, 1: [n1, n1]}, "a nullifier listed twice"),
        ("join-record-reject-nine", {**body, 1: sorted(_nul(str(i)) for i in range(9))}, "nine nullifiers"),
        ("join-record-reject-mixed", {**body, 4: []}, "a record carrying the snapshot key 4"),
        ("join-record-reject-no-day", {k: v for k, v in body.items() if k != 5}, "day missing"),
        ("join-record-reject-old-shape", {**{k: v for k, v in body.items() if k != 1}, 1: n1}, "key 1 as one bstr (the pre-ADR-0104 shape)"),
    ):  # fmt: skip
        raw = cbor.encode(bad)
        try:
            chat.decode("join-record", raw)
            raise AssertionError(suffix)
        except chat.ChatError as e:
            f.add(
                suffix,
                f"Reject: {why}",
                "5.17",
                {"view": jsonable(bad), "bytes": hexify(raw)},
                rejection={"step": None, "check": "content", "reason": str(e)},
            )
    records = [rec_a, rec_b]
    live = {ida, idb}
    rj = [_rec_json(r) for r in records]
    for suffix, desc, ticket, live_set in (
        ("join-ticket-admit-new", "A ticket whose nullifiers are all new", [n4], live),
        (
            "join-ticket-discard-second-nullifier-recorded",
            "A two-card ticket whose first nullifier is new and whose second is recorded for a "
            "live identity: discarded (any of the proof's nullifiers)",
            [n4, n2],
            live,
        ),
        (
            "join-ticket-admit-removed-identity",
            "The same nullifier recorded only for an identity that has left the all-members group: "
            "admitted",
            [n4, n2],
            {idb},
        ),
    ):
        decision, reason = chat.join_ticket_decision(ticket, records, live_set)
        f.add(
            suffix,
            desc,
            "2.5 step 4",
            {
                "ticket_nullifiers": [hexify(n) for n in ticket],
                "records": rj,
                "live_identities": sorted(hexify(i) for i in live_set),
            },
            {"decision": decision, "reason": reason},
        )
    # ---- the sequence: record first, then the Add commit (RT4)
    t1 = t0 + 1_000_000
    rec_d = chat.JoinRecord((n4,), idd, 20711, 70, t1)
    decision, reason = chat.join_precommit_decision(rec_d, records + [rec_d], live)
    f.add(
        "join-greeter-sequence",
        "The greeter's order (RT4): send the join-record, wait until the delivery service has "
        "sequenced it, re-check the records, then fetch KeyPackages and commit the Add. Here no "
        "earlier record shares a nullifier, so the greeter commits",
        "2.5 step 4",
        {"own_record": _rec_json(rec_d), "records": [_rec_json(r) for r in records + [rec_d]],
         "live_identities": sorted(hexify(i) for i in live)},
        {"sequence": ["join-record", "wait-for-sequencing", "pre-commit-check", "add-commit"],
         "decision": decision, "reason": reason},
    )  # fmt: skip
    # ---- two greeters open two tickets from one card at once
    rec_c = chat.JoinRecord((n1, n2), idc, 20711, 58, t0 + 864_120)
    rec_c2 = chat.JoinRecord((n1, n2), idd, 20711, 59, t0 + 864_125)
    race_records = [rec_a, rec_b, rec_c, rec_c2]
    first, first_reason = chat.join_precommit_decision(rec_c, race_records, {idb})
    later, later_reason = chat.join_precommit_decision(rec_c2, race_records, {idb})
    assert (first, later) == ("commit", "stop")
    f.add(
        "join-two-greeters-later-record-stops",
        "Two tickets from one card (identity a has left, so its record is inert) opened by two "
        "greeters at once: both send records before committing; the greeter whose record has "
        "the lower sequence number commits, the one with the later record finds a pending "
        "earlier record for a different identity and stops (RT4; was a post-commit removal "
        "under TS9)",
        "2.5 step 4",
        {"records": [_rec_json(r) for r in race_records], "live_identities": sorted(hexify(i) for i in {idb})},
        {"greeters": [
            {"own_record_seq": rec_c.seq, "decision": first, "reason": first_reason},
            {"own_record_seq": rec_c2.seq, "decision": later, "reason": later_reason},
        ]},
    )  # fmt: skip
    # ---- the backstop when both committed anyway
    race = [rec_a, rec_b, rec_c]
    removed = chat.join_duplicates_to_remove(race, {ida, idb, idc})
    assert removed == [idc]
    f.add(
        "join-two-live-identities-backstop",
        "Backstop: two live identities whose records share nullifiers (a greeter committed against "
        "the rule); every greeter removes the identity whose join-record has the higher "
        "delivery-service sequence number",
        "2.5 step 4",
        {"records": [_rec_json(r) for r in race], "live_identities": sorted(hexify(i) for i in {ida, idb, idc})},
        {"remove": [hexify(i) for i in removed], "keep": sorted(hexify(i) for i in {ida, idb})},
    )  # fmt: skip
    decision, reason = chat.join_ticket_decision([n1, n2], race, {ida, idb, idc})
    f.add(
        "join-rebase-recheck-drops-add",
        "A greeter whose Add is rebased onto a new epoch re-checks the records: the other "
        "greeter's record for the same card is now live, so it drops its Add",
        "2.5 step 4",
        {"ticket_nullifiers": [hexify(n1), hexify(n2)], "records": [_rec_json(r) for r in race]},
        {"decision": decision, "reason": reason},
    )
    # ---- a greeter that fails between its record and its commit (RT4)
    failed = chat.JoinRecord((n4,), idd, 20711, 70, t1)
    recs = records + [failed]
    retry_decision, retry_reason = chat.join_ticket_decision([n4], recs, live)
    pre, pre_reason = chat.join_precommit_decision(failed, recs, live)
    f.add(
        "join-greeter-fails-before-commit",
        "A greeter sends its record and fails before the commit: the record names an identity "
        "that is not a member, so it is inert. Another greeter opening the same ticket within "
        "JOIN_PENDING admits the same identity under the existing record (a retried ticket "
        "matches its own record): the ticket decision ignores records of non-members and the "
        "pre-commit check ignores a record naming the same identity",
        "2.5 step 4",
        {"ticket_nullifiers": [hexify(n4)], "identity": hexify(idd), "records": [_rec_json(r) for r in recs],
         "live_identities": sorted(hexify(i) for i in live), "retry_at": t1 + 600},
        {"ticket": {"decision": retry_decision, "reason": retry_reason},
         "existing_record_usable": chat.join_record_usable(failed, t1 + 600),
         "pre_commit": {"decision": pre, "reason": pre_reason}},
    )  # fmt: skip
    f.add(
        "join-greeter-record-expired-resend",
        "The same retry two hours later: the existing record is older than JOIN_PENDING, so the "
        "greeter sends a fresh record before committing",
        "2.5 step 4",
        {"records": [_rec_json(failed)], "retry_at": t1 + 7_200},
        {"existing_record_usable": chat.join_record_usable(failed, t1 + 7_200), "action": "send-fresh-record"},
    )  # fmt: skip
    for age in (3_599, 3_600, 3_601):
        usable = chat.join_record_usable(failed, failed.received + age)
        f.add(
            f"join-own-record-age-{age}",
            "An own record is usable strictly before JOIN_PENDING; at the boundary send fresh",
            "2.5 step 4",
            {"record": _rec_json(failed), "retry_at": failed.received + age},
            {
                "existing_record_usable": usable,
                "action": "commit" if usable else "send-fresh-record",
            },
        )
    # ---- the pre-commit check against an earlier record for a different identity (RU2)
    own = chat.JoinRecord((n4,), idd, 20711, 90, t1 + 7_200)
    for suffix, desc, earlier, live_set in (
        ("join-precommit-live-stop", "the earlier record's identity is a live member: stop",
         chat.JoinRecord((n4,), idc, 20711, 80, t1), {idc}),
        ("join-precommit-pending-stop", "the earlier record is 30 minutes old and its identity is not a member: pending, stop",
         chat.JoinRecord((n4,), idc, 20711, 80, t1 + 7_200 - 1_800), set()),
        ("join-precommit-boundary-commit", "the earlier record is exactly 3600 seconds old: no longer pending",
         chat.JoinRecord((n4,), idc, 20711, 80, own.received - 3_600), set()),
        ("join-precommit-boundary-stop", "the earlier record is 3599 seconds old: still pending",
         chat.JoinRecord((n4,), idc, 20711, 80, own.received - 3_599), set()),
        ("join-precommit-inert-commit", "the earlier record is two hours old and its identity is not a member: inert, commit",
         chat.JoinRecord((n4,), idc, 20711, 80, t1), set()),
    ):  # fmt: skip
        decision, reason = chat.join_precommit_decision(own, [earlier, own], live_set)
        f.add(
            suffix,
            f"Pre-commit check against an earlier record for a different identity: {desc}",
            "2.5 step 4",
            {"own_record": _rec_json(own), "records": [_rec_json(earlier), _rec_json(own)],
             "live_identities": sorted(hexify(i) for i in live_set)},
            {"decision": decision, "reason": reason},
        )  # fmt: skip
    # ---- the no-record backstop (RU1)
    add_t = t1 + 100_000
    base = dict(leaf_kind=1, was_member=False, entry_yields_nullifier=True, add_received=add_t,
                fetched_to=add_t + 600, identity=idd, records=records,
                snapshots_ready_before_add=True, record_observed_for_add=False)  # fmt: skip
    for suffix, desc, over in (
        ("join-no-record-removed-after-grace",
         "an Add of a new human identity with no join-record, with the organizers group fetched "
         "600 s past the Add: the leaf is removed", {}),
        ("join-no-record-kept-before-grace",
         "the same Add seen with the organizers group fetched only 599 s past it: kept",
         {"fetched_to": add_t + 599}),
        ("join-no-record-kept-unfetched",
         "the same Add when the organizers group cannot be fetched: the greeter does nothing",
         {"fetched_to": None}),
        ("join-no-record-kept-historical-add",
         "a newly initialized greeter sees existing members but no historical record in its snapshot: kept",
         {"snapshots_ready_before_add": False}),
        ("join-no-record-kept-retained-expired-record",
         "a retained record 397 days old names this identity: it is enough for the identity-only no-record check",
         {"records": [chat.JoinRecord((n4,), idd, 20712 - 397, 95, add_t - 397 * 86_400)]}),
        ("join-no-record-kept-pruned-observed-record",
         "this Add already had an observed record, later expired and pruned: omission cannot revoke admission",
         {"record_observed_for_add": True}),
        ("join-no-record-kept-open-entry",
         "the same in a context with entry = [0]: kept, no record exists there",
         {"entry_yields_nullifier": False}),
        ("join-no-record-kept-agent-leaf",
         "an agent (kind 2) leaf with no record: kept", {"leaf_kind": 2}),
        ("join-no-record-kept-second-device",
         "a second device of an identity that is already a member, with no record: kept",
         {"was_member": True}),
        ("join-no-record-kept-record-arrived",
         "a record naming the identity is found by the time of the fetch: kept",
         {"records": records + [chat.JoinRecord((n4,), idd, 20712, 95, add_t + 30)]}),
    ):  # fmt: skip
        args = {**base, **over}
        action, reason = chat.join_backstop_decision(**args)
        f.add(
            suffix,
            f"No-record backstop: {desc}",
            "2.5 step 4",
            {"leaf_kind": args["leaf_kind"], "was_member": args["was_member"],
             "entry_yields_nullifier": args["entry_yields_nullifier"], "add_received": args["add_received"],
             "organizers_fetched_to": args["fetched_to"], "identity": hexify(idd),
             "snapshots_ready_before_add": args["snapshots_ready_before_add"],
             "record_observed_for_add": args["record_observed_for_add"],
             "records": [_rec_json(r) for r in args["records"]]},
            {"action": action, "reason": reason},
        )  # fmt: skip
    # ---- 5.17: a record more than 396 days old is inert, deleted or not
    today = 20733
    old = chat.JoinRecord(
        (n4,), fixtures.fixed_bytes("identity-old", 32), today - 397, 3, t0 - 86_400 * 397
    )
    edge = chat.JoinRecord((n3,), idb, today - 396, 4, t0 - 86_400 * 396)
    old_live = {ida, idb, old.identity}
    held = [rec_a, old, edge]
    ticket_d, reason_d = chat.join_ticket_decision([n4], held, old_live, today)
    ticket_e, reason_e = chat.join_ticket_decision([n3], held, old_live, today)
    own_old = chat.JoinRecord((n4,), idd, today, 90, t0 + 50)
    pre, pre_reason = chat.join_precommit_decision(own_old, held + [own_old], old_live, today)
    removed = chat.join_duplicates_to_remove(held + [own_old], old_live | {idd}, today)
    f.add(
        "join-record-expired-inert",
        "A record 397 days old for a live identity is present and undeleted: a ticket sharing its "
        "nullifier is admitted, a greeter's own record after it commits, and the duplicate "
        "backstop removes nothing; a record exactly 396 days old still blocks",
        "5.17",
        {"records": [_rec_json(r) for r in held], "live_identities": sorted(hexify(i) for i in old_live),
         "today": today, "ticket_old": [hexify(n4)], "ticket_edge": [hexify(n3)],
         "own_record": _rec_json(own_old)},
        {"ticket_old": {"decision": ticket_d, "reason": reason_d},
         "ticket_edge": {"decision": ticket_e, "reason": reason_e},
         "precommit": {"decision": pre, "reason": pre_reason},
         "backstop_removed": [hexify(i) for i in removed]},
    )  # fmt: skip
    assert ticket_d == "admit" and ticket_e == "discard" and pre == "commit" and removed == []
    snap = chat.join_snapshot_body(held, today)
    f.add(
        "join-record-expired-snapshot-omits",
        "The snapshot sent to a newcomer omits the 397-day-old record and keeps the 396-day-old one",
        "5.17",
        {"records": [_rec_json(r) for r in held], "today": today, "view": jsonable(snap)},
        {"content_type": chat.media_type("join-record"), "bytes": hexify(chat.encode("join-record", snap)),
         "rows": len(snap[4])},
    )  # fmt: skip
    kept = chat.join_records_prune(held, old_live, today)
    f.add(
        "join-records-prune",
        "Deletion (advisory, MAY): the reference deletes a record whose identity left and a record "
        "more than 396 days old; an implementation that keeps the old record also conforms, since "
        "it is inert either way",
        "5.17",
        {"records": [_rec_json(r) for r in held], "live_identities": sorted(hexify(i) for i in old_live), "today": today},
        {"kept": [_rec_json(r) for r in kept]},
    )  # fmt: skip
    return f


def delivery_file() -> File:
    f = File(
        SPEC,
        "delivery",
        "The delivery service's service manifest (kind delivery): DL-1 to DL-5 of 12.1 after "
        "services.md S-1 to S-8. Built on its own copy of the base world; step-10 failures and "
        "the version 2 cases were appended by a misbehaving log so a phone reaches the rule. "
        "DL-4 bounds limits.tokensPerIssuance (64) and limits.commitsPerHour (3,600). Keys that "
        "do not belong to a delivery manifest are refused at step 4 by services.md S-1, S-3 and "
        "S-7, which the two S-* cases here show.",
    )
    fx = fixtures.build()
    w = fx.world
    for suffix in ("", "-rotate"):
        fx.keys[f"svc-ds{suffix}"] = key_from_label(f"svc-ds{suffix}")
    ks = fixtures.service_keyset("svc-ds", "svc-ds-rotate", fx.keys)
    authority = w.append(ks, [(b"svc-ds-rotate", fx.keys["svc-ds-rotate"])]).cid
    kc = sv.key_config(key_from_label("ds-gateway").public)
    good = sv.body(
        "delivery",
        ["https://ds.example/"],
        ohttp=kc,
        token_issuers=[cid(b"ds issuer")],
        **sv.delivery_defaults(),
    )
    signer = [(b"svc-ds", fx.keys["svc-ds"])]

    def log(name, body, version=1, prev=None):
        env = m.envelope(
            "service",
            body,
            authority=authority,
            issued=fixtures.ISSUED + version,
            version=version,
            lineage=prev.cid if prev is not None else None,
            prev=prev.cid if prev is not None else None,
        )
        return w.append(env, signer)

    v1 = log("v1", good)
    v2_body = copy.deepcopy(good)
    v2_body[sv.LIMITS]["sendsPerMinute"] = 1200
    v2 = log("v2", v2_body, 2, v1)
    # DL-5 needs its own lineage: a second version 2 of v1's lineage would stop at step 8
    v1_dl5 = log("dl5-v1", {**copy.deepcopy(good), sv.ENDPOINTS: ["https://ds2.example/"]})

    def mut(fn):
        b = copy.deepcopy(good)
        fn(b)
        return b

    cases = [
        ("service-delivery-valid", "Valid delivery manifest: VOPRF issuer, six limits, 30-day content retention", v1, None, None),
        ("service-delivery-valid-v2", "Version 2 raising a limit; issuer.name unchanged", v2, None, None),
        ("service-delivery-invalid-DL-1-type", "issuer.type 2 (not VOPRF)", log("dl1t", mut(lambda b: b[sv.ISSUER].__setitem__(sv.ISS_TYPE, 2))), 10, "DL-1"),
        ("service-delivery-invalid-DL-1-rotation", "issuer.rotation 2,592,001 seconds", log("dl1r", mut(lambda b: b[sv.ISSUER].__setitem__(sv.ISS_ROTATION, sv.DL_ROTATION_MAX + 1))), 10, "DL-1"),
        ("service-delivery-invalid-DL-2-missing", "limits without ticketsPerContextDay", log("dl2m", mut(lambda b: b[sv.LIMITS].pop("ticketsPerContextDay"))), 10, "DL-2"),
        ("service-delivery-invalid-DL-2-extra", "limits with a seventh name", log("dl2e", mut(lambda b: b[sv.LIMITS].__setitem__("welcomesPerDay", 10))), 10, "DL-2"),
        ("service-delivery-invalid-DL-2-zero", "commitsPerHour 0", log("dl2z", mut(lambda b: b[sv.LIMITS].__setitem__("commitsPerHour", 0))), 10, "DL-2"),
        ("service-delivery-invalid-DL-2-absent", "no limits map", log("dl2a", mut(lambda b: b.pop(sv.LIMITS))), 10, "DL-2"),
        ("service-delivery-invalid-DL-3-content", "retention.content 31 days", log("dl3c", mut(lambda b: b[sv.RETENTION].__setitem__("content", sv.DL_CONTENT_MAX + 1))), 10, "DL-3"),
        ("service-delivery-invalid-DL-3-no-errors", "retention without errors", log("dl3e", mut(lambda b: b[sv.RETENTION].pop("errors"))), 10, "DL-3"),
        ("service-delivery-invalid-DL-4-tokens", "limits.tokensPerIssuance 65", log("dl4t", mut(lambda b: b[sv.LIMITS].__setitem__("tokensPerIssuance", sv.DL_TOKENS_PER_ISSUANCE_MAX + 1))), 10, "DL-4"),
        ("service-delivery-invalid-DL-4-commits", "limits.commitsPerHour 3,601", log("dl4c", mut(lambda b: b[sv.LIMITS].__setitem__("commitsPerHour", sv.DL_COMMITS_PER_HOUR_MAX + 1))), 10, "DL-4"),
        ("service-delivery-invalid-S-1-key-17", "key 17 (a blob store's limits) on a delivery manifest: refused at step 4 by services.md S-1", log("dl4", mut(lambda b: b.__setitem__(17, {0: 1}))), 4, "S-1"),
        ("service-delivery-invalid-S-3-origin", "key 7 origin on a delivery manifest: refused at step 4 by services.md S-3", log("dl4o", mut(lambda b: b.__setitem__(sv.ORIGIN, "hum/log/x"))), 4, "S-3"),
        ("service-delivery-invalid-DL-5-name", "version 2 renaming the issuer", log("dl5", {**mut(lambda b: b[sv.ISSUER].__setitem__(sv.ISS_NAME, "hum-ds-2")), sv.ENDPOINTS: ["https://ds2.example/"]}, 2, v1_dl5), 10, "DL-5"),
    ]  # fmt: skip
    w.finalize()
    ctx = w.context(now=fixtures.NOW)
    for suffix, desc, bundle, step, rule in cases:
        inputs = {
            "bundle": bundle_json(bundle),
            "view": jsonable(cbor.decode(bundle.envelope)[m.BODY]),
        }
        try:
            env = m.verify_bundle(ctx, bundle)
        except m.Rejection as e:
            assert step is not None and (e.step, e.rule) == (step, rule), (suffix, str(e), e.rule)
            f.add(
                suffix,
                desc,
                "12.1",
                inputs,
                rejection={"step": e.step, "rule": e.rule, "reason": e.reason},
            )
            continue
        assert step is None, suffix
        f.add(suffix, desc, "12.1", inputs, {"accept": True, "kind": env[m.BODY][sv.KIND]})
    return f


def generate() -> list[File]:
    fx = fixtures.build()
    return [content_file(fx), derivations_file(fx), join_records_file(), delivery_file()]
