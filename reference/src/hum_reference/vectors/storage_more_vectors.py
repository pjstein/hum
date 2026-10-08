"""The storage.md section 12 vectors not in storage_vectors.py: ranges, appended chunk,
ExternalPart, more reference rejections, keyring-share rejections, folders, delete orders,
store API decisions, promotion.
"""

from __future__ import annotations

import hashlib

from .. import cbor, chat, fixtures, services, storage
from .. import storage_folders as sf
from ..cid import cid
from . import File, hexify, jsonable
from .storage_vectors import KEY, SECRET, pattern

SPEC = "storage"


def ranges_file() -> File:
    f = File(
        SPEC, "ranges", "§1.4: P, n and C from size; content-length mismatch; an appended chunk."
    )
    for size in (0, 100, 65535, 65536, 150_000):
        f.add(
            "range-c-from-size",
            f"Expected lengths for a {size}-byte plaintext",
            "1.4",
            {"size": size},
            sf.range_params(size),
        )
    p = sf.range_params(100)
    f.add(
        "range-content-length-mismatch",
        "A Content-Length that cannot hold a 100-byte blob fails with size-mismatch before any fetch",
        "1.4",
        {"size": 100, "content_length": p["C"] + 16},
        rejection={
            "step": None,
            "check": "content-length",
            "reason": sf.check_content_length(100, p["C"] + 16),
        },
    )
    two = storage.seal(pattern(65_536), KEY)
    extra = storage.seal(pattern(70_000), KEY)[1 : 1 + storage.CHUNK + storage.TAG]
    appended = two + extra
    try:
        storage.open_sealed(appended, KEY)
        raise AssertionError
    except storage.SealedError as e:
        assert e.reason == "bad-tag"
    f.add(
        "seal-appended-chunk",
        "A full 65,552-byte chunk appended after the last: n recomputes and the old last chunk fails",
        "1.4",
        {
            "key": hexify(KEY),
            "ciphertext_sha256": hashlib.sha256(appended).hexdigest(),
            "ciphertext_length": len(appended),
            "ciphertext_rule": "seal-two-chunks followed by chunk 0 of seal(pattern(70000))",
        },
        rejection={"step": None, "check": "open-sealed", "reason": "bad-tag"},
    )
    return f


def references_more_file() -> File:
    f = File(
        SPEC,
        "reference-more",
        "§3.1 rejections not in reference.json and the §3.2 ExternalPart reverse rule.",
    )
    ref, _ = storage.SealedReference.direct(
        b"text", KEY, "text/plain", "a.txt", fixtures.EXPIRES, description="caption"
    )
    base = ref.to_item()

    def reject(name, item, why):
        data = cbor.encode(item)
        try:
            storage.SealedReference.decode(data)
            raise AssertionError(name)
        except storage.SealedError:
            pass
        f.add(
            name,
            f"Reject: {why}",
            "3.1",
            {"reference": hexify(data)},
            rejection={"step": None, "check": "decode-reference", "reason": "bad-reference"},
        )

    reject(
        "ref-media-too-long",
        {**base, storage.REF_MEDIA: "m" * 128},
        "media type of 128 bytes",
    )
    reject(
        "ref-description-too-long",
        {**base, storage.REF_DESCRIPTION: "d" * 1025},
        "description of 1,025 bytes",
    )
    reject("ref-key-wrong-length", {**base, storage.REF_KEY: bytes(15)}, "15-byte key")
    reject("ref-unknown-key", {**base, 11: 1}, "unknown map key 11")
    reject("ref-format-3", {**base, storage.REF_FORMAT: 3}, "format 3")
    part = chat.external_part_from_reference(ref)
    f.add(
        "external-part-valid",
        "Forward mapping of a direct reference",
        "3.2",
        {"reference": jsonable(base)},
        {"external_part": jsonable(part)},
    )
    back = chat.external_part_to_reference(part)
    assert back.cid == ref.cid and back.key == ref.key
    bads = [
        # Indexes into chat.EP_FIELDS, the flat draft-09 nestedPart layout.
        ("external-part-bad-enc-alg", 7, 2),
        ("external-part-bad-hash-alg", 11, 2),
        ("external-part-bad-key-length", 8, bytes(15)),
        ("external-part-nonce-present", 9, bytes(12)),
        ("external-part-aad-present", 10, b"x"),
        ("external-part-bad-hash-length", 12, bytes(31)),
        ("external-part-bad-url", 4, "https://example.com/blob"),
    ]
    for name, idx, value in bads:
        p = list(part)
        p[idx] = value
        try:
            chat.external_part_to_reference(p)
            raise AssertionError(name)
        except chat.ChatError:
            pass
        f.add(
            name,
            f"Reverse rule: {chat.EP_FIELDS[idx]} invalid",
            "3.2",
            {"external_part": jsonable(p)},
            rejection={"step": None, "check": "external-part", "reason": name},
        )
    return f


def keyring_more_file() -> File:
    f = File(SPEC, "keyring-share", "§4.2 keyring-share rejections.")
    payload = storage.keyring_share([(1, 4, SECRET)])
    f.add(
        "keyring-share-unauthorized-sender",
        "A keyring-share from a member that did not commit the Add is ignored",
        "4.2",
        {"payload": hexify(payload), "sender_committed_add": False},
        rejection={"step": None, "check": "keyring-share", "reason": "unauthorized-sender"},
    )
    other = hashlib.sha256(b"other secret").digest()[:16]
    f.add(
        "keyring-share-conflicting-secret",
        "An entry for epoch 1 with a different secret than the one held: ignored and the sender flagged",
        "4.2",
        {
            "held": {"k": 1, "secret": hexify(SECRET)},
            "payload": hexify(storage.keyring_share([(1, 4, other)])),
        },
        rejection={
            "step": None,
            "check": "keyring-share",
            "reason": "conflicting-secret",
            "flag_sender": True,
        },
    )
    return f


def _ops() -> tuple[list[sf.FolderOp], dict[bytes, set[str]], dict[str, int]]:
    """40 file-ops from three members exercising every §5.4 rule. Returns ops, rights, rule->index."""
    alice, bob, carol = (fixtures.fixed_bytes(n) for n in ("alice", "bob", "carol"))
    rights = {alice: {"files-write"}, bob: {"files-write", "files-delete-any"}, carol: set()}
    ops: list[sf.FolderOp] = []
    rule_index: dict[str, int] = {}

    def msg(i):
        return fixtures.fixed_bytes(f"msg-{i}")

    def part(i):
        ref, _ = storage.SealedReference.direct(
            b"file %d" % i, fixtures.fixed_bytes(f"k{i}", 16), "text/plain", f"f{i}.txt"
        )
        return chat.external_part_from_reference(ref)

    def fid(n):
        return fixtures.fixed_bytes(f"file-{n}", 16)

    def add(sender, body, p=None, rule=None):
        i = len(ops)
        ops.append(sf.FolderOp(i + 1, sender, msg(i), body, p))
        if rule and rule not in rule_index:
            rule_index[rule] = i

    add(alice, {0: 1, 1: 1, 2: fid(1), 3: "a.txt", 4: []}, part(1))
    add(bob, {0: 1, 1: 1, 2: fid(2), 3: "b.txt", 4: ["docs"]}, part(2))
    add(carol, {0: 1, 1: 1, 2: fid(3), 3: "c.txt", 4: []}, part(3), "5.3")  # no files-write
    add(alice, {0: 1, 1: 1, 2: fid(1), 3: "dup.txt", 4: []}, part(4), "5.4-2")  # existing id
    add(alice, {0: 1, 1: 2, 2: fid(1), 3: "a2.txt"})
    add(bob, {0: 1, 1: 2, 2: fid(1), 3: "a3.txt"})  # delete-any may rename others
    add(alice, {0: 1, 1: 3, 2: fid(1), 4: ["moved"]})
    add(alice, {0: 1, 1: 4, 2: fid(1), 5: msg(0)}, part(5))
    add(alice, {0: 1, 1: 4, 2: fid(1), 5: msg(0)}, part(6), "5.4-4")  # stale prev, kept
    add(
        bob, {0: 1, 1: 1, 2: fid(4), 3: "a2.txt", 4: ["moved"]}, part(7), "5.4-5"
    )  # same name+path allowed
    add(alice, {0: 1, 1: 2, 2: fid(9), 3: "ghost"}, None, "5.4-3")  # nonexistent
    add(alice, {0: 1, 1: 3, 2: fid(1), 4: ["a/b"]}, None, "5.4-6")  # slash in path element
    add(alice, {0: 1, 1: 3, 2: fid(1), 4: ["x"] * 17}, None, "5.4-6b")  # too deep
    add(alice, {0: 1, 1: 5, 2: fid(2)}, None, "5.3b")  # alice cannot delete bob's
    add(bob, {0: 1, 1: 5, 2: fid(2)}, None, "5.4-7")
    add(bob, {0: 1, 1: 2, 2: fid(2), 3: "zombie"}, None, "5.4-3b")  # deleted
    add(bob, {0: 1, 1: 6, 2: fid(5), 3: "pinned.txt", 4: [], 6: msg(99)}, part(8))
    add(bob, {0: 1, 1: 7, 2: fid(5)})
    add(alice, {0: 1, 1: 9, 2: fid(1)}, None, "5.2-malformed")  # unknown op
    add(alice, {0: 2, 1: 2, 2: fid(1), 3: "v2"}, None, "5.2-malformed-version")
    add(alice, {0: 1, 1: 1, 2: fid(6), 3: "noref.txt", 4: []}, None, "5.2-no-part")
    bad_part = part(9)
    bad_part[7] = 2  # encAlg (chat.EP_FIELDS index 7) must be 1
    add(alice, {0: 1, 1: 1, 2: fid(7), 3: "badref.txt", 4: []}, bad_part, "5.2-reference")
    for i in range(8, 24):
        add(
            alice if i % 2 else bob,
            {0: 1, 1: 1, 2: fid(100 + i), 3: f"bulk{i}.txt", 4: ["bulk"]},
            part(100 + i),
        )
    assert len(ops) == 38
    # duplicate message id (rule 1): replay op 0 under a later seq
    ops.append(sf.FolderOp(39, alice, msg(0), {0: 1, 1: 1, 2: fid(1), 3: "a.txt", 4: []}, part(1)))
    rule_index["5.4-1"] = 38
    add(alice, {0: 1, 1: 4, 2: fid(1), 5: msg(8)}, part(10))
    assert len(ops) == 40
    return ops, rights, rule_index


def folders_file() -> File:
    f = File(
        SPEC,
        "folders",
        "§5: folder-replay (40 ops, every §5.4 rule named by op index), folder-rights, folder-index.",
    )
    ops, rights, rule_index = _ops()

    def op_json(o):
        return {
            "seq": o.seq,
            "sender": hexify(o.sender),
            "msg": hexify(o.msg),
            "body": jsonable(o.body),
            "external_part": None if o.part is None else jsonable(o.part),
        }

    def state_json(folder):
        return {
            "files": [
                {
                    "id": hexify(fl.id),
                    "name": fl.name,
                    "path": fl.path,
                    "created_by": hexify(fl.created_by),
                    "versions": len(fl.versions),
                }
                for _, fl in sorted(folder.files.items())
                if not fl.deleted
            ],
            "ignored": [{"seq": s, "rule": r} for s, r in folder.ignored],
        }

    folder = sf.apply_ops(ops, rights)
    snap = sf.snapshot(folder)
    f.add(
        "folder-replay",
        "Replay of 40 ops from alice (files-write), bob (files-write, files-delete-any), carol (no rights)",
        "5.4",
        {
            "ops": [op_json(o) for o in ops],
            "rights": {hexify(k): sorted(v) for k, v in rights.items()},
            "rule_op_index": rule_index,
        },
        {
            "state": state_json(folder),
            "snapshot": hexify(snap),
            "snapshot_sha256": hashlib.sha256(snap).hexdigest(),
        },
    )
    rights2 = dict(rights)
    rights2[fixtures.fixed_bytes("alice")] = set()
    folder2 = sf.apply_ops(ops, rights2)
    f.add(
        "folder-rights",
        "The same sequence with alice lacking files-write (roles serial 2 assumed)",
        "5.3",
        {"roles_serial": 2, "rights": {hexify(k): sorted(v) for k, v in rights2.items()}},
        {"state": state_json(folder2), "snapshot": hexify(sf.snapshot(folder2))},
    )
    small = sf.apply_ops(ops[:2], rights)
    f.add(
        "folder-index",
        "Canonical snapshot bytes for a two-file folder",
        "5.5",
        {"ops": [op_json(o) for o in ops[:2]]},
        {"snapshot": hexify(sf.snapshot(small)), "view": jsonable(cbor.decode(sf.snapshot(small)))},
    )
    return f


def delete_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "delete-order",
        "§8.2 delete orders signed by the context's 2-of-3 keyset (a1, a2, a3).",
    )
    keys = {n.encode(): fx.keys[n].public for n in ("a1", "a2", "a3")}
    cids = (cid(b"blob two"), cid(b"blob one"))
    order = sf.DeleteOrder(fx.authority_a, cids, fixtures.ISSUED, fixtures.ISSUED + 86_400)
    body = sf.sign_order(order, [(b"a1", fx.keys["a1"]), (b"a2", fx.keys["a2"])])
    common = dict(
        now=fixtures.ISSUED + 10,
        tombstone_window=30 * 86_400,
        token_context_authority=fx.authority_a,
    )
    assert sf.verify_order(body, keys, 2, **common) == (True, None)
    f.add(
        "delete-order",
        "Canonical order bytes, signed payload and a valid 2-of-3 signature set",
        "8.2",
        {
            "authority": hexify(fx.authority_a),
            "cids": [hexify(c) for c in cids],
            "issued": order.issued,
            "expires": order.expires,
            "signers": ["a1", "a2"],
        },
        {
            "order": hexify(order.encode()),
            "payload": hexify(sf.delete_order_payload(order.encode())),
            "body": hexify(body),
            "accept": True,
        },
    )
    one = sf.sign_order(order, [(b"a1", fx.keys["a1"])])
    f.add(
        "delete-order-threshold",
        "One of three signatures",
        "8.2",
        {"body": hexify(one)},
        rejection={
            "step": None,
            "check": "delete-order",
            "status": 403,
            "code": "forbidden",
            "detail": "order",
        },
    )
    wrong = sf.sign_order(
        order, [(b"a1", fx.keys["a1"]), (b"a2", fx.keys["a2"])], domain=b"hum/manifest/1"
    )
    f.add(
        "delete-order-wrong-domain",
        "Signed as hum/manifest/1",
        "8.2",
        {"body": hexify(wrong)},
        rejection={
            "step": None,
            "check": "delete-order",
            "status": 403,
            "code": "forbidden",
            "detail": "order",
        },
    )
    f.add(
        "delete-order-expired",
        "Presented after expires",
        "8.2",
        {"body": hexify(body), "now": order.expires + 1},
        rejection={
            "step": None,
            "check": "delete-order",
            "status": 403,
            "code": "forbidden",
            "detail": "order",
        },
    )
    f.add(
        "delete-order-wrong-context",
        "Token's context authority differs from the order's",
        "8.2",
        {"body": hexify(body), "token_context_authority": hexify(fx.keyset_b1.cid)},
        rejection={
            "step": None,
            "check": "delete-order",
            "status": 403,
            "code": "forbidden",
            "detail": "order",
        },
    )
    for name, kw in (
        ("threshold", dict(body=one)),
        ("wrong-domain", dict(body=wrong)),
        ("expired", dict(body=body, now=order.expires + 1)),
        ("wrong-context", dict(body=body, token_context_authority=fx.keyset_b1.cid)),
    ):
        args = dict(common)
        args.update({k: v for k, v in kw.items() if k != "body"})
        assert sf.verify_order(kw["body"], keys, 2, **args) == (False, "order"), name
    return f


def store_file() -> File:
    f = File(
        SPEC,
        "store-api",
        "§6 decisions: visibility table, put mismatch with exact error bytes, re-put, tombstone in another context, promotion.",
    )
    for token in ("none", "valid", "invalid", "spent"):
        for blob in ("public", "sealed-own", "sealed-other", "absent", "tombstoned"):
            f.add(
                "store-visibility",
                f"token {token}, blob {blob}",
                "6.4",
                {"token": token, "blob": blob},
                sf.visibility(token, blob),
            )
    ctx_a, ctx_b = cid(b"context A"), cid(b"context B")
    body = pattern(100)
    commit = storage.delete_commitment(hashlib.sha256(b"secret A").digest()).hex()
    st = sf.StoreState()
    res = sf.put_decision(
        st,
        context=ctx_a,
        path_cid=cid(b"wrong"),
        body=body,
        content_type="text/plain; charset=utf-8",
        content_length=100,
        retention=0,
        delete_header=commit,
        credential_ok=True,
    )
    err = services.encode_error(services.ErrorBody("conflict", "cid_mismatch"))
    f.add(
        "store-put-mismatch",
        "Body does not hash to the path CID",
        "6.3",
        {"path_cid": hexify(cid(b"wrong")), "body": hexify(body)},
        rejection={
            "step": None,
            "check": "put",
            "status": 409,
            "code": "conflict",
            "detail": "cid_mismatch",
            "body": hexify(err),
        },
    )
    assert res["status"] == 409
    ok = sf.put_decision(
        st,
        context=ctx_a,
        path_cid=cid(body),
        body=body,
        content_type="text/plain; charset=utf-8",
        content_length=100,
        retention=0,
        delete_header=commit,
        credential_ok=True,
    )
    assert ok["status"] == 201
    other_commit = storage.delete_commitment(hashlib.sha256(b"secret B").digest()).hex()
    again = sf.put_decision(
        st,
        context=ctx_a,
        path_cid=cid(body),
        body=body,
        content_type="text/plain; charset=utf-8",
        content_length=100,
        retention=0,
        delete_header=other_commit,
        credential_ok=True,
    )
    dele = sf.delete_decision(
        st, context=ctx_a, cid=cid(body), secret=hashlib.sha256(b"secret B").digest(), order_ok=None
    )
    f.add(
        "store-reput-no-new-commitment",
        "Re-put with a new commitment answers 200 and changes nothing; deleting with the new secret fails",
        "6.3",
        {"first_commitment": commit, "second_commitment": other_commit},
        {"reput": again, "delete_with_second_secret": dele},
    )
    assert dele["status"] == 403 and again["status"] == 200
    st2 = sf.StoreState()
    st2.tombstones[cid(body)] = {ctx_b}
    tomb = sf.put_decision(
        st2,
        context=ctx_a,
        path_cid=cid(body),
        body=body,
        content_type="text/plain; charset=utf-8",
        content_length=100,
        retention=0,
        delete_header=commit,
        credential_ok=True,
    )
    f.add(
        "store-put-tombstone-other-context",
        "A CID tombstoned in context B is accepted from context A",
        "6.3",
        {"tombstoned_in": hexify(ctx_b), "put_from": hexify(ctx_a)},
        tomb,
    )
    assert tomb["status"] == 201
    st3 = sf.StoreState()
    st3.tombstones[cid(body)] = {ctx_a}
    f.add(
        "store-put-tombstoned",
        "The same CID put again from the context that deleted it",
        "6.3",
        {"tombstoned_in": hexify(ctx_a), "put_from": hexify(ctx_a)},
        rejection={
            "step": None,
            "check": "put",
            **sf.put_decision(
                st3,
                context=ctx_a,
                path_cid=cid(body),
                body=body,
                content_type="text/plain; charset=utf-8",
                content_length=100,
                retention=0,
                delete_header=commit,
                credential_ok=True,
            ),
        },
    )
    order = [
        ("no-credential", dict(credential_ok=False)),
        ("too-large", dict(content_length=2**40)),
        ("bad-commitment", dict(delete_header="zz")),
        ("format", dict(content_type="application/x-unknown")),
    ]
    for name, kw in order:
        args = dict(
            context=ctx_a,
            path_cid=cid(body),
            body=body,
            content_type="text/plain; charset=utf-8",
            content_length=100,
            retention=0,
            delete_header=commit,
            credential_ok=True,
        )
        args.update(kw)
        f.add(
            f"store-put-{name}",
            f"Put check order: {name}",
            "6.3",
            {k: (hexify(v) if isinstance(v, bytes) else v) for k, v in kw.items()},
            rejection={"step": None, "check": "put", **sf.put_decision(sf.StoreState(), **args)},
        )
    ref, sealed = storage.SealedReference.direct(body, KEY, "text/plain; charset=utf-8")
    assert sf.check_promotion(ref, body) and not sf.check_promotion(ref, body + b"x")
    f.add(
        "promote-digest-ok",
        "A public copy whose CID equals the reference's digest",
        "9",
        {"reference": hexify(ref.encode()), "public_bytes": hexify(body)},
        {"upload": True, "public_cid": hexify(cid(body))},
    )
    f.add(
        "promote-digest-mismatch",
        "A client refuses a public copy whose CID differs from the digest",
        "9",
        {"reference": hexify(ref.encode()), "public_bytes": hexify(body + b"x")},
        rejection={"step": None, "check": "promotion", "reason": "digest-mismatch"},
    )
    return f


def generate() -> list[File]:
    fx = fixtures.build()
    return [
        ranges_file(),
        references_more_file(),
        keyring_more_file(),
        folders_file(),
        delete_file(fx),
        store_file(),
    ]
