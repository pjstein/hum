import hashlib

import pytest

from hum_reference import chat, fixtures, storage
from hum_reference import storage_folders as sf
from hum_reference.cid import cid
from hum_reference.keys import key_from_label


def test_range_params_and_content_length():
    p = sf.range_params(100)
    assert p == {"P": 104, "n": 1, "C": 121, "C_format2": 137}
    assert sf.range_params(65_535)["n"] == 1 and sf.range_params(65_536)["n"] == 2
    assert sf.check_content_length(100, 121) is None
    assert sf.check_content_length(100, 122) == "size-mismatch"


def _part(i):
    ref, _ = storage.SealedReference.direct(b"f%d" % i, bytes([i]) * 16, "text/plain", f"f{i}")
    return chat.external_part_from_reference(ref)


def test_folder_rules():
    a, b, c = bytes([1]) * 32, bytes([2]) * 32, bytes([3]) * 32
    rights = {a: {"files-write"}, b: {"files-write", "files-delete-any"}, c: set()}
    fid = bytes(16)
    ops = [
        sf.FolderOp(1, a, b"m1" * 16, {0: 1, 1: 1, 2: fid, 3: "a", 4: []}, _part(1)),
        sf.FolderOp(2, a, b"m1" * 16, {0: 1, 1: 2, 2: fid, 3: "dup"}),  # rule 1: duplicate msg id
        sf.FolderOp(
            3,
            c,
            {0: 1, 1: 2, 2: fid, 3: "c"} and {0: 1, 1: 2, 2: fid, 3: "c"},
            {0: 1, 1: 2, 2: fid, 3: "c"},
        ),
    ]
    ops[2] = sf.FolderOp(3, c, b"m3" * 16, {0: 1, 1: 2, 2: fid, 3: "c"})  # no rights
    ops += [
        sf.FolderOp(
            4, b, b"m4" * 16, {0: 1, 1: 4, 2: fid, 5: b"\x00" * 32}, _part(2)
        ),  # rule 4 stale prev
        sf.FolderOp(5, a, b"m5" * 16, {0: 1, 1: 3, 2: fid, 4: ["x/y"]}),  # rule 6
        sf.FolderOp(6, a, b"m6" * 16, {0: 1, 1: 1, 2: fid, 3: "again", 4: []}, _part(3)),  # rule 2
        sf.FolderOp(7, b, b"m7" * 16, {0: 1, 1: 5, 2: fid}),  # rule 7
        sf.FolderOp(8, a, b"m8" * 16, {0: 1, 1: 2, 2: fid, 3: "z"}),  # rule 3 (deleted)
    ]
    folder = sf.apply_ops(ops, rights)
    assert [r for _, r in folder.ignored] == ["5.4-1", "5.3", "5.4-6", "5.4-2", "5.4-3"]
    f = folder.files[fid]
    assert f.deleted and len(f.versions) == 2 and f.name == "a"
    snap = sf.snapshot(folder)
    assert snap == sf.snapshot(folder)
    from hum_reference import cbor

    assert cbor.decode(snap)[1] == []  # deleted files are omitted


def test_delete_order_sign_and_verify():
    keys = {n: key_from_label(n) for n in ("a1", "a2", "a3")}
    pubs = {n.encode(): k.public for n, k in keys.items()}
    auth = cid(b"ctx")
    order = sf.DeleteOrder(auth, (cid(b"b"), cid(b"a")), 1000, 2000)
    body = sf.sign_order(order, [(b"a1", keys["a1"]), (b"a2", keys["a2"])])
    kw = dict(now=1500, tombstone_window=5000, token_context_authority=auth)
    assert sf.verify_order(body, pubs, 2, **kw) == (True, None)
    assert sf.verify_order(body, pubs, 2, cid=cid(b"a"), **kw) == (True, None)
    assert sf.verify_order(body, pubs, 2, cid=cid(b"zz"), **kw) == (False, "order")
    assert sf.verify_order(body, pubs, 3, **kw) == (False, "order")
    assert sf.verify_order(
        body, pubs, 2, now=2001, tombstone_window=5000, token_context_authority=auth
    ) == (False, "order")
    assert sf.verify_order(
        body, pubs, 2, now=1500, tombstone_window=500, token_context_authority=auth
    ) == (False, "order")
    assert sf.verify_order(
        body, pubs, 2, now=1500, tombstone_window=5000, token_context_authority=cid(b"other")
    ) == (False, "order")
    wrong = sf.sign_order(
        order, [(b"a1", keys["a1"]), (b"a2", keys["a2"])], domain=b"hum/manifest/1"
    )
    assert sf.verify_order(wrong, pubs, 2, **kw) == (False, "order")
    assert (
        sf.delete_order_payload(order.encode())
        == b"hum/blob-delete/1" + hashlib.sha256(order.encode()).digest()
    )


def test_store_put_order_and_visibility():
    st = sf.StoreState()
    body = b"hello"
    commit = storage.delete_commitment(bytes(32)).hex()
    base = dict(
        context=cid(b"A"),
        path_cid=cid(body),
        body=body,
        content_type="application/cbor",
        content_length=5,
        retention=0,
        delete_header=commit,
        credential_ok=True,
    )
    assert sf.put_decision(st, **{**base, "credential_ok": False})["status"] == 401
    assert sf.put_decision(st, **{**base, "content_length": None})["status"] == 413
    assert sf.put_decision(st, **{**base, "delete_header": "x"})["detail"] == "commitment"
    assert sf.put_decision(st, **{**base, "content_type": "video/x"})["detail"] == "format"
    assert sf.put_decision(st, **{**base, "path_cid": cid(b"no")})["detail"] == "cid_mismatch"
    assert sf.put_decision(st, **base)["status"] == 201
    assert sf.put_decision(st, **base)["status"] == 200
    assert (
        sf.put_decision(
            st, **{**base, "context": cid(b"B"), "content_type": "text/plain; charset=utf-8"}
        )["detail"]
        == "media_type"
    )
    assert (
        sf.put_decision(
            st,
            **{
                **base,
                "context": cid(b"B"),
                "content_type": "application/vnd.hum.sealed",
                "body": b"\x01" + body[1:],
                "path_cid": cid(b"\x01" + body[1:]),
            },
        )["status"]
        == 201
    )
    assert (
        sf.delete_decision(
            st, context=cid(b"A"), cid=cid(body), secret=bytes(31) + b"\x01", order_ok=None
        )["detail"]
        == "secret"
    )
    assert (
        sf.delete_decision(st, context=cid(b"A"), cid=cid(body), secret=bytes(32), order_ok=None)[
            "status"
        ]
        == 204
    )
    assert sf.put_decision(st, **base)["detail"] == "tombstoned"
    assert sf.visibility("none", "sealed-own")["status"] == 401
    assert sf.visibility("valid", "sealed-other")["status"] == 404
    assert sf.visibility("valid", "tombstoned")["status"] == 410
    assert sf.visibility("spent", "public")["code"] == "token_spent"


def test_promotion_check():
    ref, _ = storage.SealedReference.direct(b"doc", bytes(16), "text/plain")
    assert sf.check_promotion(ref, b"doc") and not sf.check_promotion(ref, b"dog")
    _ = fixtures


@pytest.mark.parametrize("n", [0, 1])
def test_delete_order_cid_count_bounds(n):
    order = sf.DeleteOrder(cid(b"c"), tuple(cid(bytes([i])) for i in range(n)), 1, 2)
    if n == 0:
        with pytest.raises(ValueError):
            order.encode()
    else:
        order.encode()
