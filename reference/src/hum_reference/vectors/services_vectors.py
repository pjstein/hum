"""Vectors for docs/specs/services.md: service manifests (S-1..S-8, storage.md BS-1..BS-6),
bundles (B-1, B-4), leaves, step 9 at the log (LG-8), checkpoints, the witness protocol,
signed requests (A-1..A-3), task ids, receipts, receipt pages, errors, padding, O-5 and
bootstrap. Tokens (RFC 9578 vectors) are referenced, not reproduced.
"""

from __future__ import annotations

import copy
import hashlib

from .. import cbor, cose, fixtures, log, merkle, services
from .. import manifest as m
from ..bodies import service as sv
from ..cid import cid
from ..keys import key_from_label
from . import File, hexify, jsonable
from .manifest_vectors import bundle_json

SPEC = "services"
S_SVC = "Services are named by key"
S_BUNDLE = "The bundle"
S_LOG = "Log and ledger"
S_WIT = "Witness"
S_AUTH = "Signed requests"
S_AGG = "Aggregator"
S_ERR = "Errors"
S_RELAY = "OHTTP relay"

KC = sv.key_config(key_from_label("ohttp-gateway").public)


def _kinds(fx: fixtures.Fixture) -> dict[str, dict]:
    w = fx.world
    wit = [(log.witness_name(a), k.public) for a, k in w.witnesses.items()]
    store = sv.blob_store_defaults()
    return {
        "log": sv.body(
            "log",
            ["https://log.example/"],
            ohttp=KC,
            witnesses=wit,
            origin=w.origin(),
            retention={"requests": 86400 * 30},
        ),
        "witness": sv.body("witness", ["https://witness.example/"], jurisdiction="CH"),
        "aggregator": sv.body("aggregator", ["https://agg.example/"], ohttp=KC, phase=1),
        "issuer": sv.body("issuer", ["https://issuer.example/"], ohttp=KC),
        "delivery": sv.body(
            "delivery",
            ["https://ds.example/"],
            ohttp=KC,
            token_issuers=[cid(b"ds issuer")],
            **sv.delivery_defaults(),
        ),
        "blob-store": sv.body(
            "blob-store",
            ["https://store.example/"],
            ohttp=KC,
            token_issuers=[cid(b"store issuer")],
            **store,
        ),
        "resolver": sv.body("resolver", ["https://resolve.example/"], ohttp=KC),
        "relay": sv.body("relay", ["https://relay.example/"], jurisdiction="IS"),
        "gallery": sv.body(
            "gallery",
            ["https://gallery.example/"],
            ohttp=KC,
            retention={"requests": 86400 * 30, "errors": 86400},
        ),
    }


def manifests_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "service-manifests",
        "One valid service manifest per kind, one failing per rule "
        "S-1..S-8 and BS-1..BS-6. Each service is its own 1-of-1 authority (keyset logged in world.json).",
    )
    w = fx.world
    kinds = _kinds(fx)
    authorities = {}
    for kind in kinds:
        for suffix in ("", "-rotate"):
            fx.keys[f"svc-{kind}{suffix}"] = key_from_label(f"svc-{kind}{suffix}")
        ks = fixtures.service_keyset(f"svc-{kind}", f"svc-{kind}-rotate", fx.keys)
        b = w.append(ks, [(f"svc-{kind}-rotate".encode(), fx.keys[f"svc-{kind}-rotate"])])
        authorities[kind] = b.cid
    bundles = {}
    for kind, body in kinds.items():
        env = m.envelope("service", body, authority=authorities[kind], issued=fixtures.ISSUED)
        bundles[kind] = w.append(env, [(f"svc-{kind}".encode(), fx.keys[f"svc-{kind}"])])
    # a second blob-store version (valid: formats grow)
    store_v2_body = copy.deepcopy(kinds["blob-store"])
    store_v2_body[sv.FORMATS][sv.FMT_SEALED] = [1, 2, 3]
    store_v1 = bundles["blob-store"]
    store_v2 = w.append(
        m.envelope(
            "service",
            store_v2_body,
            authority=authorities["blob-store"],
            version=2,
            lineage=store_v1.cid,
            prev=store_v1.cid,
            issued=fixtures.ISSUED + 10,
        ),
        [(b"svc-blob-store", fx.keys["svc-blob-store"])],
    )

    def mut(kind, fn):
        body = copy.deepcopy(kinds[kind])
        fn(body)
        return body

    # step-10 failures must be logged (step 7 runs first): a misbehaving log appended them
    logged_bad = {}

    def log_bad(name, kind, body, version=1, prev=None):
        lineage = None
        if prev is not None:
            lineage = cbor.decode(prev.envelope).get(m.LINEAGE) or prev.cid
        env = m.envelope(
            "service",
            body,
            authority=authorities[kind],
            issued=fixtures.ISSUED + 5,
            version=version,
            lineage=lineage,
            prev=prev.cid if prev else None,
        )
        logged_bad[name] = w.append(env, [(f"svc-{kind}".encode(), fx.keys[f"svc-{kind}"])])

    log_bad(
        "S-3-one-witness",
        "log",
        mut("log", lambda b: b.__setitem__(sv.WITNESSES, b[sv.WITNESSES][:1])),
    )
    log_bad(
        "S-3-duplicate-key",
        "log",
        mut(
            "log",
            lambda b: b.__setitem__(
                sv.WITNESSES, [b[sv.WITNESSES][0], {**b[sv.WITNESSES][0], sv.W_NAME: "other"}]
            ),
        ),
    )
    log_bad(
        "S-4-origin",
        "log",
        mut("log", lambda b: b.__setitem__(sv.ORIGIN, "hum/log/other")),
        2,
        bundles["log"],
    )
    log_bad(
        "S-4-kind",
        "gallery",
        mut("gallery", lambda b: b.__setitem__(sv.KIND, "resolver")),
        2,
        bundles["gallery"],
    )
    log_bad(
        "BS-5-name",
        "blob-store",
        {**store_v2_body, sv.ISSUER: {**store_v2_body[sv.ISSUER], sv.ISS_NAME: "renamed"}},
        3,
        store_v2,
    )
    # a second store lineage so the format-dropped case is not a fork of the first
    for suffix in ("", "-rotate"):
        fx.keys[f"svc-store-b{suffix}"] = key_from_label(f"svc-store-b{suffix}")
    ks_b = w.append(
        fixtures.service_keyset("svc-store-b", "svc-store-b-rotate", fx.keys),
        [(b"svc-store-b-rotate", fx.keys["svc-store-b-rotate"])],
    )
    authorities["store-b"] = ks_b.cid
    store_b1 = w.append(
        m.envelope("service", store_v2_body, authority=ks_b.cid, issued=fixtures.ISSUED),
        [(b"svc-store-b", fx.keys["svc-store-b"])],
    )
    log_bad(
        "BS-5-format",
        "store-b",
        {**store_v2_body, sv.FORMATS: {**store_v2_body[sv.FORMATS], sv.FMT_SEALED: [1, 2]}},
        2,
        store_b1,
    )
    w.finalize()

    def run(suffix, desc, bundle, step=None, rule=None):
        ctx = w.context(now=fixtures.NOW)
        inputs = {
            "bundle": bundle_json(bundle),
            "view": jsonable(cbor.decode(bundle.envelope)[m.BODY]),
        }
        try:
            env = m.verify_bundle(ctx, bundle)
        except m.Rejection as e:
            assert step is not None and e.step == step and e.rule == rule, (
                suffix,
                desc,
                str(e),
                e.rule,
            )
            f.add(
                suffix,
                desc,
                S_SVC,
                inputs,
                rejection={"step": e.step, "rule": e.rule, "reason": e.reason},
            )
            return
        assert step is None, (suffix, desc)
        f.add(suffix, desc, S_SVC, inputs, {"accept": True, "kind": env[m.BODY][sv.KIND]})

    for kind, b in bundles.items():
        run(f"service-valid-{kind}", f"Valid {kind} manifest", b)
    run(
        "service-blob-store-valid-v2",
        "Store version 2 adds a sealed format (BS-5 allows growth)",
        store_v2,
    )

    def resign(kind, body, step, rule, suffix, desc):
        env = m.envelope("service", body, authority=authorities[kind], issued=fixtures.ISSUED + 5)
        data = cbor.encode(env)
        c = cid(data)
        sig = cose.encode_cose_sign(
            [cose.sign_cid(fx.keys[f"svc-{kind}"], f"svc-{kind}".encode(), c)]
        )
        run(suffix, desc, m.Bundle(data, sig, c, copy.deepcopy(bundles[kind].proof)), step, rule)

    resign(
        "relay",
        mut("relay", lambda b: b.__setitem__(sv.KIND, "gateway")),
        4,
        "S-1",
        "service-invalid-S-1-kind",
        "Unknown kind gateway",
    )
    resign(
        "relay",
        mut("relay", lambda b: b.__setitem__(12, 1)),
        4,
        "S-1",
        "service-invalid-S-1-reserved",
        "Reserved key 12 present",
    )
    resign(
        "relay",
        mut("relay", lambda b: b.__setitem__(sv.ENDPOINTS, [])),
        4,
        "S-2",
        "service-invalid-S-2-empty",
        "No endpoints",
    )
    resign(
        "relay",
        mut("relay", lambda b: b.__setitem__(sv.ENDPOINTS, ["http://relay.example/"])),
        4,
        "S-2",
        "service-invalid-S-2-http",
        "An http endpoint",
    )
    resign(
        "relay",
        mut("relay", lambda b: b.__setitem__(sv.ENDPOINTS, ["https://relay.example/?x=1"])),
        4,
        "S-2",
        "service-invalid-S-2-query",
        "An endpoint with a query",
    )
    run(
        "service-invalid-S-3-one-witness",
        "Log with one witness",
        logged_bad["S-3-one-witness"],
        10,
        "S-3",
    )
    run(
        "service-invalid-S-3-duplicate-key",
        "Log with two witnesses sharing a key",
        logged_bad["S-3-duplicate-key"],
        10,
        "S-3",
    )
    resign(
        "log",
        mut("log", lambda b: b.pop(sv.ORIGIN)),
        4,
        "S-3",
        "service-invalid-S-3-no-origin",
        "Log without origin",
    )
    resign(
        "relay",
        mut("relay", lambda b: b.__setitem__(sv.WITNESSES, [])),
        4,
        "S-3",
        "service-invalid-S-3-witnesses-on-relay",
        "witnesses on a non-log",
    )
    run(
        "service-invalid-S-4-origin",
        "Version 2 changes the origin",
        logged_bad["S-4-origin"],
        10,
        "S-4",
    )
    run("service-invalid-S-4-kind", "Version 2 changes the kind", logged_bad["S-4-kind"], 10, "S-4")
    resign(
        "resolver",
        mut("resolver", lambda b: b.pop(sv.OHTTP)),
        4,
        "S-5",
        "service-invalid-S-5-missing",
        "Resolver without ohttp",
    )
    resign(
        "resolver",
        mut("resolver", lambda b: b.__setitem__(sv.OHTTP, KC[:-2])),
        4,
        "S-5",
        "service-invalid-S-5-malformed",
        "Truncated KeyConfig",
    )
    resign(
        "relay",
        mut("relay", lambda b: b.__setitem__(sv.OHTTP, KC)),
        4,
        "S-5",
        "service-invalid-S-5-relay",
        "Relay with ohttp",
    )
    resign(
        "delivery",
        mut("delivery", lambda b: b.pop(sv.TOKEN_ISSUERS)),
        4,
        "S-6",
        "service-invalid-S-6-no-token-issuers",
        "Delivery without tokenIssuers",
    )
    resign(
        "delivery",
        mut("delivery", lambda b: b.pop(sv.ISSUER)),
        4,
        "S-6",
        "service-invalid-S-6-no-issuer-map",
        "Delivery without the issuer map",
    )
    resign(
        "aggregator",
        mut("aggregator", lambda b: b.__setitem__(sv.PHASE, 3)),
        4,
        "S-7",
        "service-invalid-S-7-phase",
        "Aggregator phase 3",
    )
    resign(
        "aggregator",
        mut("aggregator", lambda b: b.__setitem__(sv.HPKE, b"\x01\x02")),
        4,
        "S-7",
        "service-invalid-S-7-hpke-phase1",
        "hpke with phase 1",
    )
    resign(
        "aggregator",
        mut("aggregator", lambda b: b.__setitem__(sv.PHASE, 2)),
        4,
        "S-7",
        "service-invalid-S-7-no-hpke",
        "Phase 2 without hpke",
    )
    resign(
        "gallery",
        mut("gallery", lambda b: b.__setitem__(sv.RETENTION, {"traces": 1})),
        4,
        "S-8",
        "service-invalid-S-8-class",
        "Unknown retention class",
    )
    resign(
        "gallery",
        mut("gallery", lambda b: b.__setitem__(sv.RETENTION, {"requests": 86400 * 31})),
        4,
        "S-8",
        "service-invalid-S-8-ceiling",
        "Gallery retention above 30 days",
    )
    resign(
        "blob-store",
        mut("blob-store", lambda b: b[sv.ISSUER].__setitem__(sv.ISS_TYPE, 1)),
        4,
        "BS-1",
        "service-blob-store-bad-token-type",
        "issuer.type 1",
    )
    resign(
        "blob-store",
        mut("blob-store", lambda b: b[sv.BLOB_LIMITS].__setitem__(sv.BL_MAX_BLOB, 1000)),
        4,
        "BS-2",
        "service-blob-store-small-maxblob",
        "maxBlob 1000",
    )
    resign(
        "blob-store",
        mut("blob-store", lambda b: b[sv.BLOB_LIMITS].pop(sv.BL_TOKENS_DAY)),
        4,
        "BS-2",
        "service-blob-store-missing-limit",
        "blobLimits missing tokensPerMemberDay",
    )
    resign(
        "blob-store",
        mut("blob-store", lambda b: b[sv.FORMATS].__setitem__(sv.FMT_SEALED, [1])),
        4,
        "BS-3",
        "service-blob-store-formats",
        "formats.sealed without 2",
    )
    resign(
        "blob-store",
        mut("blob-store", lambda b: b[sv.BLOB_RETENTION].__setitem__(sv.BR_TOMBSTONE, 3600)),
        4,
        "BS-4",
        "service-blob-store-short-tombstone",
        "tombstone one hour",
    )
    run(
        "service-blob-store-name-changed",
        "Version 3 renames the issuer",
        logged_bad["BS-5-name"],
        10,
        "BS-5",
    )
    run(
        "service-blob-store-format-dropped",
        "Version 2 of store B drops sealed format 3",
        logged_bad["BS-5-format"],
        10,
        "BS-5",
    )
    resign(
        "blob-store",
        mut("blob-store", lambda b: b.__setitem__(sv.PHASE, 1)),
        4,
        "BS-6",
        "service-blob-store-foreign-key",
        "Store with key 11 (phase)",
    )
    f.add(
        "key-config",
        "A well-formed RFC 9458 KeyConfig (X25519, one suite)",
        S_SVC,
        {
            "key_id": 1,
            "kem": 32,
            "public": hexify(key_from_label("ohttp-gateway").public),
            "suites": [[1, 1]],
        },
        {"key_config": hexify(KC), "parsed": {"key_id": 1, "kem": 32, "suites": [[1, 1]]}},
    )
    f.world_names = authorities  # type: ignore[attr-defined]
    return f


def bundle_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "bundle",
        "Bundle wire map {0 envelope, 1 signatures, 2 proofs, 3 hints, 4 authorship?}: B-1, B-4, a bad path.",
    )
    w = fx.world
    b = fx.deck_v3
    wire = m.encode_bundle(b, ["https://resolver.example/"])
    f.add(
        "bundle-valid",
        "deck v3 with one proof and a hint",
        S_BUNDLE,
        {"bundle": hexify(wire)},
        {"cid": hexify(b.cid), "proofs": 1},
    )
    two = cbor.decode(wire)
    two[2] = two[2] + [{**two[2][0], 0: cid(b"second log")}]
    f.add(
        "bundle-two-proofs",
        "A bundle with two proofs (second log) decodes; proof 0 is the one verified here",
        S_BUNDLE,
        {"bundle": hexify(cbor.encode(two))},
        {"proofs": 2},
    )
    auth = dict(cbor.decode(wire))
    del auth[1]
    auth[4] = b"\x01" * 40
    f.add(
        "bundle-authorship",
        "A bundle with authorship and no signatures decodes (B-4)",
        S_BUNDLE,
        {"bundle": hexify(cbor.encode(auth))},
        {"authorship_bytes": 40},
    )
    big = dict(cbor.decode(wire))
    big[3] = ["x" * 97_000]
    f.add(
        "bundle-reject-B-1",
        "Over 96 KiB",
        S_BUNDLE,
        {
            "bundle_sha256": hashlib.sha256(cbor.encode(big)).hexdigest(),
            "bytes": len(cbor.encode(big)),
        },
        rejection={"step": None, "check": "decode-bundle", "rule": "B-1", "reason": "too_large"},
    )
    both = dict(cbor.decode(wire))
    both[4] = b"\x01"
    f.add(
        "bundle-reject-B-4-both",
        "signatures and authorship both present",
        S_BUNDLE,
        {"bundle": hexify(cbor.encode(both))},
        rejection={"step": None, "check": "decode-bundle", "rule": "B-4", "reason": "malformed"},
    )
    neither = dict(cbor.decode(wire))
    del neither[1]
    f.add(
        "bundle-reject-B-4-neither",
        "neither signatures nor authorship",
        S_BUNDLE,
        {"bundle": hexify(cbor.encode(neither))},
        rejection={"step": None, "check": "decode-bundle", "rule": "B-4", "reason": "malformed"},
    )
    bad = copy.deepcopy(b)
    bad.proof.inclusion = [bytes(32)] * len(bad.proof.inclusion)
    ctx = w.context(now=fixtures.NOW)
    try:
        m.verify_bundle(ctx, bad)
        raise AssertionError
    except m.Rejection as e:
        assert e.step == 7
    f.add(
        "bundle-reject-bad-path",
        "A proof whose path does not verify",
        S_BUNDLE,
        {"bundle": hexify(m.encode_bundle(bad))},
        rejection={"step": 7, "reason": "inclusion proof does not verify"},
    )
    return f


def leaves_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "leaves",
        "Leaf bytes and hashes per manifest type present in the world, an entry bundle, and a leaf hashed without the 0x00 prefix (reject).",
    )
    w = fx.world
    seen = set()
    for b in w.bundles.values():
        env = cbor.decode(b.envelope)
        t = env[m.TYPE]
        if t in seen:
            continue
        seen.add(t)
        leaf = w.leaves[b.proof.position]
        f.add(
            f"leaf-{t}",
            f"Leaf for the first {t} in the world",
            S_LOG,
            {
                "cid": hexify(b.cid),
                "type": t,
                "authority": hexify(env.get(m.AUTHORITY, b.cid)),
                "lineage": None if m.LINEAGE not in env else hexify(env[m.LINEAGE]),
                "version": env[m.VERSION],
            },
            {"leaf": hexify(leaf), "leaf_hash": hexify(merkle.leaf_hash(leaf))},
        )
    three = w.leaves[:3]
    f.add(
        "entry-bundle",
        "Entry bundle of leaves 0..2 (uint16 BE length prefixes)",
        S_LOG,
        {"leaves": [hexify(x) for x in three]},
        {"entry_bundle": hexify(b"".join(len(x).to_bytes(2, "big") + x for x in three))},
    )
    leaf = w.leaves[0]
    f.add(
        "leaf-reject-no-prefix",
        "SHA-256(leaf) without the 0x00 prefix is not the leaf hash (LG-6)",
        S_LOG,
        {"leaf": hexify(leaf), "claimed_hash": hashlib.sha256(leaf).hexdigest()},
        rejection={"step": 7, "rule": "LG-6", "reason": "leaf hash must prefix 0x00"},
    )
    return f


def step9_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "step9-at-log",
        "LG-8: a manifest-valued ref absent from the log is refused at step 9; a context "
        "whose only unresolvable ref is the about blob is accepted. Covers the types whose bodies exist in the reference "
        "at generation time: " + ", ".join(sorted(m.TYPE_RULES)) + ".",
    )
    w = fx.world
    base = fixtures.context_body(fx, fx.authority_a)
    ok_env = m.envelope(
        "context",
        base,
        authority=fx.authority_a,
        issued=fixtures.ISSUED + 50,
        refs={"parent": fx.context_v1.cid},
    )
    ok = w.append(ok_env, [(b"b1", fx.keys["b1"]), (b"b2", fx.keys["b2"])])
    blob_only = m.envelope(
        "context",
        base,
        authority=fx.authority_a,
        issued=fixtures.ISSUED + 51,
        refs={"about": cid(b"about text not fetched")},
    )
    blob_b = w.append(blob_only, [(b"b1", fx.keys["b1"]), (b"b2", fx.keys["b2"])])
    bad_env = m.envelope(
        "context",
        base,
        authority=fx.authority_a,
        issued=fixtures.ISSUED + 52,
        refs={"parent": cid(b"never logged")},
    )
    bad = w.append(bad_env, [(b"b1", fx.keys["b1"]), (b"b2", fx.keys["b2"])])
    w.finalize()
    ctx = w.context(now=fixtures.NOW)
    m.verify_bundle(ctx, ok)
    f.add(
        "step9-accept-context",
        "context with a logged parent ref",
        S_LOG,
        {"bundle": bundle_json(ok)},
        {"accept": True},
    )
    f.add(
        "step9-accept-context-blob-ref",
        "context whose about ref is a blob the log does not resolve (accepted at the log; a phone "
        "fetching the blob is outside step 9 as this reference runs it, see conformance.md)",
        S_LOG,
        {"bundle": bundle_json(blob_b), "log_rule": "blobs are not resolved at the log"},
        {"accept_at_log": True},
    )
    try:
        m.verify_bundle(w.context(now=fixtures.NOW), bad)
        raise AssertionError
    except m.Rejection as e:
        assert e.step == 9
    f.add(
        "step9-reject-context",
        "context whose parent ref is not in the log (LG-8)",
        S_LOG,
        {"bundle": bundle_json(bad)},
        rejection={"step": 9, "rule": "LG-8", "reason": "unresolved_ref"},
    )
    return f


def checkpoint_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "checkpoint",
        "Checkpoint acceptance as services.md lists it; the log key id derivation.",
    )
    w = fx.world
    note = w.note()
    keys = w.witness_keys()
    f.add(
        "checkpoint-valid",
        "Log signature and two cosignatures",
        S_LOG,
        {"note": note.text(), "witness_keys": [hexify(k) for k in keys]},
        {"cosigners": 2, "log_key_id": hexify(log.note_key_id(w.origin(), w.log_public))},
    )
    one = log.Note(note.checkpoint, note.signatures[:2])
    f.add(
        "checkpoint-reject-one-cosignature",
        "One cosignature (W-2)",
        S_LOG,
        {"note": one.text(), "witness_keys": [hexify(k) for k in keys]},
        rejection={"step": 7, "rule": "W-2"},
    )
    nolog = log.Note(note.checkpoint, note.signatures[1:])
    f.add(
        "checkpoint-reject-no-log-signature",
        "Missing the log's own signature",
        S_LOG,
        {"note": nolog.text()},
        rejection={"step": 7, "reason": "checkpoint is not signed by the log"},
    )
    other = key_from_label("unlisted-witness")
    extra = log.Note(
        note.checkpoint,
        note.signatures[:2]
        + [log.cosign_checkpoint(note.checkpoint, "hum/witness/unlisted", other, 1_791_259_200)],
    )
    f.add(
        "checkpoint-reject-unlisted-witness",
        "A cosignature from an unlisted witness does not count",
        S_LOG,
        {"note": extra.text(), "witness_keys": [hexify(k) for k in keys]},
        rejection={"step": 7, "rule": "W-2", "cosigners": 1},
    )
    renamed = log.Note(
        note.checkpoint,
        [
            note.signatures[0],
            log.NoteSignature("hum/witness/renamed", note.signatures[1].payload),
            note.signatures[2],
        ],
    )
    assert len(log.cosigners(renamed, keys)) == 1
    f.add(
        "checkpoint-reject-key-id-mismatch",
        "A cosignature whose name does not match its key id (recomputed from name and key)",
        S_LOG,
        {"note": renamed.text(), "witness_keys": [hexify(k) for k in keys]},
        rejection={"step": 7, "rule": "W-2", "cosigners": 1},
    )
    s = note.signatures[1]
    tampered = log.Note(
        note.checkpoint,
        [
            note.signatures[0],
            log.NoteSignature(
                s.name, s.payload[:4] + (1_791_259_201).to_bytes(8, "big") + s.payload[12:]
            ),
            note.signatures[2],
        ],
    )
    f.add(
        "checkpoint-reject-tampered-timestamp",
        "A tampered cosignature timestamp",
        S_LOG,
        {"note": tampered.text(), "witness_keys": [hexify(k) for k in keys]},
        rejection={"step": 7, "rule": "W-2", "cosigners": 1},
    )
    return f


def witness_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "witness-protocol",
        "tlog-witness request and response bodies: 200, 409 stale size, 409 same size different root, 422.",
    )
    w = fx.world
    n = len(w.leaves)
    old = 3
    note = w.note().text()
    proof = merkle.consistency_proof(w.leaves, old)
    req = services.witness_request(old, proof, note)
    cases = [
        (
            "witness-200",
            "Fresh checkpoint extending the witness's size 3",
            req,
            3,
            merkle.root_hash(w.leaves[:3]),
            (200, ""),
        ),
        (
            "witness-409-stale",
            "Witness already holds size 5",
            req,
            5,
            merkle.root_hash(w.leaves[:5]),
            (409, "5"),
        ),
        (
            "witness-409-same-size-different-root",
            f"Witness holds size {n} with another root",
            services.witness_request(n, [], note),
            n,
            bytes(32),
            (409, str(n)),
        ),
        (
            "witness-422",
            "A wrong consistency proof",
            services.witness_request(old, [bytes(32)] * len(proof), note),
            3,
            merkle.root_hash(w.leaves[:3]),
            (422, ""),
        ),
        (
            "witness-400",
            "old larger than the checkpoint size",
            services.witness_request(n + 1, [], note),
            3,
            merkle.root_hash(w.leaves[:3]),
            (400, ""),
        ),
    ]
    for name, desc, r, known, root, expected in cases:
        got = services.witness_decide(r, w.log_public, known, root)
        assert got == expected, (name, got)
        f.add(
            name,
            desc,
            S_WIT,
            {
                "request": r,
                "log_public": hexify(w.log_public),
                "known_size": known,
                "known_root": hexify(root),
            },
            {"status": expected[0], "body": expected[1]},
        )
    return f


def requests_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "signed-requests",
        "A-1 payload bytes, A-2 COSE_Sign under hum/service-request/1, A-3 freshness.",
    )
    nonce = fixtures.fixed_bytes("request-nonce", 16)
    issued = fixtures.ISSUED
    method, target, body = "POST", "/v1/log/add?x=1", b"{}"
    pre = (
        services.DOMAIN_REQUEST
        + b"\x00"
        + b"POST /v1/log/add?x=1"
        + b"\x00"
        + hashlib.sha256(body).digest()
        + nonce
        + issued.to_bytes(8, "big")
    )
    payload = services.request_payload(method, target, body, nonce, issued)
    f.add(
        "service-request-payload",
        "The exact A-1 layout",
        S_AUTH,
        {
            "method": method,
            "target": target,
            "body": hexify(body),
            "nonce": hexify(nonce),
            "issued": issued,
        },
        {"preimage": hexify(pre), "payload": hexify(payload)},
    )
    signers = [(b"a1", fx.keys["a1"]), (b"a2", fx.keys["a2"])]
    keys = {n.encode(): fx.keys[n].public for n in ("a1", "a2", "a3")}
    cs, header = services.sign_request(signers, method, target, body, nonce, issued)
    assert services.verify_request(cs, keys, 2, method, target, body, nonce, issued) == 2
    f.add(
        "request-valid",
        "authority request signed a1+a2 (threshold 2)",
        S_AUTH,
        {
            "method": method,
            "target": target,
            "body": hexify(body),
            "nonce": hexify(nonce),
            "issued": issued,
            "keyset_sign_threshold": 2,
        },
        {"cose_sign": hexify(cs), "hum_authority_header": header, "valid_signatures": 2},
    )
    f.add(
        "request-reject-A-1-target",
        "The same signature over a different target",
        S_AUTH,
        {
            "cose_sign": hexify(cs),
            "method": method,
            "target": "/v1/log/add",
            "body": hexify(body),
            "nonce": hexify(nonce),
            "issued": issued,
        },
        rejection={
            "step": None,
            "check": "verify-request",
            "rule": "A-1",
            "valid_signatures": services.verify_request(
                cs, keys, 2, method, "/v1/log/add", body, nonce, issued
            ),
        },
    )
    one, _ = services.sign_request(signers[:1], method, target, body, nonce, issued)
    f.add(
        "request-reject-A-2-threshold",
        "One signature below a threshold of 2",
        S_AUTH,
        {"cose_sign": hexify(one), "keyset_sign_threshold": 2},
        rejection={"step": None, "check": "verify-request", "rule": "A-2", "valid_signatures": 1},
    )
    f.add(
        "request-reject-A-3-stale",
        "Issued 301 seconds ago",
        S_AUTH,
        {"issued": issued, "now": issued + 301, "nonce": hexify(nonce)},
        rejection={
            "step": None,
            "check": "freshness",
            "rule": "A-3",
            "code": services.check_freshness(issued, issued + 301, nonce, set()),
        },
    )
    f.add(
        "request-reject-A-3-replay",
        "A nonce seen in the window",
        S_AUTH,
        {"issued": issued, "now": issued + 10, "nonce": hexify(nonce), "seen": [hexify(nonce)]},
        rejection={
            "step": None,
            "check": "freshness",
            "rule": "A-3",
            "code": services.check_freshness(issued, issued + 10, nonce, {nonce}),
        },
    )
    f.add(
        "tokens",
        "Privacy Pass tokens use the RFC 9578 test vectors for types 0x0001 and 0x0002 unchanged (T-1 replay: a second redemption answers 401 token_spent)",
        S_AUTH,
        {"reference": "RFC 9578 appendix test vectors"},
        {
            "replay_status": 401,
            "replay_code": "token_spent",
            "body": hexify(services.encode_error(services.ErrorBody("token_spent"))),
        },
    )
    return f


def aggregator_file(fx: fixtures.Fixture) -> File:
    f = File(SPEC, "aggregator", "Task ids, receipt signatures, receipt pages.")
    deck = fx.deck_v1.cid  # the deck lineage CID (version 1); every version shares it
    for r in range(4):
        f.add(
            "task-id",
            f"taskId for round {r}, part {r} (the round's first part in the full plan)",
            S_AGG,
            {"deck_lineage_cid": hexify(deck), "round": r, "part": r},
            {"task_id": hexify(services.task_id(deck, r, r))},
        )
    f.add(
        "task-id",
        "taskId is the same for every version of the deck lineage (lineage CID, not version CID)",
        S_AGG,
        {
            "deck_lineage_cid": hexify(deck),
            "other_version_cid": hexify(fx.deck_v3.cid),
            "round": 0,
            "part": 0,
        },
        {"task_id": hexify(services.task_id(deck, 0, 0))},
    )
    key = key_from_label("aggregator-receipt")
    leaf = fixtures.fixed_bytes("receipt-leaf")
    t0 = services.task_id(deck, 0, 0)
    sig = services.receipt_sign(key, t0, leaf)
    f.add(
        "receipt-valid",
        "Receipt signature over hum/receipt/1 || taskId(0) || leaf",
        S_AGG,
        {
            "seed": hexify(key.seed),
            "public": hexify(key.public),
            "task_id": hexify(t0),
            "leaf": hexify(leaf),
        },
        {"message": hexify(services.DOMAIN_RECEIPT + t0 + leaf), "signature": hexify(sig)},
    )
    f.add(
        "receipt-reject-wrong-key",
        "Verified under another key",
        S_AGG,
        {
            "public": hexify(key_from_label("other").public),
            "task_id": hexify(t0),
            "leaf": hexify(leaf),
            "signature": hexify(sig),
        },
        rejection={"step": None, "check": "receipt-verify", "reason": "wrong-key"},
    )
    f.add(
        "receipt-reject-other-round",
        "Verified under round 1's task id",
        S_AGG,
        {
            "public": hexify(key.public),
            "task_id": hexify(services.task_id(deck, 1, 1)),
            "leaf": hexify(leaf),
            "signature": hexify(sig),
        },
        rejection={"step": None, "check": "receipt-verify", "reason": "other-round"},
    )
    kid = fixtures.fixed_bytes("agg-sign-kid", 8)
    rcpt = services.receipt_body(leaf, sig, kid)
    f.add(
        "receipt-body",
        "The receipt body {0: leaf, 1: signature, 2: kid}, kid naming the sign key that signed",
        S_AGG,
        {"leaf": hexify(leaf), "signature": hexify(sig), "kid": hexify(kid)},
        {"body": hexify(rcpt), "view": jsonable(cbor.decode(rcpt))},
    )
    f.add(
        "receipts-below-minimum",
        "GET .../rounds/{n}/receipts for a release below the minimum: 404, bare not_found (AG-4; "
        "release.md R13: no receipt tree)",
        S_AGG,
        {"below_minimum": True},
        {"status": 404, "body": hexify(services.receipts_response(True)[1])},
    )
    for n in (100, 4096, 4097):
        leaves = [hashlib.sha256(b"leaf%d" % i).digest() for i in range(n)]
        pages = services.receipt_pages(leaves)
        exp = {
            "k": pages["k"],
            "page_count": 1 << pages["k"],
            "page_lengths": [len(p) // 32 for p in pages["pages"]],
            "page_cids": [hexify(c) for c in pages["page_cids"]],
            "root": hexify(pages["root"]),
            "root_blob": hexify(pages["root_blob"]),
            "root_blob_cid": hexify(pages["root_blob_cid"]),
            "first_sorted_leaf": hexify(pages["sorted"][0]),
        }
        exp["response_body"] = hexify(
            services.receipts_response(False, pages["root"], pages["k"], pages["page_cids"])[1]
        )
        f.add(
            f"receipt-pages-{n}",
            f"Pages for {n} padded leaves (leaf i = SHA-256('leaf' + decimal i)); the GET "
            "response {0: root, 1: k, 2: pages} and the root blob {0: k, 1: pages}",
            S_AGG,
            {
                "leaf_rule": "SHA-256(b'leaf' + str(i))",
                "count": n,
                "root_blob_encoding": "CBOR {0: k, 1: [page CID...]}",
            },
            exp,
        )
    leaves = [hashlib.sha256(b"leaf%d" % i).digest() for i in range(100)]
    pages = services.receipt_pages(leaves)
    good = services.receipts_response(False, pages["root"], pages["k"], pages["page_cids"])[1]
    blob = pages["root_blob"]
    assert services.check_receipts_response(good, pages["root"], blob) is None
    f.add(
        "receipts-response-matches-blob",
        "A phone checks the GET .../receipts response {0: root, 1: k, 2: pages} against the "
        "logged release's root and the pinned root blob {0: k, 1: pages} before fetching a page: "
        "all three match",
        S_AGG,
        {
            "response": hexify(good),
            "release_root": hexify(pages["root"]),
            "pinned_root_blob": hexify(blob),
        },  # fmt: skip
        {"accepted": True},
    )
    other_pages = services.receipt_pages(leaves[:50])
    for suffix, resp, desc in (
        ("k", services.receipts_response(False, pages["root"], pages["k"] + 1, pages["page_cids"])[1], "k differs from the pinned blob's"),
        ("pages", services.receipts_response(False, pages["root"], pages["k"], [other_pages["page_cids"][0]] + pages["page_cids"][1:])[1], "a page CID differs from the pinned blob's"),
        ("root", services.receipts_response(False, other_pages["root"], pages["k"], pages["page_cids"])[1], "root differs from the logged release's receipts[n]"),
    ):  # fmt: skip
        reason = services.check_receipts_response(resp, pages["root"], blob)
        assert reason == f"{suffix}_mismatch", reason
        f.add(
            f"receipts-response-{suffix}-mismatch",
            f"The GET .../receipts response's {desc}: the phone rejects it (services.md Receipts; "
            "the response and the pinned blob are two distinct bodies by design)",
            S_AGG,
            {
                "response": hexify(resp),
                "release_root": hexify(pages["root"]),
                "pinned_root_blob": hexify(blob),
            },  # fmt: skip
            rejection={"step": None, "check": "receipts-response", "reason": reason},
        )
    n = 1_000_000
    leaves = [hashlib.sha256(b"leaf%d" % i).digest() for i in range(n)]
    pages = services.receipt_pages(leaves)
    f.add(
        "receipt-pages-1000000",
        "Pages for 1,000,000 leaves: k = 8, 256 pages",
        S_AGG,
        {"leaf_rule": "SHA-256(b'leaf' + str(i))", "count": n},
        {
            "k": pages["k"],
            "page_count": 1 << pages["k"],
            "page_lengths_sha256": hashlib.sha256(
                cbor.encode([len(p) // 32 for p in pages["pages"]])
            ).hexdigest(),
            "root": hexify(pages["root"]),
            "root_blob_cid": hexify(pages["root_blob_cid"]),
        },
    )
    return f


def errors_file() -> File:
    f = File(SPEC, "errors", "One CBOR error body per code, and the two bare forms (E-2).")
    details = {
        "malformed": "encoding",
        "rejected": None,
        "conflict": "cid_mismatch",
        "forbidden": "secret",
        "closed": "tombstoned",
        "rate_limited": "quota_put",
        "floor": None,
    }
    for code, (status, bare) in services.CODES.items():
        err = services.ErrorBody(
            code,
            detail=None if bare else details.get(code),
            step=7 if code == "rejected" else None,
            rule="D10" if code == "floor" else None,
            retry_after=30 if code in ("rate_limited", "pending") else None,
        )
        f.add(
            f"error-{code}",
            f"{code} -> HTTP {status}",
            S_ERR,
            {
                "code": code,
                "detail": err.detail,
                "step": err.step,
                "rule": err.rule,
                "retryAfter": err.retry_after,
            },
            {
                "status": status,
                "media_type": services.ERROR_MEDIA_TYPE,
                "body": hexify(services.encode_error(err)),
            },
        )
    for code in ("unauthorized", "not_found"):
        f.add(
            f"error-{code.split('_')[0] if code == 'unauthorized' else '404'}-bare".replace(
                "unauthorized", "401"
            ),
            f"Bare {code}: the code and nothing else",
            S_ERR,
            {"code": code},
            {
                "status": services.CODES[code][0],
                "body": hexify(services.encode_error(services.ErrorBody(code))),
            },
        )
    for code_ in (0, 3):
        err = services.host_rejection(code_)
        f.add(
            "error-rejected-host",
            f"A verifier host's rejection carries the masked verifier-runtime code as rule vr-{code_}",
            S_ERR,
            {"code": "rejected", "masked_code": code_},
            {"status": 422, "rule": err.rule, "body": hexify(services.encode_error(err))},
        )
    f.add(
        "error-too_large-presentation",
        "A ballot whose presentation is over 8 KiB: too_large (services.md intake check 1, "
        "ballot.md B1)",
        S_ERR,
        {"code": "too_large", "presentation_bytes": 9216},
        {"status": 413, "body": hexify(services.encode_error(services.ErrorBody("too_large")))},
    )
    f.add(
        "error-reject-detail-leak",
        "A detail that is not a fixed string (a CID text) is refused by the encoder (E-1)",
        S_ERR,
        {
            "code": "not_found",
            "detail": "caewpetn2l6ykgdrg5a5svrnz4kpbwfq6lqp2oqs6omcdgyutromci-leak!",
        },
        rejection={"step": None, "check": "encode-error", "rule": "E-1"},
    )
    return f


def relay_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "relay",
        "O-3 padding buckets, O-5 relay authority, O-6 relay selection, bootstrap gateway "
        "configurations and witnesses. O-6 picks come from a fixed stream, "
        "SHA-256(hum/relay-pick/1 ‖ seed ‖ uint32be(counter)) read as 32-bit draws with "
        "rejection sampling over the set in the order given (shipped relays, then the "
        "context's): a reference device so the vectors are deterministic, not a protocol rule; "
        "a phone uses its CSPRNG and only the set membership and the re-pick rule are normative.",
    )
    for size in (0, 1, 1024, 1025, 4096, 5000, 70_000, 262_144, 262_145, 600_000):
        f.add(
            "padding",
            f"Bucket for a {size}-byte request",
            S_RELAY,
            {"size": size},
            {"bucket": services.padding_bucket(size)},
        )
    svc_auths = [fx.authority_a, fx.keyset_b1.cid]
    f.add(
        "o5-accept",
        "A relay under its own authority",
        S_RELAY,
        {
            "relay_authority": hexify(fx.keyset_d1.cid),
            "service_authorities": [hexify(a) for a in svc_auths],
        },
        {"accept": True},
    )
    f.add(
        "o5-reject",
        "A relay signed by the authority of a service the phone reaches through it",
        S_RELAY,
        {
            "relay_authority": hexify(fx.authority_a),
            "service_authorities": [hexify(a) for a in svc_auths],
        },
        rejection={"step": None, "check": "relay-authority", "rule": "O-5"},
    )
    for suffix, shipped, supported, desc in (
        (
            "bootstrap-gateway-config-one-rotation-old",
            1,
            [1, 2],
            "A first request made with the shipped gateway key configuration one rotation old: "
            "the gateway still decrypts under every configuration shipped in a supported build, "
            "and the phone then replaces the shipped bundle with the lineage's latest version",
        ),
        (
            "bootstrap-gateway-config-unsupported",
            0,
            [1, 2],
            "A shipped configuration from a build no longer supported: the gateway does not "
            "decrypt it (structural: the key configuration id is what is compared)",
        ),
    ):
        got = services.gateway_accepts_config(shipped, supported, 2)
        f.add(
            suffix,
            desc,
            S_RELAY,
            {
                "shipped_key_id": shipped,
                "gateway_supported_key_ids": supported,
                "current_key_id": 2,
            },
            got if got["accepted"] else None,
            rejection=None
            if got["accepted"]
            else {"step": None, "check": "gateway-config", "reason": "unsupported_key_config"},
        )
    shipped = [fx.keyset_d1.cid, cid(b"shipped relay 2 service manifest")]
    relay_a = cid(b"context A relay service manifest")
    relay_b = cid(b"context B relay service manifest")
    seed = fixtures.fixed_bytes("relay-pick-seed")
    picker = services.RelayPicker(seed)
    o6_cases = [
        ("delivery-fetch", "delivery", relay_a, None, "A fetch from context A's delivery service: the set is the shipped relays plus A's relay"),
        ("ballot", "ballot", relay_a, None, "A ballot of context A: shipped relays only; a ballot frame's size is recognisable"),
        ("deck-status-poll", "deck-status", relay_a, None, "A deck status poll of context A: every request to an aggregator uses the shipped relays only (12.13)"),
        ("authored-text-blob-put", "store-put-authored-text", relay_a, None, "The put of an unsigned issue-map object's text blob to A's store: shipped relays only, so A's relay never sees an address write to the store seconds before the object appears in the log (12.13)"),
        ("attachment-put", "store", relay_a, None, "An ordinary attachment put to A's store: the set includes A's relay"),
        ("log-submit", "log-submit", relay_a, None, "An unsigned object's POST /v1/log/add: every submission to a log uses the shipped relays only (12.13)"),
        ("log-read", "log-read", relay_a, None, "A lineage read from A's log for A's own lineage: the set includes A's relay"),
        ("second-context", "delivery", relay_b, None, "A delivery fetch of context B: the set is the shipped relays plus B's relay, never A's"),
        ("no-context", "no-context", None, None, "A request that belongs to no context (a verifier manifest, the gallery): shipped relays only"),
    ]  # fmt: skip
    for suffix, kind, ctx_relay, _, desc in o6_cases:
        candidates = services.relay_set(kind, shipped, [ctx_relay] if ctx_relay else None)
        before = len(picker.draws)
        chosen = picker.pick(candidates)
        f.add(
            f"o6-{suffix}",
            desc,
            S_RELAY,
            {
                "request_kind": kind,
                "context_relays": [hexify(ctx_relay)] if ctx_relay else [],
                "shipped_relays": [hexify(r) for r in shipped],
                "stream_seed": hexify(seed),
                "stream_label": services.RELAY_PICK_LABEL.decode(),
                "stream_counter_before": before,
            },
            {
                "relay_set": [hexify(r) for r in candidates],
                "context_relay_allowed": (ctx_relay in candidates) if ctx_relay else False,
                "draws": picker.draws[before:],
                "chosen": hexify(chosen),
            },
        )
    candidates = services.relay_set("delivery", shipped, [relay_a])
    before = len(picker.draws)
    first = picker.pick(candidates)
    second = picker.pick(candidates, failed=[first])
    assert second != first
    f.add(
        "o6-repick-after-failure",
        "The chosen relay for a delivery fetch is unreachable: the next pick is from the rest of "
        "the set (never the failed one, never a direct connection)",
        S_RELAY,
        {
            "request_kind": "delivery",
            "context_relays": [hexify(relay_a)],
            "shipped_relays": [hexify(r) for r in shipped],
            "stream_seed": hexify(seed),
            "stream_counter_before": before,
        },
        {
            "relay_set": [hexify(r) for r in candidates],
            "first_chosen": hexify(first),
            "failed": [hexify(first)],
            "rest": [hexify(r) for r in candidates if r != first],
            "draws": picker.draws[before:],
            "chosen": hexify(second),
        },
    )
    f.add(
        "o6-all-failed",
        "Every relay in the set has failed: no pick; the phone waits and never connects directly",
        S_RELAY,
        {"request_kind": "ballot", "shipped_relays": [hexify(r) for r in shipped], "failed": [hexify(r) for r in shipped]},
        rejection={"step": None, "check": "relay-pick", "rule": "O-6", "reason": "no relay left; wait, never direct"},
    )  # fmt: skip
    consts = fx.world.witness_keys()
    other = [key_from_label("bootstrap-x").public, key_from_label("bootstrap-y").public]
    f.add(
        "bootstrap-accept",
        "First checkpoint cosigned by both shipped constant keys",
        S_LOG,
        {"constants": [hexify(k) for k in consts], "cosigners": [hexify(k) for k in consts]},
        {"accept": True},
    )
    f.add(
        "bootstrap-reject-outside-constants",
        "Cosigned by two keys outside the constants",
        S_LOG,
        {"constants": [hexify(k) for k in consts], "cosigners": [hexify(k) for k in other]},
        rejection={"step": 7, "rule": "MIN_WITNESSES", "reason": "no constant key cosigned"},
    )
    f.add(
        "bootstrap-reject-one-constant",
        "Cosigned by one constant key only",
        S_LOG,
        {
            "constants": [hexify(k) for k in consts],
            "cosigners": [hexify(consts[0]), hexify(other[0])],
        },
        rejection={"step": 7, "rule": "MIN_WITNESSES", "reason": "one constant cosigner"},
    )
    return f


def log_submission_file() -> File:
    """credentials.md "Validity", logged presentations row, as the log applies it."""
    from .. import credentials as cr

    f = File(
        SPEC,
        "log-submission",
        "The log of record's clock check on objects that carry a membership or sponsor proof: "
        "the disclosed epoch is current (first-hour grace) and issued is within 3,600 s of the "
        "log's clock T, bounds included. V = 3; B is an epoch boundary.",
    )
    v = 3
    e = 40
    boundary = (e + 1) * v * cr.PERIOD
    cases = [
        (
            "accept-current-epoch",
            "current epoch, issued = T",
            e + 1,
            boundary + 9000,
            boundary + 9000,
        ),
        (
            "accept-old-epoch-T-plus-1800",
            "old epoch at T = B + 1800",
            e,
            boundary + 1800,
            boundary + 1800,
        ),
        (
            "reject-old-epoch-T-plus-3660",
            "old epoch at T = B + 3660",
            e,
            boundary + 3660,
            boundary + 3660,
        ),
        (
            "reject-issued-T-plus-7200",
            "issued = T + 7200",
            e + 1,
            boundary + 9000,
            boundary + 16200,
        ),
        (
            "accept-issued-T-plus-3600",
            "issued = T + 3600 (bound included)",
            e + 1,
            boundary + 9000,
            boundary + 12600,
        ),
        (
            "accept-issued-T-minus-3600",
            "issued = T - 3600 (bound included)",
            e + 1,
            boundary + 9000,
            boundary + 5400,
        ),
        (
            "reject-issued-T-minus-3601",
            "issued = T - 3601",
            e + 1,
            boundary + 9000,
            boundary + 5399,
        ),
        (
            "reject-next-epoch-early",
            "a card of the next epoch before the boundary",
            e + 1,
            boundary - 600,
            boundary - 600,
        ),
    ]
    for name, desc, epoch, log_now, issued in cases:
        err = services.log_submission_check(issued, log_now, [(epoch, v)])
        assert (err is None) == name.startswith("accept"), name
        inputs = {
            "card_epoch": epoch,
            "V": v,
            "log_clock_T": log_now,
            "issued": issued,
            "B": boundary,
        }
        if err is None:
            f.add(name, desc, S_LOG, inputs, {"append": True})
        else:
            f.add(
                name,
                desc,
                S_LOG,
                inputs,
                rejection={
                    "step": None,
                    "check": "log-submission",
                    "rule": err.rule,
                    "reason": err.detail,
                    "status": err.status,
                    "body": hexify(services.encode_error(err)),
                },
            )
    return f


def bodies_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "bodies",
        'services.md "Body keys": one service-body-* case per row, each with a JSON view by '
        "field name and the deterministic CBOR bytes with integer keys in field order. Six rows "
        "are provisional (cross-spec.md 12.10): the two log proof responses and the four gallery "
        "responses had no earlier definition; their keys and shapes may change.",
    )
    c33 = fx.deck_v1.cid
    h32 = fixtures.fixed_bytes("h32")
    samples: dict[str, dict] = {
        "log-add-response": {"index": 41, "checkpoint": "hum/log/c...\n42\n...", "path": [h32, h32]},
        "log-entry": {"index": 41, "type": "deck", "authority": fx.authority_a},
        "log-lineage-element": {"index": 41, "cid": c33, "version": 1, "authority": fx.authority_a},
        "agg-deck-open": {
            "taskIds": [[services.task_id(c33, r, p) for p in (0, 4, 8)] for r in range(1)],
            "round0": {"opens": fixtures.ISSUED, "closes": fixtures.ISSUED + 86_400 * 20},
            "cap": 18,
            "phase": 1,
            "leader": fx.authority_a,
            "helper": fx.keyset_b1.cid,
        },
        "agg-deck-state": {
            "taskIds": [[services.task_id(c33, r, p) for p in (0, 4, 8)] for r in range(1)],
            "round0": {"opens": fixtures.ISSUED, "closes": fixtures.ISSUED + 86_400 * 20},
            "cap": 18,
            "phase": 1,
            "leader": fx.authority_a,
            "helper": fx.keyset_b1.cid,
            "state": "round 1",
            "rounds": [
                {"n": 0, "opens": fixtures.ISSUED, "closes": fixtures.ISSUED + 86_400 * 20, "version": None},
                {"n": 1, "opens": fixtures.ISSUED + 86_400 * 21, "closes": fixtures.ISSUED + 86_400 * 24, "version": c33},
            ],
            "versions": [c33],
        },
        "ballot-receipt": {"leaf": h32, "signature": fixtures.fixed_bytes("sig", 64), "kid": fixtures.fixed_bytes("kid", 8)},
        "agg-receipts": {"root": h32, "k": 1, "pages": [c33, c33]},
        "receipt-root-blob": {"k": 1, "pages": [c33, c33]},
        "agg-daily": {"sigma": [10, 1], "buckets": [{"bucket": 0, "increment": 12}, {"bucket": 1, "increment": -3}], "total": 9},
        "agg-propose-request": {"bundle": fixtures.fixed_bytes("bundle", 40), "tables": [c33], "pages": [c33]},
        "agg-propose-response": {"signature": fixtures.fixed_bytes("sig", 64)},
        "verifier-session-request": {"manifest": c33},
        "verifier-session-response": {"id": fixtures.fixed_bytes("session-id", 16), "expires": fixtures.ISSUED + 3600},
        "verifier-evidence": {"name": "match", "kid": fixtures.fixed_bytes("hkid", 8), "ciphertext": fixtures.fixed_bytes("ct", 48)},
        "verifier-issue": {"kid": fixtures.fixed_bytes("hkid", 8), "ciphertext": fixtures.fixed_bytes("ct", 48)},
        "verifier-revocation": {"method": "reissue", "accumulator": None},
        "releases-element": {"cid": c33, "index": 70, "deck": c33, "context": fx.authority_a, "issued": fixtures.ISSUED, "parts": ["tallies", "count", "receipts"]},
        "log-proof-inclusion": {"index": 41, "size": 64, "path": [h32] * 6},
        "log-proof-consistency": {"from": 32, "to": 64, "path": [h32] * 2},
        "gallery-takes": {
            "takes": [services.gallery_takes_element(c33, 90, 2, 0.4123454, True)],
            "ratings": [c33],
            "next": "c3VwZXJjdXJzb3I",
        },
        "gallery-take": {"bundle": fixtures.fixed_bytes("bundle", 40), "ratings": [c33], "versions": [c33], "releases": [c33]},
        "gallery-take-forks": {"takes": [c33]},
        "gallery-ratings": {"releases": [c33, c33]},
    }  # fmt: skip
    assert set(samples) == set(services.BODIES) - {
        "agg-deck-round0",
        "agg-deck-round",
        "agg-daily-bucket",
        "gallery-takes-element",
    }
    for name, named in samples.items():
        data = services.encode_body(name, named)
        assert services.decode_body(name, data) == named
        prov = name in services.PROVISIONAL_BODIES
        f.add(
            f"service-body-{name}",
            ("PROVISIONAL (cross-spec.md 12.10): " if prov else "") + f"body keys for {name}",
            "Body keys",
            {"body": name, "fields": list(services.BODIES[name]), "view": jsonable(_named_view(named)), "provisional": prov},
            {"bytes": hexify(data), "item": jsonable(cbor.decode(data))},
        )  # fmt: skip
    listing = {
        "takes": [
            services.gallery_takes_element(c33, 90, 2, 0.4123454, True),
            services.gallery_takes_element(c33, 91, 0, 1 / 128, False),
            services.gallery_takes_element(c33, 95, 1, None, False),
        ],
        "ratings": [c33],
    }
    data = services.encode_body("gallery-takes", listing)
    assert services.decode_body("gallery-takes", data) == listing
    assert listing["takes"][1]["score"] == 7812 and "score" not in listing["takes"][2]
    f.add(
        "service-body-gallery-takes-unrated-and-tie",
        "PROVISIONAL (cross-spec.md 12.10, fields renamed in 12.12): a listing with a rated "
        "take (score 0.4123454 → 412345), a take whose score 1/128 = 0.0078125 sits exactly on "
        "a six-decimal rounding tie (half to even in binary64 → 0.007812 → 7812, hasGroupScore "
        "false: scored from the overall row), and an unrated take with rated false and no "
        "score key; forkCount and logIndex are take.md's sort-key names; next absent",
        "Body keys",
        {
            "body": "gallery-takes",
            "fields": list(services.BODIES["gallery-takes"]),
            "element_fields": list(services.BODIES["gallery-takes-element"]),
            "scores": [0.4123454, 1 / 128, None],
            "view": jsonable(_named_view(listing)),
            "provisional": True,
        },
        {"bytes": hexify(data), "item": jsonable(cbor.decode(data))},
    )
    f.add(
        "service-body-reject-unknown-field",
        "A body with a field the row does not list is refused by the encoder",
        "Body keys",
        {"body": "agg-receipts", "view": {"root": hexify(h32), "k": 0, "pages": [], "count": 812}},
        rejection={"step": None, "check": "encode-body", "reason": "unknown field: no exact count in the receipts response"},
    )  # fmt: skip
    return f


def _named_view(value):
    if isinstance(value, dict):
        return {k: _named_view(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_named_view(v) for v in value]
    return value


def host_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "host",
        "V-2 at the verifier host: one issuance request per session; an identical retry gets the "
        "identical response in the session or in a later session mapping to the same dedup row; "
        "a different request in the session is conflict; a different request in a later session "
        "against a spent row gets the masked code vr-0, never conflict (TS8). V-4 (RT1): the "
        "host holds every evidence item sealed until the issue call, then opens each under "
        "aad = session ID ‖ SHA-256(request plaintext); an item sealed for another request or "
        "another session ID ends the session with rejected, rule V-4, and nothing is issued. "
        "The response bytes are a placeholder derived from the host secret and the request "
        "hash; the real response is pending BBS and HPKE. Each case is one step of one "
        "sequence against one host, in order.",
    )
    secret = fixtures.fixed_bytes("host-secret")
    authority = fx.authority_a
    s1, s2, s3, s4, s5, s6 = (fixtures.fixed_bytes(f"session-{i}", 16) for i in range(1, 7))
    kid = fixtures.fixed_bytes("kid", 8)
    req_a = cbor.encode({0: 1, 1: fx.deck_v1.cid, 2: kid, 3: [fixtures.fixed_bytes("commit-a", 200)], 4: [1]})  # fmt: skip
    req_b = cbor.encode({0: 1, 1: fx.deck_v1.cid, 2: kid, 3: [fixtures.fixed_bytes("commit-b", 200)], 4: [1]})  # fmt: skip
    req_c = cbor.encode({0: 1, 1: fx.deck_v1.cid, 2: kid, 3: [fixtures.fixed_bytes("commit-c", 200)], 4: [1]})  # fmt: skip
    req_h = cbor.encode({0: 1, 1: fx.deck_v1.cid, 2: kid, 3: [fixtures.fixed_bytes("commit-h1", 200), fixtures.fixed_bytes("commit-h2", 200)], 4: [1]})  # fmt: skip
    row = fixtures.fixed_bytes("dedup-row-1")
    row_c = fixtures.fixed_bytes("dedup-row-c")
    row_h = fixtures.fixed_bytes("dedup-row-h")
    info = services.evidence_info(authority, "match")
    ct = fixtures.fixed_bytes("evidence-ct", 48)

    def sealed(sess, req):
        return {"info": info, "aad": services.evidence_aad(sess, req), "ciphertext": ct}

    host = services.HostSessions(secret, authority)
    # (expected outcome, session, request, dedup row, evidence sealed as (session, request) or None, description)
    steps = [
        ("issued", s1, req_a, row, (s1, req_a), "Evidence sealed for session 1 and request A; request A: opens, issued"),
        ("identical_retry", s1, req_a, row, None, "The identical request again in session 1: the identical response"),
        ("conflict_in_session", s1, req_b, row, None, "A different request in session 1 after one was answered: conflict"),
        ("identical_retry_new_session", s2, req_a, row, (s2, req_a), "Lost response: the identical request in a later session, evidence re-sealed under the new session ID and the same request hash, mapping to the same dedup row: opens, the identical response"),
        ("duplicate_masked", s3, req_b, row, (s3, req_b), "A different request in a later session against the spent row: rejected, rule vr-0 (masked), never conflict"),
        ("evidence_other_request", s4, req_c, row_c, (s4, req_b), "Evidence sealed for request B, request C submitted in the same session: the aad's hash differs, rejected, rule V-4, nothing issued"),
        ("session_ended", s4, req_b, row_c, None, "The same session after a V-4 failure answers nothing more"),
        ("evidence_other_session", s5, req_c, row_c, (s1, req_c), "Session ID replaced in transit: the phone sealed under session 1's ID, the request arrives in session 5: rejected, rule V-4"),
        ("issued", s6, req_h, row_h, (s6, req_h), "Handover first session: one request with two commitments, evidence sealed under its one hash: opens, issued"),
    ]  # fmt: skip
    first_response = None
    for pos, (expect, sess, req, dk, ev, desc) in enumerate(steps):
        if ev is not None:
            host.submit_evidence(sess, "match", sealed(*ev))
        status, out, outcome = host.issue(sess, req, dk)
        assert outcome == expect, (expect, outcome)
        inputs = {
            "host_secret": hexify(secret),
            "verifier_authority": hexify(authority),
            "session_id": hexify(sess),
            "request": hexify(req),
            "request_hash": hexify(services.request_hash(req)),
            "dedup_key": hexify(dk),
            "sequence_position": pos,
        }
        if ev is not None:
            inputs["evidence_sealed_aad"] = hexify(services.evidence_aad(*ev))
            inputs["evidence_sealed_info"] = hexify(info)
        name = expect.replace("_", "-")
        if pos == len(steps) - 1:
            name = "handover-two-commitments"
        if status == 200:
            if first_response is None:
                first_response = out
            expected = {"status": 200, "response": hexify(out)}
            if dk == row:
                assert out == first_response
                expected["same_as_first"] = True
            f.add(f"host-v2-{name}", desc, "Issuer and verifier host", inputs, expected)
        else:
            rule = "V-4" if out.rule == "V-4" else "V-2"
            f.add(
                f"host-v4-{name}" if rule == "V-4" else f"host-v2-{name}",
                desc,
                "Issuer and verifier host",
                inputs,
                rejection={"step": None, "check": "host-issue", "rule": rule, "status": status, "code": out.code, "error_rule": out.rule, "body": hexify(services.encode_error(out))},
            )  # fmt: skip
    return f


def logging_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "logging",
        "L-6 and L-5 (RT2, RU3): a log line is a map of named fields; L-6's table is the "
        "complete set of field names each service may write, with domains, and a line with any "
        "other field or a value outside its domain is forbidden. One allowed and one forbidden "
        "line per service row, plus the aggregator and gateway cases of L-5: never a count of "
        "accepted ballots for a deck or a round, exact or bucketed, before or after the final "
        "version; for ballot intake no line per request, no per-request minute and no count per "
        "deck, round or path; rejections counted by code per deck only for malformed, too_large, "
        "rejected and forbidden; closed and conflict counted at no grain, appearing only in the "
        "service's daily total (rejected_count with no deck and no code). The gateway logs a "
        "path and result code with no connection identifier, or counts per path, nothing for a "
        "ballot-intake path and no intake counter at any grain: ballot requests appear only "
        "inside its daily total of all requests (count with no path). `rule` is L-5 where that "
        "rule names the failure (every L-5 failure is also an L-6 failure) and L-6 otherwise. "
        "Readings the spec leaves open: the delivery row defers to chat.md §12.9's error-log "
        "row, which names no fields (the reference uses service, day, code, minute, context); "
        "`day` is a day number or YYYY-MM-DD; `code` is an error code string or an HTTP status; "
        "`minute` is a Unix time that is a multiple of 60; the resolver's after-24-hours shape "
        "is exactly {cid, count}.",
    )
    deck = hexify(fx.deck_v1.cid)
    ctx = hexify(fx.context_v1.cid)
    auth = hexify(fx.authority_a)
    sec = "What services log"

    def ok(service, suffix, line, desc):
        assert services.check_log_line(service, line) is None, (service, suffix)
        f.add(
            f"log-line-{suffix}", desc, sec, {"service": service, "line": line}, {"allowed": True}
        )

    def bad(service, suffix, line, desc, rule):
        got = services.check_log_line(service, line)
        assert got == rule, (service, suffix, got)
        f.add(f"log-line-{suffix}", desc, sec, {"service": service, "line": line},
              rejection={"step": None, "check": "log-line", "rule": rule})  # fmt: skip

    # ---- aggregator (L-5 and L-6)
    ok("aggregator", "accepted-noised-before-final", {"service": "aggregator", "day": 20740, "deck": deck, "round": 0, "state": "round 0", "code": "malformed", "rejected_count": 3}, "allowed fields only while round 0 is open: a per-deck count of a code that says nothing about a voter")  # fmt: skip
    ok("aggregator", "accepted-noised-after-final", {"service": "aggregator", "day": 20761, "deck": deck, "round": 3, "state": "final", "n_hat": 812, "part": 1, "part_n": 790, "padded_leaves": 1184, "k": 1, "release": deck, "version": 4}, "allowed fields only after the final version: already-noised and public values")  # fmt: skip
    ok("aggregator", "daily-series", {"service": "aggregator", "day": 20741, "deck": deck, "daily_bucket": 3, "daily_increment": -3}, "the noised daily series: a bucket and its noised increment")  # fmt: skip
    ok("aggregator", "daily-total-rejections", {"service": "aggregator", "day": 20741, "rejected_count": 41}, "the service's daily total of rejected requests of every code, with no deck and no code: the only place closed and conflict rejections appear (RU3)")  # fmt: skip
    bad("aggregator", "exact-count-before-final", {"service": "aggregator", "day": 20740, "deck": deck, "round": 0, "accepted": 807}, "an exact count of accepted ballots while round 0 is open", "L-5")  # fmt: skip
    bad("aggregator", "exact-count-after-final", {"service": "aggregator", "day": 20761, "deck": deck, "round": 3, "release": deck, "ballots": 807}, "an exact count after the final version", "L-5")  # fmt: skip
    bad("aggregator", "bucketed-count", {"service": "aggregator", "day": 20740, "deck": deck, "round": 0, "accepted_bucket_50": 800}, "a count bucketed to the nearest 50 from the exact value (12.10 replaces the bucket of 50 of 12.9)", "L-5")  # fmt: skip
    bad("aggregator", "per-request-intake", {"service": "aggregator", "day": 20740, "deck": deck, "round": 0, "minute": 1791849600}, "one line per ballot-intake request, marked by a per-request minute (RT2)", "L-5")  # fmt: skip
    bad("aggregator", "conflict-duplicate-per-deck", {"service": "aggregator", "day": 20740, "deck": deck, "round": 0, "code": "conflict", "rejected_count": 2}, "a per-deck count of conflict (detail duplicate): with one open deck it is a per-deck count of pseudonyms that voted before (RT2); the code domain with deck present is the four voter-neutral codes", "L-5")  # fmt: skip
    bad("aggregator", "conflict-duplicate-any-grain", {"service": "aggregator", "day": 20740, "code": "conflict", "rejected_count": 2}, "a count of conflict with no deck, service-wide: still a count by a nullifier-dependent code; it may appear only inside the daily total (RU3)", "L-5")  # fmt: skip
    bad("aggregator", "closed-per-deck", {"service": "aggregator", "day": 20745, "deck": deck, "round": 1, "code": "closed", "rejected_count": 5}, "a per-deck count of closed on a different round-0 body (nullifier-dependent)", "L-5")  # fmt: skip
    bad("aggregator", "nullifier-field", {"service": "aggregator", "day": 20740, "deck": deck, "nullifier": "00" * 32}, "a nullifier in a log line: a field outside the aggregator row (and invariant 1)", "L-6")  # fmt: skip
    bad("aggregator", "round-out-of-domain", {"service": "aggregator", "day": 20740, "deck": deck, "round": 7}, "round 7: a value outside its domain (0..3)", "L-6")  # fmt: skip
    # ---- gateway (L-5 and L-6)
    ballot_path = f"/v1/agg/decks/{deck[:12]}/rounds/0/ballots"
    ok("gateway", "gateway-path-count-non-ballot", {"service": "gateway", "day": 20740, "path": "/v1/log/entry", "code": 200, "count": 1203}, "a per-path count for a path that is not ballot intake")  # fmt: skip
    ok("gateway", "gateway-daily-total-all", {"service": "gateway", "day": 20740, "count": 48_211}, "the gateway's daily total of all requests to every service it fronts (count with no path): the only place ballot requests appear")  # fmt: skip
    bad("gateway", "gateway-path-count-ballot", {"service": "gateway", "day": 20740, "path": ballot_path, "count": 807}, "a per-path count for a ballot-intake path: a count of accepted sends (RT2)", "L-5")  # fmt: skip
    bad("gateway", "gateway-ballot-line", {"service": "gateway", "day": 20740, "path": ballot_path, "code": 200}, "one line per request on a ballot-intake path, even without a connection identifier", "L-5")  # fmt: skip
    bad("gateway", "gateway-intake-daily-counter", {"service": "gateway", "day": 20740, "ballot_intake_daily": 807}, "a daily counter for ballot intake: with one open deck it equals that deck's accepted sends (RU3)", "L-5")  # fmt: skip
    bad("gateway", "gateway-connection", {"service": "gateway", "day": 20740, "path": "/v1/log/entry", "code": 200, "connection": 4471}, "a connection identifier beside a path: joins a relay connection to a request", "L-6")  # fmt: skip
    # ---- one allowed and one forbidden line per remaining service row (L-6)
    ok("log", "log-ok", {"service": "log", "day": 20740, "cid": deck, "type": "deck", "authority": auth, "code": 201, "index": 36, "minute": 1791849600, "size": 1402}, "a submission line: CID, type, authority, result code, leaf index, minute, size")  # fmt: skip
    ok("log", "log-rate-counter", {"service": "log", "day": 20740, "window": 20740, "chat_key_count": 3, "nullifier_set_size": 1207}, "the rate-limit counters for one AUTHOR_WINDOW")  # fmt: skip
    bad("log", "log-relay-connection", {"service": "log", "day": 20740, "cid": deck, "code": 201, "relay_connection": 9}, "which relay connection submitted what", "L-6")  # fmt: skip
    bad("log", "log-minute-not-rounded", {"service": "log", "day": 20740, "cid": deck, "code": 201, "minute": 1791849617}, "a timestamp not rounded to the minute (L-1): outside the minute domain", "L-6")  # fmt: skip
    ok("witness", "witness-ok", {"service": "witness", "day": 20740, "origin": "hum/log/c" + "a" * 20, "tree_size": 4096, "code": 200, "minute": 1791849600}, "origin, tree size, result code, minute")  # fmt: skip
    bad("witness", "witness-client", {"service": "witness", "day": 20740, "origin": "hum/log/x", "client_ip": "203.0.113.9"}, "who fetched a checkpoint", "L-6")  # fmt: skip
    ok("host", "host-session-ok", {"session_id": "00112233445566778899aabbccddeeff", "authority": auth, "version": 3, "day": 20740, "outcome": "issued", "memory_bucket": 2, "fuel_bucket": 1}, "the session log line of verifier-runtime.md, exactly")  # fmt: skip
    ok("host", "host-session-rejected", {"session_id": "ffeeddccbbaa99887766554433221100", "authority": auth, "version": 3, "day": 20740, "outcome": 1, "memory_bucket": 2, "fuel_bucket": 1}, "the true outcome: rejection code 1 even when the phone saw 0")  # fmt: skip
    bad("host", "host-dedup-hash", {"session_id": "00112233445566778899aabbccddeeff", "authority": auth, "version": 3, "day": 20740, "outcome": "issued", "dedup_hash": "ab" * 32}, "a dedup key's hash", "L-6")  # fmt: skip
    bad("host", "host-short-session-id", {"session_id": "0011", "authority": auth, "version": 3, "day": 20740, "outcome": "issued"}, "a session ID that is not 16 bytes", "L-6")  # fmt: skip
    ok("delivery", "delivery-error-ok", {"service": "delivery", "day": 20740, "code": 429, "minute": 1791849600, "context": ctx}, "an error line: no body, no client address, minute-rounded (chat.md §12.9)")  # fmt: skip
    bad("delivery", "delivery-sender", {"service": "delivery", "day": 20740, "code": 200, "sender": "alice"}, "a sender identity", "L-6")  # fmt: skip
    ok("store", "store-counters-ok", {"context": ctx, "counter": "bytes_stored", "value": 10_485_760, "token_key_id": 2, "nonce_count": 311}, "per-context counters and per-key redeemed nonce counts (storage.md §6.8)")  # fmt: skip
    bad("store", "store-cid", {"context": ctx, "counter": "bytes_stored", "value": 1, "cid": deck}, "a CID in a store log line", "L-6")  # fmt: skip
    ok("resolver", "resolver-ok", {"service": "resolver", "day": 20740, "cid": deck, "code": 200, "size": 1402, "minute": 1791849600}, "CID requested, result code, size, minute")  # fmt: skip
    ok("resolver", "resolver-after-24h", {"cid": deck, "count": 17}, "after 24 hours only cid and count")  # fmt: skip
    bad("resolver", "resolver-count-with-minute", {"cid": deck, "count": 17, "minute": 1791849600}, "a count beside a minute: the after-24-hours shape is exactly {cid, count}", "L-6")  # fmt: skip
    ok("gallery", "gallery-ok", {"service": "gallery", "day": 20740, "query_shape": "takes?context&cursor", "code": 200, "minute": 1791849600}, "query shape, result code, minute")  # fmt: skip
    bad("gallery", "gallery-viewer", {"service": "gallery", "day": 20740, "query_shape": "takes", "viewer": "v-19"}, "a per-viewer identifier", "L-6")  # fmt: skip
    ok("relay", "relay-ok", {"day": 20740, "client_ip": "203.0.113.9", "window": 20740, "request_count": 240, "gateway": auth, "code": 200}, "client IP and request count per window, gateway, result code")  # fmt: skip
    bad("relay", "relay-path", {"day": 20740, "client_ip": "203.0.113.9", "window": 20740, "request_count": 1, "path": "/v1/log/add"}, "a client paired with a request's content", "L-6")  # fmt: skip
    return f


def generate() -> list[File]:
    fx = fixtures.build()
    return [
        manifests_file(fx),
        bundle_file(fx),
        leaves_file(fx),
        step9_file(fx),
        checkpoint_file(fx),
        witness_file(fx),
        requests_file(fx),
        aggregator_file(fx),
        errors_file(),
        relay_file(fx),
        log_submission_file(),
        bodies_file(fx),
        host_file(fx),
        logging_file(fx),
    ]
