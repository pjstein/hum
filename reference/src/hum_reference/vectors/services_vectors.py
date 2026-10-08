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
            issuer={0: "hum-ds", 1: 1, 2: 86400 * 30},
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
        f.add(
            f"receipt-pages-{n}",
            f"Pages for {n} padded leaves (leaf i = SHA-256('leaf' + decimal i))",
            S_AGG,
            {
                "leaf_rule": "SHA-256(b'leaf' + str(i))",
                "count": n,
                "root_blob_encoding": "CBOR {0: k, 1: [page CID...]}",
            },
            exp,
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
    f = File(SPEC, "relay", "O-3 padding buckets, O-5 relay authority, bootstrap witnesses.")
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
    ]
