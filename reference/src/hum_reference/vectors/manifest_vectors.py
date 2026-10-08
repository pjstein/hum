"""Vectors for docs/specs/manifest.md: CBOR, CIDs, signatures, keysets, the test world and the
eleven verification steps."""

from __future__ import annotations

import copy
from typing import Any

from .. import cbor, cose, fixtures, log
from .. import manifest as m
from ..cid import cid, cid_from_text, cid_text
from ..keys import key_from_label
from . import File, hexify, jsonable

SPEC = "manifest"
S_ENC = "Encoding and content addressing"
S_ENV = "The envelope"
S_KEYS = "Authorities and keys"
S_VER = "Verification"


# ---------------------------------------------------------------- CBOR


def cbor_file() -> File:
    f = File(
        SPEC,
        "cbor",
        "Deterministic CBOR, RFC 8949 section 4.2.1. Inputs use the JSON form from "
        "conformance.md. Reject cases give bytes an implementation must refuse at "
        "verification step 2.",
    )
    good: list[tuple[str, Any]] = [
        ("uint-0", 0),
        ("uint-23", 23),
        ("uint-24", 24),
        ("uint-255", 255),
        ("uint-256", 256),
        ("uint-65535", 65535),
        ("uint-65536", 65536),
        ("uint-2^32", 1 << 32),
        ("uint-max", (1 << 64) - 1),
        ("negative-1", -1),
        ("negative-24", -24),
        ("negative-25", -25),
        ("negative-256", -256),
        ("negative-min", -(1 << 64)),
        ("bytes-empty", b""),
        ("bytes-33", bytes(range(33))),
        ("text-ascii", "deck"),
        ("text-utf8", "ρ ≤ 0.254"),
        ("false", False),
        ("true", True),
        ("null", None),
        ("array-empty", []),
        ("array-mixed", [1, "a", b"\x00", [None]]),
        ("rat", [127, 500]),
        ("map-int-keys-sorted", {10: 0, 1: 0, 256: 0}),
        ("map-text-keys-bytewise", {"b": 0, "aa": 0, "a": 0}),
        ("map-mixed-key-types", {-1: 0, 1: 0, "a": 0, b"\x00": 0, 0: 0}),
        ("map-nested", {9: {0: "x", 1: [1, 2]}, 8: {"context": b"\x01" + bytes(32)}}),
        ("tag-98", cbor.Tag(98, [b"", {}, None, []])),
    ]
    for name, value in good:
        f.add(
            "encode",
            f"Encode {name}",
            S_ENC,
            {"value": jsonable(value)},
            {"cbor": hexify(cbor.encode(value))},
        )

    bad: list[tuple[str, str, str]] = [
        ("int-not-shortest-1", "1800", "uint 0 encoded with a one-byte argument"),
        ("int-not-shortest-2", "190018", "uint 24 encoded with a two-byte argument"),
        ("int-not-shortest-4", "1a0000ffff", "uint 65535 encoded with a four-byte argument"),
        ("int-not-shortest-8", "1b00000000ffffffff", "uint 2^32-1 encoded with eight bytes"),
        ("map-keys-unsorted", "a20100 0000".replace(" ", ""), "map keys 1 then 0"),
        (
            "map-keys-length-first",
            "a2 6162 00 626161 00".replace(" ", "")[:0] + "a2 626161 00 6162 00".replace(" ", ""),
            'RFC 7049 length-first order ("b" before "aa") is not bytewise order',
        ),
        ("map-duplicate-key", "a201000100", "map with key 1 twice"),
        ("indefinite-array", "9f0102ff", "indefinite-length array"),
        ("indefinite-bytes", "5f4101ff", "indefinite-length byte string"),
        ("indefinite-map", "bf0100ff", "indefinite-length map"),
        ("float16", "f93c00", "half-precision float 1.0"),
        ("float64", "fb3ff0000000000000", "double 1.0"),
        ("trailing-bytes", "0100", "two items where one is expected"),
        ("truncated", "a2010002", "map that ends before its second value"),
        ("invalid-utf8", "61ff", "text string that is not UTF-8"),
        ("undefined-simple", "f7", "simple value undefined (23)"),
        ("map-key-array", "a1800100", "an array used as a map key"),
    ]
    for name, hexs, desc in bad:
        assert not cbor.is_canonical(bytes.fromhex(hexs)), name
        f.add(
            "reject", f"Reject {desc}", S_ENC, {"cbor": hexs}, rejection={"step": 2, "reason": name}
        )
    return f


# ---------------------------------------------------------------- CID


def cid_file(fx: fixtures.Fixture) -> File:
    f = File(SPEC, "cid", "0x01 + SHA-256; text form 'c' + lowercase base32, no padding.")
    for name, data in [
        ("empty", b""),
        ("hello", b"hello"),
        ("one-kib", bytes(1024)),
        ("deck-v1-envelope", fx.deck_v1.envelope),
    ]:
        c = cid(data)
        f.add(
            "compute",
            f"CID of {name}",
            S_ENC,
            {"data": hexify(data)},
            {"cid": hexify(c), "text": cid_text(c)},
        )
    c = cid(b"hello")
    f.add(
        "parse",
        "Parse the text form back to bytes",
        S_ENC,
        {"text": cid_text(c)},
        {"cid": hexify(c)},
    )
    text = cid_text(c)
    bad = [
        ("uppercase", text.upper(), "text form must be lowercase"),
        ("padding", text + "=", "no padding allowed"),
        ("no-prefix", text[1:], "missing the 'c' prefix"),
        ("wrong-length", text[:-4], "digest is not 32 bytes"),
        ("unknown-alg", "c" + cid_text(b"\x01" + c[1:])[1:3].replace("a", "b", 1) + text[3:],
         "algorithm byte is not 0x01"),
    ]  # fmt: skip
    for name, bad_text, why in bad:
        try:
            cid_from_text(bad_text)
            raise AssertionError(f"expected {name} to fail")
        except ValueError:
            pass
        f.add(
            "reject",
            f"Reject text form: {why}",
            S_ENC,
            {"text": bad_text},
            rejection={"step": 3, "reason": name},
        )
    return f


# ---------------------------------------------------------------- signatures


def signature_file() -> File:
    f = File(
        SPEC,
        "signature",
        "COSE_Sign with a detached payload (the CID) and external_aad 'hum/manifest/1' "
        "(ADR 0081-w0-08). Keys are Ed25519; seeds are given so signatures are reproducible.",
    )
    key = key_from_label("a1")
    c = cid(b"a manifest")
    sig = cose.sign_cid(key, b"a1", c)
    f.add(
        "sign",
        "Sign a CID with one key",
        S_ENV,
        {
            "seed": hexify(key.seed),
            "public": hexify(key.public),
            "kid": hexify(b"a1"),
            "cid": hexify(c),
        },
        {
            "protected": hexify(sig.protected),
            "sig_structure": hexify(cose.sig_structure(sig.protected, c)),
            "signature": hexify(sig.signature),
            "cose_sign": hexify(cose.encode_cose_sign([sig])),
        },
    )
    key2 = key_from_label("a2")
    sig2 = cose.sign_cid(key2, b"a2", c)
    f.add(
        "sign",
        "Two signers on one CID; signatures are independent of each other",
        S_ENV,
        {
            "signers": [
                {"seed": hexify(key.seed), "kid": hexify(b"a1")},
                {"seed": hexify(key2.seed), "kid": hexify(b"a2")},
            ],
            "cid": hexify(c),
        },
        {"cose_sign": hexify(cose.encode_cose_sign([sig, sig2]))},
    )
    f.add(
        "verify",
        "A valid signature verifies",
        S_ENV,
        {
            "public": hexify(key.public),
            "cid": hexify(c),
            "cose_sign": hexify(cose.encode_cose_sign([sig])),
        },
        {"valid": True},
    )
    other = cid(b"another manifest")
    f.add(
        "reject",
        "The same signature over another CID does not verify",
        S_ENV,
        {
            "public": hexify(key.public),
            "cid": hexify(other),
            "cose_sign": hexify(cose.encode_cose_sign([sig])),
        },
        rejection={"step": 6, "reason": "wrong-cid"},
    )
    raw = key.sign(cose.sig_structure(sig.protected, c, external_aad=b""))
    nodomain = cose.Signature(sig.protected, b"a1", cose.ALG_EDDSA, raw)
    f.add(
        "reject",
        "A signature made without the hum/manifest/1 domain string does not verify",
        S_ENV,
        {
            "public": hexify(key.public),
            "cid": hexify(c),
            "cose_sign": hexify(cose.encode_cose_sign([nodomain])),
        },
        rejection={"step": 6, "reason": "no-domain-string"},
    )
    raw2 = key.sign(cose.sig_structure(sig.protected, c, external_aad=b"ballot/1"))
    f.add(
        "reject",
        "A signature under another domain (ballot/1) does not verify",
        S_ENV,
        {
            "public": hexify(key.public),
            "cid": hexify(c),
            "cose_sign": hexify(
                cose.encode_cose_sign([cose.Signature(sig.protected, b"a1", cose.ALG_EDDSA, raw2)])
            ),
        },
        rejection={"step": 6, "reason": "other-domain"},
    )
    bad_alg = cose.Signature(cbor.encode({1: -7, 4: b"a1"}), b"a1", -7, sig.signature)
    f.add(
        "reject",
        "An unknown algorithm (-7, ES256) in the protected header does not verify",
        S_ENV,
        {
            "public": hexify(key.public),
            "cid": hexify(c),
            "cose_sign": hexify(cose.encode_cose_sign([bad_alg])),
        },
        rejection={"step": 6, "reason": "unknown-algorithm"},
    )
    return f


# ---------------------------------------------------------------- keysets


def keyset_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "keyset",
        "Keyset bodies and the pre-rotation commitment (provisional body layout, ADR 0081-w0-08).",
    )
    b_keys = [fixtures.kk(n, fx.keys[n], "sign", "rotate") for n in ("b1", "b2", "b3")]
    f.add(
        "commitment",
        "Next-keyset commitment: SHA-256 of CBOR [[kid, public]...] sorted by kid",
        S_KEYS,
        {"keys": [{"kid": hexify(k.kid), "public": hexify(k.public)} for k in b_keys]},
        {"commitment": hexify(m.next_commitment(b_keys))},
    )
    env = cbor.decode(fx.keyset_a1.envelope)
    f.add(
        "body",
        "Keyset A version 1 as built in the test world (no authority field: it is its own)",
        S_KEYS,
        {
            "keys": [
                {
                    "kid": hexify(n.encode()),
                    "public": hexify(fx.keys[n].public),
                    "roles": ["sign", "rotate"],
                }
                for n in ("a1", "a2", "a3")
            ],
            "sign_threshold": 2,
            "rotate_threshold": 2,
            "next": [{"kid": hexify(k.kid), "public": hexify(k.public)} for k in b_keys],
        },
        {
            "body": jsonable(env[m.BODY]),
            "envelope": hexify(fx.keyset_a1.envelope),
            "cid": hexify(fx.keyset_a1.cid),
        },
    )
    env2 = cbor.decode(fx.keyset_a2.envelope)
    f.add(
        "body",
        f"Keyset A version 2: rotation with a revocation of a3 from log position "
        f"{fixtures.REVOKE_A3_FROM}",
        S_KEYS,
        {
            "prev": hexify(fx.keyset_a1.cid),
            "revocations": [{"kid": hexify(b"a3"), "from_position": fixtures.REVOKE_A3_FROM}],
        },
        {
            "body": jsonable(env2[m.BODY]),
            "envelope": hexify(fx.keyset_a2.envelope),
            "cid": hexify(fx.keyset_a2.cid),
        },
    )
    return f


# ---------------------------------------------------------------- world and verification


def bundle_json(b: m.Bundle) -> dict[str, Any]:
    out: dict[str, Any] = {
        "cid": hexify(b.cid),
        "envelope": hexify(b.envelope),
        "signatures": hexify(b.signatures),
    }
    if b.proof is not None:
        out["log"] = {
            "log": hexify(b.proof.log),
            "index": b.proof.position,
            "checkpoint": b.proof.checkpoint_note,
            "path": [hexify(h) for h in b.proof.inclusion],
        }
        if b.proof.consistency is not None:
            out["log"]["consistency_from_held"] = [hexify(h) for h in b.proof.consistency]
    return out


def world_file(fx: fixtures.Fixture) -> File:
    w = fx.world
    f = File(
        SPEC,
        "world",
        "The test world every verification case resolves against: the log, its witnesses, every "
        "logged bundle, and a readable view of each envelope. Positions 9 and up were appended "
        "by a misbehaving log and are there to be rejected.",
    )
    names = {b.cid: n for n, b in fx.named.items()}
    f.add(
        "world",
        "Log, witnesses and all bundles",
        S_VER,
        {
            "log": {
                "authority": hexify(w.log_authority),
                "public": hexify(w.log_public),
                "origin": w.origin(),
                "seed": hexify(w.log_key.seed),
            },
            "witnesses": [
                {
                    "authority": hexify(a),
                    "name": log.witness_name(a),
                    "public": hexify(k.public),
                    "seed": hexify(k.seed),
                    "keyset_envelope": hexify(fx.witness_keysets[a]),
                }
                for a, k in w.witnesses.items()
            ],
            "keys": {
                n: {"seed": hexify(k.seed), "public": hexify(k.public)} for n, k in fx.keys.items()
            },
        },
        {
            "entries": [hexify(leaf) for leaf in w.leaves],
            "checkpoint": w.note().text(),
            "bundles": [
                {"name": names[b.cid], **bundle_json(b), "view": jsonable(cbor.decode(b.envelope))}
                for b in w.bundles.values()
            ],
        },
    )
    return f


def _ctx_json(fx, *, now, held, witnesses, for_action) -> dict[str, Any]:
    return {
        "now": now,
        "log_authority": hexify(fx.world.log_authority),
        "log_public": hexify(fx.world.log_public),
        "held_checkpoint": None if held is None else {"size": held[0], "root": hexify(held[1])},
        "witness_keys": [hexify(k) for k in witnesses],
        "min_witnesses": 2,
        "for_action": for_action,
    }


def verification_file(fx: fixtures.Fixture) -> File:
    f = File(
        SPEC,
        "verification",
        "The eleven verification steps. Each case gives a bundle and the phone's state; unresolved "
        "CIDs are looked up in world.json. A fresh verification cache is used for every case. At "
        "least one rejecting case per step.",
    )
    w = fx.world
    all_witnesses = w.witness_keys()

    def run(
        suffix,
        desc,
        bundle,
        *,
        now=fixtures.NOW,
        held_size=0,
        held_root=None,
        witnesses=None,
        for_action=True,
        step=None,
        checkpoint_override=None,
        log_override=None,
    ):
        witnesses = all_witnesses if witnesses is None else witnesses
        ctx = w.context(now=now, held_size=held_size)
        if held_root is not None:
            ctx.held_checkpoint = (held_size, held_root)
        ctx.witness_keys = list(witnesses)
        if checkpoint_override is not None:
            # The phone received every bundle under this (tampered) checkpoint.
            ctx.resolver = {c: copy.deepcopy(b) for c, b in ctx.resolver.items()}
            for b in ctx.resolver.values():
                if b.proof is not None:
                    b.proof.checkpoint_note = checkpoint_override
            bundle = copy.deepcopy(bundle)
            bundle.proof.checkpoint_note = checkpoint_override
        if log_override is not None:
            bundle = copy.deepcopy(bundle)
            bundle.proof.log = log_override
        held = ctx.held_checkpoint
        inputs = {
            "bundle": bundle_json(bundle),
            "context": _ctx_json(
                fx, now=now, held=held, witnesses=witnesses, for_action=for_action
            ),
        }
        if checkpoint_override is not None:
            inputs["context"]["checkpoint_override"] = checkpoint_override
        try:
            env = m.verify_bundle(ctx, bundle, for_action=for_action)
        except m.Rejection as e:
            if step is None or e.step != step:
                raise AssertionError(f"{suffix} {desc!r}: expected step {step}, got {e}") from e
            f.add(suffix, desc, S_VER, inputs, rejection={"step": e.step, "reason": e.reason})
            return
        if step is not None:
            raise AssertionError(f"{suffix} {desc!r}: expected rejection at step {step}, accepted")
        f.add(
            suffix,
            desc,
            S_VER,
            inputs,
            {"accept": True, "type": env[m.TYPE], "version": env[m.VERSION]},
        )

    # accepted
    for name in [
        "keyset_log",
        "keyset_a1",
        "context_v1",
        "deck_v1",
        "deck_v2",
        "keyset_a2",
        "deck_v3",
        "keyset_b1",
        "keyset_d1",
        "chain_16",
    ]:
        run("accept", f"{name} verifies", fx.named[name])
    run(
        "accept",
        "deck v3 verifies with a held checkpoint of size 3 and a consistency proof",
        fixtures.build(held_size=3).deck_v3,
        held_size=3,
    )
    run(
        "accept",
        f"deck v1 (signed by a3 at position 3) stands: a3 is revoked only from position "
        f"{fixtures.REVOKE_A3_FROM}",
        fx.deck_v1,
    )
    run(
        "accept",
        "An expired deck still verifies when not acting under it (for_action false)",
        fx.deck_v3,
        now=fixtures.EXPIRES + 1,
        for_action=False,
    )

    def resign(env, signers, proof_from=None):
        data = cbor.encode(env)
        c = cid(data)
        sigs = [cose.sign_cid(fx.keys[s], s.encode(), c) for s in signers]
        proof = copy.deepcopy(proof_from.proof) if proof_from else None
        return m.Bundle(data, cose.encode_cose_sign(sigs), c, proof)

    deck_env = cbor.decode(fx.deck_v1.envelope)

    # step 1
    big = copy.deepcopy(deck_env)
    big[m.BODY][7] = bytes(m.MAX_ENVELOPE_BYTES)
    run("step-01", "Envelope over 64 KiB", resign(big, ["a1", "a2"], fx.deck_v1), step=1)

    # step 2
    def raw_bundle(data, proof_from):
        c = cid(data)
        sigs = [cose.sign_cid(fx.keys[s], s.encode(), c) for s in ("a1", "a2")]
        return m.Bundle(data, cose.encode_cose_sign(sigs), c, copy.deepcopy(proof_from.proof))

    canon = fx.deck_v1.envelope
    assert canon[1:2] == b"\x00"
    run(
        "step-02",
        "Envelope with a non-shortest integer",
        raw_bundle(canon[:1] + b"\x18\x00" + canon[2:], fx.deck_v1),
        step=2,
    )
    items = sorted(
        ((cbor.encode(k), cbor.encode(v)) for k, v in deck_env.items()), key=lambda kv: kv[0]
    )
    items[0], items[1] = items[1], items[0]
    unsorted = bytes([0xA0 | len(items)]) + b"".join(k + v for k, v in items)
    run(
        "step-02",
        "Envelope with map keys out of bytewise order",
        raw_bundle(unsorted, fx.deck_v1),
        step=2,
    )
    run("step-02", "Envelope with trailing bytes", raw_bundle(canon + b"\x00", fx.deck_v1), step=2)
    run(
        "step-02",
        "Envelope that is an indefinite-length map",
        raw_bundle(b"\xbf" + canon[1:] + b"\xff", fx.deck_v1),
        step=2,
    )
    fl = copy.deepcopy(deck_env)
    fl[m.BODY][3] = 1  # placeholder; spliced into a half-precision float 1.0 (f9 3c00) below
    fl_bytes = cbor.encode(fl).replace(b"\x03\x01", b"\x03\xf9\x3c\x00", 1)
    run(
        "step-02",
        "Envelope containing a floating-point value",
        raw_bundle(fl_bytes, fx.deck_v1),
        step=2,
    )
    # step 3
    wrong = m.Bundle(
        fx.deck_v1.envelope, fx.deck_v1.signatures, fx.deck_v2.cid, copy.deepcopy(fx.deck_v1.proof)
    )
    run("step-03", "Bundle presented under a CID that is not the hash of its bytes", wrong, step=3)

    # step 4
    def mutate(desc, fn, signers=("a1", "a2"), step=4):
        env = copy.deepcopy(deck_env)
        fn(env)
        run(f"step-{step:02d}", desc, resign(env, list(signers), fx.deck_v1), step=step)

    mutate("Unknown type 'poll'", lambda e: e.__setitem__(m.TYPE, "poll"))
    mutate("Unknown spec version 2", lambda e: e.__setitem__(m.SPEC, 2))
    mutate("Version 1 carrying prev", lambda e: e.__setitem__(m.PREV, fx.deck_v1.cid))
    mutate("Version 2 without lineage", lambda e: e.__setitem__(m.VERSION, 2))
    mutate("Missing authority on a non-keyset", lambda e: e.pop(m.AUTHORITY))
    mutate("Unknown envelope key 12", lambda e: e.__setitem__(12, 1))
    mutate("Body is not a map", lambda e: e.__setitem__(m.BODY, []))
    mutate("Refs value is not a CID", lambda e: e[m.REFS].__setitem__("x", b"\x01\x02"))
    mutate(
        "Refs value with an unknown algorithm byte",
        lambda e: e[m.REFS].__setitem__("x", b"\x02" + bytes(32)),
    )
    mutate("Version 0", lambda e: e.__setitem__(m.VERSION, 0))

    def too_many_refs(e):
        for i in range(m.MAX_REFS + 1):
            e[m.REFS][f"r{i}"] = cid(i.to_bytes(4, "big"))

    mutate("More than 1,024 references", too_many_refs)
    ks_env = cbor.decode(fx.keyset_a1.envelope)

    def ks_mutate(desc, fn, step=4, signers=("a1", "a2")):
        env = copy.deepcopy(ks_env)
        fn(env)
        run(f"step-{step:02d}", desc, resign(env, list(signers), fx.keyset_a1), step=step)

    ks_mutate(
        "Keyset with a 31-byte public key",
        lambda e: e[m.BODY][m.KS_KEYS][0].__setitem__(m.KEY_PUBLIC, bytes(31)),
    )
    ks_mutate(
        "Keyset with an unknown role",
        lambda e: e[m.BODY][m.KS_KEYS][0].__setitem__(m.KEY_ROLES, ["admin"]),
    )
    ks_mutate(
        "Keyset missing the rotate threshold", lambda e: e[m.BODY][m.KS_THRESHOLDS].pop("rotate")
    )
    ks_mutate(
        "Keyset with a zero threshold",
        lambda e: e[m.BODY][m.KS_THRESHOLDS].__setitem__("sign", 0),
    )
    ks_mutate(
        "Keyset with duplicate key ids",
        lambda e: e[m.BODY][m.KS_KEYS][1].__setitem__(m.KEY_ID, b"a1"),
    )

    # step 5
    mutate(
        "Authority CID that resolves to nothing",
        lambda e: e.__setitem__(m.AUTHORITY, cid(b"no such authority")),
        step=5,
    )
    mutate(
        "Authority CID that resolves to a context, not a keyset lineage",
        lambda e: e.__setitem__(m.AUTHORITY, fx.context_v1.cid),
        step=5,
    )
    early = resign(deck_env, ["a1", "a2"], fx.deck_v1)
    early.proof.position = 1
    run(
        "step-05",
        "Manifest at log position 1, not after any keyset of its authority (keyset A is at 1)",
        early,
        step=5,
    )

    # step 6
    run(
        "step-06",
        "Only one of two required sign signatures",
        resign(deck_env, ["a1"], fx.deck_v1),
        step=6,
    )
    run(
        "step-06",
        "Two signatures from the same key count once",
        resign(deck_env, ["a1", "a1"], fx.deck_v1),
        step=6,
    )
    run(
        "step-06",
        "Signed by a key the keyset does not list (c1)",
        resign(deck_env, ["a1", "c1"], fx.deck_v1),
        step=6,
    )
    run(
        "step-06",
        f"deck X at position {fixtures.REVOKE_A3_FROM} signed by a3, revoked from that position",
        fx.deck_x,
        step=6,
    )
    tampered = m.Bundle(
        fx.deck_v1.envelope,
        fx.deck_v1.signatures[:-1] + bytes([fx.deck_v1.signatures[-1] ^ 1]),
        fx.deck_v1.cid,
        copy.deepcopy(fx.deck_v1.proof),
    )
    run("step-06", "Last byte of a signature flipped", tampered, step=6)
    run(
        "step-06",
        "Signatures that are not a COSE_Sign structure",
        m.Bundle(
            fx.deck_v1.envelope,
            cbor.encode([1, 2]),
            fx.deck_v1.cid,
            copy.deepcopy(fx.deck_v1.proof),
        ),
        step=6,
    )
    ksb2 = m.envelope(
        "keyset",
        m.build_keyset_body(
            [fixtures.kk("c1", fx.keys["c1"], "sign"), fixtures.kk("c2", fx.keys["c2"], "rotate")],
            1,
            1,
        ),
        authority=fx.keyset_b1.cid,
        version=2,
        lineage=fx.keyset_b1.cid,
        prev=fx.keyset_b1.cid,
        issued=fixtures.ISSUED + 5,
    )
    run(
        "step-06",
        "Keyset rotation signed by a sign-only key, not the rotate threshold",
        resign(ksb2, ["c1"], fx.keyset_b1),
        step=6,
    )

    # step 7
    noproof = m.Bundle(fx.deck_v3.envelope, fx.deck_v3.signatures, fx.deck_v3.cid, None)
    run("step-07", "No inclusion proof (a promise to log is not enough)", noproof, step=7)
    bad_incl = copy.deepcopy(fx.deck_v1)
    bad_incl.proof.inclusion[0] = bytes(32)
    run("step-07", "Inclusion proof with a wrong hash", bad_incl, step=7)
    bad_pos = copy.deepcopy(fx.deck_v1)
    bad_pos.proof.position = 4
    run("step-07", "Inclusion proof for the wrong position", bad_pos, step=7)
    run(
        "step-07",
        "Only one of the checkpoint's cosigners is a listed witness key",
        fx.deck_v1,
        witnesses=all_witnesses[:1],
        step=7,
    )
    run(
        "step-07",
        "None of the checkpoint's cosigners is a listed witness key",
        fx.deck_v1,
        witnesses=[key_from_label("not-a-witness").public],
        step=7,
    )
    run(
        "step-07",
        "Proof from a log that is not the context's accepted log",
        fx.deck_v1,
        log_override=cid(b"another log"),
        step=7,
    )
    note = w.note()
    note.signatures = note.signatures[1:]
    run(
        "step-07",
        "Checkpoint without the log's own signature (applied to every bundle held)",
        fx.deck_v1,
        checkpoint_override=note.text(),
        step=7,
    )
    note = w.note()
    first = note.signatures[0]
    note.signatures[0] = log.NoteSignature(first.name, first.payload[:4] + bytes(64))
    run(
        "step-07",
        "Checkpoint with a forged log signature (applied to every bundle held)",
        fx.deck_v1,
        checkpoint_override=note.text(),
        step=7,
    )
    note = w.note()
    note.signatures = note.signatures[:2]
    run(
        "step-07",
        "Checkpoint cosigned by only one witness (applied to every bundle held)",
        fx.deck_v1,
        checkpoint_override=note.text(),
        step=7,
    )
    run(
        "step-07",
        "Held checkpoint with the same size but a different root",
        fx.deck_v1,
        held_size=len(w.leaves),
        held_root=bytes(32),
        step=7,
    )
    run(
        "step-07",
        "Held checkpoint newer than the one in the bundle",
        fx.deck_v1,
        held_size=len(w.leaves) + 1,
        held_root=bytes(32),
        step=7,
    )
    nocons = fixtures.build(held_size=3).deck_v3
    nocons.proof.consistency = None
    run("step-07", "Held checkpoint older, but no consistency proof", nocons, held_size=3, step=7)
    badcons = fixtures.build(held_size=3).deck_v3
    badcons.proof.consistency[0] = bytes(32)
    run("step-07", "Consistency proof with a wrong hash", badcons, held_size=3, step=7)

    # step 8
    run(
        "step-08",
        "Fork: a second version 2 of the deck lineage, logged after the first",
        fx.deck_v2_fork,
        step=8,
    )
    run("step-08", "prev resolves to nothing", fx.deck_orphan, step=8)
    run("step-08", "prev is version 1 but this is version 3", fx.deck_skip, step=8)
    run("step-08", "Authority changes within the lineage", fx.deck_hijack, step=8)

    # step 9
    run("step-09", "A reference resolves to nothing", fx.deck_dangling, step=9)
    run("step-09", "A reference fails verification (deck X, step 6)", fx.deck_bad_ref, step=9)
    run("step-09", "Reference chain 17 deep (limit 16)", fx.chain_17, step=9)

    # step 10
    run(
        "step-10",
        "Keyset whose keys break the previous version's next-keyset commitment",
        fx.keyset_d2_broken_commitment,
        step=10,
    )
    run(
        "step-10",
        "Keyset whose sign threshold exceeds the keys holding the role",
        fx.keyset_e_threshold,
        step=10,
    )

    # step 11
    run(
        "step-11",
        "Acting under a deck at its expiry time",
        fx.deck_v3,
        now=fixtures.EXPIRES,
        step=11,
    )
    run(
        "step-11",
        "Acting under a deck after its expiry",
        fx.deck_v3,
        now=fixtures.EXPIRES + 86400,
        step=11,
    )
    run(
        "accept",
        "Acting under a deck one second before expiry",
        fx.deck_v3,
        now=fixtures.EXPIRES - 1,
    )
    return f


def generate() -> list[File]:
    fx = fixtures.build()
    return [
        cbor_file(),
        cid_file(fx),
        signature_file(),
        keyset_file(fx),
        world_file(fx),
        verification_file(fx),
    ]
