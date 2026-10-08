"""Vectors for docs/specs/trust-list.md: the core list's three versions, a community list, an
agent list, one invalid case per rule 1-13, and the resolution algorithm of "How a context
uses trust lists".
"""

from __future__ import annotations

import copy
from typing import Any

from .. import cbor, cose, fixtures
from .. import manifest as m
from ..bodies import context as c
from ..bodies import trust_list as tl
from ..bodies import verifier as vf
from ..cid import cid as compute_cid
from ..cid import cid_text
from ..keys import key_from_label
from . import File, hexify, jsonable
from .manifest_vectors import bundle_json
from .verifier_vectors import World as VerifierWorld
from .verifier_vectors import agent_class, district, issuer

SPEC = "trust-list"
S_RULES = "Validation rules"
S_RESOLVE = "How a context uses trust lists"


def auth(label: str) -> bytes:
    return compute_cid(b"verifier authority " + label.encode())


DISTRICT, PILOT, AGE, UNIQUE, AGENT = (
    auth(x) for x in ("district", "pilot", "age-band", "uniqueness", "agent")
)
CODE_DISTRICT = compute_cid(b"district module")
CODE_AGE = compute_cid(b"age module")
CODE_UNIQUE = compute_cid(b"uniqueness module")


class World:
    def __init__(self) -> None:
        self.fx = fixtures.build()
        self.w = self.fx.world
        self.keys = {n: key_from_label(f"trust-list-{n}") for n in ("ts", "tr")}
        self.authority = self.w.append(
            fixtures.service_keyset("ts", "tr", self.keys), [(b"tr", self.keys["tr"])]
        ).cid
        self.named: dict[str, m.Bundle] = {}

    def envelope(self, body, *, version=1, lineage=None, prev=None, offset=0) -> dict:
        return m.envelope(
            "trust-list",
            body,
            authority=self.authority,
            version=version,
            lineage=lineage,
            prev=prev,
            issued=fixtures.ISSUED + offset,
        )

    def append(self, name: str, env: dict) -> m.Bundle:
        b = self.w.append(env, [(b"ts", self.keys["ts"])])
        self.named[name] = b
        return b


def core(version: int) -> dict:
    entries = [
        tl.entry(
            DISTRICT,
            ["ward", "area"],
            attested=[CODE_DISTRICT],
            note="District verifier. County voter file, reviewed 2026-09.",
        ),
    ]
    removed = None
    if version == 1:
        entries.append(tl.entry(PILOT, ["ward"], note="Pilot district verifier."))
    if version >= 2:
        entries.append(
            tl.entry(
                AGE,
                ["age-band"],
                min_assurance=2,
                attested=[CODE_AGE],
                note="Age band from voter file or document.",
            )
        )
        entries.append(
            tl.entry(
                UNIQUE,
                ["unique"],
                min_assurance=3,
                min_version=2,
                attested=[CODE_UNIQUE],
                note="Uniqueness. Version 1 had a dedup flaw; version 2 fixed it under a new issuer key.",
            )
        )
    if version == 2:
        entries.insert(1, tl.entry(PILOT, ["ward"], note="Pilot district verifier."))
    if version == 3:
        removed = [tl.removal(PILOT, "retired", "Pilot district verifier, superseded.")]
    return tl.body(
        name="Hum core verifiers",
        publisher="Hum reference operator",
        kind="core",
        entries=entries,
        min_assurance=2,
        removed=removed,
        review_period=7_776_000,
    )


def community() -> dict:
    return tl.body(
        name="Millbrook civic verifiers",
        publisher="Millbrook Civic Alliance",
        kind="community",
        area="Millbrook",
        min_assurance=1,
        entries=[
            tl.entry(DISTRICT, [], note="Anything the district verifier issues"),
            tl.entry(auth("library"), ["approved"], note="Library card holders"),
        ],
    )


def agent_list() -> dict:
    return tl.body(
        name="Hum agent sponsors",
        publisher="Hum reference operator",
        kind="core",
        classes=["agent"],
        min_assurance=1,
        entries=[tl.entry(AGENT, ["agent-sponsor"], note="Platform agent sponsor verifier")],
    )


def build() -> tuple[World, dict[str, Any]]:
    w = World()
    valid: dict[str, m.Bundle] = {}
    c1 = w.append("core-v1", w.envelope(core(1)))
    c2 = w.append("core-v2", w.envelope(core(2), version=2, lineage=c1.cid, prev=c1.cid, offset=60))
    c3 = w.append(
        "core-v3", w.envelope(core(3), version=3, lineage=c1.cid, prev=c2.cid, offset=120)
    )
    valid.update({"core-v1": c1, "core-v2": c2, "core-v3": c3})
    valid["community"] = w.append("community", w.envelope(community()))
    valid["agent"] = w.append("agent", w.envelope(agent_list()))
    bad10 = []

    def lineage(name, rule, v1_body, v2_body):
        v1 = w.append(f"lineage-{name}-v1", w.envelope(v1_body))
        bad10.append(
            (
                name,
                rule,
                w.append(
                    f"lineage-{name}-bad",
                    w.envelope(v2_body, version=2, lineage=v1.cid, prev=v1.cid, offset=60),
                ),
            )
        )

    cm = community()
    cm[tl.NAME] = "Community lineage for 11"
    cm2 = copy.deepcopy(cm)
    cm2[tl.SCOPE][tl.SC_KIND] = "core"
    cm2[tl.MIN_ASSURANCE] = 2
    lineage("11-kind", "11", cm, cm2)
    v1 = core(1)
    v1[tl.NAME] = "Core lineage for 12"
    drop = core(3)
    drop[tl.NAME] = v1[tl.NAME]
    drop.pop(tl.REMOVED)
    lineage("12-dropped-without-removed", "12", v1, drop)
    v1b = core(1)
    v1b[tl.NAME] = "Core lineage for 13"
    phantom = core(3)
    phantom[tl.NAME] = v1b[tl.NAME]
    phantom[tl.REMOVED] = [
        tl.removal(PILOT, "retired"),
        tl.removal(auth("never-listed"), "conduct"),
    ]
    lineage("13-removal-never-entry", "13", v1b, phantom)
    w.w.finalize()
    return w, {"valid": valid, "bad10": bad10}


def _resign(w: World, env: dict, proof_from: m.Bundle) -> m.Bundle:
    data = cbor.encode(env)
    cid = compute_cid(data)
    return m.Bundle(
        data,
        cose.encode_cose_sign([cose.sign_cid(w.keys["ts"], b"ts", cid)]),
        cid,
        copy.deepcopy(proof_from.proof),
    )


def _run(f, w, suffix, desc, bundle, *, step=None, rule=None):
    ctx = w.fx.world.context(now=fixtures.NOW)
    inputs = {"bundle": bundle_json(bundle), "view": jsonable(cbor.decode(bundle.envelope))}
    try:
        env = m.verify_bundle(ctx, bundle)
    except m.Rejection as e:
        if step is None or e.step != step or (rule is not None and e.rule != rule):
            raise AssertionError(
                f"{suffix}: expected step {step} rule {rule}, got {e} (rule {e.rule})"
            ) from e
        f.add(
            suffix,
            desc,
            S_RULES,
            inputs,
            rejection={"step": e.step, "rule": e.rule, "reason": e.reason},
        )
        return
    if step is not None:
        raise AssertionError(f"{suffix}: expected rejection, accepted")
    f.add(
        suffix,
        desc,
        S_RULES,
        inputs,
        {"accept": True, "entries": len(env[m.BODY][tl.ENTRIES]), "version": env[m.VERSION]},
    )


def manifests_file(w: World, built) -> File:
    f = File(
        SPEC,
        "manifests",
        "Trust lists: the core list's three versions (version 3 removes the pilot "
        "verifier), a community list, an agent list; one invalid per rule. Rules 1-9 reject at step 4; "
        "rule 10 is the 64 KiB envelope (manifest step 1, see manifest/verification step-01); rules 11-13 "
        "reject at step 10.",
    )
    for name, b in built["valid"].items():
        _run(f, w, f"trust-list-valid-{name}", f"{name} verifies", b)
    body = lambda e: e[m.BODY]  # noqa: E731
    cases = [
        (
            "1",
            "kind",
            "scope.kind 'regional'",
            lambda e: body(e)[tl.SCOPE].__setitem__(tl.SC_KIND, "regional"),
            "core-v1",
        ),
        (
            "1",
            "classes-empty",
            "scope.classes empty",
            lambda e: body(e)[tl.SCOPE].__setitem__(tl.SC_CLASSES, []),
            "core-v1",
        ),
        (
            "1",
            "classes-unknown",
            "scope.classes with 'robot'",
            lambda e: body(e)[tl.SCOPE].__setitem__(tl.SC_CLASSES, ["robot"]),
            "core-v1",
        ),
        (
            "1",
            "lang",
            "lang '1en' fails the pattern",
            lambda e: body(e).__setitem__(tl.LANG, "1en"),
            "core-v1",
        ),
        (
            "2",
            "name-long",
            "name of 65 bytes",
            lambda e: body(e).__setitem__(tl.NAME, "n" * 65),
            "core-v1",
        ),
        (
            "2",
            "note-long",
            "entry note of 141 bytes",
            lambda e: body(e)[tl.ENTRIES][0].__setitem__(tl.EN_NOTE, "n" * 141),
            "core-v1",
        ),
        (
            "2",
            "entries-257",
            "257 entries",
            lambda e: body(e).__setitem__(
                tl.ENTRIES, [tl.entry(auth(f"v{i}"), ["x"]) for i in range(257)]
            ),
            "core-v1",
        ),
        (
            "3",
            "floor-4",
            "minAssurance 4",
            lambda e: body(e).__setitem__(tl.MIN_ASSURANCE, 4),
            "core-v1",
        ),
        (
            "3",
            "entry-below-floor",
            "entry minAssurance 1 under a floor of 2",
            lambda e: body(e)[tl.ENTRIES][0].__setitem__(tl.EN_MIN_ASSURANCE, 1),
            "core-v1",
        ),
        (
            "4",
            "duplicate-authority",
            "two entries for one authority",
            lambda e: body(e)[tl.ENTRIES].append(tl.entry(DISTRICT, ["area"])),
            "core-v1",
        ),
        (
            "5",
            "authority-alg",
            "entry authority with algorithm byte 0x02",
            lambda e: body(e)[tl.ENTRIES][0].__setitem__(tl.EN_AUTHORITY, b"\x02" + DISTRICT[1:]),
            "core-v1",
        ),
        (
            "5",
            "authority-short",
            "removal authority of 32 bytes",
            lambda e: body(e)[tl.REMOVED][0].__setitem__(tl.RM_AUTHORITY, PILOT[1:]),
            "core-v3",
        ),
        (
            "6",
            "attribute-pattern",
            "attribute 'Ward'",
            lambda e: body(e)[tl.ENTRIES][0].__setitem__(tl.EN_ATTRIBUTES, ["Ward"]),
            "core-v1",
        ),
        (
            "6",
            "attribute-duplicate",
            "attribute listed twice in one entry",
            lambda e: body(e)[tl.ENTRIES][0].__setitem__(tl.EN_ATTRIBUTES, ["ward", "ward"]),
            "core-v1",
        ),
        (
            "7",
            "reason",
            "removal reason 'bored'",
            lambda e: body(e)[tl.REMOVED][0].__setitem__(tl.RM_REASON, "bored"),
            "core-v3",
        ),
        (
            "7",
            "removed-and-entry",
            "removed authority also in entries",
            lambda e: body(e)[tl.REMOVED].append(tl.removal(DISTRICT, "scope")),
            "core-v3",
        ),
        (
            "7",
            "removed-duplicate",
            "the same authority removed twice",
            lambda e: body(e)[tl.REMOVED].append(tl.removal(PILOT, "scope")),
            "core-v3",
        ),
        (
            "8",
            "attested-duplicate",
            "attested CID listed twice",
            lambda e: body(e)[tl.ENTRIES][0].__setitem__(
                tl.EN_ATTESTED, [CODE_DISTRICT, CODE_DISTRICT]
            ),
            "core-v1",
        ),
        (
            "9",
            "minversion-0",
            "minVersion 0",
            lambda e: body(e)[tl.ENTRIES][0].__setitem__(tl.EN_MIN_VERSION, 0),
            "core-v1",
        ),
    ]
    for rule, name, desc, fn, base in cases:
        env = copy.deepcopy(cbor.decode(w.named[base].envelope))
        fn(env)
        _run(
            f,
            w,
            f"trust-list-invalid-{rule}-{name}",
            desc,
            _resign(w, env, w.named[base]),
            step=4,
            rule=rule,
        )
    for name, rule, b in built["bad10"]:
        _run(
            f,
            w,
            f"trust-list-invalid-{name}",
            f"version 2 breaks rule {rule}",
            b,
            step=10,
            rule=rule,
        )
    return f


def resolution_file() -> File:
    f = File(
        SPEC,
        "resolution",
        "Rows a context's sources resolve to, sorted bytewise on canonical CBOR, and "
        "whether a credential satisfies a leaf (step 4 of the algorithm, rules 5 and 6). Verifier versions "
        "are the district lineage and the agent verifier from vectors/verifier.",
    )
    vw = VerifierWorld()
    core3 = core(3)
    ctx_body = fixtures.context_body(vw.fx, vw.authority)
    ctx_body[c.ISSUERS] = [auth("approved-list")]
    rows = tl.resolve_rows(ctx_body, [core3])
    f.add(
        "trust-list-resolve-rows",
        "A context with one list source (core v3) and one direct issuer",
        S_RESOLVE,
        {"trust_lists": [jsonable(core3)], "issuers": [hexify(a) for a in ctx_body[c.ISSUERS]]},
        {
            name: {"rows": jsonable(r), "canonical": [hexify(cbor.encode(x)) for x in r]}
            for name, r in rows.items()
        },
    )
    tl_rows = rows["tl/0"]
    d2 = m.envelope(
        "verifier",
        district(vw, 2),
        authority=DISTRICT,
        version=2,
        lineage=b"\x01" + bytes(32),
        prev=b"\x01" + bytes(32),
        issued=fixtures.ISSUED,
    )
    kid1 = issuer("district-1")[vf.IK_KID]
    kid2 = issuer("district-2", since=2)[vf.IK_KID]
    # uniqueness verifier: the core list wants minVersion 2 and assurance 3
    uni_v2 = m.envelope(
        "verifier",
        district(vw, 2),
        authority=UNIQUE,
        version=2,
        lineage=b"\x01" + bytes(32),
        prev=b"\x01" + bytes(32),
        issued=fixtures.ISSUED,
    )
    uni_v2[m.BODY][vf.ATTRIBUTES].append(vf.attribute("unique", "bool", "gate", "Unique"))
    uni_v2[m.BODY][vf.ASSURANCE] = 3
    agent_env = m.envelope("verifier", agent_class(vw), authority=AGENT, issued=fixtures.ISSUED)
    agent_rows = tl.rows_for_source([c.SRC_TRUST_LIST, 0], ctx_body, [agent_list()])
    checks = [
        ("ward-from-district", tl_rows, "ward", DISTRICT, d2, kid2, "gate", "entry", True),
        (
            "unique-kid-since-1-minversion-2",
            tl_rows,
            "unique",
            UNIQUE,
            uni_v2,
            kid1,
            "gate",
            "vote",
            False,
        ),
        (
            "unique-kid-since-2-minversion-2",
            tl_rows,
            "unique",
            UNIQUE,
            uni_v2,
            kid2,
            "gate",
            "vote",
            True,
        ),
        ("area-breakdown-use", tl_rows, "area", DISTRICT, d2, kid2, "breakdown", "entry", True),
        ("ward-wrong-authority", tl_rows, "ward", PILOT, d2, kid2, "gate", "entry", False),
        ("attribute-not-declared", tl_rows, "age-band", DISTRICT, d2, kid2, "gate", "entry", False),
        ("retired-lineage", tl_rows, "ward", DISTRICT, None, kid2, "gate", "entry", False),
        (
            "agent-list-entry-leaf",
            agent_rows,
            "agent-sponsor",
            AGENT,
            agent_env,
            issuer("agent")[vf.IK_KID],
            "gate",
            "entry",
            True,
        ),
        (
            "agent-list-vote-leaf",
            agent_rows,
            "agent-sponsor",
            AGENT,
            agent_env,
            issuer("agent")[vf.IK_KID],
            "gate",
            "vote",
            False,
        ),
        (
            "direct-issuer-wildcard",
            rows["issuers/0"],
            "approved",
            auth("approved-list"),
            _approved_env(vw),
            issuer("approved")[vf.IK_KID],
            "gate",
            "entry",
            True,
        ),
    ]
    for name, rws, attr_name, authority, venv, kid, use, policy, expected in checks:
        got = tl.credential_satisfies(
            rws,
            attr_name,
            verifier_authority=authority,
            verifier_env=venv,
            kid=kid,
            use=use,
            policy=policy,
        )
        assert got == expected, name
        f.add(
            f"trust-list-satisfies-{name}",
            f"credential_satisfies: {name}",
            S_RESOLVE,
            {
                "rows": jsonable(rws),
                "attribute": attr_name,
                "verifier_authority": hexify(authority),
                "verifier_env": None if venv is None else jsonable(venv),
                "kid": hexify(kid),
                "use": use,
                "policy": policy,
            },
            {"satisfies": expected},
        )
    return f


def _approved_env(vw):
    from .verifier_vectors import approved_list

    return m.envelope(
        "verifier", approved_list(vw), authority=auth("approved-list"), issued=fixtures.ISSUED
    )


def world_file(w: World) -> File:
    f = File(
        SPEC, "world", "The trust-list publisher authority and every logged trust-list bundle."
    )
    f.add(
        "world",
        "Authority and bundles",
        S_RULES,
        {
            "authority": hexify(w.authority),
            "authority_text": cid_text(w.authority),
            "keys": {
                n: {"seed": hexify(k.seed), "public": hexify(k.public)} for n, k in w.keys.items()
            },
            "base_world": "vectors/manifest/world.json",
        },
        {
            "bundles": [{"name": n, **bundle_json(b)} for n, b in w.named.items()],
            "checkpoint": w.w.note().text(),
        },
    )
    return f


def generate() -> list[File]:
    w, built = build()
    return [world_file(w), manifests_file(w, built), resolution_file()]
