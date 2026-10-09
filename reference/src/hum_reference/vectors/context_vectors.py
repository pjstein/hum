"""Vectors for docs/specs/context.md: whole context manifests (the valid list and one invalid
case per rule and sub-condition for C1 to C16), policy evaluation, daily-count buckets and the
results key.

The world is the base fixture world plus: four verifiers (district, a second district, unique,
approved) under their own authorities, four trust lists under a publisher authority (one
verifier per attribute; two verifiers for ``area`` by name; one named entry plus one empty
``attributes`` entry; a list with the district verifier alone), a public parent context, and
every context under authority A, signed by b1 and b2 (authority A rotated at position 6).
Invalid contexts were appended by a misbehaving log so that step 10 is reached.
"""

from __future__ import annotations

import copy
from fractions import Fraction

from .. import cbor, fixtures, storage
from .. import manifest as m
from ..bodies import context as c
from ..bodies import trust_list as tl
from ..bodies import verifier as vf
from ..cid import cid as compute_cid
from ..keys import SigningKey, key_from_label
from . import File, hexify, jsonable
from .manifest_vectors import bundle_json

SPEC = "context"
S_RULES = "Validation rules (verification step 10 for context)"
S_POLICY = "Entry policy"
S_COUNT = "The noised daily count"
S_RESULTS = "The results key"
TOOLCHAIN = vf.TOOLCHAIN  # verifier.md "Code"
RESULTS_SECRET = fixtures.fixed_bytes("context-results-epoch-3", 16)
ABOUT_SALT = fixtures.fixed_bytes("context-about-salt", 16)


class World:
    def __init__(self) -> None:
        self.fx = fixtures.build()
        self.w = self.fx.world
        self.keys: dict[str, SigningKey] = dict(self.fx.keys)
        self.a = self.fx.authority_a
        self.named: dict[str, m.Bundle] = {}
        self.cases: list[tuple[str, str, str | None, int | None, m.Bundle]] = []
        self._build()

    # -- helpers
    def organizers(self):
        return [(b"b1", self.keys["b1"]), (b"b2", self.keys["b2"])]

    def keyset(self, label: str, sign: str, rotate: str) -> m.Bundle:
        for n in (sign, rotate):
            self.keys.setdefault(n, key_from_label(f"context-world-{n}"))
        ks = [
            m.KeysetKey(sign.encode(), self.keys[sign].public, ("sign",)),
            m.KeysetKey(rotate.encode(), self.keys[rotate].public, ("rotate",)),
        ]
        env = m.envelope(
            "keyset", m.build_keyset_body(ks, 1, 1), authority=None, issued=fixtures.ISSUED
        )
        b = self.w.append(env, [(rotate.encode(), self.keys[rotate])])
        self.named[f"keyset-{label}"] = b
        return b

    def blob(self, label: str) -> bytes:
        return self.w.put_blob(cbor.encode({"hum-vector-blob": label}))

    def verifier(self, label: str, attrs: list[dict], assurance: int) -> m.Bundle:
        ks = self.keyset(f"v-{label}", f"v-{label}-s", f"v-{label}-r")
        body = vf.body(
            name=f"{label} verifier",
            operator="Hum vector operator",
            profile="custom",
            issuer_keys=[
                vf.issuer_key(
                    fixtures.fixed_bytes(f"ckid-{label}", 8),
                    fixtures.fixed_bytes(f"cbbs-{label}", 96),
                )
            ],
            host_keys=[
                vf.host_key(
                    fixtures.fixed_bytes(f"chkid-{label}", 8),
                    fixtures.fixed_bytes(f"chpke-{label}", 32),
                )
            ],
            attributes=attrs,
            evidence_=[vf.evidence("match", "other", "text", "Something else: a record to match")],
            dedup_=[vf.dedup("evidence", "match", "One card per record")],
            code_=vf.code(fixtures.fixed_bytes(f"csource-{label}"), TOOLCHAIN),
            assurance=assurance,
        )
        env = m.envelope(
            "verifier",
            body,
            authority=ks.cid,
            issued=fixtures.ISSUED,
            refs={"code": self.blob(f"code-{label}"), "build": self.blob(f"build-{label}")},
        )
        b = self.w.append(env, [(f"v-{label}-s".encode(), self.keys[f"v-{label}-s"])])
        self.named[f"verifier-{label}"] = b
        return b

    def trust_list(self, label: str, entries: list[dict]) -> m.Bundle:
        body = tl.body(
            name=f"Vector list {label}",
            publisher="Hum vector operator",
            kind="community",
            entries=entries,
            min_assurance=1,
        )
        env = m.envelope("trust-list", body, authority=self.tks.cid, issued=fixtures.ISSUED)
        b = self.w.append(env, [(b"cts", self.keys["cts"])])
        self.named[f"trust-list-{label}"] = b
        return b

    def context_env(self, body: dict, refs: dict | None = None, **kw) -> dict:
        kw.setdefault("issued", fixtures.ISSUED)
        return m.envelope("context", body, authority=self.a, refs=refs or {}, **kw)

    def log(self, name: str, env: dict) -> m.Bundle:
        cid = m.envelope_cid(env)
        assert cid not in self.w.bundles, f"{name} duplicates an earlier envelope"
        b = self.w.append(env, self.organizers())
        self.named[name] = b
        return b

    def case(self, suffix: str, desc: str, rule: str | None, b: m.Bundle, now: int | None = None):
        self.cases.append((suffix, desc, rule, now, b))

    # -- the example body (context.md "Example (JSON view)")
    def example(self, tl_ref: bytes | None = None) -> tuple[dict, dict]:
        base = fixtures.context_body(self.fx, self.a)
        _, results_pub = c.results_key(RESULTS_SECRET)
        body = c.body(
            name="Millbrook Tenants Union",
            sealed=True,
            entry=c.attr([c.SRC_TRUST_LIST, 0], "area", [c.PRED_SET, [1]]),
            vote=[
                c.NODE_ALL,
                [
                    c.attr([c.SRC_TRUST_LIST, 0], "area", [c.PRED_SET, [1]]),
                    c.attr([c.SRC_TRUST_LIST, 0], "unique", [c.PRED_PRESENT]),
                ],
            ],
            nullifier=[[c.SRC_TRUST_LIST, 0], "unique"],
            perms={c.P_CARDS: 1, c.P_RESULTS: 1, c.P_MEMBER_LIST: 1},
            floors_=c.floors(rho_year=Fraction(51, 50)),
            logs=[{c.L_LOG: self.w.log_authority, c.L_WITNESSES: self.witnesses3}],
            aggregators=base[c.AGGREGATORS],
            stores=base[c.STORES],
            storage=c.storage_policy(),
            chat=base[c.CHAT],
            mix_global=True,
            results_key=results_pub,
            results_epoch=3,
            map_limits={c.MAP_UNSIGNED: 20, c.MAP_SIGNED: 60, c.MAP_AGENT: 20},
            agents={c.AG_ANY: False, c.AG_SPONSORS: [self.sponsor_auth], c.AG_ADD_ROLE: 0},
            about_epoch=3,
        )
        refs = {"tl/0": tl_ref or self.tl_one.cid, "about": self.about_sealed}
        return body, refs

    def open_body(self) -> tuple[dict, dict]:
        base = fixtures.context_body(self.fx, self.a)
        body = c.body(
            name="Open context",
            sealed=False,
            entry=[c.NODE_TRUE],
            vote=c.attr([c.SRC_TRUST_LIST, 0], "unique", [c.PRED_PRESENT]),
            nullifier=[[c.SRC_TRUST_LIST, 0], "unique"],
            perms={c.P_CARDS: 2, c.P_RESULTS: 0, c.P_MEMBER_LIST: 2},
            floors_=c.floors(),
            logs=[{c.L_LOG: self.w.log_authority, c.L_WITNESSES: self.witnesses3}],
            aggregators=base[c.AGGREGATORS],
            stores=base[c.STORES],
            storage=c.storage_policy(),
            chat=base[c.CHAT],
            mix_global=False,
        )
        return body, {"tl/0": self.tl_one.cid}

    # -- build
    def _build(self) -> None:
        w = self.w
        self.witnesses3 = w.witness_keys() + [fixtures.fixed_bytes("extra-witness-key")]
        area = vf.attribute(
            "area", "enum", "breakdown", "Area", vf.enum_values(["Millbrook", "Out"])
        )
        ward = vf.attribute("ward", "enum", "breakdown", "Ward", vf.enum_values(["W1", "W2", "W3"]))
        self.vd = self.verifier("district", [area, ward], 2)
        self.vd2 = self.verifier("district-2", [copy.deepcopy(area)], 2)
        self.vu = self.verifier("unique", [vf.attribute("unique", "bool", "gate", "Unique")], 3)
        self.va = self.verifier(
            "approved", [vf.attribute("approved", "bool", "gate", "Approved")], 1
        )

        def auth(b):
            return cbor.decode(b.envelope)[m.AUTHORITY]

        self.vd_auth, self.vd2_auth = auth(self.vd), auth(self.vd2)
        self.vu_auth, self.va_auth = auth(self.vu), auth(self.va)
        self.tks = self.keyset("trust", "cts", "ctr")
        self.tl_one = self.trust_list(
            "one-per-attribute",
            [tl.entry(self.vd_auth, ["area", "ward"]), tl.entry(self.vu_auth, ["unique"])],
        )
        self.tl_two_named = self.trust_list(
            "two-by-name", [tl.entry(self.vd_auth, ["area"]), tl.entry(self.vd2_auth, ["area"])]
        )
        self.tl_two_empty = self.trust_list(
            "named-plus-empty", [tl.entry(self.vd_auth, ["area"]), tl.entry(self.vd2_auth, [])]
        )
        self.tl_district = self.trust_list("district-alone", [tl.entry(self.vd_auth, [])])
        self.sponsor_auth = self.keyset("sponsor", "csp", "cspr").cid
        self.about_public = w.put_blob(b"About this context.")
        self.about_sealed = w.put_blob(
            storage.seal_keyring(b"About this context.", RESULTS_SECRET, ABOUT_SALT)
        )
        # a public parent with looser floors than the example (equal to the protocol floors)
        pbody, _ = self.open_body()
        pbody[c.NAME] = "Millbrook public parent"
        self.parent = self.log(
            "context-parent",
            self.context_env(pbody, {"tl/0": self.tl_one.cid, "about": self.about_public}),
        )
        # ---- valid
        obody, orefs = self.open_body()
        self.case(
            "valid-open",
            "entry [0], vote names a trust-list uniqueness attribute, results 0, no parent",
            None,
            self.log("context-valid-open", self.context_env(obody, orefs)),
        )
        ebody, erefs = self.example()
        self.example_v1 = self.log(
            "context-valid-sealed-parent",
            self.context_env(ebody, {**erefs, "parent": self.parent.cid}),
        )
        self.case(
            "valid-sealed-parent",
            "the example plus refs[parent] to a public parent with looser floors",
            None,
            self.example_v1,
        )
        v2body = copy.deepcopy(ebody)
        v2body[c.FLOORS][c.F_RHO] = [1, 5]
        v2body[c.FLOORS][c.F_MIN_VOTERS] = 300
        self.case(
            "valid-v2-tighten",
            "version 2 of the example: rho 1/5, minVoters 300",
            None,
            self.v2(
                "context-valid-v2-tighten",
                self.example_v1,
                v2body,
                {**erefs, "parent": self.parent.cid},
            ),
        )
        dbody = copy.deepcopy(obody)
        dbody[c.RESOLVERS] = [compute_cid(cbor.encode(b"resolver authority"))]
        dbody[c.RELAYS] = [
            compute_cid(cbor.encode(b"relay authority A")),
            compute_cid(cbor.encode(b"relay authority B")),
        ]
        self.case(
            "valid-discovery",
            "the open context plus resolvers (key 20, one entry) and relays (key 21, two entries "
            "under their own authorities)",
            None,
            self.log("context-valid-discovery", self.context_env(dbody, orefs)),
        )
        cbody = copy.deepcopy(obody)
        cbody[c.COUNT] = {c.CNT_RHO_MAX: [1, 400]}
        self.case(
            "valid-count",
            "count.rhoMax 1/400",
            None,
            self.log("context-valid-count", self.context_env(cbody, orefs)),
        )
        sbody, _ = self.open_body()
        sbody[c.ENTRY] = [
            c.NODE_ALL,
            [
                c.attr([c.SRC_TRUST_LIST, 0], "area", [c.PRED_SET, [1]]),
                c.attr([c.SRC_TRUST_LIST, 0], "ward", [c.PRED_RANGE, 2, 2]),
            ],
        ]
        sbody[c.VOTE] = c.attr([c.SRC_TRUST_LIST, 1], "unique", [c.PRED_PRESENT])
        sbody[c.NULLIFIER] = [[c.SRC_TRUST_LIST, 1], "unique"]
        self.case(
            "valid-C16-same-verifier",
            "two leaves on different attributes the list accepts from one verifier",
            None,
            self.log(
                "context-valid-C16-same-verifier",
                self.context_env(sbody, {"tl/0": self.tl_district.cid, "tl/1": self.tl_one.cid}),
            ),
        )
        # ---- invalid, one per sub-condition
        self._invalid(ebody, erefs, obody, orefs)

    def v2(self, name: str, v1: m.Bundle, body: dict, refs: dict) -> m.Bundle:
        return self.log(
            name,
            self.context_env(
                body, refs, version=2, lineage=v1.cid, prev=v1.cid, issued=fixtures.ISSUED + 60
            ),
        )

    def _invalid(self, ebody, erefs, obody, orefs) -> None:
        tlr = {"tl/0": self.tl_one.cid}

        def bad(rule: str, name: str, desc: str, fn, *, base=None, refs=None):
            body = copy.deepcopy(base if base is not None else obody)
            r = dict(refs if refs is not None else orefs)
            fn(body, r)
            self.case(
                f"invalid-{rule}-{name}",
                desc,
                rule,
                self.log(f"context-invalid-{rule}-{name}", self.context_env(body, r)),
            )

        def badv2(rule: str, name: str, desc: str, fn, *, v1_changes=None):
            body1 = copy.deepcopy(ebody)
            body1[c.NAME] = f"Example for {rule} {name}"
            for k, v in (v1_changes or {}).items():
                body1[k] = v
            v1 = self.log(f"context-v1-for-{rule}-{name}", self.context_env(body1, erefs))
            body2 = copy.deepcopy(body1)
            fn(body2)
            self.case(
                f"invalid-{rule}-{name}",
                desc,
                rule,
                self.v2(f"context-invalid-{rule}-{name}", v1, body2, erefs),
            )

        def leaf(name, pred=None, src=(c.SRC_TRUST_LIST, 0)):
            return c.attr(list(src), name, pred or [c.PRED_PRESENT])

        area1 = leaf("area", [c.PRED_SET, [1]])
        # C1
        bad("C1", "missing-logs", "logs absent", lambda b, r: b.pop(c.LOGS))
        bad("C1", "unknown-key", "unknown body key 22", lambda b, r: b.__setitem__(22, 1))
        bad(
            "C1",
            "relays-not-auth",
            "relays holding a 32-byte string that is not a CID",
            lambda b, r: b.__setitem__(c.RELAYS, [fixtures.fixed_bytes("not-a-cid", 32)]),
        )
        bad(
            "C1",
            "rat-not-lowest",
            "floors.rho [2, 4]",
            lambda b, r: b[c.FLOORS].__setitem__(c.F_RHO, [2, 4]),
        )
        # C2
        bad("C2", "empty-name", "name empty", lambda b, r: b.__setitem__(c.NAME, ""))
        bad(
            "C2",
            "name-121-bytes",
            "name of 121 bytes",
            lambda b, r: b.__setitem__(c.NAME, "n" * 121),
        )
        # C3
        bad(
            "C3",
            "rho-3-10",
            "floors.rho 3/10",
            lambda b, r: b[c.FLOORS].__setitem__(c.F_RHO, [3, 10]),
        )
        bad(
            "C3",
            "delta-1-100000",
            "floors.delta 1/100000",
            lambda b, r: b[c.FLOORS].__setitem__(c.F_DELTA, [1, 100000]),
        )
        bad(
            "C3",
            "minvoters-50",
            "floors.minVoters 50",
            lambda b, r: b[c.FLOORS].__setitem__(c.F_MIN_VOTERS, 50),
        )
        bad(
            "C3",
            "releasesperdeck-2",
            "floors.releasesPerDeck 2",
            lambda b, r: b[c.FLOORS].__setitem__(c.F_RELEASES, 2),
        )
        bad(
            "C3",
            "minwitnesses-1",
            "floors.minWitnesses 1",
            lambda b, r: b[c.FLOORS].__setitem__(c.F_MIN_WITNESSES, 1),
        )
        # C4
        bad(
            "C4",
            "rhoyear-below-rho",
            "rhoYear 1/10 below rho",
            lambda b, r: b[c.FLOORS].__setitem__(c.F_RHO_YEAR, [1, 10]),
        )
        # C5
        bad("C5", "unknown-node-kind", "node kind 7", lambda b, r: b.__setitem__(c.ENTRY, [7]))
        bad(
            "C5",
            "all-no-children",
            "all with no children",
            lambda b, r: b.__setitem__(c.ENTRY, [c.NODE_ALL, []]),
        )

        def deep(n):
            node = area1
            for _ in range(n - 1):
                node = [c.NODE_ALL, [node]]
            return node

        bad("C5", "depth-5", "policy depth 5", lambda b, r: b.__setitem__(c.ENTRY, deep(5)))
        bad(
            "C5",
            "33-leaves",
            "33 attr leaves",
            lambda b, r: b.__setitem__(
                c.ENTRY,
                [
                    c.NODE_ALL,
                    [
                        [c.NODE_ALL, [copy.deepcopy(area1) for _ in range(16)]],
                        [c.NODE_ALL, [copy.deepcopy(area1) for _ in range(17)]],
                    ],
                ],
            ),
        )
        bad(
            "C5",
            "tl-2-with-only-tl-0",
            "[0, 2] with only tl/0",
            lambda b, r: b.__setitem__(
                c.ENTRY, leaf("area", [c.PRED_SET, [1]], (c.SRC_TRUST_LIST, 2))
            ),
        )
        bad(
            "C5",
            "issuer-3-with-one-issuer",
            "[1, 3] with one issuer",
            lambda b, r: (
                b.__setitem__(c.ISSUERS, [self.va_auth]),
                b.__setitem__(c.ENTRY, leaf("approved", None, (c.SRC_ISSUER, 3))),
            ),
        )
        bad(
            "C5",
            "text-value-in-predicate",
            "a text value in a set predicate",
            lambda b, r: b.__setitem__(c.ENTRY, leaf("area", [c.PRED_SET, ["1"]])),
        )
        bad(
            "C5",
            "two-value-set",
            "a two-value set (draft 0.1 proves equality only)",
            lambda b, r: b.__setitem__(c.ENTRY, leaf("area", [c.PRED_SET, [1, 2]])),
        )
        bad(
            "C5",
            "lo-lt-hi",
            "range lo < hi",
            lambda b, r: b.__setitem__(c.ENTRY, leaf("ward", [c.PRED_RANGE, 1, 2])),
        )
        bad(
            "C5",
            "lo-gt-hi",
            "range lo > hi",
            lambda b, r: b.__setitem__(c.ENTRY, leaf("ward", [c.PRED_RANGE, 3, 2])),
        )
        bad(
            "C5",
            "present-on-enum",
            "[0] on the enum attribute area (checked after step 9 resolves the verifier)",
            lambda b, r: b.__setitem__(c.ENTRY, leaf("area")),
        )
        bad(
            "C5",
            "any-same-source-name",
            "an any with two leaves on one (source, name)",
            lambda b, r: b.__setitem__(
                c.ENTRY,
                [c.NODE_ANY, [leaf("area", [c.PRED_SET, [1]]), leaf("area", [c.PRED_SET, [2]])]],
            ),
        )
        bad(
            "C5",
            "bad-attribute-name",
            "attribute name Area",
            lambda b, r: b.__setitem__(c.ENTRY, leaf("Area", [c.PRED_SET, [1]])),
        )
        # C6
        bad(
            "C6",
            "nullifier-source-missing",
            "nullifier names tl/5",
            lambda b, r: b.__setitem__(c.NULLIFIER, [[c.SRC_TRUST_LIST, 5], "unique"]),
        )
        bad(
            "C6",
            "nullifier-leaf-absent",
            "no leaf for the nullifier credential",
            lambda b, r: b.__setitem__(c.NULLIFIER, [[c.SRC_TRUST_LIST, 0], "ward"]),
        )
        bad(
            "C6",
            "nullifier-under-any",
            "nullifier leaf only under an any",
            lambda b, r: b.__setitem__(
                c.VOTE, [c.NODE_ANY, [leaf("unique"), leaf("area", [c.PRED_SET, [1]])]]
            ),
        )
        # C7
        bad(
            "C7",
            "gapped-tl",
            "refs tl/0 and tl/2",
            lambda b, r: r.__setitem__("tl/2", self.tl_district.cid),
        )
        bad(
            "C7",
            "unused-trust-list",
            "tl/1 used by neither policy",
            lambda b, r: r.__setitem__("tl/1", self.tl_district.cid),
        )
        bad(
            "C7",
            "equal-aggregators",
            "aggregators[0] = aggregators[1]",
            lambda b, r: b.__setitem__(c.AGGREGATORS, [b[c.AGGREGATORS][0]] * 2),
        )
        bad(
            "C7",
            "duplicate-store",
            "the same store twice",
            lambda b, r: b.__setitem__(c.STORES, b[c.STORES] * 2),
        )
        relay_a = compute_cid(cbor.encode(b"relay authority A"))
        bad(
            "C7",
            "duplicate-relay",
            "the same relay twice",
            lambda b, r: b.__setitem__(c.RELAYS, [relay_a, relay_a]),
        )
        bad(
            "C7",
            "five-relays",
            "five relays (the limit is 4)",
            lambda b, r: b.__setitem__(
                c.RELAYS, [compute_cid(cbor.encode(f"relay {i}".encode())) for i in range(5)]
            ),
        )
        bad(
            "C7",
            "empty-resolvers",
            "an empty resolvers array (1..8 when present)",
            lambda b, r: b.__setitem__(c.RESOLVERS, []),
        )
        bad(
            "C7",
            "relay-is-leader",
            "a relay equal to the context's Leader authority (services.md O-5, the lookup-free part)",
            lambda b, r: b.__setitem__(c.RELAYS, [b[c.AGGREGATORS][0]]),
        )
        bad(
            "C7",
            "relay-is-delivery",
            "a relay equal to chat.delivery",
            lambda b, r: b.__setitem__(c.RELAYS, [b[c.CHAT][c.CH_DELIVERY]]),
        )
        # C8
        bad(
            "C8",
            "minwitnesses-3-two-witnesses",
            "minWitnesses 3 with two witness keys",
            lambda b, r: (
                b[c.FLOORS].__setitem__(c.F_MIN_WITNESSES, 3),
                b[c.LOGS][0].__setitem__(c.L_WITNESSES, self.w.witness_keys()),
            ),
        )
        bad(
            "C8",
            "duplicate-witness-key",
            "a witness key listed twice",
            lambda b, r: b[c.LOGS][0].__setitem__(
                c.L_WITNESSES, [self.witnesses3[0]] * 2 + self.witnesses3[1:]
            ),
        )
        # C9
        bad(
            "C9",
            "retention-missing-kind-4",
            "retention without kind 4",
            lambda b, r: b[c.STORAGE][c.S_RETENTION].pop(4),
        )
        bad(
            "C9",
            "maxblob-1000",
            "maxBlob 1000",
            lambda b, r: b[c.STORAGE].__setitem__(c.S_MAX_BLOB, 1000),
        )
        bad("C9", "history-3", "history 3", lambda b, r: b[c.STORAGE].__setitem__(c.S_HISTORY, 3))
        bad(
            "C9",
            "keyringhistory-2",
            "keyringHistory 2",
            lambda b, r: b[c.STORAGE].__setitem__(c.S_KEYRING_HISTORY, 2),
        )
        bad(
            "C9",
            "sensitivemax-small",
            "sensitiveMax 1000",
            lambda b, r: b[c.STORAGE].__setitem__(c.S_SENSITIVE_MAX, 1000),
        )
        # C10 (version 2 of the example)
        badv2(
            "C10",
            "raises-rho",
            "version 2 raises rho",
            lambda b: b[c.FLOORS].__setitem__(c.F_RHO, [127, 500]),
            v1_changes={c.FLOORS: c.floors(rho=Fraction(1, 5), rho_year=Fraction(51, 50))},
        )
        badv2(
            "C10",
            "raises-delta",
            "version 2 raises delta",
            lambda b: b[c.FLOORS].__setitem__(c.F_DELTA, [1, 1000000]),
            v1_changes={c.FLOORS: c.floors(delta=Fraction(1, 10**7), rho_year=Fraction(51, 50))},
        )
        badv2(
            "C10",
            "lowers-minvoters",
            "version 2 lowers minVoters",
            lambda b: b[c.FLOORS].__setitem__(c.F_MIN_VOTERS, 100),
            v1_changes={c.FLOORS: c.floors(min_voters=300, rho_year=Fraction(51, 50))},
        )
        badv2(
            "C10",
            "lowers-minwitnesses",
            "version 2 lowers minWitnesses",
            lambda b: b[c.FLOORS].__setitem__(c.F_MIN_WITNESSES, 2),
            v1_changes={c.FLOORS: c.floors(min_witnesses=3, rho_year=Fraction(51, 50))},
        )
        badv2(
            "C10",
            "drops-rhoyear",
            "version 2 drops rhoYear",
            lambda b: b[c.FLOORS].pop(c.F_RHO_YEAR),
        )
        badv2(
            "C10",
            "raises-rhoyear",
            "version 2 raises rhoYear",
            lambda b: b[c.FLOORS].__setitem__(c.F_RHO_YEAR, [2, 1]),
        )
        # C11
        badv2(
            "C11",
            "changes-allmembers",
            "version 2 changes chat.allMembers",
            lambda b: b[c.CHAT].__setitem__(c.CH_ALL, fixtures.fixed_bytes("other-all-members")),
        )
        badv2(
            "C11",
            "changes-sealed",
            "version 2 changes sealed",
            lambda b: (b.__setitem__(c.SEALED, False), b.pop(c.ABOUT_EPOCH)),
        )
        other_log = compute_cid(cbor.encode(b"another log authority"))
        other_witnesses = [fixtures.fixed_bytes(f"other-witness-{i}", 32) for i in range(3)]
        badv2(
            "C11",
            "changes-log0",
            "version 2 changes logs[0].log (the ledger of record is frozen from version 1; "
            "TS7 option a)",
            lambda b: b[c.LOGS][0].__setitem__(c.L_LOG, other_log),
        )
        badv2(
            "C11",
            "swaps-logs",
            "version 2 swaps the first two logs entries: the second log becomes logs[0]",
            lambda b: b.__setitem__(c.LOGS, [b[c.LOGS][1], b[c.LOGS][0]]),
            v1_changes={
                c.LOGS: [
                    {c.L_LOG: self.w.log_authority, c.L_WITNESSES: self.witnesses3},
                    {c.L_LOG: other_log, c.L_WITNESSES: other_witnesses},
                ]
            },
        )
        body1 = copy.deepcopy(ebody)
        body1[c.NAME] = "Example for C11 valid logs change"
        v1_logs = self.log("context-v1-for-C11-valid-logs", self.context_env(body1, erefs))
        body2 = copy.deepcopy(body1)
        body2[c.LOGS] = [
            {c.L_LOG: self.w.log_authority, c.L_WITNESSES: other_witnesses},
            {c.L_LOG: other_log, c.L_WITNESSES: self.witnesses3},
        ]
        self.case(
            "valid-v2-logs-witnesses-and-second-log",
            "version 2 keeps logs[0].log, replaces logs[0].witnesses and adds a second log: "
            "valid under C11",
            None,
            self.v2("context-valid-v2-logs", v1_logs, body2, erefs),
        )
        bad(
            "C11",
            "greeting-missing",
            "chat.greeting absent",
            lambda b, r: b[c.CHAT].pop(c.CH_GREETING),
        )
        bad(
            "C11",
            "issuerkeys-one-entry",
            "chat.issuerKeys with one entry",
            lambda b, r: b[c.CHAT][c.CH_ISSUER_KEYS].pop(1),
        )
        # C12
        bad(
            "C12",
            "results-2",
            "perms.results 2",
            lambda b, r: b[c.PERMS].__setitem__(c.P_RESULTS, 2),
        )
        bad(
            "C12",
            "results-1-no-key",
            "results 1 without resultsKey",
            lambda b, r: b[c.PERMS].__setitem__(c.P_RESULTS, 1),
        )
        bad(
            "C12",
            "results-0-with-key",
            "results 0 with resultsKey",
            lambda b, r: (
                b.__setitem__(c.RESULTS_KEY, c.results_key(RESULTS_SECRET)[1]),
                b.__setitem__(c.RESULTS_EPOCH, 3),
            ),
        )
        bad(
            "C12",
            "sealed-about-no-aboutepoch",
            "sealed about blob without aboutEpoch",
            lambda b, r: b.pop(c.ABOUT_EPOCH),
            base=ebody,
            refs=erefs,
        )
        # C13
        strict = copy.deepcopy(obody)
        strict[c.NAME] = "Strict parent"
        strict[c.FLOORS][c.F_MIN_VOTERS] = 300
        strict_parent = self.log("context-parent-strict", self.context_env(strict, orefs))
        bad(
            "C13",
            "parent-stricter-minvoters",
            "parent with minVoters 300 above the child's 100",
            lambda b, r: r.__setitem__("parent", strict_parent.cid),
        )
        own = copy.deepcopy(obody)
        own[c.NAME] = "Lineage for C13"
        v1 = self.log("context-v1-for-C13-parent-same-lineage", self.context_env(own, orefs))
        self.case(
            "invalid-C13-parent-same-lineage",
            "version 2 names its own version 1 as parent",
            "C13",
            self.v2(
                "context-invalid-C13-parent-same-lineage",
                v1,
                copy.deepcopy(own),
                {**orefs, "parent": v1.cid},
            ),
        )
        # C14
        bad(
            "C14",
            "count-rhomax-1-20",
            "count.rhoMax 1/20",
            lambda b, r: b.__setitem__(c.COUNT, {c.CNT_RHO_MAX: [1, 20]}),
        )
        # C15
        bad(
            "C15",
            "vote-agent-sponsor",
            "a vote leaf naming agent-sponsor",
            lambda b, r: b.__setitem__(
                c.VOTE, [c.NODE_ALL, [leaf("unique"), leaf("agent-sponsor")]]
            ),
        )
        bad(
            "C15",
            "unsignedperwindow-21",
            "map.unsignedPerWindow 21",
            lambda b, r: b.__setitem__(c.MAP, {c.MAP_UNSIGNED: 21}),
        )
        bad(
            "C15",
            "sponsors-with-anysponsor",
            "sponsors non-empty with anySponsor",
            lambda b, r: b.__setitem__(
                c.AGENTS, {c.AG_ANY: True, c.AG_SPONSORS: [self.sponsor_auth]}
            ),
        )
        bad(
            "C15",
            "addrole-3",
            "agents.addRole 3",
            lambda b, r: b.__setitem__(c.AGENTS, {c.AG_ADD_ROLE: 3}),
        )
        # C16
        bad(
            "C16",
            "entry-any",
            "an any node in entry (two different leaves)",
            lambda b, r: b.__setitem__(
                c.ENTRY,
                [c.NODE_ANY, [leaf("area", [c.PRED_SET, [1]]), leaf("ward", [c.PRED_SET, [2]])]],
            ),
        )
        bad(
            "C16",
            "vote-any-under-all",
            "a vote with an any node nested under an all",
            lambda b, r: b.__setitem__(
                c.VOTE,
                [
                    c.NODE_ALL,
                    [
                        leaf("unique"),
                        [
                            c.NODE_ANY,
                            [leaf("area", [c.PRED_SET, [1]]), leaf("ward", [c.PRED_SET, [2]])],
                        ],
                    ],
                ],
            ),
        )
        bad(
            "C16",
            "two-verifiers-by-name",
            "the leaf's trust list accepts area from two verifiers by name",
            lambda b, r: (
                b.__setitem__(c.ENTRY, leaf("area", [c.PRED_SET, [1]], (c.SRC_TRUST_LIST, 1))),
                r.__setitem__("tl/1", self.tl_two_named.cid),
            ),
        )
        bad(
            "C16",
            "one-named-one-empty",
            "the leaf's trust list has one named entry and one entry with empty attributes",
            lambda b, r: (
                b.__setitem__(c.ENTRY, leaf("area", [c.PRED_SET, [1]], (c.SRC_TRUST_LIST, 1))),
                r.__setitem__("tl/1", self.tl_two_empty.cid),
            ),
        )
        del tlr
        self.w.finalize()


_WORLD: World | None = None


def get_world() -> World:
    global _WORLD
    if _WORLD is None:
        _WORLD = World()
    return _WORLD


# ---------------------------------------------------------------- files


def world_file(wd: World) -> File:
    f = File(
        SPEC,
        "world",
        "Every bundle the context cases resolve against beyond manifest/world.json: "
        "verifier and trust-list authorities and manifests, the publisher and sponsor keysets, "
        "the parent contexts, and every context version (valid and invalid). Invalid contexts were "
        "appended by a misbehaving log.",
    )
    names = {b.cid: n for n, b in wd.named.items()}
    f.add(
        "world",
        "Bundles and blobs",
        S_RULES,
        {
            "keys": {
                n: {"seed": hexify(k.seed), "public": hexify(k.public)}
                for n, k in sorted(wd.keys.items())
            }
        },
        {
            "checkpoint": wd.w.note().text(),
            "bundles": [
                {"name": names[b.cid], **bundle_json(b), "view": jsonable(cbor.decode(b.envelope))}
                for b in wd.w.bundles.values()
                if b.cid in names
            ],
            "blobs": {
                hexify(cid): hexify(data) for cid, data in wd.w.blobs.items() if len(data) <= 4096
            },
        },
    )
    return f


def manifests_file(wd: World) -> File:
    f = File(
        SPEC,
        "manifests",
        "Valid contexts and one invalid context per rule and sub-condition (context.md "
        "Vectors). The reference runs shape rules (C1, C2, C11's greeting and issuerKeys, C5's node "
        "shapes) at step 4 and the rest at step 10; each case records the step it fails at.",
    )
    for suffix, desc, rule, now, b in wd.cases:
        ctx = wd.w.context(now=now or fixtures.NOW)
        inputs = {
            "bundle": bundle_json(b),
            "now": now or fixtures.NOW,
            "view": jsonable(cbor.decode(b.envelope)),
        }
        try:
            env = m.verify_bundle(ctx, b)
        except m.Rejection as e:
            assert rule is not None and e.rule == rule, (suffix, rule, str(e))
            f.add(
                f"context-{suffix}",
                desc,
                S_RULES,
                inputs,
                rejection={"step": e.step, "rule": e.rule, "reason": e.reason},
            )
            continue
        assert rule is None, (suffix, "expected rejection", rule)
        f.add(
            f"context-{suffix}",
            desc,
            S_RULES,
            inputs,
            {"accept": True, "type": env[m.TYPE], "version": env[m.VERSION]},
        )
    return f


def policy_file(wd: World) -> File:
    f = File(
        SPEC,
        "policy-eval",
        "Policy evaluation on trees plus held (source, attribute, value) triples. "
        "These test the evaluator; a context holding the any, range or set trees is itself rejected "
        "by C5 or C16 in draft 0.1. Sources are given as resolved source ids [kind, index].",
    )
    TL0, TL1, IS0 = (0, 0), (0, 1), (1, 0)
    cases = [
        (
            "all-two-credentials",
            [
                c.NODE_ALL,
                [
                    c.attr([0, 0], "area", [c.PRED_SET, [1]]),
                    c.attr([0, 1], "unique", [c.PRED_PRESENT]),
                ],
            ],
            [(TL0, "area", 1), (TL1, "unique", 1)],
            True,
        ),
        (
            "all-missing-one",
            [
                c.NODE_ALL,
                [
                    c.attr([0, 0], "area", [c.PRED_SET, [1]]),
                    c.attr([0, 1], "unique", [c.PRED_PRESENT]),
                ],
            ],
            [(TL0, "area", 1)],
            False,
        ),
        (
            "any-second-child",
            [
                c.NODE_ANY,
                [
                    c.attr([1, 0], "approved", [c.PRED_PRESENT]),
                    c.attr([0, 0], "area", [c.PRED_SET, [1]]),
                ],
            ],
            [(TL0, "area", 1)],
            True,
        ),
        (
            "any-neither",
            [
                c.NODE_ANY,
                [
                    c.attr([1, 0], "approved", [c.PRED_PRESENT]),
                    c.attr([0, 0], "area", [c.PRED_SET, [1]]),
                ],
            ],
            [(TL0, "area", 2)],
            False,
        ),
        ("range-inside", c.attr([0, 0], "ward", [c.PRED_RANGE, 1, 3]), [(TL0, "ward", 2)], True),
        ("range-outside", c.attr([0, 0], "ward", [c.PRED_RANGE, 1, 3]), [(TL0, "ward", 4)], False),
        ("set-member", c.attr([0, 0], "ward", [c.PRED_SET, [1, 2, 3]]), [(TL0, "ward", 3)], True),
        (
            "set-not-member",
            c.attr([0, 0], "ward", [c.PRED_SET, [1, 2, 3]]),
            [(TL0, "ward", 5)],
            False,
        ),
        ("true", [c.NODE_TRUE], [], True),
        (
            "nullifier-leaf",
            [c.NODE_ALL, [[c.NODE_TRUE], c.attr([0, 1], "unique", [c.PRED_PRESENT])]],
            [(TL1, "unique", 1)],
            True,
        ),
        (
            "wrong-source",
            c.attr([1, 0], "approved", [c.PRED_PRESENT]),
            [(TL0, "approved", 1)],
            False,
        ),
    ]
    del IS0
    for name, tree, held, expected in cases:
        got = c.evaluate_policy(tree, held)
        assert got == expected, name
        f.add(
            f"context-policy-eval-{name}",
            f"Policy evaluation: {name}",
            S_POLICY,
            {
                "tree": tree,
                "held": [{"source": list(s), "attribute": a, "value": v} for s, a, v in held],
            },
            {"satisfied": got},
        )
    return f


def count_file(wd: World) -> File:
    f = File(
        SPEC,
        "count",
        "Daily-count buckets: bucket d = floor((t - opens) / 86400); the bucket holding "
        "closes is the last; noise is an input, one integer draw per bucket.",
    )
    opens = fixtures.ISSUED
    day = 86_400

    def case(name, desc, times, closes, noise):
        out = c.count_buckets(times, opens, closes, noise)
        f.add(
            f"context-count-{name}",
            desc,
            S_COUNT,
            {"opens": opens, "closes": closes, "receipt_times": times, "noise": noise},
            out,
        )

    times = [
        opens + 10,
        opens + 3600,
        opens + day + 5,
        opens + 2 * day + 100,
        opens + 2 * day + 200,
        opens + 3 * day - 1,
    ]
    case("three-days", "three full days", times, opens + 3 * day - 1, [1, -2, 0])
    case(
        "closes-mid-bucket",
        "closes mid-way through day 3; the bucket holding closes is noised at closes",
        times + [opens + 3 * day + 600],
        opens + 3 * day + 1800,
        [0, 1, 0, -1],
    )
    case(
        "extension",
        "closes extended by two days: the series continues with new buckets",
        times + [opens + 3 * day + 600, opens + 4 * day + 50],
        opens + 5 * day,
        [0, 1, 0, -1, 2, 0],
    )
    case(
        "late-ballot-ignored",
        "a receipt after closes is outside every bucket",
        times + [opens + 10 * day],
        opens + 3 * day - 1,
        [0, 0, 0],
    )
    return f


def results_key_file(wd: World) -> File:
    f = File(
        SPEC,
        "results-key",
        "The results key: X25519 private scalar from HKDF(secret_k, info hum/results-key/1), "
        "clamped, and its public key; a version a member phone must refuse.",
    )
    for name, secret in [
        ("zero", bytes(16)),
        ("epoch-3", RESULTS_SECRET),
        ("pattern", bytes(range(16))),
    ]:
        private, public = c.results_key(secret)
        f.add(
            f"context-results-key-{name}",
            f"Results key from secret '{name}'",
            S_RESULTS,
            {"secret_k": hexify(secret)},
            {"private": hexify(private), "resultsKey": hexify(public)},
        )
    _, right = c.results_key(RESULTS_SECRET)
    wrong = fixtures.fixed_bytes("not-derived-from-the-keyring")
    f.add(
        "context-results-key-mismatch",
        "A context version whose resultsKey is not the key derived from epoch 3's secret; "
        "a member phone that holds the epoch recomputes it and refuses the version",
        S_RESULTS,
        {
            "secret_k": hexify(RESULTS_SECRET),
            "resultsEpoch": 3,
            "resultsKey": hexify(wrong),
            "expected": hexify(right),
        },
        rejection={
            "step": None,
            "check": "results-key",
            "reason": "resultsKey does not match the keyring derivation",
        },
    )
    return f


def generate() -> list[File]:
    wd = get_world()
    return [
        world_file(wd),
        manifests_file(wd),
        policy_file(wd),
        count_file(wd),
        results_key_file(wd),
    ]
