"""Vectors for docs/specs/deck.md, and the shared world that release_body_vectors reuses.

The world sits on ``fixtures.build()``: two aggregator authorities, three custom verifiers, a
trust list, a Global context with one position, four contexts under authority A, an issue
map (18 positions, arguments), the valid decks and, after them, the invalid decks a
misbehaving log appended. Rating decks and releases are pending the take module.
"""

from __future__ import annotations

import copy
import functools
from fractions import Fraction
from typing import Any

from .. import cbor, cose, fixtures
from .. import manifest as m
from .. import release as rmath
from ..bodies import context as c
from ..bodies import deck as dk
from ..bodies import issue_map as im
from ..bodies import trust_list as tl
from ..bodies import verifier as vf
from ..cid import cid as compute_cid
from ..keys import SigningKey, key_from_label
from . import File, hexify, jsonable
from .manifest_vectors import bundle_json

SPEC = "deck"
S_RULES = "Validation rules (verification step 10 for deck)"
S_LOG = "Validation rules (D16, at the ledger and the aggregators)"
DAY = 86_400
T_DECK = fixtures.ISSUED + 5 * DAY  # decks are issued five days after the base world
OPENS = T_DECK + DAY
CLOSES = OPENS + 20 * DAY
WINDOW = dk.DEFAULT_ROUND_WINDOW
EXPIRES_FULL = CLOSES + 4 * WINDOW
EXPIRES_TALLIES = CLOSES + WINDOW
NOW = fixtures.NOW
CARDS = 18
TOPICS = ["Housing", "Money", "Politics", "Union"]
TOOLCHAIN = vf.TOOLCHAIN  # verifier.md "Code"


# ---------------------------------------------------------------- the world


class World:
    def __init__(self) -> None:
        self.fx = fixtures.build()
        self.w = self.fx.world
        self.keys = dict(self.fx.keys)
        self.a = self.fx.authority_a
        self.named: dict[str, m.Bundle] = {}
        self.decks: dict[str, m.Bundle] = {}
        self.d16_v2: m.Bundle | None = None  # a version 2 verified at closes ± 1 (D16)
        self.positions: list[m.Bundle] = []
        self.args: dict[str, m.Bundle] = {}
        self.text_counter = 0
        self._build()

    # -- keys and authorities
    def organizers(self) -> list[tuple[bytes, SigningKey]]:
        return [(b"b1", self.keys["b1"]), (b"b2", self.keys["b2"])]

    def keyset(self, label: str, sign: list[str], rotate: str, threshold: int = 1) -> m.Bundle:
        """A keyset lineage with ``sign`` keys (threshold) and one rotate key."""
        for n in sign + [rotate]:
            self.keys.setdefault(n, key_from_label(f"deck-world-{n}"))
        ks = [m.KeysetKey(n.encode(), self.keys[n].public, ("sign",)) for n in sign]
        ks.append(m.KeysetKey(rotate.encode(), self.keys[rotate].public, ("rotate",)))
        env = m.envelope(
            "keyset",
            m.build_keyset_body(ks, threshold, 1),
            authority=None,
            issued=fixtures.ISSUED,
        )
        b = self.w.append(env, [(rotate.encode(), self.keys[rotate])])
        self.named[f"keyset-{label}"] = b
        return b

    def signers(self, *names: str) -> list[tuple[bytes, SigningKey]]:
        return [(n.encode(), self.keys[n]) for n in names]

    def append(self, name: str, env: dict, signers) -> m.Bundle:
        b = self.w.append(env, signers)
        self.named[name] = b
        return b

    # -- blobs
    def blob(self, label: str, payload: Any = None) -> bytes:
        data = cbor.encode({"hum-vector-blob": label, "payload": payload})
        return self.w.put_blob(data)

    def text(self, text: str) -> bytes:
        return self.w.put_blob(text.encode())

    # -- verifiers and the trust list
    def verifier(self, label: str, attrs: list[dict], assurance: int, class_="person") -> m.Bundle:
        ks = self.keyset(f"v-{label}", [f"v-{label}-s"], f"v-{label}-r")
        code = self.blob(f"code-{label}")
        build = self.blob(f"build-{label}")
        body = vf.body(
            name=f"{label} verifier",
            operator="Hum vector operator",
            profile="custom",
            issuer_keys=[
                vf.issuer_key(
                    fixtures.fixed_bytes(f"kid-{label}", 8),
                    fixtures.fixed_bytes(f"bbs-{label}", 96),
                )
            ],
            host_keys=[
                vf.host_key(
                    fixtures.fixed_bytes(f"hkid-{label}", 8),
                    fixtures.fixed_bytes(f"hpke-{label}", 32),
                )
            ],
            attributes=attrs,
            evidence_=[
                vf.evidence("match", "other", "text", "Something else: a record to match"),
            ],
            dedup_=[vf.dedup("evidence", "match", "One card per record")],
            code_=vf.code(fixtures.fixed_bytes(f"source-{label}"), TOOLCHAIN),
            assurance=assurance,
            class_=class_,
        )
        env = m.envelope(
            "verifier",
            body,
            authority=ks.cid,
            issued=fixtures.ISSUED,
            refs={"code": code, "build": build},
        )
        return self.append(f"verifier-{label}", env, self.signers(f"v-{label}-s"))

    # -- contexts
    def context_body(self, changes: dict | None = None) -> dict:
        body = fixtures.context_body(self.fx, self.a)
        body[c.AGGREGATORS] = [self.leader.cid, self.helper.cid]
        body[c.ISSUERS] = [self.va_auth]
        # Draft 0.1 (context.md C5 and C16): no ``any`` node, single-valued leaves, and each
        # leaf's source resolves to exactly one verifier.
        body[c.ENTRY] = c.attr([c.SRC_ISSUER, 0], "approved", [c.PRED_PRESENT])
        body[c.VOTE] = [
            c.NODE_ALL,
            [
                c.attr([c.SRC_TRUST_LIST, 0], "ward", [c.PRED_SET, [1]]),
                c.attr([c.SRC_TRUST_LIST, 0], "unique", [c.PRED_PRESENT]),
            ],
        ]
        body[c.NULLIFIER] = [[c.SRC_TRUST_LIST, 0], "unique"]
        body[c.MIX_GLOBAL] = True
        for k, v in (changes or {}).items():
            body[k] = v
        return body

    def context(self, name: str, body: dict, refs: dict | None = None) -> m.Bundle:
        env = m.envelope("context", body, authority=self.a, issued=fixtures.ISSUED, refs=refs or {})
        return self.append(f"context-{name}", env, self.organizers())

    # -- issue map objects (authority form, so the context keys sign)
    def obj(
        self,
        name: str,
        type_: str,
        kind: int,
        ctx: m.Bundle,
        *,
        parent: m.Bundle | None = None,
        text: str = "Words.",
        signers=None,
        authority: bytes | None = None,
    ) -> m.Bundle:
        self.text_counter += 1
        body = {
            im.KIND: kind,
            im.AUTHOR: im.AUTHORITY,
            im.EDIT_KEY: key_from_label(f"deck-world-edit-{self.text_counter}").public,
            im.STATE: im.ACTIVE,
            im.SEALED: False,
        }
        refs = {"context": ctx.cid, "text": self.text(f"{text} #{self.text_counter}")}
        if parent is not None:
            refs["parent"] = parent.cid
        env = m.envelope(
            type_,
            body,
            authority=authority or self.a,
            issued=fixtures.ISSUED + 2 * DAY + self.text_counter,
            refs=refs,
        )
        return self.append(name, env, signers or self.organizers())

    def withdraw(self, name: str, v1: m.Bundle) -> m.Bundle:
        env = cbor.decode(v1.envelope)
        env2 = copy.deepcopy(env)
        env2[m.VERSION] = 2
        env2[m.LINEAGE] = v1.cid
        env2[m.PREV] = v1.cid
        env2[m.ISSUED] = env[m.ISSUED] + 60
        env2[m.BODY][im.STATE] = im.WITHDRAWN
        env2[m.BODY][im.MODERATION] = im.MOD_WITHDRAW
        return self.append(name, env2, self.organizers())

    # -- decks
    def deck_env(
        self,
        ctx: m.Bundle,
        plan_: dict,
        cards: list[dict],
        refs: dict[str, bytes],
        *,
        title: str = "Spring priorities",
        topics: list[str] | None = None,
        opens: int = OPENS,
        closes: int = CLOSES,
        expires: int | None = None,
        order: int = 0,
        kind: int = 0,
        version: int = 1,
        lineage: bytes | None = None,
        prev: bytes | None = None,
        issued: int = T_DECK,
    ) -> dict:
        rounds = 3 if dk.COVARIANCE in plan_[dk.P_PARTS] else 0
        window = plan_.get(dk.P_ROUND_WINDOW, WINDOW)
        if expires is None:
            expires = closes + (rounds + 1) * window
        all_refs = {"context": ctx.cid}
        all_refs.update(refs)
        body = dk.body(
            title=title,
            opens=opens,
            closes=closes,
            topics=topics if topics is not None else TOPICS,
            cards=cards,
            plan_=plan_,
            order=order,
            kind=kind,
        )
        return m.envelope(
            "deck",
            body,
            authority=self.a,
            version=version,
            lineage=lineage,
            prev=prev,
            issued=issued,
            expires=expires,
            refs=all_refs,
        )

    def full_refs(self, n: int = CARDS) -> tuple[list[dict], dict[str, bytes]]:
        """18 cards: 16 positions, one Global position (card 16), one statement blob (card 17)."""
        cards = []
        refs = {}
        for i in range(n - 2):
            cards.append(dk.card(dk.CARD_POSITION, i % len(TOPICS)))
            refs[f"card/{i}"] = self.positions[i].cid
        cards.append(dk.card(dk.CARD_POSITION, 2, dk.ORIGIN_GLOBAL))
        refs[f"card/{n - 2}"] = self.global_position.cid
        cards.append(dk.card(dk.CARD_BLOB, 3))
        refs[f"card/{n - 1}"] = self.statement_blob
        refs["card/0/pro"] = self.args["p0-pro"].cid
        refs["card/0/con"] = self.args["p0-con"].cid
        for i in range(1, 9):
            refs[f"card/{i}/pro"] = self.args[f"p{i}-pro"].cid
        return cards, refs

    def blob_cards(self, n: int) -> tuple[list[dict], dict[str, bytes]]:
        """n statement-blob cards (public), for decks in contexts that hold no positions."""
        cards = [dk.card(dk.CARD_BLOB, i % len(TOPICS)) for i in range(n)]
        refs = {f"card/{i}": self.text(f"Statement blob {i}") for i in range(n)}
        return cards, refs

    def deck(self, name: str, env: dict, signers=None) -> m.Bundle:
        b = self.append(f"deck-{name}", env, signers or self.organizers())
        self.decks[name] = b
        return b

    # -- the build
    def _build(self) -> None:
        self.leader = self.keyset("leader", ["l1"], "lr")
        self.helper = self.keyset("helper", ["h1", "h2"], "hr", threshold=2)
        # a helper whose keyset shares the leader's key (for release R2)
        self.keys["l1-shared"] = self.keys["l1"]
        self.helper_shared = self.keyset("helper-shared", ["l1-shared"], "hsr")
        # verifiers
        ward = vf.attribute("ward", "enum", "breakdown", "Ward", vf.enum_values(["W1", "W2", "W3"]))
        area = vf.attribute("area", "enum", "breakdown", "Area", vf.enum_values(["In", "Out"]))
        unit = vf.attribute("unit", "uint", "gate", "Unit", max_=5000)
        self.vd = self.verifier("district", [ward, area, unit], 2)
        # a second verifier that also exposes ward (for D9: a source resolving to two verifiers)
        self.vd2 = self.verifier("district-two", [ward], 2)
        self.vd2_auth = cbor.decode(self.vd2.envelope)[m.AUTHORITY]
        self.vu = self.verifier("unique", [vf.attribute("unique", "bool", "gate", "Unique")], 3)
        self.va = self.verifier("approved", [vf.attribute("approved", "bool", "gate")], 1)
        self.vd_auth = cbor.decode(self.vd.envelope)[m.AUTHORITY]
        self.vu_auth = cbor.decode(self.vu.envelope)[m.AUTHORITY]
        self.va_auth = cbor.decode(self.va.envelope)[m.AUTHORITY]
        # trust list
        tks = self.keyset("trust", ["ts"], "tr")
        tl_body = tl.body(
            name="Vector core list",
            publisher="Hum vector operator",
            kind="community",
            entries=[
                tl.entry(self.vd_auth, ["ward", "area"], note="District: ward and area"),
                tl.entry(self.vu_auth, ["unique"], min_assurance=3),
            ],
            min_assurance=2,
        )
        self.tl = self.append(
            "trust-list",
            m.envelope("trust-list", tl_body, authority=tks.cid, issued=fixtures.ISSUED),
            self.signers("ts"),
        )
        self.assurance = sorted([(self.vd_auth, 2), (self.vu_auth, 3)])
        # a second list in which two authorities accept ward and one accepts area
        tl2_body = tl.body(
            name="Vector second list",
            publisher="Hum vector operator",
            kind="community",
            entries=[
                tl.entry(self.vd_auth, ["ward", "area"], note="District: ward and area"),
                tl.entry(self.vd2_auth, ["ward"], note="District two: ward only"),
            ],
            min_assurance=2,
        )
        self.tl2 = self.append(
            "trust-list-two",
            m.envelope("trust-list", tl2_body, authority=tks.cid, issued=fixtures.ISSUED + 1),
            self.signers("ts"),
        )
        # Global context under its own authority, with one position
        gks = self.keyset("global", ["g1"], "gr")
        gbody = fixtures.context_body(self.fx, gks.cid)
        gbody[c.NAME] = "Global"
        self.global_ctx = self.append(
            "context-global",
            m.envelope("context", gbody, authority=gks.cid, issued=fixtures.ISSUED),
            self.signers("g1"),
        )
        self.w.global_context = self.global_ctx.cid
        gissue = self.obj(
            "global-issue", "issue", im.KIND_ISSUE, self.global_ctx, text="Global question",
            signers=self.signers("g1"), authority=gks.cid,
        )  # fmt: skip
        self.global_position = self.obj(
            "global-position", "position", im.KIND_POSITION, self.global_ctx, parent=gissue,
            text="A Global position", signers=self.signers("g1"), authority=gks.cid,
        )  # fmt: skip
        # contexts under authority A
        tlrefs = {"tl/0": self.tl.cid}
        self.ctx = self.context("main", self.context_body(), tlrefs)
        secret = fixtures.fixed_bytes("results-epoch-3", 16)
        _, results_pub = c.results_key(secret)
        self.ctx_sealed = self.context(
            "sealed-results",
            self.context_body({
                c.PERMS: {c.P_CARDS: 2, c.P_RESULTS: 1, c.P_MEMBER_LIST: 1},
                c.RESULTS_KEY: results_pub,
                c.RESULTS_EPOCH: 3,
            }),
            tlrefs,
        )  # fmt: skip
        self.ctx_year = self.context(
            "rho-year", self.context_body({c.FLOORS: c.floors(rho_year=Fraction(1))}), tlrefs
        )
        self.ctx_nomix = self.context("no-global", self.context_body({c.MIX_GLOBAL: False}), tlrefs)
        self.ctx_sealed_text = self.context(
            "sealed-text", self.context_body({c.SEALED: True}), tlrefs
        )
        self.ctx_shared = self.context(
            "shared-key",
            self.context_body({c.AGGREGATORS: [self.leader.cid, self.helper_shared.cid]}),
            tlrefs,
        )
        self.ctx_count = self.context(
            "count-cap",
            self.context_body({c.COUNT: {c.CNT_RHO_MAX: rmath.rat(Fraction(1, 400))}}),
            tlrefs,
        )
        # a context with two trust lists; tl/1 is used for area (one authority) so C16 holds,
        # while a breakdown on ward through tl/1 resolves to two authorities (D9)
        two_lists = self.context_body()
        two_lists[c.VOTE][1].append(c.attr([c.SRC_TRUST_LIST, 1], "area", [c.PRED_SET, [0]]))
        self.ctx_two_lists = self.context(
            "two-lists", two_lists, {"tl/0": self.tl.cid, "tl/1": self.tl2.cid}
        )
        # issue map in the main context
        self.issue = self.obj("issue", "issue", im.KIND_ISSUE, self.ctx, text="What next?")
        for i in range(CARDS):
            self.positions.append(
                self.obj(f"position-{i}", "position", im.KIND_POSITION, self.ctx,
                         parent=self.issue, text=f"Position {i}")
            )  # fmt: skip
        self.args["p0-pro"] = self.obj("arg-p0-pro", "argument", im.KIND_PRO, self.ctx,
                                       parent=self.positions[0], text="For 0")  # fmt: skip
        self.args["p0-con"] = self.obj("arg-p0-con", "argument", im.KIND_CON, self.ctx,
                                       parent=self.positions[0], text="Against 0")  # fmt: skip
        for i in range(1, 10):  # p9-pro is pinned by no valid deck (the D12 ref-added case)
            self.args[f"p{i}-pro"] = self.obj(f"arg-p{i}-pro", "argument", im.KIND_PRO, self.ctx,
                                              parent=self.positions[i], text=f"For {i}")  # fmt: skip
        self.withdrawn = self.obj("position-withdrawn", "position", im.KIND_POSITION, self.ctx,
                                  parent=self.issue, text="Withdrawn later")  # fmt: skip
        self.withdrawn_v2 = self.withdraw("position-withdrawn-v2", self.withdrawn)
        sissue = self.obj("sealed-issue", "issue", im.KIND_ISSUE, self.ctx_sealed, text="Sealed?")
        self.foreign_position = self.obj("position-other-context", "position", im.KIND_POSITION,
                                         self.ctx_sealed, parent=sissue, text="Elsewhere")  # fmt: skip
        self.statement_blob = self.text("A statement that is not a position.")
        self.other_statement = self.text("Another plain statement.")
        # valid decks
        cards, refs = self.full_refs()
        self.deck(
            "valid-full",
            self.deck_env(
                self.ctx, dk.plan_full(CARDS, cov_statements=CARDS, absorb=True), cards, refs
            ),
        )
        self.deck(
            "valid-tallies-only",
            self.deck_env(self.ctx, dk.plan_tallies_only(CARDS), cards, refs, title="Tallies only"),
        )
        self.deck(
            "valid-ibis", self.deck_env(self.ctx, dk.plan_ibis(CARDS), cards, refs, title="IBIS")
        )
        self.deck(
            "valid-breakdown",
            self.deck_env(
                self.ctx,
                dk.plan_breakdown(CARDS, [c.SRC_TRUST_LIST, 0], "ward", [1, 2, 3]),
                cards,
                refs,
                title="Breakdown",
            ),
        )
        self.deck(
            "valid-fixed-order",
            self.deck_env(self.ctx, dk.plan_full(CARDS), cards, refs, title="Fixed", order=1),
        )
        self.deck(
            "valid-expires-max",
            self.deck_env(
                self.ctx, dk.plan_full(CARDS), cards, refs, title="Expires at the bound",
                expires=CLOSES + dk.PUBLISH_WINDOW + 4 * WINDOW,
            ),
        )  # fmt: skip
        v1 = self.deck(
            "valid-v2-extend-v1",
            self.deck_env(self.ctx, dk.plan_full(CARDS), cards, refs, title="Extended"),
        )
        self.deck(
            "valid-v2-extend",
            self.extend(v1, closes=CLOSES + 2 * DAY, expires=EXPIRES_FULL + 2 * DAY),
        )
        self.cards, self.refs = cards, refs
        self.invalid_decks = build_invalid_decks(self)
        from . import release_body_vectors as rbv

        self.releases = rbv.build_releases(self)
        self.w.finalize()

    def extend(self, v1: m.Bundle, *, closes: int | None = None, expires: int | None = None,
               mutate=None) -> dict:  # fmt: skip
        env = copy.deepcopy(cbor.decode(v1.envelope))
        env[m.VERSION] = 2
        env[m.LINEAGE] = v1.cid
        env[m.PREV] = v1.cid
        env[m.ISSUED] = env[m.ISSUED] + DAY
        if closes is not None:
            env[m.BODY][dk.CLOSES] = closes
        if expires is not None:
            env[m.EXPIRES] = expires
        if mutate is not None:
            mutate(env)
        return env


@functools.lru_cache(maxsize=1)
def get_world() -> World:
    return World()


# ---------------------------------------------------------------- running cases


def run(f: File, wd: World, suffix: str, desc: str, bundle: m.Bundle, *, step=None, rule=None,
        now: int = NOW, section: str = S_RULES, extra: dict | None = None) -> None:  # fmt: skip
    ctx = wd.w.context(now=now)
    inputs = {"bundle": bundle_json(bundle), "now": now}
    if extra:
        inputs.update(extra)
    try:
        env = m.verify_bundle(ctx, bundle)
    except m.Rejection as e:
        if step is None or e.step != step or (rule is not None and e.rule != rule):
            raise AssertionError(
                f"{suffix} {desc!r}: expected step {step} {rule}, got {e} ({e.rule})"
            ) from e
        rej = {"step": e.step, "rule": e.rule, "reason": e.reason}
        f.add(suffix, desc, section, inputs, rejection=rej)
        return
    if step is not None:
        raise AssertionError(f"{suffix} {desc!r}: expected step {step} {rule}, accepted")
    f.add(
        suffix,
        desc,
        section,
        inputs,
        {"accept": True, "type": env[m.TYPE], "version": env[m.VERSION]},
    )


def resign(wd: World, env: dict, proof_from: m.Bundle, signers=None) -> m.Bundle:
    data = cbor.encode(env)
    cid = compute_cid(data)
    sigs = [cose.sign_cid(k, kid, cid) for kid, k in (signers or wd.organizers())]
    return m.Bundle(data, cose.encode_cose_sign(sigs), cid, copy.deepcopy(proof_from.proof))


# ---------------------------------------------------------------- deck files


def build_invalid_decks(wd: World) -> list[tuple[str, str, str, m.Bundle]]:
    """Append every invalid deck to the log (step-10 failures must be logged to reach step 10)."""
    cases: list[tuple[str, str, str, m.Bundle]] = []
    cards, refs = wd.cards, wd.refs

    def logged(rule: str, name: str, desc: str, env: dict, signers=None):
        b = wd.deck(f"invalid-{rule}-{name}", env, signers)
        cases.append((rule, name, desc, b))

    def mut(rule: str, name: str, desc: str, fn, *, ctx=None, plan_=None, cards_=None, refs_=None,
            title=None, **kw):  # fmt: skip
        env = wd.deck_env(
            ctx or wd.ctx,
            plan_ if plan_ is not None else dk.plan_full(CARDS, cov_statements=CARDS, absorb=True),
            cards_ if cards_ is not None else copy.deepcopy(cards),
            refs_ if refs_ is not None else dict(refs),
            title=title or f"{rule} {name}",
            **kw,
        )
        fn(env)
        logged(rule, name, desc, env)

    body = lambda e: e[m.BODY]  # noqa: E731
    plan = lambda e: e[m.BODY][dk.PLAN]  # noqa: E731

    # D1
    mut("D1", "missing-order", "missing order", lambda e: body(e).pop(dk.ORDER))
    mut("D1", "kind-2", "kind 2", lambda e: body(e).__setitem__(dk.KIND, 2))
    mut("D1", "unknown-key", "unknown body key 8", lambda e: body(e).__setitem__(8, 1))
    # D2
    mut("D2", "closes-ten-minutes", "closes 10 minutes after opens",
        lambda e: body(e).__setitem__(dk.CLOSES, OPENS + 600), expires=OPENS + 600 + 4 * WINDOW)  # fmt: skip
    mut("D2", "window-400-days", "a 400-day window",
        lambda e: body(e).__setitem__(dk.CLOSES, OPENS + 400 * DAY), expires=OPENS + 400 * DAY + 4 * WINDOW)  # fmt: skip
    # D3
    mut(
        "D3",
        "duplicate-topic",
        "duplicate topic",
        lambda e: body(e).__setitem__(dk.TOPICS, ["A", "A", "B", "C"]),
    )
    mut(
        "D3",
        "topic-out-of-range",
        "topic index out of range",
        lambda e: body(e)[dk.CARDS][0].__setitem__(dk.C_TOPIC, 4),
    )
    # D4
    three = [dk.card(0, 0), dk.card(0, 1), dk.card(0, 2)]
    three_refs = {"card/0": wd.positions[0].cid, "card/1": wd.positions[1].cid}
    mut(
        "D4",
        "card-2-missing",
        "card/2 missing with three cards",
        lambda e: None,
        cards_=three,
        refs_=three_refs,
    )
    dup_refs = dict(three_refs)
    dup_refs["card/2"] = wd.positions[1].cid
    mut(
        "D4",
        "duplicate-card-cid",
        "duplicate card CID",
        lambda e: None,
        cards_=three,
        refs_=dup_refs,
    )
    four = [dk.card(0, 0), dk.card(0, 1), dk.card(0, 2), dk.card(0, 3)]
    four_refs = {f"card/{i}": wd.positions[i].cid for i in range(4)}
    four_refs["card/5/pro"] = wd.args["p0-pro"].cid
    mut(
        "D4",
        "pro-without-card",
        "card/5/pro with four cards",
        lambda e: None,
        cards_=four,
        refs_=four_refs,
    )
    blobcards = [dk.card(0, 0), dk.card(1, 1)]
    blobrefs = {
        "card/0": wd.positions[0].cid,
        "card/1": wd.statement_blob,
        "card/1/pro": wd.args["p1-pro"].cid,
    }
    mut(
        "D4",
        "pro-on-blob-card",
        "card/1/pro on a kind 1 card",
        lambda e: None,
        cards_=blobcards,
        refs_=blobrefs,
    )
    # D5
    mut("D5", "context-is-deck", "context ref points at a deck",
        lambda e: e[m.REFS].__setitem__("context", wd.decks["valid-full"].cid))  # fmt: skip
    # D6
    gcards = [dk.card(0, 0, dk.ORIGIN_GLOBAL)]
    grefs = {"card/0": wd.global_position.cid}
    mut("D6", "mixglobal-false", "Global card with mixGlobal false", lambda e: None,
        ctx=wd.ctx_nomix, cards_=gcards, refs_=grefs, plan_=dk.plan_full(1))  # fmt: skip
    mut("D6", "object-not-global", "Global card whose object is in this context", lambda e: None,
        cards_=gcards, refs_={"card/0": wd.positions[0].cid}, plan_=dk.plan_full(1))  # fmt: skip
    # D7
    one = [dk.card(0, 0)]
    mut("D7", "position-other-context", "position from another context", lambda e: None,
        cards_=one, refs_={"card/0": wd.foreign_position.cid}, plan_=dk.plan_full(1))  # fmt: skip
    mut("D7", "withdrawn-position", "withdrawn position", lambda e: None,
        cards_=one, refs_={"card/0": wd.withdrawn.cid}, plan_=dk.plan_full(1))  # fmt: skip
    mut("D7", "con-under-pro", "con argument under /pro", lambda e: None, cards_=one,
        refs_={"card/0": wd.positions[0].cid, "card/0/pro": wd.args["p0-con"].cid}, plan_=dk.plan_full(1))  # fmt: skip
    mut("D7", "argument-other-card", "argument whose parent is another card", lambda e: None, cards_=one,
        refs_={"card/0": wd.positions[0].cid, "card/0/pro": wd.args["p1-pro"].cid}, plan_=dk.plan_full(1))  # fmt: skip
    mut("D7", "sealed-blob-no-epoch", "sealed statement blob without epoch", lambda e: None,
        ctx=wd.ctx_sealed_text, cards_=[dk.card(1, 0)], refs_={"card/0": wd.statement_blob}, plan_=dk.plan_full(1))  # fmt: skip
    mut("D7", "global-blob-with-epoch", "Global statement blob with epoch", lambda e: None,
        cards_=[dk.card(1, 0, dk.ORIGIN_GLOBAL, epoch=3)], refs_={"card/0": wd.statement_blob}, plan_=dk.plan_full(1))  # fmt: skip
    mut("D7", "take-card-in-vote-deck", "kind 2 card in a vote deck", lambda e: None,
        cards_=[dk.card(2, 0)], refs_={"card/0": wd.statement_blob}, plan_=dk.plan_full(1))  # fmt: skip
    # D8
    mut("D8", "no-receipts", "part 8 missing", lambda e: plan(e)[dk.P_PARTS].pop(dk.RECEIPTS))
    mut("D8", "partial-tier", "part 1 without 2 and 3",
        lambda e: (plan(e)[dk.P_PARTS].pop(dk.MAP), plan(e)[dk.P_PARTS].pop(dk.GROUPS)))  # fmt: skip
    mut(
        "D8",
        "unknown-part",
        "unknown part 9",
        lambda e: plan(e)[dk.P_PARTS].__setitem__(9, [1, 1000]),
    )
    mut("D8", "zero-rho", "zero rho", lambda e: plan(e)[dk.P_PARTS].__setitem__(dk.COUNT, [0, 1]))
    mut(
        "D8",
        "sum-below-rho",
        "parts sum below rho",
        lambda e: plan(e).__setitem__(dk.P_RHO, [3, 10]),
    )
    # D9
    mut("D9", "absorb-without-count", "absorb without part 4", lambda e: None,
        plan_=dk.plan_full(CARDS, count=False, absorb=True))  # fmt: skip
    ibis_noargs_refs = {k: v for k, v in refs.items() if "/pro" not in k and "/con" not in k}
    mut("D9", "movement-no-arguments", "part 5 with no argument refs", lambda e: None,
        plan_=dk.plan_ibis(CARDS), refs_=ibis_noargs_refs)  # fmt: skip
    mut("D9", "ratings-no-cap", "part 6 without capRatings", lambda e: plan(e).pop(dk.P_CAP_RATINGS),
        plan_=dk.plan_ibis(CARDS))  # fmt: skip
    mut("D9", "breakdown-one-value", "breakdown with one value", lambda e: None,
        plan_=dk.plan_breakdown(CARDS, [0, 0], "ward", [1]))  # fmt: skip
    mut("D9", "breakdown-gate-only", "breakdown on a gate-only attribute", lambda e: None,
        plan_=dk.plan_breakdown(CARDS, [0, 0], "unit", [1, 2]))  # fmt: skip
    mut("D9", "breakdown-source-missing", "breakdown source not in the context", lambda e: None,
        plan_=dk.plan_breakdown(CARDS, [0, 5], "ward", [1, 2, 3]))  # fmt: skip
    mut("D9", "breakdown-source-two-verifiers",
        "breakdown source tl/1 accepts ward from two verifier authorities", lambda e: None,
        ctx=wd.ctx_two_lists, cards_=[dk.card(1, 0)], refs_={"card/0": wd.statement_blob},
        plan_=dk.plan_breakdown(1, [c.SRC_TRUST_LIST, 1], "ward", [1, 2, 3]))  # fmt: skip
    # D10
    mut("D10", "rho-above-floor", "rho above the context floor", lambda e: None,
        plan_=dk.plan_full(CARDS, rho=Fraction(3, 10)))  # fmt: skip
    mut("D10", "delta-above-floor", "delta above the context floor", lambda e: None,
        plan_=dk.plan_full(CARDS, delta=Fraction(1, 100_000)))  # fmt: skip
    mut("D10", "minvoters-below-floor", "minVoters below the context floor", lambda e: None,
        plan_=dk.plan_full(CARDS, min_voters=50))  # fmt: skip
    mut("D10", "count-above-rhomax", "part 4 above count.rhoMax", lambda e: None, ctx=wd.ctx_count,
        cards_=[dk.card(1, 0)], refs_={"card/0": wd.statement_blob}, plan_=dk.plan_full(1))  # fmt: skip
    # D11
    mut(
        "D11",
        "gate-below-protocol",
        "gates[0] = 50",
        lambda e: None,
        plan_=dk.plan_full(CARDS, gates={0: 50}),
    )
    mut(
        "D11",
        "gate-on-count",
        "gates[4]",
        lambda e: None,
        plan_=dk.plan_full(CARDS, gates={4: 100}),
    )
    mut("D11", "minvoters-above-gate", "minVoters 900 with map gate 800", lambda e: None,
        plan_=dk.plan_full(CARDS, min_voters=900))  # fmt: skip
    mut("D11", "covstatements-over-cards", "covStatements > cards", lambda e: None,
        plan_=dk.plan_full(CARDS, cov_statements=CARDS + 1))  # fmt: skip
    cs130, rs130 = wd.blob_cards(130)
    mut("D11", "covstatements-129", "covStatements 129 on a 130-card deck", lambda e: None,
        plan_=dk.plan_full(130, cov_statements=129), cards_=cs130, refs_=rs130)  # fmt: skip
    mut("D11", "grid-7", "grid 7", lambda e: None, plan_=dk.plan_full(CARDS, grid=7))
    mut(
        "D11",
        "blur-over-grid",
        "blur > grid",
        lambda e: None,
        plan_=dk.plan_full(CARDS, blur=Fraction(25)),
    )
    mut(
        "D11",
        "covscale-1000",
        "covScale 1000",
        lambda e: None,
        plan_=dk.plan_full(CARDS, cov_scale=1000),
    )
    mut("D11", "roundwindow-60", "roundWindow 60", lambda e: None, plan_=dk.plan_full(CARDS, round_window=60),
        expires=CLOSES + 4 * WINDOW)  # fmt: skip

    # D12: each case gets its own version-1 lineage
    def v2_case(name, desc, mutate, *, closes=None, expires=None, rule="D12"):
        v1 = wd.deck(
            f"lineage-{rule}-{name}-v1",
            wd.deck_env(
                wd.ctx,
                dk.plan_full(CARDS),
                copy.deepcopy(cards),
                dict(refs),
                title=f"{rule} {name}",
            ),
        )
        env = wd.extend(v1, closes=closes, expires=expires, mutate=mutate)
        logged(rule, name, desc, env)

    v2_case(
        "card-changed",
        "version 2 changes a card",
        lambda e: body(e)[dk.CARDS][0].__setitem__(dk.C_TOPIC, 1),
    )
    v2_case("closes-earlier", "version 2 moves closes earlier", None, closes=CLOSES - DAY)
    v2_case(
        "opens-changed",
        "version 2 changes opens",
        lambda e: body(e).__setitem__(dk.OPENS, OPENS + 3600),
    )
    v2_case(
        "plan-changed", "version 2 changes the plan", lambda e: plan(e).__setitem__(dk.P_GRID, 32)
    )
    v2_case(
        "ref-added",
        "version 2 adds a ref",
        lambda e: e[m.REFS].__setitem__("card/9/pro", wd.args["p9-pro"].cid),
    )
    v2_case("expires-lowered", "version 2 lowers expires", None, expires=EXPIRES_FULL - 1)
    v2_case("expires-raised-closes-unchanged", "version 2 raises expires with closes unchanged",
            None, expires=EXPIRES_FULL + DAY)  # fmt: skip
    # D13
    mut("D13", "expires-absent", "expires absent", lambda e: e.pop(m.EXPIRES))
    mut(
        "D13",
        "expires-short",
        "expires too short for three rounds",
        lambda e: None,
        expires=CLOSES + 3 * WINDOW,
    )
    mut(
        "D13",
        "expires-far",
        "expires one second past closes + PUBLISH_WINDOW + four roundWindows",
        lambda e: None,
        expires=CLOSES + dk.PUBLISH_WINDOW + 4 * WINDOW + 1,
    )
    v2_case("extend-outruns-expires", "version 2 extends closes so that expires is too short",
            None, closes=CLOSES + 2 * DAY, rule="D13")  # fmt: skip
    # D14
    mut("D14", "cap-0", "cap 0", lambda e: None, plan_=dk.plan_full(0))
    mut("D14", "cap-300", "cap 300", lambda e: None, plan_=dk.plan_full(300))
    mut("D14", "capmovement-over-cards", "capMovement larger than the deck", lambda e: None,
        plan_=dk.plan_ibis(CARDS, cap_movement=CARDS + 1))  # fmt: skip
    mut("D14", "capratings-over-arguments", "capRatings larger than the argument count", lambda e: None,
        plan_=dk.plan_ibis(CARDS, cap_ratings=11))  # fmt: skip
    # D16 needs a clock: one version 2 bundle, verified at closes ± 1 by manifests_file
    d16_v1 = wd.deck(
        "lineage-D16-v1",
        wd.deck_env(wd.ctx, dk.plan_full(CARDS), copy.deepcopy(cards), dict(refs), title="D16"),
    )
    wd.d16_v2 = wd.deck(
        "lineage-D16-v2", wd.extend(d16_v1, closes=CLOSES + DAY, expires=EXPIRES_FULL + DAY)
    )
    # D15 (vote-deck half; rating decks are pending the take module)
    mut("D15", "vote-deck-source-ref", "vote deck with a source ref",
        lambda e: e[m.REFS].__setitem__("source", wd.decks["valid-full"].cid))  # fmt: skip
    return cases


VALID_DECKS = (
    "valid-full",
    "valid-tallies-only",
    "valid-ibis",
    "valid-breakdown",
    "valid-fixed-order",
    "valid-expires-max",
    "valid-v2-extend",
)


def manifests_file(wd: World, invalid) -> File:
    f = File(
        SPEC,
        "manifests",
        "Valid decks and one invalid deck per rule sub-condition (deck.md Vectors). Invalid decks "
        "were appended by a misbehaving log so that step 10 is reached. Each case names the "
        "context it pins; all bundles are in world.json. Rating decks (deck-valid-rating and "
        "the D15 rating cases) are pending the take module.",
    )
    for name in VALID_DECKS:
        b = wd.decks[name]
        plan_ = cbor.decode(b.envelope)[m.BODY][dk.PLAN]
        run(f, wd, f"deck-{name}", f"{name} verifies", b,
            extra={"context": hexify(cbor.decode(b.envelope)[m.REFS]["context"]),
                   "plan_view": jsonable(plan_)})  # fmt: skip
    for rule, name, desc, b in invalid:
        run(f, wd, f"deck-invalid-{rule}-{name}", desc, b, step=10, rule=rule,
            extra={"context": hexify(cbor.decode(b.envelope)[m.REFS]["context"])})  # fmt: skip
    # D16: a submission-time rule the ledger and aggregators run with their own clock (phones
    # never do: the same version 2 verifies at steps 1 to 11 at any clock). One version 2,
    # submitted one second after and one second before version 1's closes.
    env2 = cbor.decode(wd.d16_v2.envelope)
    prev = cbor.decode(wd.named["deck-lineage-D16-v1"].envelope)
    for suffix, desc, log_now in (
        ("deck-invalid-D16-after-closes", "version 2 submitted one second after version 1's "
         "closes: refused by the ledger's clock", CLOSES + 1),
        ("deck-valid-D16-before-closes", "version 2 submitted one second before version 1's "
         "closes: admitted", CLOSES - 1),
    ):  # fmt: skip
        inputs = {"log_now": log_now, "bundle": bundle_json(wd.d16_v2),
                  "previous_closes": prev[m.BODY][dk.CLOSES]}  # fmt: skip
        result = dk.log_check(env2, prev, log_now)
        if result is None:
            assert suffix.startswith("deck-valid-"), suffix
            f.add(suffix, desc, S_LOG, inputs, {"admitted": True, "version": env2[m.VERSION]})
        else:
            rule, reason = result
            assert suffix.startswith("deck-invalid-") and rule == "D16", suffix
            f.add(suffix, desc, S_LOG, inputs,
                  rejection={"step": None, "check": "log-admission", "rule": rule,
                             "reason": reason})  # fmt: skip
    return f


def plan_math_file(wd: World) -> File:
    f = File(
        SPEC,
        "plan-math",
        "σ per part for the valid plans (micro-units from the exact rational σ², ADR 0010) and "
        "Δ_cov for (M, covScale) pairs (release.md Round 1).",
    )
    for name in ("valid-full", "valid-tallies-only", "valid-ibis", "valid-breakdown"):
        env = cbor.decode(wd.decks[name].envelope)
        plan_ = env[m.BODY][dk.PLAN]
        cards = len(env[m.BODY][dk.CARDS])
        out = {}
        for p, r in plan_[dk.P_PARTS].items():
            rho_p = Fraction(r[0], r[1])
            rp = dk.to_release_plan(plan_, cards)
            d2 = rmath.delta_squared(p, rp, cards)
            s_r = rmath.sigma_rational(d2, rho_p)
            scale = rp.cov_scale if p == rmath.COVARIANCE else 1
            out[str(p)] = {"delta_squared": d2, "rho": {"num": r[0], "den": r[1]},
                           "sigma_r": {"num": s_r.numerator, "den": s_r.denominator},
                           "sigma_micro": rmath.sigma_micro(d2, rho_p, scale)}  # fmt: skip
        f.add("sigma", f"σ per part for {name}", "The release plan",
              {"plan": jsonable(plan_), "cards": cards}, out)  # fmt: skip
    rating = dk.plan_rating()
    rp = dk.to_release_plan(rating, 12)
    f.add("sigma", "σ per part for the rating plan (parts 0, 3, 8; cap 20; 12 cards)", "Rating decks",
          {"plan": jsonable(rating), "cards": 12},
          {str(p): {"delta_squared": rmath.delta_squared(p, rp, 12),
                    "sigma_r": {"num": rmath.sigma_rational(rmath.delta_squared(p, rp, 12), Fraction(r[0], r[1])).numerator,
                                "den": rmath.sigma_rational(rmath.delta_squared(p, rp, 12), Fraction(r[0], r[1])).denominator},
                    "sigma_micro": rmath.sigma_micro(rmath.delta_squared(p, rp, 12), Fraction(r[0], r[1]))}
           for p, r in rating[dk.P_PARTS].items()})  # fmt: skip
    import math

    for m_, scale in ((18, 2**16), (60, 2**16), (60, 2**8), (256, 2**24)):
        d_cov = scale + math.ceil(math.sqrt(m_ * (m_ + 1) / 2) / 2)
        f.add("delta-cov", f"Δ_cov for M {m_}, covScale {scale}", "release.md Round 1",
              {"M": m_, "covScale": scale}, {"delta_cov": d_cov, "delta_cov_squared": d_cov * d_cov})  # fmt: skip
    return f


def world_file(wd: World) -> File:
    f = File(
        SPEC,
        "world",
        "Every bundle the deck and release cases resolve against, beyond the base "
        "manifest world: aggregator keysets, verifiers, the trust list, the Global context, the "
        "contexts, the issue map, every deck and every release.",
    )
    base = {b.cid for b in fixtures.build().world.bundles.values()}
    names = {b.cid: n for n, b in wd.named.items()}
    bundles = []
    for b in wd.w.bundles.values():
        if b.cid in base:
            continue
        bundles.append({"name": names.get(b.cid, "?"), **bundle_json(b),
                        "view": jsonable(cbor.decode(b.envelope))})  # fmt: skip
    f.add("world", "Bundles, blobs, checkpoint", "Vectors",
          {"keys": {n: {"seed": hexify(k.seed), "public": hexify(k.public)}
                    for n, k in wd.keys.items() if n not in fixtures.KEY_LABELS},
           "global_context": hexify(wd.w.global_context),
           "sealed_results_secret_k": hexify(fixtures.fixed_bytes("results-epoch-3", 16))},
          {"checkpoint": wd.w.note().text(),
           "entries": [hexify(x) for x in wd.w.leaves],
           "blobs": {hexify(k): (hexify(v) if len(v) <= 4096 else {"sha256": __import__("hashlib").sha256(v).hexdigest()})
                     for k, v in wd.w.blobs.items()},
           "bundles": bundles})  # fmt: skip
    return f


def generate() -> list[File]:
    wd = get_world()
    return [world_file(wd), manifests_file(wd, wd.invalid_decks), plan_math_file(wd)]
