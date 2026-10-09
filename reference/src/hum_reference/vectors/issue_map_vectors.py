"""Vectors for docs/specs/issue-map.md: the three authored types, authorship bundles, edit keys,
annotations and duplicate detection.

Membership proofs are credentials.md presentations whose BBS proof (P4) is an input, so
`im-bad-proof-unbound` has no vector. The world has one log of record; a second listed log is
modelled minimally for `im-ok-two-logs` (a second `manifest.World` under its own log
authority holding the same bundle). Pending: `im-bad-slot-reused-other-log` and the chat
`promote` flow.
"""

from __future__ import annotations

from typing import Any

from .. import cbor, fixtures, storage
from .. import credentials as cr
from .. import manifest as m
from ..bodies import agent_sponsor as sp
from ..bodies import context as c
from ..bodies import issue_map as im
from ..bodies import verifier as vf
from ..keys import SigningKey, key_from_label
from . import File, hexify, jsonable

SPEC = "issue-map"
S_AUTH = "Authority and authorship"
S_RULES = "Validation rules"
S_AFTER = "After a release"
DAY = 86_400
T0 = fixtures.ISSUED + 10 * DAY  # objects are issued ten days after the base world
NOW = T0 + 3600
EXPIRES = T0 + 30 * DAY
EPOCH_SECRET = fixtures.fixed_bytes("keyring-epoch-4", 16)
VALIDITY = 7_776_000  # 90 days: V = 3 periods per issuer epoch
V = cr.validity_periods(VALIDITY)
EPOCH0 = cr.epoch_now(T0, V)  # the issuer epoch the objects' cards carry
NEXT_EPOCH_NOW = (EPOCH0 + 1) * V * cr.PERIOD + 7200  # a phone syncing in the next epoch
LOG_SKEW_T = T0 + 7200  # a log clock two hours from the objects' issued
VERIFY_AT = {"im-ok-verified-next-epoch": NEXT_EPOCH_NOW}  # per-object `now` overrides


def bundle_json(b: m.Bundle) -> dict[str, Any]:
    """Like manifest_vectors.bundle_json, allowing absent signatures and an authorship field."""
    out: dict[str, Any] = {"cid": hexify(b.cid), "envelope": hexify(b.envelope)}
    if b.signatures is not None:
        out["signatures"] = hexify(b.signatures)
    if b.authorship is not None:
        out["authorship"] = hexify(b.authorship)
    if b.proof is not None:
        out["log"] = {
            "log": hexify(b.proof.log),
            "index": b.proof.position,
            "checkpoint": b.proof.checkpoint_note,
            "path": [hexify(h) for h in b.proof.inclusion],
        }
    return out


class World:
    """The issue-map test world on top of ``fixtures.build()``."""

    def __init__(self) -> None:
        self.fx = fixtures.build()
        self.w = self.fx.world
        self.keys = self.fx.keys
        self.a = self.fx.authority_a
        self.alice = key_from_label("chat-alice")
        self.bob = key_from_label("chat-bob")
        self.edit_root = fixtures.fixed_bytes("edit-root-alice")
        self.agent_key = key_from_label("agent-key")
        self.named: dict[str, m.Bundle] = {}
        self._slot_counter = 0
        self.kid0 = fixtures.fixed_bytes("kid-im-approved", 8)
        self.kid1 = fixtures.fixed_bytes("kid-im-approved-2", 8)
        self.kid = self.kid0
        vkeys = {"v-im": key_from_label("v-im"), "v-im-rotate": key_from_label("v-im-rotate")}
        self.verifier_keys = vkeys
        self.verifier_keyset = self.w.append(
            fixtures.service_keyset("v-im", "v-im-rotate", vkeys),
            [(b"v-im-rotate", vkeys["v-im-rotate"])],
        )
        self.named["verifier-approved-keyset"] = self.verifier_keyset
        self.verifier_cid = self.verifier_keyset.cid  # the verifier authority (keyset) CID
        self.verifier_v1 = self.verifier_version(1)
        self.kid_r = fixtures.fixed_bytes("kid-im-resident", 8)
        vkeys2 = {"v-im-2": key_from_label("v-im-2"), "v-im-2-rotate": key_from_label("v-im-2-r")}
        self.verifier2_keyset = self.w.append(
            fixtures.service_keyset("v-im-2", "v-im-2-rotate", vkeys2),
            [(b"v-im-2-rotate", vkeys2["v-im-2-rotate"])],
        )
        self.named["verifier-resident-keyset"] = self.verifier2_keyset
        self.verifier2_cid = self.verifier2_keyset.cid
        self.verifier2 = self.w.append(
            m.envelope(
                "verifier",
                self.verifier_body(
                    "Residency verifier", "resident", self.kid_r, "bbs-im-r", "-r", None, None
                ),
                authority=self.verifier2_cid,
                issued=fixtures.ISSUED,
                refs={
                    "code": self.w.put_blob(fixtures.fixed_bytes("code-im-r", 64)),
                    "build": self.w.put_blob(fixtures.fixed_bytes("build-im-r", 64)),
                },
            ),
            [(b"v-im-2", vkeys2["v-im-2"])],
        )
        self.named["verifier-resident-v1"] = self.verifier2
        self._build()

    def verifier_body(self, name, attribute, kid, bbs, tag, from_epoch, since) -> dict:
        """A one-gate person-class verifier body, validity 90 days (V = 3)."""
        key = (
            vf.issuer_key(kid, fixtures.fixed_bytes(bbs, 96))
            if from_epoch is None
            else vf.issuer_key(kid, fixtures.fixed_bytes(bbs, 96), from_epoch, since)
        )
        return vf.body(
            name=name,
            operator="Hum vector operator",
            profile="custom",
            issuer_keys=[key],
            host_keys=[
                vf.host_key(
                    fixtures.fixed_bytes("hkid-im" + tag, 8),
                    fixtures.fixed_bytes("hpke-im" + tag, 32),
                )
            ],
            attributes=[vf.attribute(attribute, "bool", "gate", attribute.capitalize())],
            evidence_=[vf.evidence("match", "other", "text", "Something else: a record to match")],
            dedup_=[vf.dedup("evidence", "match", "One card per record")],
            code_=vf.code(fixtures.fixed_bytes("source-im" + tag)),
            assurance=1,
            validity=VALIDITY,
        )

    def verifier_version(self, version: int) -> m.Bundle:
        """The person-class verifier the contexts name as issuers[0]: one bool gate `approved`,
        validity 90 days (V = 3). Version 2 drops kid0 for kid1."""
        if version == 1:
            keys, retired = [vf.issuer_key(self.kid0, fixtures.fixed_bytes("bbs-im", 96))], None
        else:
            keys = [vf.issuer_key(self.kid1, fixtures.fixed_bytes("bbs-im-2", 96), EPOCH0 + 2, 2)]
            retired = [self.kid0]
        body = vf.body(
            name="Approved-list verifier",
            operator="Hum vector operator",
            profile="custom",
            issuer_keys=keys,
            host_keys=[
                vf.host_key(fixtures.fixed_bytes("hkid-im", 8), fixtures.fixed_bytes("hpke-im", 32))
            ],
            attributes=[vf.attribute("approved", "bool", "gate", "Approved")],
            evidence_=[vf.evidence("match", "other", "text", "Something else: a record to match")],
            dedup_=[vf.dedup("evidence", "match", "One card per record")],
            code_=vf.code(fixtures.fixed_bytes("source-im")),
            assurance=1,
            validity=VALIDITY,
            retired_kids=retired,
        )
        v1 = getattr(self, "verifier_v1", None)
        env = m.envelope(
            "verifier",
            body,
            authority=self.verifier_keyset.cid,
            version=version,
            issued=fixtures.ISSUED if version == 1 else T0 + 1,
            refs={
                "code": self.w.put_blob(fixtures.fixed_bytes("code-im", 64)),
                "build": self.w.put_blob(fixtures.fixed_bytes("build-im", 64)),
            },
            lineage=v1.cid if v1 else None,
            prev=v1.cid if v1 else None,
        )
        b = self.w.append(env, [(b"v-im", self.verifier_keys["v-im"])])
        self.named[f"verifier-approved-v{version}"] = b
        return b

    def context_body(self, authority: bytes) -> dict:
        """The fixture context with entry and vote on the logged verifier (one leaf, C16)."""
        body = fixtures.context_body(self.fx, authority)
        leaf = c.attr([c.SRC_ISSUER, 0], "approved", [c.PRED_PRESENT])
        body[c.ISSUERS] = [self.verifier_cid]
        body[c.ENTRY] = leaf
        body[c.VOTE] = leaf
        body[c.NULLIFIER] = [[c.SRC_ISSUER, 0], "approved"]
        return body

    def proof_for(self, label, ctx_cid, *, epoch=None, kid=None, length=3) -> tuple[bytes, bytes]:
        """A membership proof (presentation of the entry policy) and its nullifier. The BBS
        proof and pseudonym are fixed opaque bytes (pending a library)."""
        pseudonym = fixtures.fixed_bytes(f"pseudonym-{label}", 48)
        card = cr.CardProof(
            self.verifier_cid,
            kid or self.kid,
            length,
            {0: EPOCH0 if epoch is None else epoch, 1: 1},
            fixtures.fixed_bytes(f"proof-{label}", 96),
            pseudonym,
        )
        return cr.Presentation([card], [], ctx_cid).encode(), cr.nullifier(pseudonym)

    def proof_two(self, label, ctx_cid, second=None) -> tuple[bytes, bytes]:
        """A two-card membership proof for ``ctx-two-cards`` (entry = all(approved, resident)):
        the approved card's nullifier is the primary (the designated leaf names issuers[0]);
        the resident card uses pseudonym label ``second`` (default: ``label``)."""
        p1 = fixtures.fixed_bytes(f"pseudonym-{label}", 48)
        p2 = fixtures.fixed_bytes(f"pseudonym-{second or label}-resident", 48)
        cards = [
            cr.CardProof(
                self.verifier_cid,
                self.kid,
                3,
                {0: EPOCH0, 1: 1},
                fixtures.fixed_bytes(f"proof-{label}", 96),
                p1,
            ),
            cr.CardProof(
                self.verifier2_cid,
                self.kid_r,
                3,
                {0: EPOCH0, 1: 1},
                fixtures.fixed_bytes(f"proof-{label}-r", 96),
                p2,
            ),
        ]
        return cr.Presentation(cards, [], ctx_cid).encode(), cr.nullifier(p1)

    def organizers(self) -> list[tuple[bytes, SigningKey]]:
        """The context authority's sign keys in force after the rotation at position 6."""
        return [(b"b1", self.keys["b1"]), (b"b2", self.keys["b2"])]

    def context(self, name: str, changes: dict | None = None) -> m.Bundle:
        body = self.context_body(self.a)
        for key, value in (changes or {}).items():
            body[key] = value
        env = m.envelope("context", body, authority=self.a, issued=fixtures.ISSUED)
        b = self.w.append(env, self.organizers())
        self.named[name] = b
        return b

    def sponsor(self, name: str, kid: str, **kw) -> m.Bundle:
        """An agent-sponsor manifest under its own authority (a 1-of-1 keyset)."""
        keys = {kid: key_from_label(kid), f"{kid}-rotate": key_from_label(f"{kid}-rotate")}
        ks = self.w.append(
            fixtures.service_keyset(kid, f"{kid}-rotate", keys),
            [(f"{kid}-rotate".encode(), keys[f"{kid}-rotate"])],
        )
        body = sp.body(
            agent_key=kw.pop("agent_key", self.agent_key.public),
            tier=0,
            runtime=1,
            capabilities=kw.pop("capabilities", [0, 3]),
            label=kw.pop("label", "millbrook-facilitator"),
            description="Drafts the strongest pro and con for each position.",
            sponsor_kind=1,
            rate_limits=kw.pop("rate_limits", {0: DAY, 1: 4, 2: 50, 3: 2}),
        )
        env = m.envelope(
            "agent-sponsor",
            body,
            authority=ks.cid,
            issued=fixtures.ISSUED,
            expires=fixtures.ISSUED + 60 * DAY,
        )
        b = self.w.append(env, [(kid.encode(), keys[kid])])
        self.named[name] = b
        self.named[f"{name}-keyset"] = ks
        return b

    def text_blob(self, text: bytes, sealed: bool = False) -> bytes:
        if sealed:
            salt = fixtures.fixed_bytes("salt-" + text[:8].hex(), 16)
            return self.w.put_blob(storage.seal_keyring(text, EPOCH_SECRET, salt))
        return self.w.put_blob(text)

    def authorship_for(
        self,
        form,
        label,
        *,
        ctx_cid,
        key=None,
        slot=None,
        edit_key=None,
        agent=None,
        card_epoch=None,
        kid=None,
    ):
        def make(cid_: bytes) -> bytes:
            if form in (im.MEMBER, im.ANONYMOUS):
                proof, _nullifier = self.proof_for(label, ctx_cid, epoch=card_epoch, kid=kid)
            if form == im.MEMBER:
                k = key or self.alice
                a = im.Authorship(1, key=k.public, sig=im.sign_author(k, cid_), proof=proof)
            elif form == im.ANONYMOUS:
                a = im.Authorship(2, slot=slot, proof=proof)
            else:
                a = im.Authorship(3, sig=im.sign_author(agent or self.agent_key, cid_))
            if edit_key is not None:
                a.edit_sig = im.sign_edit(edit_key, cid_)
            return a.encode()

        return make

    def obj(
        self,
        name,
        type_,
        kind,
        author,
        ctx,
        *,
        parent=None,
        text=b"A position.",
        state=im.ACTIVE,
        sealed=False,
        epoch=None,
        issued=T0,
        expires=None,
        lang=None,
        origin=None,
        moderation=None,
        version=1,
        v1=None,
        prev=None,
        refs=None,
        form=None,
        key=None,
        slot=None,
        agent=None,
        sponsor=None,
        signers=None,
        authorship_override=None,
        text_cid=None,
        card_epoch=None,
        kid=None,
        edit_key_override=None,
    ) -> m.Bundle:
        body: dict[int, Any] = {
            im.KIND: kind,
            im.AUTHOR: author,
            im.STATE: state,
            im.SEALED: sealed,
        }
        for k, v in (
            (im.EPOCH, epoch),
            (im.LANG, lang),
            (im.ORIGIN, origin),
            (im.MODERATION, moderation),
        ):
            if v is not None:
                body[k] = v
        all_refs: dict[str, bytes] = {"context": ctx.cid}
        if parent is not None:
            all_refs["parent"] = parent.cid
        if text_cid is None and text is not None:
            text_cid = self.text_blob(text, sealed)
        if text_cid is not None:
            all_refs["text"] = text_cid
        if sponsor is not None:
            all_refs["sponsor"] = sponsor.cid
        if refs:
            all_refs.update(refs)
        env = m.envelope(
            type_,
            body,
            authority=self.a,
            version=version,
            issued=issued,
            expires=expires,
            refs=all_refs,
            lineage=v1.cid if v1 else None,
            prev=prev.cid if prev else None,
        )
        edit_key = im.derive_edit_key(
            self.edit_root, env if version == 1 else cbor.decode(v1.envelope)
        )
        body[im.EDIT_KEY] = edit_key_override or edit_key.public
        form = author if form is None else form
        if authorship_override is not None:
            b = self.w.append(env, signers, authorship=authorship_override)
        elif signers is not None or form == im.AUTHORITY:
            b = self.w.append(env, signers or self.organizers())
        else:
            if slot is None and form == im.ANONYMOUS:
                slot = self._slot_counter
                self._slot_counter += 1
            b = self.w.append(
                env,
                authorship=self.authorship_for(
                    form,
                    name,
                    ctx_cid=ctx.cid,
                    key=key,
                    slot=slot,
                    agent=agent,
                    edit_key=edit_key if version > 1 else None,
                    card_epoch=card_epoch,
                    kid=kid,
                ),
            )
        self.named[name] = b
        return b

    def _build(self) -> None:
        w, o = self.w, self.obj
        self.sponsor_ok = self.sponsor("sponsor-ok", "sp-ok")
        self.sponsor_nocap = self.sponsor(
            "sponsor-nocap",
            "sp-nocap",
            capabilities=[0],
            agent_key=key_from_label("agent-key-2").public,
            label="reader-only",
        )
        self.sponsor_foreign = self.sponsor(
            "sponsor-foreign",
            "sp-foreign",
            agent_key=key_from_label("agent-key-3").public,
            label="uninvited",
        )
        agents = {
            c.AG_ANY: False,
            c.AG_ADD_ROLE: 0,
            c.AG_SPONSORS: [
                self.named["sponsor-ok-keyset"].cid,
                self.named["sponsor-nocap-keyset"].cid,
            ],
        }
        self.ctx_open = self.context("ctx-open", {c.AGENTS: agents})
        self.ctx_review = self.context(
            "ctx-review", {c.PERMS: {c.P_CARDS: 0, c.P_RESULTS: 0, c.P_MEMBER_LIST: 1}}
        )
        self.ctx_sealed = self.context("ctx-sealed", {c.SEALED: True})
        self.ctx_limited = self.context(
            "ctx-limited", {c.MAP: {c.MAP_UNSIGNED: 3, c.MAP_SIGNED: 2, c.MAP_AGENT: 2}}
        )
        two_leaves = [
            c.NODE_ALL,
            [
                c.attr([c.SRC_ISSUER, 0], "approved", [c.PRED_PRESENT]),
                c.attr([c.SRC_ISSUER, 1], "resident", [c.PRED_PRESENT]),
            ],
        ]
        self.ctx_two_cards = self.context(
            "ctx-two-cards",
            {
                c.ISSUERS: [self.verifier_cid, self.verifier2_cid],
                c.ENTRY: two_leaves,
                c.VOTE: two_leaves,
            },
        )
        ksb = self.fx.keyset_b1
        self.ctx_other = w.append(
            m.envelope(
                "context",
                self.context_body(ksb.cid),
                authority=ksb.cid,
                issued=fixtures.ISSUED,
            ),
            [(b"c1", self.keys["c1"])],
        )
        self.named["ctx-other-authority"] = self.ctx_other
        stale_v1 = self.context("ctx-stale-v1")
        body2 = self.context_body(self.a)
        body2[c.NAME] = "Test context, renamed"
        self.named["ctx-stale-v2"] = w.append(
            m.envelope(
                "context",
                body2,
                authority=self.a,
                version=2,
                lineage=stale_v1.cid,
                prev=stale_v1.cid,
                issued=fixtures.ISSUED + 1,
            ),
            self.organizers(),
        )
        self.ctx_stale_v1 = stale_v1

        def text_of(b: m.Bundle) -> bytes:
            return cbor.decode(b.envelope)[m.REFS]["text"]

        def base(name: str) -> m.Bundle:
            return o(
                f"base-{name}",
                "position",
                im.KIND_POSITION,
                im.MEMBER,
                self.ctx_open,
                parent=self.issue,
                text=f"Base for {name}".encode(),
            )

        # ---- valid objects
        self.issue = o(
            "im-ok-issue",
            "issue",
            im.KIND_ISSUE,
            im.MEMBER,
            self.ctx_open,
            text=b"Ignored repair requests: what do we do?",
        )
        o(
            "im-ok-subquestion",
            "issue",
            im.KIND_ISSUE,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"Which buildings would join a strike?",
            key=self.bob,
        )
        self.issue_sealed = o(
            "sealed-issue",
            "issue",
            im.KIND_ISSUE,
            im.MEMBER,
            self.ctx_sealed,
            text=b"A sealed issue",
            sealed=True,
            epoch=4,
        )
        o(
            "im-ok-position-anon-sealed",
            "position",
            im.KIND_POSITION,
            im.ANONYMOUS,
            self.ctx_sealed,
            parent=self.issue_sealed,
            text=b"If repairs are ignored for 60 days, organize a rent strike.",
            sealed=True,
            epoch=4,
            lang="en",
        )
        self.position = o(
            "position-main",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"File group complaints with code enforcement first.",
            lang="en",
        )
        o(
            "im-ok-argument-pro-member-origin",
            "argument",
            im.KIND_PRO,
            im.MEMBER,
            self.ctx_open,
            parent=self.position,
            text=b"Escrowing rent keeps it legal.",
            origin=fixtures.fixed_bytes("mimi-message-id"),
            key=self.bob,
        )
        o(
            "im-ok-agent-proposed",
            "argument",
            im.KIND_CON,
            im.AGENT,
            self.ctx_open,
            parent=self.position,
            text=b"Strikers risk eviction filings.",
            state=im.PROPOSED,
            expires=EXPIRES,
            sponsor=self.sponsor_ok,
        )
        reviewed = o(
            "review-position",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_review,
            parent=self.issue,
            text=b"A reviewed position",
            state=im.PROPOSED,
        )
        o(
            "im-ok-authority-activate",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_review,
            parent=self.issue,
            text_cid=text_of(reviewed),
            state=im.ACTIVE,
            moderation=im.MOD_ACTIVATE,
            version=2,
            v1=reviewed,
            prev=reviewed,
            signers=self.organizers(),
        )
        o(
            "im-ok-authority-v1",
            "position",
            im.KIND_POSITION,
            im.AUTHORITY,
            self.ctx_open,
            parent=self.issue,
            text=b"An organizer-written position",
        )
        revisable = o(
            "revisable-v1",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"First wording",
        )
        self.revised = o(
            "im-ok-revise-text",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"Second wording",
            version=2,
            v1=revisable,
            prev=revisable,
        )
        withdrawable = o(
            "withdrawable-v1",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"Withdraw me",
        )
        self.withdrawn = o(
            "im-ok-withdraw",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text_cid=text_of(withdrawable),
            state=im.WITHDRAWN,
            version=2,
            v1=withdrawable,
            prev=withdrawable,
        )
        survivor = o(
            "survivor",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"The surviving position",
        )
        dup = o(
            "duplicate-v1",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"The surviving position, duplicated",
        )
        o(
            "im-ok-merge",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text_cid=text_of(dup),
            state=im.MERGED,
            version=2,
            v1=dup,
            prev=dup,
            refs={"mergedInto": survivor.cid},
        )
        arg_under_dup = o(
            "argument-under-duplicate",
            "argument",
            im.KIND_PRO,
            im.MEMBER,
            self.ctx_open,
            parent=dup,
            text=b"Pro of the duplicate",
        )
        o(
            "im-ok-reparent-after-merge",
            "argument",
            im.KIND_PRO,
            im.MEMBER,
            self.ctx_open,
            parent=survivor,
            text_cid=text_of(arg_under_dup),
            version=2,
            v1=arg_under_dup,
            prev=arg_under_dup,
        )
        self.dealt2 = o(
            "dealt-position-2",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"Also dealt",
        )
        from ..bodies import deck as dk

        self.deck = w.append(
            m.envelope(
                "deck",
                dk.body(
                    title="Dealing deck",
                    opens=T0 + DAY,
                    closes=T0 + 8 * DAY,
                    topics=["Repairs"],
                    cards=[dk.card(dk.CARD_POSITION, 0), dk.card(dk.CARD_POSITION, 0)],
                    plan_=dk.plan_full(2),
                ),
                authority=self.a,
                issued=T0,
                expires=EXPIRES,
                refs={
                    "context": self.ctx_open.cid,
                    "card/0": self.position.cid,
                    "card/1": self.dealt2.cid,
                },
            ),
            self.organizers(),
        )
        self.named["deck-pinning-positions"] = self.deck
        o(
            "im-ok-dealt-state-only",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text_cid=text_of(self.position),
            state=im.WITHDRAWN,
            version=2,
            v1=self.position,
            prev=self.position,
            lang="en",
        )
        for i in range(3):
            o(
                f"im-ok-slots-{i}",
                "position",
                im.KIND_POSITION,
                im.ANONYMOUS,
                self.ctx_open,
                parent=self.issue,
                text=f"Unsigned position {i}".encode(),
                slot=i,
            )
        # ---- objects a misbehaving log appended (rejected)
        o(
            "im-bad-kind-type",
            "position",
            im.KIND_ISSUE,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"kind 0 as a position",
        )
        o(
            "im-bad-parent-type",
            "argument",
            im.KIND_PRO,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"argument under an issue",
        )
        o(
            "im-bad-parent-not-v1",
            "argument",
            im.KIND_PRO,
            im.MEMBER,
            self.ctx_open,
            parent=self.revised,
            text=b"parent by a v2 CID",
        )
        o(
            "im-bad-authority",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_other,
            parent=self.issue,
            text=b"context of another authority",
        )
        o(
            "im-bad-stale-context-version",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_stale_v1,
            parent=self.issue,
            text=b"pins v1 after v2",
        )
        o(
            "im-bad-text-missing",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=None,
        )
        o(
            "im-bad-sealed-no-epoch",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_sealed,
            parent=self.issue_sealed,
            text=b"sealed, no epoch",
            sealed=True,
        )
        o(
            "im-bad-sealed-format",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_sealed,
            parent=self.issue_sealed,
            text_cid=self.text_blob(b"not a format 2 blob"),
            sealed=True,
            epoch=4,
        )
        o(
            "im-bad-text-long",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"x" * 561,
        )
        o(
            "im-bad-plain-in-private",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_sealed,
            parent=self.issue_sealed,
            text=b"plain text in a sealed context",
        )
        o(
            "im-bad-sig",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"bad signature",
            authorship_override=lambda cid_: im.Authorship(
                1,
                key=self.alice.public,
                sig=self.bob.sign(im.bound_message(cid_)),
                proof=self.proof_for("badsig", self.ctx_open.cid)[0],
            ).encode(),
        )
        o(
            "im-bad-form-mismatch",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"author 1, form 2",
            form=im.ANONYMOUS,
            slot=9,
        )
        o(
            "im-bad-slot-range",
            "position",
            im.KIND_POSITION,
            im.ANONYMOUS,
            self.ctx_open,
            parent=self.issue,
            text=b"slot 20",
            slot=20,
        )
        o(
            "im-bad-agent-capability",
            "argument",
            im.KIND_CON,
            im.AGENT,
            self.ctx_open,
            parent=self.position,
            text=b"no author-map capability",
            state=im.PROPOSED,
            expires=EXPIRES,
            sponsor=self.sponsor_nocap,
            agent=key_from_label("agent-key-2"),
        )
        o(
            "im-bad-agent-not-admitted",
            "argument",
            im.KIND_CON,
            im.AGENT,
            self.ctx_open,
            parent=self.position,
            text=b"sponsor not admitted",
            state=im.PROPOSED,
            expires=EXPIRES,
            sponsor=self.sponsor_foreign,
            agent=key_from_label("agent-key-3"),
        )
        o(
            "im-bad-sponsor-missing",
            "argument",
            im.KIND_CON,
            im.AGENT,
            self.ctx_open,
            parent=self.position,
            text=b"agent-signed, no sponsor ref",
            state=im.PROPOSED,
            expires=EXPIRES,
        )
        carol = key_from_label("chat-carol")
        o(
            "im-ok-two-cards",
            "issue",
            im.KIND_ISSUE,
            im.MEMBER,
            self.ctx_two_cards,
            text=b"Two cards, two nullifiers, both new",
            key=carol,
            authorship_override=lambda cid_: im.Authorship(
                1,
                key=carol.public,
                sig=im.sign_author(carol, cid_),
                proof=self.proof_two("two-cards", self.ctx_two_cards.cid)[0],
            ).encode(),
        )
        o(
            "im-bad-secondary-nullifier-reused",
            "issue",
            im.KIND_ISSUE,
            im.MEMBER,
            self.ctx_two_cards,
            text=b"Primary new, the resident card's nullifier seen",
            key=carol,
            authorship_override=lambda cid_: im.Authorship(
                1,
                key=carol.public,
                sig=im.sign_author(carol, cid_),
                proof=self.proof_two("second-try", self.ctx_two_cards.cid, "two-cards")[0],
            ).encode(),
        )
        o(
            "im-bad-slot-reused",
            "position",
            im.KIND_POSITION,
            im.ANONYMOUS,
            self.ctx_open,
            parent=self.issue,
            text=b"reused nullifier",
            authorship_override=lambda cid_: im.Authorship(
                2,
                slot=5,
                proof=self.proof_for("im-ok-slots-1", self.ctx_open.cid)[0],
            ).encode(),
        )
        o(
            "im-bad-origin-anon",
            "position",
            im.KIND_POSITION,
            im.ANONYMOUS,
            self.ctx_open,
            parent=self.issue,
            text=b"anon with origin",
            origin=fixtures.fixed_bytes("mimi-2"),
        )
        o(
            "im-bad-sponsor-on-member",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"member with a sponsor ref",
            sponsor=self.sponsor_ok,
        )
        b2 = base("authority-no-moderation")
        o(
            "im-bad-authority-no-moderation",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text_cid=text_of(b2),
            state=im.WITHDRAWN,
            version=2,
            v1=b2,
            prev=b2,
            signers=self.organizers(),
        )
        o(
            "im-bad-agent-active",
            "argument",
            im.KIND_CON,
            im.AGENT,
            self.ctx_open,
            parent=self.position,
            text=b"agent born active",
            state=im.ACTIVE,
            expires=EXPIRES,
            sponsor=self.sponsor_ok,
        )
        full = o(
            "full-position",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"A position with 40 arguments",
        )
        for i in range(im.MAX_ARGUMENTS_ACTIVE):
            o(
                f"full-argument-{i}",
                "argument",
                im.KIND_PRO,
                im.MEMBER,
                self.ctx_open,
                parent=full,
                text=f"Argument {i}".encode(),
                key=self.bob,
            )
        o(
            "im-bad-cap-active",
            "argument",
            im.KIND_PRO,
            im.MEMBER,
            self.ctx_open,
            parent=full,
            text=b"The 41st argument, born active",
            key=self.bob,
        )
        b3 = base("frozen-editkey")
        o(
            "im-bad-frozen-editkey",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text_cid=text_of(b3),
            version=2,
            v1=b3,
            prev=b3,
            edit_key_override=key_from_label("edit-key-other").public,
        )
        b4 = base("no-editsig")
        o(
            "im-bad-no-editsig",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"Third wording",
            version=2,
            v1=b4,
            prev=b4,
            authorship_override=lambda cid_: im.Authorship(
                1,
                key=self.alice.public,
                sig=im.sign_author(self.alice, cid_),
                proof=self.proof_for("noedit", self.ctx_open.cid)[0],
            ).encode(),
        )
        o(
            "im-bad-transition-from-withdrawn",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text_cid=text_of(withdrawable),
            state=im.ACTIVE,
            version=3,
            v1=withdrawable,
            prev=self.withdrawn,
        )
        arg2 = o(
            "argument-under-duplicate-2",
            "argument",
            im.KIND_CON,
            im.MEMBER,
            self.ctx_open,
            parent=dup,
            text=b"Con of the duplicate",
        )
        o(
            "im-bad-reparent-unrelated",
            "argument",
            im.KIND_CON,
            im.MEMBER,
            self.ctx_open,
            parent=self.position,
            text_cid=text_of(arg2),
            version=2,
            v1=arg2,
            prev=arg2,
        )
        b5 = base("moderation-changes-text")
        o(
            "im-bad-moderation-changes-text",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"Moderator rewrote this",
            state=im.HIDDEN,
            moderation=im.MOD_HIDE,
            version=2,
            v1=b5,
            prev=b5,
            signers=self.organizers(),
        )
        o(
            "im-bad-edit-after-dealt",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"New words after dealt",
            version=2,
            v1=self.dealt2,
            prev=self.dealt2,
        )
        o(
            "im-bad-agent-no-expiry",
            "argument",
            im.KIND_CON,
            im.AGENT,
            self.ctx_open,
            parent=self.position,
            text=b"no expiry",
            state=im.PROPOSED,
            sponsor=self.sponsor_ok,
        )
        evidence = {f"evidence/{i}": w.put_blob(f"evidence {i}".encode()) for i in range(9)}
        o(
            "im-bad-evidence-count",
            "argument",
            im.KIND_PRO,
            im.MEMBER,
            self.ctx_open,
            parent=self.position,
            text=b"nine evidence refs",
            refs=evidence,
        )
        o(
            "im-bad-lang",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"bad lang",
            lang="e",
        )
        o(
            "limited-agent-0",
            "argument",
            im.KIND_CON,
            im.AGENT,
            self.ctx_open,
            parent=self.position,
            text=b"agent object 2",
            state=im.PROPOSED,
            expires=EXPIRES,
            sponsor=self.sponsor_ok,
        )
        o(
            "im-bad-rate-limit",
            "argument",
            im.KIND_CON,
            im.AGENT,
            self.ctx_open,
            parent=self.position,
            text=b"the fifth agent object in the window, over mapObjects 4",
            state=im.PROPOSED,
            expires=EXPIRES,
            sponsor=self.sponsor_ok,
        )
        lim_issue = o(
            "limited-issue",
            "issue",
            im.KIND_ISSUE,
            im.MEMBER,
            self.ctx_limited,
            text=b"Limited context issue",
        )
        o(
            "limited-position",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_limited,
            parent=lim_issue,
            text=b"Second signed object",
        )
        o(
            "im-bad-rate-limit-context",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_limited,
            parent=lim_issue,
            text=b"Third signed object in the window",
        )
        o(
            "im-bad-window-stale",
            "position",
            im.KIND_POSITION,
            im.ANONYMOUS,
            self.ctx_open,
            parent=self.issue,
            text=b"stale window",
            issued=T0 - 3 * DAY,
            slot=7,
        )
        o(
            "as-x-unlabeled-object",
            "argument",
            im.KIND_PRO,
            im.MEMBER,
            self.ctx_open,
            parent=self.position,
            text=b"agent key as a member",
            key=self.agent_key,
        )
        # ADR 0101: logged presentations are checked against issued, not a clock
        o(
            "im-ok-verified-next-epoch",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"Still valid after the issuer epoch ends",
            expires=T0 + 200 * DAY,
        )
        o(
            "im-bad-proof-epoch-mismatch",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"card of the next epoch",
            card_epoch=EPOCH0 + 1,
        )
        o(
            "im-ok-issued-skew-candidate",
            "position",
            im.KIND_POSITION,
            im.ANONYMOUS,
            self.ctx_open,
            parent=self.issue,
            text=b"the log clock decides",
        )
        o(
            "im-ok-kid-removed-after",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"kid0 is removed at a higher log index",
        )
        self.verifier_v2 = self.verifier_version(2)
        self.kid = self.kid1
        o(
            "im-bad-kid-removed-before",
            "position",
            im.KIND_POSITION,
            im.MEMBER,
            self.ctx_open,
            parent=self.issue,
            text=b"kid0 was removed at a lower log index",
            kid=self.kid0,
        )
        # ---- several logs: a context listing a second log; the log of record stays first
        log2_keys = {"log2": key_from_label("log2"), "log2-rotate": key_from_label("log2-rotate")}
        log2_env = fixtures.service_keyset("log2", "log2-rotate", log2_keys)
        self.w2 = m.World(
            log_authority=m.compute_cid(m.encode_envelope(log2_env)),
            log_key=log2_keys["log2"],
            witnesses=dict(w.witnesses),
        )
        self.w2.append(log2_env, [(b"log2-rotate", log2_keys["log2-rotate"])])
        self.ctx_two_logs = self.context(
            "ctx-two-logs",
            {
                c.LOGS: [
                    {c.L_LOG: w.log_authority, c.L_WITNESSES: w.witness_keys()},
                    {c.L_LOG: self.w2.log_authority, c.L_WITNESSES: w.witness_keys()},
                ]
            },
        )
        two = o(
            "im-ok-two-logs",
            "issue",
            im.KIND_ISSUE,
            im.ANONYMOUS,
            self.ctx_two_logs,
            text=b"Logged in the log of record and in a second log",
            slot=0,
        )
        self.in_second_log = self.w2.append(cbor.decode(two.envelope), authorship=two.authorship)
        # the retry story: a rebuilt unsigned object after a lost response (same slot, same card)
        o(
            "im-bad-rebuilt-after-logged",
            "position",
            im.KIND_POSITION,
            im.ANONYMOUS,
            self.ctx_open,
            parent=self.issue,
            text=b"Unsigned position 0, rebuilt with a fresh issued",
            issued=T0 + 4000,
            authorship_override=lambda cid_: im.Authorship(
                2,
                slot=0,
                proof=self.proof_for("im-ok-slots-0", self.ctx_open.cid)[0],
            ).encode(),
        )
        w.finalize()
        self.w2.finalize()


EXPECTED_REJECTIONS = {
    "im-bad-kind-type": (10, "IM-1"),
    "im-bad-parent-type": (10, "IM-2"),
    "im-bad-parent-not-v1": (10, "IM-2"),
    "im-bad-authority": (10, "IM-3"),
    "im-bad-stale-context-version": (10, "IM-3"),
    "im-bad-text-missing": (10, "IM-4a"),
    "im-bad-sealed-no-epoch": (10, "IM-4a"),
    "im-bad-sealed-format": (10, "IM-4b"),
    "im-bad-text-long": (10, "IM-4b"),
    "im-bad-plain-in-private": (10, "IM-5"),
    "im-bad-sig": (6, "IM-6"),
    "im-bad-form-mismatch": (6, "IM-6"),
    "im-bad-slot-range": (6, "IM-6"),
    "im-bad-agent-capability": (6, "IM-6"),
    "im-bad-agent-not-admitted": (6, "IM-6"),
    "im-bad-sponsor-missing": (6, "IM-6"),
    "im-bad-slot-reused": (6, "IM-7"),
    "im-bad-secondary-nullifier-reused": (6, "IM-7"),
    "im-bad-origin-anon": (10, "IM-8"),
    "im-bad-sponsor-on-member": (10, "IM-9"),
    "im-bad-authority-no-moderation": (10, "IM-9"),
    "im-bad-agent-active": (10, "IM-10"),
    "im-bad-cap-active": (10, "IM-10"),
    "im-bad-frozen-editkey": (10, "IM-11"),
    "im-bad-no-editsig": (10, "IM-11"),
    "im-bad-transition-from-withdrawn": (10, "IM-11"),
    "im-bad-reparent-unrelated": (10, "IM-11"),
    "im-bad-moderation-changes-text": (10, "IM-11"),
    "im-bad-edit-after-dealt": (10, "IM-12"),
    "im-bad-agent-no-expiry": (10, "IM-13"),
    "im-bad-evidence-count": (10, "IM-14"),
    "im-bad-lang": (10, "IM-14"),
    "im-bad-rate-limit": (6, "IM-15"),
    "im-bad-rate-limit-context": (6, "IM-15"),
    "im-bad-window-stale": (6, "IM-15"),
    "as-x-unlabeled-object": (6, "IM-6"),
    "im-bad-proof-epoch-mismatch": (6, "IM-6"),
    "im-bad-kid-removed-before": (6, "IM-6"),
    "im-bad-rebuilt-after-logged": (6, "IM-7"),
}
LOG_CHECKS = {
    # name -> (object, log clock T, accepted): the log of record's own check at submission
    "im-ok-issued-within-hour": ("im-ok-issued-skew-candidate", T0 + 3600, True),
    "im-bad-issued-skew": ("im-ok-issued-skew-candidate", LOG_SKEW_T, False),
}
HELPERS = {
    "sealed-issue",
    "position-main",
    "review-position",
    "revisable-v1",
    "withdrawable-v1",
    "survivor",
    "duplicate-v1",
    "argument-under-duplicate",
    "argument-under-duplicate-2",
    "full-position",
    "limited-agent-0",
    "limited-issue",
    "limited-position",
    "dealt-position-2",
    "im-ok-issued-skew-candidate",
}


def _authorship_view(b: m.Bundle) -> dict | None:
    return None if b.authorship is None else jsonable(cbor.decode(b.authorship))


def world_file(wd: World) -> File:
    f = File(
        SPEC,
        "world",
        "The issue-map test world on top of manifest/world.json: contexts, sponsors, authored "
        "objects and the deck that deals two positions. Objects named im-bad-* and as-x-* were "
        "appended by a misbehaving log and are there to be rejected.",
    )
    entries = []
    for name, b in wd.named.items():
        entry = {"name": name, **bundle_json(b), "view": jsonable(cbor.decode(b.envelope))}
        if b.authorship is not None:
            entry["authorship_view"] = _authorship_view(b)
        entries.append(entry)
    f.add(
        "world",
        "Every bundle appended after the base world (positions 36 and up)",
        S_RULES,
        {
            "base": "manifest/world.json",
            "keys": {
                "chat-alice": hexify(wd.alice.seed),
                "chat-bob": hexify(wd.bob.seed),
                "agent-key": hexify(wd.agent_key.seed),
                "agent-key-2": hexify(key_from_label("agent-key-2").seed),
                "agent-key-3": hexify(key_from_label("agent-key-3").seed),
                "edit-root-alice": hexify(wd.edit_root),
                "keyring-epoch-4-secret": hexify(EPOCH_SECRET),
            },
            "blobs": {hexify(k): hexify(v) for k, v in wd.w.blobs.items()},
        },
        {
            "entries": [hexify(leaf) for leaf in wd.w.leaves[36:]],
            "checkpoint": wd.w.note().text(),
            "bundles": entries,
        },
    )
    return f


def _scopes(wd: World, b: m.Bundle, env: dict) -> dict | None:
    if b.authorship is None:
        return None
    try:
        a = im.Authorship.decode(b.authorship)
    except im.TypeRule:
        return None
    out = {"bound_message": hexify(im.bound_message(b.cid))}
    if a.form == im.MEMBER:
        out["scope"] = hexify(im.once_scope(b.cid))
    elif a.form == im.ANONYMOUS:
        ctx_cid = env[m.REFS]["context"]
        ctx_env = cbor.decode(wd.w.bundles[ctx_cid].envelope)
        window = env[m.ISSUED] // im.AUTHOR_WINDOW
        out["window"] = window
        out["scope"] = hexify(im.slot_scope(ctx_env.get(m.LINEAGE, ctx_cid), window, a.slot))
    return out


def objects_file(wd: World) -> File:
    f = File(
        SPEC,
        "objects",
        "Every object of the world verified with a fresh phone state (now = T0 + 1 h, or the "
        "next issuer epoch where `now` says so). Membership proofs are credentials.md "
        "presentations of the pinned entry policy, verified against the object's issued and the "
        "verifier version in force at its log position (ADR 0101); the BBS proof bytes and "
        "pseudonyms are fixed (P4 pending). The scope and bound-message bytes each proof covers "
        "are given in `scopes`. The log-submission cases are the log of record's own clock check.",
    )
    for name, b in wd.named.items():
        env = cbor.decode(b.envelope)
        if env[m.TYPE] not in im.TYPES:
            continue
        now = VERIFY_AT.get(name, NOW)
        ctx = wd.w.context(now=now)
        inputs = {"bundle": bundle_json(b), "now": now}
        if b.authorship is not None:
            inputs["authorship_view"] = _authorship_view(b)
            inputs["scopes"] = _scopes(wd, b, env)
        try:
            m.verify_bundle(ctx, b)
        except m.Rejection as e:
            exp = EXPECTED_REJECTIONS.get(name)
            if exp is None or (e.step, e.rule) != exp:
                raise AssertionError(
                    f"{name}: got step {e.step} rule {e.rule} ({e.reason}), expected {exp}"
                ) from e
            f.add(
                name,
                f"{name}: rejected at step {e.step}, rule {e.rule}",
                S_RULES,
                inputs,
                rejection={"step": e.step, "rule": e.rule, "reason": e.reason},
            )
            continue
        if name in EXPECTED_REJECTIONS:
            raise AssertionError(f"{name} was accepted; expected {EXPECTED_REJECTIONS[name]}")
        f.add(
            name,
            f"{name}: verifies" + (" (helper object)" if name in HELPERS else ""),
            S_RULES,
            inputs,
            {
                "accept": True,
                "type": env[m.TYPE],
                "version": env[m.VERSION],
                "state": env[m.BODY][im.STATE],
            },
        )
    v_of = {wd.verifier_cid: V}
    for name, (obj_name, log_now, accepted) in LOG_CHECKS.items():
        b = wd.named[obj_name]
        env = cbor.decode(b.envelope)
        reason = im.log_submission_check(b.authorship, env[m.ISSUED], log_now, v_of)
        assert (reason is None) == accepted, name
        inputs = {
            "object": obj_name,
            "cid": hexify(b.cid),
            "authorship": hexify(b.authorship),
            "issued": env[m.ISSUED],
            "log_clock_T": log_now,
            "V": V,
        }
        if accepted:
            f.add(
                name,
                "At the log of record: issued within an hour of T",
                S_RULES,
                inputs,
                {"accept": True},
            )
        else:
            f.add(
                name,
                "At the log of record: issued two hours from T",
                S_RULES,
                inputs,
                rejection={"step": None, "check": "log-submission", "rule": "P5", "reason": reason},
            )
    _several_logs_cases(wd, f, v_of)
    return f


def _several_logs_cases(wd: World, f: File, v_of: dict[bytes, int]) -> None:
    """im-ok-two-logs at the second log, the object present only in the second log, and the
    lost-response retry story (issue-map.md, "Several logs" and "Posting" step 3)."""
    two = wd.named["im-ok-two-logs"]
    env = cbor.decode(two.envelope)
    ctx_body = cbor.decode(wd.ctx_two_logs.envelope)[m.BODY]
    logs = [e[c.L_LOG] for e in ctx_body[c.LOGS]]
    second = wd.in_second_log
    assert second.cid == two.cid and im.log_of_record(ctx_body) == two.proof.log == logs[0]
    a = im.Authorship.decode(two.authorship)
    card = cr.Presentation.decode(a.proof).creds[0]
    base = {
        "object": "im-ok-two-logs",
        "cid": hexify(two.cid),
        "logs": [hexify(x) for x in logs],
        "log_of_record": hexify(logs[0]),
        "issued": env[m.ISSUED],
        "card_epoch": card.disclosed[0],
        "V": v_of[card.issuer],
    }
    stale = env[m.ISSUED] + 10800
    for name, desc, proof_logs, accept in (
        (
            "im-ok-two-logs-second-log-accepts",
            "At the second listed log, three hours after issued: accepted because the bundle "
            "carries the log of record's inclusion proof; the nullifier is counted in the log "
            "of record only",
            [logs[0]],
            True,
        ),
        (
            "im-bad-two-logs-no-record-proof",
            "At the second listed log, three hours after issued, with no proof from the log "
            "of record",
            [],
            False,
        ),
    ):
        reason = cr.log_accepts_logged_object(
            this_log=logs[1],
            logs=logs,
            proof_logs=proof_logs,
            issuer_lineage_in_history=True,
            card_epoch=card.disclosed[0],
            v=v_of[card.issuer],
            log_now=stale,
            issued=env[m.ISSUED],
        )
        assert (reason is None) == accept, name
        inputs = {
            **base,
            "this_log": hexify(logs[1]),
            "log_clock_T": stale,
            "record_proof": bundle_json(two)["log"] if proof_logs else None,
            "second_log_proof": bundle_json(second)["log"],
        }
        if accept:
            f.add(name, desc, S_RULES, inputs, {"accept": True, "counted_in": hexify(logs[0])})
        else:
            f.add(
                name,
                desc,
                S_RULES,
                inputs,
                rejection={"step": None, "check": "log-submission", "rule": "P5", "reason": reason},
            )
    # the same object handed to a phone with only the second log's proof
    ctx = wd.w.context(now=NOW)
    try:
        m.verify_bundle(ctx, second)
        raise AssertionError("second-log-only bundle verified")
    except m.Rejection as e:
        assert e.step in (5, 6, 7), (e.step, e.rule, e.reason)
        f.add(
            "im-bad-only-in-second-log",
            "The object's bundle carrying only the second log's inclusion proof, handed to a "
            "phone that holds the log of record: positions in two logs are never compared, so "
            "the proof places nothing in the log of record and the bundle is rejected before "
            "the authorship check (an object is valid only if it is in its context's log of "
            "record)",
            S_RULES,
            {"bundle": bundle_json(second), "now": NOW, **base},
            rejection={"step": e.step, "rule": e.rule, "reason": e.reason},
        )
    # lost response: ask the log of record for the old CID before rebuilding
    old = wd.named["im-ok-slots-0"]
    f.add(
        "im-ok-lost-response-retry",
        "The response to a submission was lost; the phone asks the log of record for the old "
        "CID, finds it at its position, and does not rebuild",
        "Posting",
        {"cid": hexify(old.cid), "log_entry": {"found": True, "index": old.proof.position}},
        {"decision": im.rebuild_decision(True)},
    )
    f.add(
        "im-ok-lost-response-rebuild",
        "The log of record does not hold the old CID: the phone rebuilds with a fresh issued "
        "(a new CID, edit key and proof); an unsigned object keeps its slot",
        "Posting",
        {"cid": hexify(old.cid), "log_entry": {"found": False}},
        {"decision": im.rebuild_decision(False)},
    )
    rebuilt = wd.named["im-bad-rebuilt-after-logged"]
    f.add(
        "im-bad-rebuilt-after-logged-next-slot",
        "The rebuilt object was refused under IM-7: the first one was logged after all; the "
        "phone treats it as published and uses the next slot",
        "Posting",
        {"old_cid": hexify(old.cid), "rebuilt_cid": hexify(rebuilt.cid), "refused": "IM-7"},
        {"decision": im.rebuild_decision(False, refused_im7=True), "next_slot": 1},
    )


def authorship_file(wd: World) -> File:
    f = File(
        SPEC,
        "authorship",
        "Canonical bytes of the bundle's authorship map for each form, and forms a verifier refuses.",
    )
    for case, name in [
        ("im-authorship-member", "im-ok-issue"),
        ("im-authorship-anon", "im-ok-slots-0"),
        ("im-authorship-agent", "im-ok-agent-proposed"),
        ("im-authorship-v2", "im-ok-revise-text"),
    ]:
        b = wd.named[name]
        f.add(
            case,
            f"Authorship of {name}",
            S_AUTH,
            {"object": name, "cid": hexify(b.cid)},
            {"authorship": hexify(b.authorship), "view": _authorship_view(b)},
        )
    good = cbor.decode(wd.named["im-ok-issue"].authorship)
    for case, item, why in [
        ("im-authorship-extra-key", {**good, 9: 1}, "unknown key 9"),
        (
            "im-authorship-key-4",
            {**good, 4: fixtures.fixed_bytes("carried-nullifier", 32)},
            "a carried nullifier: key 4 was removed by ADR 0104 and is not reused",
        ),
        (
            "im-authorship-scope-carried",
            {**good, 3: 0},
            "a member form carrying a slot (the scope is never carried)",
        ),
    ]:
        data = cbor.encode(item)
        try:
            im.Authorship.decode(data)
            raise AssertionError(case)
        except im.TypeRule:
            pass
        f.add(
            case,
            f"Reject: {why}",
            S_AUTH,
            {"authorship": hexify(data)},
            rejection={"step": 6, "rule": "IM-6", "reason": why},
        )
    items = sorted(
        ((cbor.encode(k), cbor.encode(v)) for k, v in good.items()), key=lambda kv: kv[0]
    )
    items[0], items[1] = items[1], items[0]
    noncanon = bytes([0xA0 | len(items)]) + b"".join(k + v for k, v in items)
    try:
        im.Authorship.decode(noncanon)
        raise AssertionError
    except im.TypeRule:
        pass
    f.add(
        "im-authorship-non-canonical",
        "Reject: the same map with keys out of order",
        S_AUTH,
        {"authorship": hexify(noncanon)},
        rejection={"step": 6, "rule": "IM-6", "reason": "not deterministic CBOR"},
    )
    return f


def derived_file(wd: World) -> File:
    f = File(
        SPEC,
        "derived",
        "Derived checks that are not manifests: edit-key derivation, release annotations, duplicate detection.",
    )
    v1 = cbor.decode(wd.named["revisable-v1"].envelope)
    stripped = dict(v1)
    stripped[m.BODY] = {k: v for k, v in v1[m.BODY].items() if k != im.EDIT_KEY}
    key = im.derive_edit_key(wd.edit_root, v1)
    f.add(
        "im-edit-key-derive",
        "HKDF-SHA256(IKM = edit root, salt = hum/edit-key/1, info = SHA-256(v1 envelope without body key 2))",
        S_AUTH,
        {"edit_root": hexify(wd.edit_root), "v1_envelope": hexify(cbor.encode(v1))},
        {
            "stripped_envelope": hexify(cbor.encode(stripped)),
            "info": hexify(im.edit_key_info(v1)),
            "seed": hexify(key.seed),
            "public": hexify(key.public),
            "matches_body_editKey": key.public == v1[m.BODY][im.EDIT_KEY],
        },
    )
    sigma_t, sigma_g = 18.3869, 10.3376
    for name, t, g in [
        ("common-ground", (900.0, 80.0, 60.0), [(500.0, 40.0, 30.0), (400.0, 40.0, 30.0)]),
        ("divides", (520.0, 480.0, 40.0), [(480.0, 60.0, 20.0), (40.0, 420.0, 20.0)]),
        ("leans-yes", (560.0, 440.0, 40.0), [(300.0, 220.0, 20.0), (260.0, 220.0, 20.0)]),
        ("leans-no", (420.0, 580.0, 40.0), None),
        ("no-label", (510.0, 500.0, 30.0), None),
        ("too-few", (60.0, 50.0, 10.0), None),
        ("group-too-few", (900.0, 80.0, 60.0), [(500.0, 40.0, 30.0), (30.0, 20.0, 10.0)]),
    ]:
        f.add(
            f"im-annotate-{name}",
            f"Label for a position: {name}",
            S_AFTER,
            {
                "tallies": list(t),
                "sigma_tallies": sigma_t,
                "group_tallies": [list(x) for x in g] if g else None,
                "sigma_groups": sigma_g,
                "z": 1.645,
            },
            im.annotate(t, sigma_t, g, sigma_g),
        )
    for i, (a, b, near) in enumerate(
        [
            (
                "File group complaints with code enforcement first.",
                "File group complaints with code enforcement first!",
                True,
            ),
            (
                "Organize a rent strike after 60 days.",
                "After 60 days, organize a rent strike.",
                True,
            ),
            ("Organize a rent strike after 60 days.", "Escrow the rent with a lawyer.", False),
            ("Fix the boiler", "Fix the boiler now", False),
        ]
    ):
        r = im.duplicate_ratio(a, b)
        assert (r >= 0.8) == near, (a, b, r)
        f.add(
            f"im-dup-detect-{i}",
            "Informative: token-set (Jaccard) ratio after NFKC, case fold and punctuation strip; near match at 0.8",
            "Merging",
            {"a": a, "b": b},
            {"ratio": r, "near_match": r >= 0.8},
        )
    return f


def generate() -> list[File]:
    wd = World()
    return [world_file(wd), objects_file(wd), authorship_file(wd), derived_file(wd)]
