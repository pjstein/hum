"""The ``issue``, ``position`` and ``argument`` bodies: docs/specs/issue-map.md.

Step 4 checks only shapes (rule id ``schema``). Step 6 is replaced by the authorship check
(IM-6, IM-7, IM-15). Every numbered rule runs at step 10, as the spec's validation table
says ("these run as step 10"); a log runs the subset the spec lists.

Membership proofs (forms 1 and 2) are ``credentials.md`` presentations verified with rules
P1 to P8 against the object's ``issued`` and its position in the context's **log of record**,
the first entry of the pinned context version's ``logs`` ("Several logs"). The BBS proof
itself (P4) is a per-card input pending a library. An object is valid only if it is in the
log of record; IM-7 and IM-15 count there and nowhere else, and another listed log accepts
the object on an inclusion proof from it (``credentials.log_accepts_logged_object``). After a
lost response the phone asks the log of record for the old CID before rebuilding
(``rebuild_decision``).

seam: credential presentation, pseudonyms and nullifiers; domain strings ``hum/author/1``,
``hum/edit/1``, ``hum/edit-key/1``, ``hum/author-once/1``, ``hum/author-slot/1``.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
import unicodedata
from typing import Any

from .. import cbor
from .. import credentials as cr
from .. import manifest as m
from ..keys import SigningKey, verify
from . import (
    LANG_RE,
    TypeRule,
    is_bytes,
    is_text,
    is_uint,
    no_unknown_keys,
    require,
    require_keys,
)
from . import context as ctxspec
from . import trust_list as tlspec
from . import verifier as vfspec

__all__ = [
    "AUTHOR_DOMAIN",
    "Authorship",
    "annotate",
    "bound_message",
    "derive_edit_key",
    "duplicate_ratio",
    "edit_key_info",
    "log_submission_check",
    "membership_proof",
    "once_scope",
    "rules",
    "schema",
    "signatures",
    "slot_scope",
]

# ---------------------------------------------------------------- constants

TYPES = {"issue": {0}, "position": {1}, "argument": {2, 3}}
KIND_ISSUE, KIND_POSITION, KIND_PRO, KIND_CON = 0, 1, 2, 3
PARENT_TYPE = {
    KIND_ISSUE: "issue",
    KIND_POSITION: "issue",
    KIND_PRO: "position",
    KIND_CON: "position",
}
TEXT_LIMIT = {KIND_ISSUE: 400, KIND_POSITION: 560, KIND_PRO: 2000, KIND_CON: 2000}

AUTHORITY, MEMBER, ANONYMOUS, AGENT = 0, 1, 2, 3
PROPOSED, ACTIVE, WITHDRAWN, MERGED, HIDDEN = 0, 1, 2, 3, 4
MOD_ACTIVATE, MOD_HIDE, MOD_MERGE, MOD_WITHDRAW, MOD_REPARENT = 0, 1, 2, 3, 4

KIND, AUTHOR, EDIT_KEY, STATE, SEALED, EPOCH, LANG, ORIGIN, ASSISTED, MODERATION = range(10)
REQUIRED = {KIND, AUTHOR, EDIT_KEY, STATE, SEALED}
ALL_KEYS = set(range(10))

A_FORM, A_KEY, A_SIG, A_SLOT, A_NULLIFIER, A_PROOF, A_EDITSIG = range(7)

UNSIGNED_WINDOW_MIN = 86_400
UNSIGNED_PER_WINDOW_MAX = 20
SIGNED_PER_WINDOW_MAX = 60
AGENT_OBJECTS_MAX = 20
MAX_POSITIONS_ACTIVE = 200
MAX_ARGUMENTS_ACTIVE = 40
AGENT_PROPOSAL_TTL = 2_592_000
MAX_EVIDENCE = 8
CAP_AUTHOR_MAP = 3

AUTHOR_DOMAIN = b"hum/author/1"
EDIT_DOMAIN = b"hum/edit/1"
EDIT_KEY_SALT = b"hum/edit-key/1"
ONCE_SCOPE = b"hum/author-once/1"
SLOT_SCOPE = b"hum/author-slot/1"

TRANSITIONS = {PROPOSED: {ACTIVE, WITHDRAWN, MERGED, HIDDEN}, ACTIVE: {WITHDRAWN, MERGED, HIDDEN}}
EVIDENCE_RE = re.compile(r"^evidence/(0|[1-9][0-9]*)$")
KNOWN_REFS = {"context", "parent", "text", "sponsor", "replaces", "mergedInto", "take"}

# Sponsor body keys read here (agent-sponsor.md).
SP_AGENT_KEY, SP_TIER, SP_CAPABILITIES, SP_RATE_LIMITS, SP_RETIRED = 0, 1, 5, 6, 11
RL_WINDOW, RL_MAP_OBJECTS = 0, 1


# ---------------------------------------------------------------- domain strings and scopes


def bound_message(cid: bytes) -> bytes:
    return AUTHOR_DOMAIN + cid


def once_scope(cid: bytes) -> bytes:
    return ONCE_SCOPE + cid


def slot_scope(context_lineage: bytes, window: int, slot: int) -> bytes:
    return SLOT_SCOPE + context_lineage + window.to_bytes(8, "big") + slot.to_bytes(2, "big")


def edit_key_info(v1_env: dict[int, Any]) -> bytes:
    """SHA-256 of the canonical version-1 envelope with body key 2 (``editKey``) removed."""
    env = dict(v1_env)
    body = {k: v for k, v in env[m.BODY].items() if k != EDIT_KEY}
    env[m.BODY] = body
    return hashlib.sha256(cbor.encode(env)).digest()


def derive_edit_key(edit_root: bytes, v1_env: dict[int, Any]) -> SigningKey:
    """HKDF-SHA256(IKM = edit root, salt = "hum/edit-key/1", info = edit_key_info) -> Ed25519."""
    prk = hmac.new(EDIT_KEY_SALT, edit_root, hashlib.sha256).digest()
    seed = hmac.new(prk, edit_key_info(v1_env) + b"\x01", hashlib.sha256).digest()[:32]
    return SigningKey(seed)


# ---------------------------------------------------------------- authorship bundle field


class Authorship:
    """The bundle's ``authorship`` map."""

    def __init__(
        self,
        form: int,
        *,
        key: bytes | None = None,
        sig: bytes | None = None,
        slot: int | None = None,
        nullifier: bytes | None = None,
        proof: bytes | None = None,
        edit_sig: bytes | None = None,
    ) -> None:
        self.form = form
        self.key = key
        self.sig = sig
        self.slot = slot
        self.nullifier = nullifier
        self.proof = proof
        self.edit_sig = edit_sig

    def to_item(self) -> dict[int, Any]:
        item: dict[int, Any] = {A_FORM: self.form}
        for k, v in (
            (A_KEY, self.key),
            (A_SIG, self.sig),
            (A_SLOT, self.slot),
            (A_NULLIFIER, self.nullifier),
            (A_PROOF, self.proof),
            (A_EDITSIG, self.edit_sig),
        ):
            if v is not None:
                item[k] = v
        return item

    def encode(self) -> bytes:
        return cbor.encode(self.to_item())

    @classmethod
    def decode(cls, data: bytes) -> Authorship:
        try:
            item = cbor.decode(data)
        except cbor.CborError as e:
            raise TypeRule("IM-6", f"authorship is not deterministic CBOR: {e}") from e
        require(isinstance(item, dict) and A_FORM in item, "IM-6", "authorship shape")
        no_unknown_keys(item, set(range(7)), "IM-6", "authorship")
        form = item[A_FORM]
        require(form in (MEMBER, ANONYMOUS, AGENT), "IM-6", "authorship form")
        a = cls(
            form,
            key=item.get(A_KEY),
            sig=item.get(A_SIG),
            slot=item.get(A_SLOT),
            nullifier=item.get(A_NULLIFIER),
            proof=item.get(A_PROOF),
            edit_sig=item.get(A_EDITSIG),
        )
        present = {k for k in item if k != A_FORM and k != A_EDITSIG}
        expected = {
            MEMBER: {A_KEY, A_SIG, A_NULLIFIER, A_PROOF},
            ANONYMOUS: {A_SLOT, A_NULLIFIER, A_PROOF},
            AGENT: {A_SIG},
        }
        require(
            present == expected[form],
            "IM-6",
            f"authorship keys {sorted(present)} do not fit form {form}",
        )
        if a.key is not None:
            require(is_bytes(a.key, 32), "IM-6", "authorship key must be 32 bytes")
        if a.sig is not None:
            require(is_bytes(a.sig, 64), "IM-6", "authorship sig must be 64 bytes")
        if a.slot is not None:
            require(is_uint(a.slot), "IM-6", "slot must be a uint")
        if a.nullifier is not None:
            require(is_bytes(a.nullifier, 32), "IM-6", "nullifier must be 32 bytes")
        if a.proof is not None:
            require(is_bytes(a.proof) and len(a.proof) > 0, "IM-6", "proof must be non-empty bytes")
        if a.edit_sig is not None:
            require(is_bytes(a.edit_sig, 64), "IM-11", "editSig must be 64 bytes")
        return a


def sign_author(key: SigningKey, cid: bytes) -> bytes:
    return key.sign(bound_message(cid))


def sign_edit(edit_key: SigningKey, cid: bytes) -> bytes:
    return edit_key.sign(EDIT_DOMAIN + cid)


# ---------------------------------------------------------------- step 4: shapes


def schema(env: dict[int, Any]) -> None:
    b = env[m.BODY]
    require_keys(b, REQUIRED, "schema")
    no_unknown_keys(b, ALL_KEYS, "schema")
    require(is_uint(b[KIND], 0, 3), "schema", "kind")
    require(is_uint(b[AUTHOR], 0, 3), "schema", "author")
    require(is_bytes(b[EDIT_KEY], 32), "schema", "editKey must be 32 bytes")
    require(is_uint(b[STATE], 0, 4), "schema", "state")
    require(isinstance(b[SEALED], bool), "schema", "sealed must be a bool")
    if EPOCH in b:
        require(is_uint(b[EPOCH]), "schema", "epoch")
    if LANG in b:
        require(isinstance(b[LANG], str), "schema", "lang must be text")
    if ORIGIN in b:
        require(is_bytes(b[ORIGIN], 32), "schema", "origin must be 32 bytes")
    if ASSISTED in b:
        require(isinstance(b[ASSISTED], bool), "schema", "assisted must be a bool")
    if MODERATION in b:
        require(is_uint(b[MODERATION], 0, 4), "schema", "moderation")
    for name in env[m.REFS]:
        require(name in KNOWN_REFS or EVIDENCE_RE.match(name), "schema", f"unknown ref {name!r}")


# ---------------------------------------------------------------- helpers over the resolver


def _is_moderation_version(view: m.Resolved) -> bool:
    return (
        view.env[m.VERSION] > 1
        and view.bundle.signatures is not None
        and view.bundle.authorship is None
    )


def _pinned_context(view: m.Resolved) -> dict[int, Any]:
    ctx = view.manifest(view.refs.get("context", b""))
    require(
        ctx is not None and ctx.get(m.TYPE) == "context", "IM-3", "refs.context is not a context"
    )
    return ctx


def _context_lineage(view: m.Resolved) -> bytes:
    return view.lineage_of(view.refs["context"])


def _effective_limits(ctx_body: dict[int, Any]) -> dict[str, int]:
    mp = ctx_body.get(ctxspec.MAP, {})
    return {
        "window": UNSIGNED_WINDOW_MIN,  # the window is the protocol constant (context.md)
        "unsigned": min(
            mp.get(ctxspec.MAP_UNSIGNED, UNSIGNED_PER_WINDOW_MAX), UNSIGNED_PER_WINDOW_MAX
        ),
        "signed": min(mp.get(ctxspec.MAP_SIGNED, SIGNED_PER_WINDOW_MAX), SIGNED_PER_WINDOW_MAX),
        "agent": min(mp.get(ctxspec.MAP_AGENT, AGENT_OBJECTS_MAX), AGENT_OBJECTS_MAX),
    }


def _sponsor_admitted(ctx_body: dict[int, Any], sponsor_authority: bytes) -> bool:
    ag = ctx_body.get(ctxspec.AGENTS, {})
    return bool(ag.get(ctxspec.AG_ANY, False)) or sponsor_authority in ag.get(
        ctxspec.AG_SPONSORS, []
    )


def log_of_record(ctx_body: dict[int, Any]) -> bytes:
    """The context's log of record: the first entry of ``logs`` (issue-map.md, "Several logs")."""
    return cr.log_of_record([e[ctxspec.L_LOG] for e in ctx_body[ctxspec.LOGS]])


def rebuild_decision(found_in_log_of_record: bool, refused_im7: bool = False) -> str:
    """ "Posting" step 3 and "Several logs": after a lost response the phone asks the log of
    record for the old CID. Found: keep it (``"keep"``). Not found: rebuild with a fresh
    ``issued`` (``"rebuild"``). A rebuilt unsigned object refused under IM-7 means the first one
    was logged: treat it as published and use the next slot (``"first-logged-next-slot"``)."""
    if found_in_log_of_record:
        return "keep"
    return "first-logged-next-slot" if refused_im7 else "rebuild"


def _authored_objects(
    view: m.Resolved, record: bytes | None = None
) -> list[tuple[int, dict[int, Any], m.Bundle, Authorship | None]]:
    """Every issue-map object in the resolver with a lower position in the log of record
    ``record`` (IM-7 and IM-15 count there and nowhere else), with its authorship."""
    out = []
    for type_ in TYPES:
        for pos, env, b in view.all_of_type(type_):
            if view.position is not None and pos >= view.position:
                continue
            if b.cid == view.bundle.cid:
                continue
            if record is not None and b.proof is not None and b.proof.log != record:
                continue
            a = None
            if b.authorship is not None:
                try:
                    a = Authorship.decode(b.authorship)
                except TypeRule:
                    a = None
            out.append((pos, env, b, a))
    return out


def _sponsor_of(view: m.Resolved, env: dict[int, Any]) -> dict[int, Any] | None:
    cid = env[m.REFS].get("sponsor")
    return view.manifest(cid) if cid else None


# ---------------------------------------------------------------- membership proofs (IM-6)

AT_FROM_EPOCH = 7  # verifier.md attribute key 7, absent in older bodies (then 0)


def _verifier_in_force(
    view: m.Resolved, authority: bytes, position: int | None
) -> dict[int, Any] | None:
    """The ``verifier`` version of ``authority`` with the highest log index below ``position``
    (credentials.md, "in force" for a logged presentation); any version when unlogged."""
    best = None
    for pos, env, _ in view.all_of_type("verifier"):
        if env[m.AUTHORITY] != authority or (position is not None and pos >= position):
            continue
        if best is None or pos > best[0]:
            best = (pos, env)
    return best[1] if best else None


def _issuer_info(body: dict[int, Any], authority: bytes) -> cr.IssuerInfo:
    keys = body[vfspec.ISSUER_KEYS]
    return cr.IssuerInfo(
        authority=authority,
        class_=body[vfspec.CLASS],
        retired=False,
        kids={k[vfspec.IK_KID] for k in keys},
        retired_kids=set(body.get(vfspec.RETIRED_KIDS, [])),
        attributes=[(a[vfspec.AT_NAME], a.get(AT_FROM_EPOCH, 0)) for a in body[vfspec.ATTRIBUTES]],
        since={k[vfspec.IK_KID]: k[vfspec.IK_SINCE] for k in keys},
    )


def _rows(
    view: m.Resolved, ctx_env: dict[int, Any], assurance: dict[bytes, int]
) -> dict[tuple[int, int], list[cr.Row]]:
    """trust-list.md rows for every source the pinned context can name."""
    refs, lists, i = ctx_env[m.REFS], [], 0
    while f"tl/{i}" in refs:
        tl_env = view.manifest(refs[f"tl/{i}"])
        require(tl_env is not None, "IM-6", f"tl/{i} is not resolvable")
        lists.append(tl_env[m.BODY])
        i += 1
    out = {}
    for key, rows in tlspec.resolve_rows(ctx_env[m.BODY], lists).items():
        kind, idx = key.split("/")
        src = (ctxspec.SRC_TRUST_LIST if kind == "tl" else ctxspec.SRC_ISSUER, int(idx))
        out[src] = [
            cr.Row(r[0], r[1], r[2], r[3], tuple(r[4]), assurance.get(r[0], 0)) for r in rows
        ]
    return out


def membership_proof(
    view: m.Resolved,
    a: Authorship,
    ctx_env: dict[int, Any],
    use: str,
    scope: bytes,
    bound: bytes,
) -> dict[str, Any]:
    """IM-6's membership proof: ``a.proof`` is a credentials.md presentation of the pinned
    context's ``entry`` policy, verified with the logged-presentation rule (the object's
    ``issued`` and log position, no clock). The authorship ``nullifier`` is the primary one:
    the nullifier of the card the context's designated ``nullifier`` leaf (context.md key 19,
    C6) names. Returns what ``verify_presentation`` returns; ``"nullifiers"`` holds one per
    card, all of which IM-7 counts."""
    env = view.env
    nul = ctx_env[m.BODY].get(ctxspec.NULLIFIER)
    designated = (list(nul[0]), nul[1]) if nul is not None else None
    try:
        pres = cr.Presentation.decode(a.proof)
        issuers, v_of, assurance = {}, {}, {}
        for cp in pres.creds:
            ver = _verifier_in_force(view, cp.issuer, view.position)
            if ver is not None:
                body = ver[m.BODY]
                issuers[cp.issuer] = _issuer_info(body, cp.issuer)
                v_of[cp.issuer] = cr.validity_periods(body[vfspec.VALIDITY])
                assurance[cp.issuer] = body[vfspec.ASSURANCE]
        out = cr.verify_presentation(
            pres,
            use=use,
            policy=ctx_env[m.BODY][ctxspec.ENTRY],
            scope=scope,
            bound=bound,
            expected_context=view.refs["context"],
            issuers=issuers,
            rows_for_source=_rows(view, ctx_env, assurance),
            now=None,
            v_of=v_of,
            issued=env[m.ISSUED],
            object_position=view.position,
            designated_leaf=designated,
        )
    except cr.PresentationError as e:
        raise TypeRule("IM-6", f"membership proof fails {e.rule}: {e.reason}") from e
    require(out["primary"] is not None, "IM-6", "the entry policy yields no nullifier")
    require(
        a.nullifier == out["primary"], "IM-6", "authorship nullifier is not the designated card's"
    )
    return out


def _all_nullifiers(a: Authorship | None) -> set[bytes]:
    """Every nullifier an authorship's presentation yields, one per card, plus the primary it
    carries (credentials.md, "Every nullifier counts")."""
    if a is None or a.nullifier is None:
        return set()
    out = {a.nullifier}
    if a.proof is not None:
        try:
            pres = cr.Presentation.decode(a.proof)
        except cr.PresentationError:
            return out
        out.update(cr.nullifier(cp.pseudonym) for cp in pres.creds)
    return out


def log_submission_check(
    authorship: bytes, issued: int, log_now: int, v_of: dict[bytes, int]
) -> str | None:
    """What the log of record checks at submission, with its own clock ``log_now``: every
    card's disclosed epoch is current (or the previous period's in the first hour) and
    ``issued`` is within 3,600 s of the clock (credentials.md "Validity"; services.md). Returns
    the reason for a ``rejected`` under rule P5, or None. ``v_of`` maps issuer to ``V``."""
    a = Authorship.decode(authorship)
    if a.proof is None:
        return None
    try:
        pres = cr.Presentation.decode(a.proof)
    except cr.PresentationError as e:
        return f"{e.rule}: {e.reason}"
    for cp in pres.creds:
        if cp.issuer not in v_of:
            return "issuer's verifier lineage is not in this log"
        reason = cr.log_submission_check(cp.disclosed.get(0, -1), v_of[cp.issuer], log_now, issued)
        if reason is not None:
            return reason
    return None


# ---------------------------------------------------------------- step 6: authorship (IM-6, 7, 15)


def signatures(
    view: m.Resolved, sigs, keyset_body: dict[int, Any], revoked: dict[bytes, int]
) -> None:
    env, body, bundle = view.env, view.body, view.bundle
    cid = bundle.cid
    threshold = keyset_body[m.KS_THRESHOLDS][m.ROLE_SIGN]

    def context_signed() -> None:
        require(sigs is not None, "IM-6", "context form needs the context's signatures")
        have = m.count_valid_signatures(keyset_body, m.ROLE_SIGN, sigs, cid, revoked, view.position)
        require(
            have >= threshold, "IM-6", f"{have} valid context signatures, threshold {threshold}"
        )

    if _is_moderation_version(view):
        context_signed()
        return
    if body[AUTHOR] == AUTHORITY:
        require(
            env[m.VERSION] == 1,
            "IM-9",
            "a later version by the context must be a moderation version",
        )
        require(bundle.authorship is None, "IM-6", "authority form carries no authorship")
        context_signed()
        return
    require(bundle.authorship is not None, "IM-6", "authorship missing")
    require(sigs is None, "IM-6", "a member or agent object carries no context signatures")
    a = Authorship.decode(bundle.authorship)
    require(
        a.form == body[AUTHOR],
        "IM-6",
        f"authorship form {a.form} differs from author {body[AUTHOR]}",
    )
    ctx_env = _pinned_context(view)
    ctx_body = ctx_env[m.BODY]
    record = log_of_record(ctx_body)
    require(
        bundle.proof is None or bundle.proof.log == record,
        "IM-6",
        "the object is not in the context's log of record",
    )
    limits = _effective_limits(ctx_body)
    window = env[m.ISSUED] // limits["window"]
    if a.form == MEMBER:
        require(
            verify(a.key, bound_message(cid), a.sig),
            "IM-6",
            "hum/author/1 signature does not verify",
        )
        # an agent key is never a member key: any logged sponsor's agentKey is refused
        for _, sponsor_env, _ in view.all_of_type("agent-sponsor"):
            require(
                sponsor_env[m.BODY].get(SP_AGENT_KEY) != a.key,
                "IM-6",
                "the signing key is a logged agentKey",
            )
        membership_proof(view, a, ctx_env, "author-once", once_scope(cid), bound_message(cid))
    elif a.form == ANONYMOUS:
        require(
            a.slot < limits["unsigned"],
            "IM-6",
            f"slot {a.slot} not below the unsigned limit {limits['unsigned']}",
        )
        scope = slot_scope(_context_lineage(view), window, a.slot)
        membership_proof(view, a, ctx_env, "author-slot", scope, bound_message(cid))
    else:
        sponsor = _sponsor_of(view, env)
        require(
            sponsor is not None and sponsor.get(m.TYPE) == "agent-sponsor",
            "IM-6",
            "refs.sponsor is not an agent-sponsor",
        )
        sb = sponsor[m.BODY]
        require(
            verify(sb[SP_AGENT_KEY], bound_message(cid), a.sig),
            "IM-6",
            "agentKey signature does not verify",
        )
        require(sb.get(SP_TIER) == 0, "IM-6", "sponsor tier is not shared")
        require(
            CAP_AUTHOR_MAP in sb.get(SP_CAPABILITIES, []),
            "IM-6",
            "sponsor lacks the author-map capability",
        )
        require(not sb.get(SP_RETIRED, False), "IM-6", "sponsor is retired")
        require(
            m.EXPIRES in sponsor and sponsor[m.EXPIRES] > env[m.ISSUED], "IM-6", "sponsor expired"
        )
        require(
            _sponsor_admitted(ctx_body, sponsor[m.AUTHORITY]),
            "IM-6",
            "sponsor not admitted by the context",
        )
    # IM-7: nullifier reuse by any card, counted in the log of record's seen-set only
    earlier = _authored_objects(view, record)
    mine = _all_nullifiers(a)
    if mine:
        for _, _, other, oa in earlier:
            if other.cid != cid and mine & _all_nullifiers(oa):
                raise TypeRule(
                    "IM-7", "a nullifier of this presentation was seen under another CID"
                )
    # IM-15: rate limits, counted in the log of record only
    ctx_lineage = _context_lineage(view)
    if a.form == MEMBER:
        n = sum(
            1
            for _, e, _, oa in earlier
            if oa is not None
            and oa.form == MEMBER
            and oa.key == a.key
            and e[m.ISSUED] // limits["window"] == window
            and view.lineage_of(e[m.REFS].get("context", b"")) == ctx_lineage
        )
        require(
            n + 1 <= limits["signed"],
            "IM-15",
            f"member over {limits['signed']} objects in the window",
        )
    elif a.form == ANONYMOUS:
        now_window = view.ctx.now // limits["window"]
        require(
            window in (now_window, now_window - 1),
            "IM-15",
            "window is not the log's current or previous",
        )
    else:
        sponsor = _sponsor_of(view, env)
        rl = sponsor[m.BODY][SP_RATE_LIMITS]
        sp_window = env[m.ISSUED] // rl[RL_WINDOW]
        same_sponsor = 0
        all_agents = 0
        for _, e, _, oa in earlier:
            if (
                oa is None
                or oa.form != AGENT
                or view.lineage_of(e[m.REFS]["context"]) != ctx_lineage
            ):
                continue
            osp = _sponsor_of(view, e)
            if osp is None:
                continue
            if e[m.ISSUED] // limits["window"] == window:
                all_agents += 1
            if (
                osp[m.AUTHORITY] == sponsor[m.AUTHORITY]
                and e[m.ISSUED] // rl[RL_WINDOW] == sp_window
            ):
                same_sponsor += 1
        require(
            same_sponsor + 1 <= rl[RL_MAP_OBJECTS], "IM-15", "sponsor over its mapObjects limit"
        )
        require(
            all_agents + 1 <= limits["agent"],
            "IM-15",
            "agents over the context's agentObjects limit",
        )


# ---------------------------------------------------------------- step 10: IM-1 to IM-14


def _dealt(view: m.Resolved) -> bool:
    """A deck with a lower position pins any version of this lineage by a card ref."""
    lineage = view.env.get(m.LINEAGE, view.bundle.cid)
    versions = {b.cid for _, _, b in view.lineage(lineage)} | {view.bundle.cid}
    for pos, deck, _ in view.all_of_type("deck"):
        if view.position is not None and pos >= view.position:
            continue
        for name, ref in deck[m.REFS].items():
            if name.startswith("card/") and ref in versions:
                return True
    return False


def _active_siblings(view: m.Resolved, parent: bytes) -> int:
    """Lineages under ``parent`` whose latest version before this position is active."""
    seen: dict[bytes, dict[int, Any]] = {}
    for pos, env, b in _iter_objects(view):
        if view.position is not None and pos >= view.position:
            continue
        if env[m.REFS].get("parent") != parent:
            continue
        lineage = env.get(m.LINEAGE, b.cid)
        best = seen.get(lineage)
        if best is None or env[m.VERSION] > best[m.VERSION]:
            seen[lineage] = env
    return sum(1 for e in seen.values() if e[m.BODY].get(STATE) == ACTIVE)


def _iter_objects(view: m.Resolved):
    for type_ in TYPES:
        yield from view.all_of_type(type_)


def rules(view: m.Resolved) -> None:
    env, body, refs = view.env, view.body, view.refs
    type_, kind = env[m.TYPE], body[KIND]
    moderation = _is_moderation_version(view)
    # IM-1
    require(kind in TYPES[type_], "IM-1", f"kind {kind} does not match type {type_}")
    # IM-2
    if "parent" in refs:
        parent = view.manifest(refs["parent"])
        require(parent is not None, "IM-2", "parent does not resolve")
        require(
            parent[m.TYPE] == PARENT_TYPE[kind], "IM-2", f"parent must be a {PARENT_TYPE[kind]}"
        )
        require(m.PREV not in parent, "IM-2", "parent must be named by its version 1 CID")
    else:
        require(kind == KIND_ISSUE, "IM-2", "only a top-level issue has no parent")
    # IM-3
    ctx = _pinned_context(view)
    require(
        ctx.get(m.AUTHORITY) == env.get(m.AUTHORITY),
        "IM-3",
        "context authority differs from the envelope authority",
    )
    ctx_lineage = view.lineage_of(refs["context"])
    latest = view.latest_before(ctx_lineage, view.position)
    require(
        latest is None or latest[m.VERSION] <= ctx[m.VERSION],
        "IM-3",
        "a later context version was logged before this object",
    )
    ctx_body = ctx[m.BODY]
    # IM-4a
    require("text" in refs, "IM-4a", "refs.text missing")
    require(body[SEALED] == (EPOCH in body), "IM-4a", "sealed must match the presence of epoch")
    # IM-4b (phones, when the blob is at hand)
    blob = view.blob(refs["text"])
    if blob is not None:
        if body[SEALED]:
            require(blob[:1] == b"\x02", "IM-4b", "sealed text must be a format 2 blob")
        else:
            require(len(blob) <= TEXT_LIMIT[kind], "IM-4b", f"text over {TEXT_LIMIT[kind]} bytes")
            try:
                blob.decode("utf-8")
            except UnicodeDecodeError as e:
                raise TypeRule("IM-4b", "text is not UTF-8") from e
    # IM-5
    require(
        body[SEALED] == ctx_body[ctxspec.SEALED], "IM-5", "sealed must equal the context's sealed"
    )
    # IM-8
    if ORIGIN in body:
        require(body[AUTHOR] == MEMBER, "IM-8", "origin allowed only on a signed member object")
    # IM-9
    require(
        ("sponsor" in refs) == (body[AUTHOR] == AGENT),
        "IM-9",
        "sponsor present iff author is agent",
    )
    require(
        (MODERATION in body) == moderation,
        "IM-9",
        "moderation present iff this is a moderation version",
    )
    # IM-10
    if env[m.VERSION] == 1:
        cards = ctx_body[ctxspec.PERMS][ctxspec.P_CARDS]
        if body[AUTHOR] == AUTHORITY:
            expected = ACTIVE
        elif body[AUTHOR] == AGENT:
            expected = PROPOSED
        else:
            expected = ACTIVE if cards == 2 else PROPOSED
        if expected == ACTIVE and "parent" in refs:
            cap = MAX_ARGUMENTS_ACTIVE if kind in (KIND_PRO, KIND_CON) else MAX_POSITIONS_ACTIVE
            if _active_siblings(view, refs["parent"]) >= cap:
                expected = PROPOSED
        require(body[STATE] == expected, "IM-10", f"version 1 state must be {expected}")
    # IM-11
    prev = view.prev_env
    if prev is not None:
        pb, prefs = prev[m.BODY], prev[m.REFS]
        for key, name in (
            (KIND, "kind"),
            (AUTHOR, "author"),
            (EDIT_KEY, "editKey"),
            (SEALED, "sealed"),
            (ORIGIN, "origin"),
        ):
            require(body.get(key) == pb.get(key), "IM-11", f"frozen field {name} changed")
        require(refs.get("context") is not None, "IM-11", "context ref missing")
        old, new = pb[STATE], body[STATE]
        if old != new:
            require(
                new in TRANSITIONS.get(old, set()),
                "IM-11",
                f"transition {old} -> {new} not allowed",
            )
            if old == PROPOSED and new == ACTIVE:
                require(moderation, "IM-11", "only a moderation version activates")
        require(
            ("mergedInto" in refs) == (new == MERGED),
            "IM-11",
            "mergedInto present iff state is merged",
        )
        if "mergedInto" in refs:
            target = view.manifest(refs["mergedInto"])
            require(
                target is not None and m.PREV not in target,
                "IM-11",
                "mergedInto must name a version 1",
            )
        if refs.get("parent") != prefs.get("parent"):
            require(
                "parent" in prefs and "parent" in refs, "IM-11", "parent cannot appear or vanish"
            )
            require(
                _merged_into_transitively(view, prefs["parent"], refs["parent"]),
                "IM-11",
                "parent may move only to the lineage the old parent merged into",
            )
        if moderation:
            require(
                body.get(MODERATION) is not None, "IM-9", "moderation version without moderation"
            )
            changed = {k for k in set(body) | set(pb) if body.get(k) != pb.get(k)}
            require(
                changed <= {STATE, MODERATION},
                "IM-11",
                f"moderation version changed body keys {sorted(changed)}",
            )
            ref_changed = {k for k in set(refs) | set(prefs) if refs.get(k) != prefs.get(k)}
            allowed = {"mergedInto"} | (
                {"parent"} if body.get(MODERATION) == MOD_REPARENT else set()
            )
            require(
                ref_changed <= allowed,
                "IM-11",
                f"moderation version changed refs {sorted(ref_changed)}",
            )
        else:
            require(
                view.bundle.authorship is not None,
                "IM-11",
                "a non-moderation later version needs authorship",
            )
            a = Authorship.decode(view.bundle.authorship)
            require(a.edit_sig is not None, "IM-11", "editSig missing")
            require(
                verify(body[EDIT_KEY], EDIT_DOMAIN + view.bundle.cid, a.edit_sig),
                "IM-11",
                "editSig does not verify",
            )
            require(a.form == pb[AUTHOR], "IM-11", "authorship form differs from version 1's")
        # IM-12
        if _dealt(view):
            for name in ("text", "parent"):
                require(refs.get(name) == prefs.get(name), "IM-12", f"{name} changed after dealt")
            require(body.get(EPOCH) == pb.get(EPOCH), "IM-12", "epoch changed after dealt")
    # IM-13
    if body[AUTHOR] == AGENT:
        require(m.EXPIRES in env, "IM-13", "agent-authored object needs expires")
        require(
            env[m.EXPIRES] - env[m.ISSUED] <= AGENT_PROPOSAL_TTL,
            "IM-13",
            "agent proposal expiry too long",
        )
    # IM-14
    indices = sorted(int(n.split("/")[1]) for n in refs if EVIDENCE_RE.match(n))
    require(len(indices) <= MAX_EVIDENCE, "IM-14", "more than 8 evidence refs")
    require(indices == list(range(len(indices))), "IM-14", "evidence indices not contiguous from 0")
    if LANG in body:
        require(
            is_text(body[LANG], 16, pattern=LANG_RE), "IM-14", "lang does not match its pattern"
        )


def _merged_into_transitively(view: m.Resolved, old_parent: bytes, new_parent: bytes) -> bool:
    current = old_parent
    for _ in range(16):
        latest = view.latest_before(current, view.position)
        if latest is None or latest[m.BODY].get(STATE) != MERGED:
            return False
        nxt = latest[m.REFS].get("mergedInto")
        if nxt is None:
            return False
        if nxt == new_parent:
            return True
        current = nxt
    return False


# ---------------------------------------------------------------- after a release: labels


Z90 = 1.645


def _share(counts: list[float], sigma: float) -> tuple[float, float] | None:
    """take.md noise math steps 1 to 3 with m = len(counts); None when the gap test fails."""
    n = sum(counts)
    if n < 10 * sigma or n <= 0:
        return None
    p = counts[0] / n
    sp = (sigma / n) * math.sqrt((1 - p) ** 2 + (len(counts) - 1) * p * p)
    return min(max(p, 0.0), 1.0), sp


def annotate(
    tallies: tuple[float, float, float],
    sigma_tallies: float,
    groups: list[tuple[float, float, float]] | None = None,
    sigma_groups: float = 0.0,
) -> dict[str, Any]:
    """Label a position from its raw noised (agree, disagree, unsure) counts (binary64)."""
    overall = _share(list(tallies), sigma_tallies)
    result: dict[str, Any] = {"share": None, "sigma": None, "label": None}
    if overall is None:
        return result
    p, sp = overall
    result["share"], result["sigma"] = p, sp
    group_shares = []
    if groups:
        for g in groups:
            s = _share(list(g), sigma_groups)
            if s is None:
                return result  # a cell failing the gap test: no label
            group_shares.append(s)
        result["groups"] = group_shares
    for i, (pa, sa) in enumerate(group_shares):
        for pb_, sb in group_shares[i + 1 :]:
            hi, lo = (pa, pb_) if pa >= pb_ else (pb_, pa)
            if abs(pa - pb_) >= Z90 * math.sqrt(sa * sa + sb * sb) and hi > 0.5 > lo:
                result["label"] = "Divides"
                return result
    if p - Z90 * sp >= 0.6 and all(pg - Z90 * sg >= 0.6 for pg, sg in group_shares):
        result["label"] = "Common ground"
    elif p - Z90 * sp > 0.5:
        result["label"] = "Leans yes"
    elif p + Z90 * sp < 0.5:
        result["label"] = "Leans no"
    return result


# ---------------------------------------------------------------- duplicate detection (informative)


def _tokens(text: str) -> set[str]:
    norm = unicodedata.normalize("NFKC", text).casefold()
    norm = "".join(c if c.isalnum() or c.isspace() else " " for c in norm)
    return set(norm.split())


def duplicate_ratio(a: str, b: str) -> float:
    """Token-set ratio |A ∩ B| / |A ∪ B| over normalized tokens (Jaccard); near match >= 0.8."""
    ta, tb = _tokens(a), _tokens(b)
    if not ta and not tb:
        return 1.0
    return len(ta & tb) / len(ta | tb)


for _t in TYPES:
    m.register(_t, schema=schema, rules=rules, signatures=signatures)
