"""Vectors for docs/specs/credentials.md, as far as the reference can produce them without a
BBS library. Proofs and pseudonyms are fixed opaque bytes; a per-card ``proof_valid`` flag
stands in for the BBS verification (P4). Sealed issuance bytes, the backup wrap and every
BBS value are pending (see the file notes)."""

from __future__ import annotations

import hashlib

from .. import cbor
from .. import credentials as cr
from ..bodies.context import NODE_ALL, NODE_ANY, PRED_PRESENT, PRED_SET, attr
from ..cid import cid
from ..fixtures import fixed_bytes
from . import File, hexify, jsonable

SPEC = "credentials"
PENDING = (
    "Pending a vetted library for draft-irtf-cfrg-bbs-signatures -12, -blind-signatures -03 and "
    "-per-verifier-linkability -03: BBS signatures, blind issuance, pseudonym computation and "
    "proof verification (P4). Pending HPKE (RFC 9180 incl. §9.8 export): sealed issuance request "
    "and response bytes. Pending Argon2id and HPKE: the backup wrap under hum/backup/1. Proofs "
    "and pseudonyms in these cases are fixed opaque bytes."
)

V = 6  # a 180-day validity: 6 periods per epoch
DISTRICT = cid(b"district verifier keyset")
UNIQUE = cid(b"uniqueness verifier keyset")
APPROVED = cid(b"approved-list verifier keyset")
AGENT_VERIFIER = cid(b"agent-class verifier keyset")
AGENT_VERIFIER_2 = cid(b"second agent-class verifier keyset")
KID_AG2 = fixed_bytes("kid-agent-2", 8)
SPONSOR = cid(b"sponsor keyset")
DECK_LINEAGE = cid(b"deck version 1")
CONTEXT_LINEAGE = cid(b"context version 1")
CONTEXT_VERSION = cid(b"context version 3")
KID_D0, KID_D1, KID_U0, KID_A0, KID_AG = (
    b"d0d0d0d0",
    b"d1d1d1d1",
    b"u0u0u0u0",
    b"a0a0a0a0",
    b"agag0001",
)
NOW = 1_791_259_200  # 2026-10-06; period 740, epoch 123 (V = 6), period 740 % 6 == 2
CLOSES_V1 = NOW + 10 * 86_400


def pseudonym(label: str) -> bytes:
    return fixed_bytes(f"pseudonym/{label}", 48)


def issuer_info(authority, class_, kids, attributes, key_of_epoch, since=None, retired=False):
    return cr.IssuerInfo(
        authority=authority,
        class_=class_,
        retired=retired,
        kids=set(kids),
        retired_kids=set(),
        attributes=[(a, 0) if isinstance(a, str) else tuple(a) for a in attributes],
        key_of_epoch=key_of_epoch,
        since=since or {k: 1 for k in kids},
    )


def issuers():
    return {
        DISTRICT: issuer_info(
            DISTRICT, "person", [KID_D0, KID_D1], ["ward", "area"], {}, {KID_D0: 1, KID_D1: 2}
        ),
        UNIQUE: issuer_info(UNIQUE, "person", [KID_U0], ["unique"], {}),
        APPROVED: issuer_info(APPROVED, "person", [KID_A0], ["approved"], {}),
        AGENT_VERIFIER: issuer_info(AGENT_VERIFIER, "agent", [KID_AG], ["agent-sponsor"], {}),
        AGENT_VERIFIER_2: issuer_info(AGENT_VERIFIER_2, "agent", [KID_AG2], ["agent-sponsor"], {}),
    }


def rows():
    return {
        (0, 0): [
            cr.Row(DISTRICT, "ward", 2, 1, ("person",), 2),
            cr.Row(DISTRICT, "area", 2, 1, ("person",), 2),
            cr.Row(UNIQUE, "unique", 3, 1, ("person",), 3),
        ],
        (1, 0): [cr.Row(APPROVED, "*", 0, 1, ("person", "agent"), 1)],
    }


def v_of():
    return {DISTRICT: V, UNIQUE: V, APPROVED: V, AGENT_VERIFIER: V, AGENT_VERIFIER_2: V}


def card(issuer, kid, length, disclosed, label, proof_valid=True):
    return cr.CardProof(
        issuer,
        kid,
        length,
        disclosed,
        fixed_bytes(f"proof/{label}", 96),
        pseudonym(label),
        proof_valid,
    )


def ballot_epoch() -> int:
    return cr.ballot_window_epoch(CLOSES_V1, V)


def card_json(c: cr.CardProof) -> dict:
    out = jsonable(c.to_item())
    out["proof_valid"] = c.proof_valid
    return out


def pres_json(p: cr.Presentation, scope: bytes, bound: bytes) -> dict:
    return {
        "presentation": hexify(p.encode()),
        "view": jsonable(p.to_item()),
        "cards": [card_json(c) for c in p.creds],
        "scope": hexify(scope),
        "bound_message": hexify(bound),
        "ph": hexify(cr.presentation_header(scope, bound, p.context)),
    }


VOTE_POLICY = [
    NODE_ALL,
    [
        [NODE_ALL, [attr([1, 0], "approved", [PRED_PRESENT])]],  # entry
        [NODE_ALL, [attr([0, 0], "area", [PRED_SET, [1]]), attr([0, 0], "unique", [PRED_PRESENT])]],
    ],
]
ENTRY_ANY = [
    NODE_ANY,
    [attr([1, 0], "approved", [PRED_PRESENT]), attr([0, 0], "area", [PRED_SET, [1]])],
]


def ballot_cards(epoch: int | None = None):
    e = ballot_epoch() if epoch is None else epoch
    return [
        card(APPROVED, KID_A0, 3, {0: e, 1: 1}, "approved"),
        card(DISTRICT, KID_D1, 4, {0: e, 2: 1}, "district"),
        card(UNIQUE, KID_U0, 3, {0: e, 1: 1}, "unique"),
    ]


def run_ballot(pres, **kw):
    body = cbor.encode(
        {0: 1, 1: cid(b"deck v1 bytes"), 2: 0, 3: fixed_bytes("nonce"), 4: {0: b"\x01\x02"}}
    )
    scope, bound = cr.scopes.ballot(DECK_LINEAGE, body)
    args = dict(
        use="ballot",
        policy=VOTE_POLICY,
        scope=scope,
        bound=bound,
        expected_context=CONTEXT_VERSION,
        issuers=issuers(),
        rows_for_source=rows(),
        now=NOW,
        v_of=v_of(),
        closes_v1=CLOSES_V1,
        designated_leaf=([0, 0], "unique"),
    )
    args.update(kw)
    return scope, bound, cr.verify_presentation(pres, **args), args


# ---------------------------------------------------------------- files


def epochs_file() -> File:
    f = File(
        SPEC,
        "epochs",
        "Periods, epochs, handover, the ballot window and the first-hour grace. " + PENDING,
    )
    for t in [0, NOW, CLOSES_V1, 2_419_200 * 745, 2_419_200 * 745 + 3599, 2_419_200 * 745 + 3600]:
        p = cr.period(t)
        f.add(
            "period",
            f"period and epoch of t = {t} with V = {V}",
            "Terms",
            {"t": t, "V": V},
            {"period": p, "epoch": cr.epoch_of_period(p, V), "handover": cr.handover(p, V)},
        )
    e = ballot_epoch()
    f.add(
        "ballot-window",
        "The ballot window epoch is epoch(period(closes of version 1))",
        "Validity",
        {"closes_v1": CLOSES_V1, "V": V},
        {"epoch": e, "starts_at_period": e * V},
    )
    edges = [
        ("first-period-of-epoch", e, e * V * cr.PERIOD + 10, "other", None, True),
        ("last-period-of-epoch", e, (e * V + V - 1) * cr.PERIOD + 10, "other", None, True),
        ("one-period-before", e, (e * V - 1) * cr.PERIOD + 10, "other", None, False),
        ("one-period-after", e, (e * V + V) * cr.PERIOD + 7200, "other", None, False),
        ("first-hour-grace", e, (e * V + V) * cr.PERIOD + 100, "other", None, True),
        ("ballot-current-card", e, NOW, "ballot", CLOSES_V1, True),
        (
            "ballot-next-epoch-card-not-started",
            e + 1,
            NOW,
            "ballot",
            (e + 1) * V * cr.PERIOD + 5,
            False,
        ),
        (
            "ballot-next-epoch-card-started",
            e + 1,
            (e + 1) * V * cr.PERIOD + 5,
            "ballot",
            (e + 1) * V * cr.PERIOD + 5,
            True,
        ),
        (
            "ballot-extended-deck-keeps-original-epoch",
            e + 1,
            (e + 1) * V * cr.PERIOD + 5,
            "ballot",
            CLOSES_V1,
            False,
        ),
        (
            "ballot-expired-card-still-acts-in-later-round",
            e,
            (e + 1) * V * cr.PERIOD + 5,
            "ballot",
            CLOSES_V1,
            True,
        ),
    ]
    for name, ce, now, use, closes, expect in edges:
        got = cr.card_accepted(ce, V, now, use=use, closes_v1=closes)
        assert got == expect, name
        f.add(
            "cred-epoch-edges",
            name,
            "Validity",
            {"card_epoch": ce, "V": V, "now": now, "use": use, "closes_v1": closes},
            {"accepted": got},
        )
    f.add(
        "key-of-epoch",
        "The key of an epoch is the one with the largest fromEpoch ≤ E",
        "Message layout",
        {
            "keys": [
                {"kid": hexify(KID_D0), "fromEpoch": 0},
                {"kid": hexify(KID_D1), "fromEpoch": 4},
            ]
        },
        {
            "epoch_3": hexify(cr.key_of_epoch([(KID_D0, 0), (KID_D1, 4)], 3)),
            "epoch_4": hexify(cr.key_of_epoch([(KID_D0, 0), (KID_D1, 4)], 4)),
            "epoch_9": hexify(cr.key_of_epoch([(KID_D0, 0), (KID_D1, 4)], 9)),
        },
    )
    return f


def layout_file() -> File:
    f = File(
        SPEC,
        "layout",
        "Card message bytes, L, the BBS header, scope bytes and bound messages for every "
        "row of the uses table, the nullifier and the presentation header.",
    )
    f.add(
        "layout",
        "District card: L = 4; epoch at 0, attributes at 1 + i, nym secret last",
        "Message layout",
        {"attributes": ["ward", "area"], "epoch": 123, "ward": 2, "area": None},
        {
            "L": cr.layout_length(2),
            "message_0_epoch": hexify(cr.message_bytes(0, None, 123)),
            "message_1_ward": hexify(cr.message_bytes(1, 2)),
            "message_2_area_absent": hexify(cr.message_bytes(2, None)),
            "message_3": "nym secret: a scalar, never octets",
        },
    )
    f.add(
        "header",
        "BBS header hum/credential/1 ‖ authority ‖ kid",
        "Message layout",
        {"authority": hexify(DISTRICT), "kid": hexify(KID_D1)},
        {"header": hexify(cr.card_header(DISTRICT, KID_D1))},
    )
    body = cbor.encode(
        {0: 1, 1: cid(b"deck v1 bytes"), 2: 0, 3: fixed_bytes("nonce"), 4: {0: b"\x01\x02"}}
    )
    handles = [fixed_bytes("handle-0"), fixed_bytes("handle-1")]
    reqs = [fixed_bytes("token-request-0", 300), fixed_bytes("token-request-1", 300)]
    obj = cid(b"an issue-map object")
    req_plain = cr.issuance_request(
        cid(b"verifier manifest"), KID_D1, [fixed_bytes("commit", 200)], [1]
    )
    uses = [
        (
            "ballot",
            cr.scopes.ballot(DECK_LINEAGE, body),
            {"deck_lineage": hexify(DECK_LINEAGE), "body_keys_0_to_4": hexify(body)},
        ),
        (
            "join",
            cr.scopes.join(CONTEXT_LINEAGE, handles),
            {"context_lineage": hexify(CONTEXT_LINEAGE), "handles": [hexify(h) for h in handles]},
        ),
        (
            "blob-token",
            cr.scopes.blob_tokens(fixed_bytes("token-key-id"), 20733, reqs),
            {
                "token_key_id": hexify(fixed_bytes("token-key-id")),
                "day": 20733,
                "requests": [hexify(r) for r in reqs],
            },
        ),
        (
            "delivery-token",
            cr.scopes.delivery_tokens(fixed_bytes("token-key-id"), 20733, reqs),
            {
                "token_key_id": hexify(fixed_bytes("token-key-id")),
                "day": 20733,
                "requests": [hexify(r) for r in reqs],
            },
        ),
        ("author-once", cr.scopes.author_once(obj), {"object": hexify(obj)}),
        (
            "author-slot",
            cr.scopes.author_slot(CONTEXT_LINEAGE, 20733, 2, obj),
            {
                "context_lineage": hexify(CONTEXT_LINEAGE),
                "window": 20733,
                "slot": 2,
                "object": hexify(obj),
            },
        ),
        (
            "sponsor",
            cr.scopes.sponsor(SPONSOR, fixed_bytes("agent-key")),
            {"sponsor_authority": hexify(SPONSOR), "agentKey": hexify(fixed_bytes("agent-key"))},
        ),
        (
            "issuance",
            cr.scopes.issuance(DISTRICT, req_plain),
            {"verifier_authority": hexify(DISTRICT), "request_plaintext": hexify(req_plain)},
        ),
    ]
    for name, (scope, bound), inputs in uses:
        f.add(
            f"scope-{name}",
            f"Scope bytes and bound message for the {name} row",
            "The uses",
            inputs,
            {"scope": hexify(scope), "bound_message": hexify(bound)},
        )
    assert cr.scopes.prefixes_distinct()
    f.add(
        "prefixes",
        "No scope prefix is a prefix of another; no ballot scope starts with hum/author-",
        "The uses",
        {"prefixes": [p.decode() for p in cr.scopes.PREFIXES]},
        {"distinct": True},
    )
    for label in ("a", "b", "c"):
        p = pseudonym(label)
        f.add(
            "cred-nullifier-derive",
            f"Nullifier of pseudonym {label}",
            "Scopes and nullifiers",
            {"pseudonym": hexify(p)},
            {"nullifier": hexify(cr.nullifier(p))},
        )
    f.add(
        "cred-nullifier-derive",
        "The same nym secret under two scopes yields unrelated nullifiers "
        "(pseudonyms given; computing them is pending the pseudonym draft)",
        "Scopes and nullifiers",
        {
            "pseudonym_scope_1": hexify(pseudonym("same-nym/scope-1")),
            "pseudonym_scope_2": hexify(pseudonym("same-nym/scope-2")),
        },
        {
            "nullifier_1": hexify(cr.nullifier(pseudonym("same-nym/scope-1"))),
            "nullifier_2": hexify(cr.nullifier(pseudonym("same-nym/scope-2"))),
            "equal": False,
        },
    )
    scope, bound = cr.scopes.ballot(DECK_LINEAGE, body)
    f.add(
        "ph",
        "Presentation header with a context, and without one",
        "Format",
        {
            "scope": hexify(scope),
            "bound_message": hexify(bound),
            "context": hexify(CONTEXT_VERSION),
        },
        {
            "ph_with_context": hexify(cr.presentation_header(scope, bound, CONTEXT_VERSION)),
            "ph_without_context": hexify(cr.presentation_header(scope, bound, None)),
        },
    )
    return f


def presentations_file() -> File:
    f = File(
        SPEC,
        "presentations",
        "Structural presentations per use and the verification rules P1–P8. "
        "P4 is the proof_valid flag per card. " + PENDING,
    )
    # valid ballot with three cards (approved, area = 1, unique); primary from unique
    pres = cr.Presentation(ballot_cards(), [], CONTEXT_VERSION)
    scope, bound, out, _ = run_ballot(pres)
    f.add(
        "cred-present-ballot-two-cards",
        "Effective voting policy [entry, vote] with area = 1 and unique; the primary "
        "nullifier is the unique card's; every epoch equals the window epoch",
        "Presentations",
        {
            **pres_json(pres, scope, bound),
            "policy": jsonable(VOTE_POLICY),
            "now": NOW,
            "closes_v1": CLOSES_V1,
        },
        {
            "nullifiers": [hexify(n) for n in out["nullifiers"]],
            "primary": hexify(out["primary"]),
            "cards_used": out["used"],
        },
    )
    # entry = area = 1 from a trust list with one verifier for area; two members, same public fields
    e_now = cr.epoch_now(NOW, V)
    entry_area = attr([0, 0], "area", [PRED_SET, [1]])
    scope2, bound2 = cr.scopes.join(CONTEXT_LINEAGE, [fixed_bytes("handle-0")])
    members = []
    for label in ("member-a", "member-b"):
        p2 = cr.Presentation(
            [card(DISTRICT, KID_D1, 4, {0: e_now, 2: 1}, label)], [], CONTEXT_VERSION
        )
        out2 = cr.verify_presentation(
            p2,
            use="join",
            policy=entry_area,
            scope=scope2,
            bound=bound2,
            expected_context=CONTEXT_VERSION,
            issuers=issuers(),
            rows_for_source=rows(),
            now=NOW,
            v_of=v_of(),
        )
        members.append((p2, out2))
    public = [
        jsonable({k: v for k, v in p2.creds[0].to_item().items() if k < cr.CP_PROOF})
        for p2, _ in members
    ]
    assert public[0] == public[1]
    f.add(
        "cred-present-entry-one-cell",
        "entry = area = 1 from a trust list with one verifier for area; branches = []; two "
        "members' presentations share every public field (issuer, kid, len, disclosed)",
        "What is proven",
        {
            "policy": jsonable(entry_area),
            "now": NOW,
            "members": [pres_json(p2, scope2, bound2) for p2, _ in members],
        },
        {
            "branches": [],
            "public_fields_equal": True,
            "public_fields": public[0],
            "nullifiers": [[hexify(n) for n in o["nullifiers"]] for _, o in members],
        },
    )
    # one per use row (entry policy = approved present), context per row
    entry = attr([1, 0], "approved", [PRED_PRESENT])
    obj = cid(b"an issue-map object")
    rows_uses = [
        ("join", cr.scopes.join(CONTEXT_LINEAGE, [fixed_bytes("handle-0")]), CONTEXT_VERSION),
        (
            "blob-token",
            cr.scopes.blob_tokens(fixed_bytes("token-key-id"), 20733, [fixed_bytes("tr", 64)]),
            CONTEXT_VERSION,
        ),
        (
            "delivery-token",
            cr.scopes.delivery_tokens(fixed_bytes("token-key-id"), 20733, [fixed_bytes("tr", 64)]),
            CONTEXT_VERSION,
        ),
        ("author-once", cr.scopes.author_once(obj), CONTEXT_VERSION),
        ("author-slot", cr.scopes.author_slot(CONTEXT_LINEAGE, 20733, 1, obj), CONTEXT_VERSION),
    ]
    for name, (sc, bd), ctx_ in rows_uses:
        p = cr.Presentation(
            [card(APPROVED, KID_A0, 3, {0: e_now, 1: 1}, f"approved-{name}")], [], ctx_
        )
        logged = cr.is_logged_use(name)
        out = cr.verify_presentation(
            p,
            use=name,
            policy=entry,
            scope=sc,
            bound=bd,
            expected_context=ctx_,
            issuers=issuers(),
            rows_for_source=rows(),
            now=None if logged else NOW,
            v_of=v_of(),
            issued=NOW if logged else None,
        )
        f.add(
            f"cred-present-{name}",
            f"A valid presentation for the {name} row"
            + (" (a logged presentation: verified against issued, no clock)" if logged else ""),
            "The uses",
            {
                **pres_json(p, sc, bd),
                "policy": jsonable(entry),
                **({"issued": NOW} if logged else {"now": NOW}),
            },
            {"nullifiers": [hexify(n) for n in out["nullifiers"]]},
        )
    sponsor_policy = cr.possession_leaf(AGENT_VERIFIER)
    sc, bd = cr.scopes.sponsor(SPONSOR, fixed_bytes("agent-key"))
    p = cr.Presentation([card(AGENT_VERIFIER, KID_AG, 3, {0: e_now}, "agent-card")], [], None)
    out = cr.verify_presentation(
        p,
        use="sponsor",
        policy=sponsor_policy,
        scope=sc,
        bound=bd,
        expected_context=None,
        issuers=issuers(),
        rows_for_source=rows(),
        now=None,
        v_of=v_of(),
        issued=NOW,
    )
    f.add(
        "cred-present-sponsor",
        "An agent-class card under hum/sponsor/1, no context, bound to agentKey; a logged "
        "presentation verified against the manifest's issued. The policy is the uses table's "
        "possession leaf [4, A], A the agent-class verifier the sponsor manifest names; only "
        "the epoch is disclosed",
        "Agent sponsor credentials",
        {**pres_json(p, sc, bd), "policy": jsonable(sponsor_policy), "issued": NOW},
        {"nullifiers": [hexify(n) for n in out["nullifiers"]]},
    )
    other = cr.Presentation(
        [card(AGENT_VERIFIER_2, KID_AG2, 3, {0: e_now}, "other-agent")], [], None
    )
    try:
        cr.verify_presentation(
            other,
            use="sponsor",
            policy=sponsor_policy,
            scope=sc,
            bound=bd,
            expected_context=None,
            issuers=issuers(),
            rows_for_source=rows(),
            now=None,
            v_of=v_of(),
            issued=NOW,
        )
        raise AssertionError("a card from another verifier satisfied the possession leaf")
    except cr.PresentationError as e:
        assert e.rule == "P6"
        f.add(
            "cred-invalid-P6-possession-issuer",
            "A sponsor presentation whose card is from an agent-class verifier other than the "
            "one the sponsor manifest names: the possession leaf [4, A] is unsatisfied",
            "Agent sponsor credentials",
            {**pres_json(other, sc, bd), "policy": jsonable(sponsor_policy), "issued": NOW},
            rejection={"step": None, "check": "presentation", "rule": "P6", "reason": e.reason},
        )
    low_since = issuers()
    low_since[AGENT_VERIFIER] = issuer_info(
        AGENT_VERIFIER, "agent", [KID_AG], ["agent-sponsor"], {}, {KID_AG: 1}
    )
    out = cr.verify_presentation(
        p,
        use="sponsor",
        policy=sponsor_policy,
        scope=sc,
        bound=bd,
        expected_context=None,
        issuers=low_since,
        rows_for_source=rows(),
        now=None,
        v_of=v_of(),
        issued=NOW,
    )
    f.add(
        "cred-valid-P6-possession-no-minversion",
        "The sponsor card's kid has since 1 and every trust-list row the phone holds says "
        "minVersion 2: accepted, because a possession leaf [4, A] has no trust-list row and so "
        "no minVersion test; its only key condition is that kid is the key of the card's epoch "
        "or a still-listed key of an earlier epoch",
        "Agent sponsor credentials",
        {
            **pres_json(p, sc, bd),
            "policy": jsonable(sponsor_policy),
            "issued": NOW,
            "since": {hexify(KID_AG): 1},
        },
        {"nullifiers": [hexify(n) for n in out["nullifiers"]]},
    )
    req_plain = cr.issuance_request(
        cid(b"verifier manifest"), KID_D1, [fixed_bytes("commit", 200)], [1]
    )
    sc, bd = cr.scopes.issuance(DISTRICT, req_plain)
    accepts_one = [(UNIQUE, ["unique"])]
    accepts_two = [(APPROVED, ["approved"]), (UNIQUE, ["unique"])]
    unique_card = card(UNIQUE, KID_U0, 3, {0: e_now, 1: 1}, "unique-issuance")

    def accepts_json(accepts):
        return [{"authority": hexify(a), "attributes": names} for a, names in accepts]

    def run_issuance(p, accepts):
        return cr.verify_presentation(
            p,
            use="issuance",
            policy=None,
            scope=sc,
            bound=bd,
            expected_context=None,
            issuers=issuers(),
            rows_for_source={},
            now=NOW,
            v_of=v_of(),
            accepts=accepts,
        )

    p = cr.Presentation([unique_card], [], None)
    out = run_issuance(p, accepts_one)
    f.add(
        "cred-present-issuance",
        "A uniqueness card presented as issuance evidence to the district verifier: the "
        "evidence item's one accepts entry, its possession leaf [4, authority] and its "
        "attribute disclosed",
        "The uses",
        {**pres_json(p, sc, bd), "accepts": accepts_json(accepts_one), "now": NOW},
        {"nullifiers": [hexify(n) for n in out["nullifiers"]], "accepts_entry": 0},
    )
    out = run_issuance(p, accepts_two)
    assert out["accepts_entry"] == 1
    assert cr.choose_accepts_entry(accepts_two, {UNIQUE}) == 1
    f.add(
        "cred-present-issuance-accepts-second-entry",
        "accepts with two entries, the phone holding a card for the second only: it presents "
        "one card, the lowest-index entry it holds a card for (index 1); entries are "
        "alternatives, not a conjunction",
        "The uses",
        {
            **pres_json(p, sc, bd),
            "accepts": accepts_json(accepts_two),
            "held": [hexify(UNIQUE)],
            "now": NOW,
        },
        {"nullifiers": [hexify(n) for n in out["nullifiers"]], "accepts_entry": 1},
    )
    two_cards = cr.Presentation(
        [card(APPROVED, KID_A0, 3, {0: e_now, 1: 1}, "approved-issuance"), unique_card], [], None
    )
    try:
        run_issuance(two_cards, accepts_two)
        raise AssertionError("two cards accepted")
    except cr.PresentationError as e:
        assert e.rule == "P6"
        f.add(
            "cred-invalid-P6-issuance-two-cards",
            "accepts with two entries and two cards, one per entry: issuance evidence carries "
            "exactly one card",
            "The uses",
            {**pres_json(two_cards, sc, bd), "accepts": accepts_json(accepts_two), "now": NOW},
            rejection={"step": None, "check": "presentation", "rule": "P6", "reason": e.reason},
        )
    f.add(
        "verify-only-key-accepted",
        "A card under a kid still listed in issuerKeys (not retired) is accepted (P3)",
        "Verification rules",
        {**pres_json(pres, scope, bound)},
        {"accepted": True},
    )

    # invalid cases
    def reject(suffix, desc, rule, build, **kw):
        p = build()
        try:
            run_ballot(p, **kw)
            raise AssertionError(suffix)
        except cr.PresentationError as e:
            assert e.rule == rule, (suffix, e.rule, e.reason)
            reason = e.reason
        sc, bd = cr.scopes.ballot(
            DECK_LINEAGE,
            cbor.encode(
                {0: 1, 1: cid(b"deck v1 bytes"), 2: 0, 3: fixed_bytes("nonce"), 4: {0: b"\x01\x02"}}
            ),
        )
        f.add(
            suffix,
            desc,
            "Verification rules",
            {**pres_json(p, sc, bd), "now": kw.get("now", NOW)},
            rejection={"step": None, "check": "presentation", "rule": rule, "reason": reason},
        )

    def with_cards(cards, branches=None, ctx_=CONTEXT_VERSION):
        return lambda: cr.Presentation(cards, branches or [], ctx_)

    # P1 byte-level cases
    big = cr.Presentation(
        [card(APPROVED, KID_A0, 3, {0: ballot_epoch(), 1: 1}, "big")], [], CONTEXT_VERSION
    )
    big.creds[0].proof = bytes(17 * 1024)
    for size_name, in_ballot in (("17-kib", False), ("9-kib-in-ballot", True)):
        data = (
            big.encode()
            if size_name == "17-kib"
            else cr.Presentation(
                [card(APPROVED, KID_A0, 3, {0: ballot_epoch(), 1: 1}, "big9")], [], CONTEXT_VERSION
            ).encode()
        )
        if size_name != "17-kib":
            p9 = cr.Presentation(
                [card(APPROVED, KID_A0, 3, {0: ballot_epoch(), 1: 1}, "big9")], [], CONTEXT_VERSION
            )
            p9.creds[0].proof = bytes(9 * 1024)
            data = p9.encode()
        try:
            cr.Presentation.decode(data, in_ballot=in_ballot)
            raise AssertionError
        except cr.PresentationError as e:
            f.add(
                f"cred-invalid-P1-{size_name}",
                f"Presentation of {len(data)} bytes",
                "Verification rules",
                {
                    "presentation_sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                    "in_ballot": in_ballot,
                },
                rejection={"step": None, "check": "presentation", "rule": "P1", "reason": e.reason},
            )
    unknown = dict(pres.to_item())
    unknown[7] = 1
    nine = cr.Presentation(
        ballot_cards()
        + [card(APPROVED, KID_A0, 3, {0: ballot_epoch(), 1: 1}, f"x{i}") for i in range(6)],
        [],
        CONTEXT_VERSION,
    )
    for name, data in (("unknown-key", cbor.encode(unknown)), ("nine-card-proofs", nine.encode())):
        try:
            cr.Presentation.decode(data)
            raise AssertionError
        except cr.PresentationError as e:
            f.add(
                f"cred-invalid-P1-{name}",
                name,
                "Verification rules",
                {"presentation": hexify(data)},
                rejection={"step": None, "check": "presentation", "rule": "P1", "reason": e.reason},
            )
    # P2
    reject(
        "cred-invalid-P2-context-absent",
        "Ballot presentation with no context",
        "P2",
        with_cards(ballot_cards(), ctx_=None),
    )
    reject(
        "cred-invalid-P2-wrong-version",
        "Against a version the deck does not pin",
        "P2",
        with_cards(ballot_cards(), ctx_=cid(b"context version 2")),
    )
    sp = cr.Presentation(
        [card(AGENT_VERIFIER, KID_AG, 3, {0: e_now}, "agent-card")], [], CONTEXT_VERSION
    )
    try:
        cr.verify_presentation(
            sp,
            use="sponsor",
            policy=sponsor_policy,
            scope=sc,
            bound=bd,
            expected_context=None,
            issuers=issuers(),
            rows_for_source=rows(),
            now=None,
            v_of=v_of(),
            issued=NOW,
        )
        raise AssertionError
    except cr.PresentationError as e:
        f.add(
            "cred-invalid-P2-sponsor-with-context",
            "A sponsor presentation carrying context",
            "Verification rules",
            pres_json(sp, sc, bd),
            rejection={"step": None, "check": "presentation", "rule": "P2", "reason": e.reason},
        )
    # P3
    retired = issuers()
    retired[UNIQUE].retired = True
    reject(
        "cred-invalid-P3-retired-lineage",
        "The uniqueness verifier lineage is retired",
        "P3",
        with_cards(ballot_cards()),
        issuers=retired,
    )
    agent_in_ballot = ballot_cards()[:2] + [
        card(AGENT_VERIFIER, KID_AG, 3, {0: ballot_epoch(), 1: 1}, "agent-in-ballot")
    ]
    reject(
        "cred-invalid-P3-agent-class-card",
        "An agent-class card in a ballot",
        "P3",
        with_cards(agent_in_ballot),
    )
    person_as_sponsor = cr.Presentation(
        [card(UNIQUE, KID_U0, 3, {0: e_now}, "person-as-sponsor")], [], None
    )
    try:
        cr.verify_presentation(
            person_as_sponsor,
            use="sponsor",
            policy=sponsor_policy,
            scope=sc,
            bound=bd,
            expected_context=None,
            issuers=issuers(),
            rows_for_source=rows(),
            now=None,
            v_of=v_of(),
            issued=NOW,
        )
        raise AssertionError
    except cr.PresentationError as e:
        f.add(
            "cred-invalid-P3-person-class-in-sponsor-proof",
            "A person-class card in a sponsor proof",
            "Verification rules",
            pres_json(person_as_sponsor, sc, bd),
            rejection={"step": None, "check": "presentation", "rule": "P3", "reason": e.reason},
        )
    retired_kid = issuers()
    retired_kid[DISTRICT].kids.discard(KID_D0)
    retired_kid[DISTRICT].retired_kids.add(KID_D0)
    old = ballot_cards()
    old[1] = card(DISTRICT, KID_D0, 4, {0: ballot_epoch(), 2: 1}, "district-old-kid")
    reject(
        "cred-invalid-P3-kid-retired",
        "kid in retiredKids",
        "P3",
        with_cards(old),
        issuers=retired_kid,
    )
    wrong_len = ballot_cards()
    wrong_len[1] = card(DISTRICT, KID_D1, 5, {0: ballot_epoch(), 2: 1}, "district-len5")
    reject(
        "cred-invalid-P3-len-wrong-epoch",
        "len of the wrong epoch's layout",
        "P3",
        with_cards(wrong_len),
    )
    strict_rows = rows()
    strict_rows[(0, 0)] = [
        cr.Row(DISTRICT, "area", 2, 2, ("person",), 2),
        cr.Row(UNIQUE, "unique", 3, 1, ("person",), 3),
    ]
    old_since = ballot_cards()
    old_since[1] = card(DISTRICT, KID_D0, 4, {0: ballot_epoch(), 2: 1}, "district-since-1")
    reject(
        "cred-invalid-P6-minversion",
        "kid with since 1 against the row's minVersion 2 (trust-list.md step 4): the accepted "
        "set admits no row, so the leaf has no satisfying card",
        "P6",
        with_cards(old_since),
        rows_for_source=strict_rows,
    )
    # P4 (flag)
    bad_proof = ballot_cards()
    bad_proof[2].proof_valid = False
    reject(
        "cred-invalid-P4-proof",
        "A card proof the BBS verification rejects (flag; the scope/bound/context and "
        "pseudonym-mismatch cases are pending a BBS library)",
        "P4",
        with_cards(bad_proof),
    )
    # P5
    no_epoch = ballot_cards()
    no_epoch[0] = card(APPROVED, KID_A0, 3, {1: 1}, "no-epoch")
    reject(
        "cred-invalid-P5-index-0-missing", "index 0 (the epoch) missing", "P5", with_cards(no_epoch)
    )
    nym = ballot_cards()
    nym[0] = card(APPROVED, KID_A0, 3, {0: ballot_epoch(), 1: 1, 2: 7}, "nym-disclosed")
    reject(
        "cred-invalid-P5-index-L-1-disclosed",
        "index L - 1 (the nym secret) disclosed",
        "P5",
        with_cards(nym),
    )
    reject(
        "cred-invalid-P5-epoch-too-low",
        "a card of the epoch before the original close",
        "P5",
        with_cards(ballot_cards(ballot_epoch() - 1)),
    )
    reject(
        "cred-invalid-P5-epoch-too-high",
        "a card of the epoch after the original close",
        "P5",
        with_cards(ballot_cards(ballot_epoch() + 1)),
    )
    later = (ballot_epoch() + 1) * V * cr.PERIOD + 10
    reject(
        "cred-invalid-P5-post-dated-not-started",
        "a post-dated card before its epoch starts (deck closing in the next epoch)",
        "P5",
        with_cards(ballot_cards(ballot_epoch() + 1)),
        closes_v1=later + 5,
        now=NOW,
    )
    # P6
    reject(
        "cred-invalid-P6-leaf-unsatisfied",
        "no card for the unique leaf",
        "P6",
        with_cards(ballot_cards()[:2]),
    )
    reject(
        "cred-invalid-P6-branches-non-empty",
        "branches = [0] under an all-only policy; branches is always empty (C16)",
        "P6",
        with_cards(ballot_cards(), branches=[0]),
    )
    decoy = ballot_cards() + [card(DISTRICT, KID_D1, 4, {0: ballot_epoch()}, "decoy")]
    reject(
        "cred-invalid-P6-card-satisfies-nothing",
        "a fourth card proof satisfying no leaf",
        "P6",
        with_cards(decoy),
    )
    two_valued = [
        NODE_ALL,
        [attr([1, 0], "approved", [PRED_PRESENT]), attr([0, 0], "ward", [PRED_SET, [1, 2]])],
    ]
    reject(
        "cred-invalid-P6-two-valued-set-leaf",
        "a presentation claiming a two-valued set leaf",
        "P6",
        with_cards(
            [
                card(APPROVED, KID_A0, 3, {0: ballot_epoch(), 1: 1}, "a"),
                card(DISTRICT, KID_D1, 4, {0: ballot_epoch(), 1: 1}, "w"),
            ]
        ),
        policy=two_valued,
    )
    pooled = cr.Presentation(
        ballot_cards()[:2]
        + [card(UNIQUE, KID_U0, 3, {0: ballot_epoch(), 1: 1}, "someone-elses-unique")],
        [],
        CONTEXT_VERSION,
    )
    scope, bound, out, _ = run_ballot(pooled)
    f.add(
        "cred-invalid-P6-pooled-presentation",
        "Two people's cards pooled under all: verifies here; ballot.md B3 rejects it "
        "when the second nullifier is already in the deck",
        "Verification rules",
        {
            **pres_json(pooled, scope, bound),
            "nullifier_already_in_deck": hexify(out["nullifiers"][2]),
        },
        {
            "verifies": True,
            "nullifiers": [hexify(n) for n in out["nullifiers"]],
            "ballot_b3": "reject",
        },
    )
    # P7
    gate = ballot_cards()
    gate[1] = card(DISTRICT, KID_D1, 4, {0: ballot_epoch(), 1: 2, 2: 1}, "ward-disclosed")
    reject(
        "cred-invalid-P7-gate-disclosed",
        "a gate attribute (ward) disclosed under a ballot",
        "P7",
        with_cards(gate),
    )
    # P8
    reject(
        "cred-invalid-P8-primary-wrong-card",
        "the designated nullifier leaf names a source no card satisfies",
        "P8",
        with_cards(ballot_cards()),
        designated_leaf=([1, 1], "unique"),
    )
    # P6 under C16: an any node, and a leaf that two verifiers could satisfy
    any_card = cr.Presentation(
        [card(APPROVED, KID_A0, 3, {0: e_now, 1: 1}, "approved-any")], [0], CONTEXT_VERSION
    )
    try:
        cr.verify_presentation(
            any_card,
            use="join",
            policy=ENTRY_ANY,
            scope=scope2,
            bound=bound2,
            expected_context=CONTEXT_VERSION,
            issuers=issuers(),
            rows_for_source=rows(),
            now=NOW,
            v_of=v_of(),
        )
        raise AssertionError
    except cr.PresentationError as e:
        assert e.rule == "P6"
        f.add(
            "cred-invalid-P6-any-node",
            "A presentation against entry = any(approved, area = 1) with branches = [0]; "
            "valid before C16, rejected in draft 0.1",
            "What is proven",
            {**pres_json(any_card, scope2, bound2), "policy": jsonable(ENTRY_ANY), "now": NOW},
            rejection={"step": None, "check": "presentation", "rule": "P6", "reason": e.reason},
        )
    district2 = cid(b"second district verifier keyset")
    kid_e0 = b"e0e0e0e0"
    two_auth_issuers = issuers()
    two_auth_issuers[district2] = issuer_info(district2, "person", [kid_e0], ["area"], {})
    two_auth_rows = rows()
    two_auth_rows[(0, 0)] = rows()[(0, 0)] + [cr.Row(district2, "area", 2, 1, ("person",), 2)]
    from_second = ballot_cards()
    from_second[1] = card(district2, kid_e0, 3, {0: ballot_epoch(), 1: 1}, "area-from-second")
    reject(
        "cred-invalid-P6-two-verifiers-for-leaf",
        "The leaf's trust list accepts area from two verifiers; the card is from the second. "
        "C16 forbids the policy, and P6 rejects any presentation against it",
        "P6",
        with_cards(from_second),
        issuers=two_auth_issuers,
        rows_for_source=two_auth_rows,
        v_of={**v_of(), district2: V},
    )

    # logged presentations: authorship verified later against issued, with no clock
    obj = cid(b"an issue-map object")
    sc_once, bd_once = cr.scopes.author_once(obj)
    area_leaf = attr([0, 0], "area", [PRED_SET, [1]])

    def run_logged(p, issued, position=None, **kw):
        args = dict(
            use="author-once",
            policy=entry,
            scope=sc_once,
            bound=bd_once,
            expected_context=CONTEXT_VERSION,
            issuers=issuers(),
            rows_for_source=rows(),
            now=None,
            v_of=v_of(),
            issued=issued,
            object_position=position,
        )
        args.update(kw)
        return cr.verify_presentation(p, **args)

    def logged_case(suffix, desc, p, issued, position=None, rule=None, extra=None, **kw):
        inputs = {**pres_json(p, sc_once, bd_once), "issued": issued, "V": V, **(extra or {})}
        if position is not None:
            inputs["object_position"] = position
        try:
            out = run_logged(p, issued, position, **kw)
        except cr.PresentationError as e:
            assert rule == e.rule, (suffix, e.rule, e.reason)
            f.add(
                suffix,
                desc,
                "Verification rules",
                inputs,
                rejection={"step": None, "check": "presentation", "rule": rule, "reason": e.reason},
            )
            return
        assert rule is None, suffix
        f.add(
            suffix,
            desc,
            "Verification rules",
            inputs,
            {"accepted": True, "nullifiers": [hexify(n) for n in out["nullifiers"]]},
        )

    def approved_card(epoch, label):
        return cr.Presentation(
            [card(APPROVED, KID_A0, 3, {0: epoch, 1: 1}, label)], [], CONTEXT_VERSION
        )

    issued_e = cr.epoch_now(NOW, V)
    logged_case(
        "cred-present-author-once-two-epochs-later",
        "An authorship proof verified two epochs after its issued: no clock, the disclosed "
        "epoch is that of issued",
        approved_card(issued_e, "logged-later"),
        NOW,
        extra={
            "verified_at": NOW + 2 * V * cr.PERIOD,
            "accepted_epochs": sorted(cr.logged_epochs(NOW, V)),
        },
    )
    logged_case(
        "cred-invalid-P5-logged-epoch-not-of-issued",
        "A logged proof whose disclosed epoch is not that of issued",
        approved_card(issued_e + 1, "logged-wrong-epoch"),
        NOW,
        rule="P5",
    )
    boundary = (issued_e + 1) * V * cr.PERIOD
    for suffix, desc, epoch, issued, rule in [
        (
            "cred-present-logged-old-epoch-90-min-after-boundary",
            "issued 90 minutes after an epoch boundary B with the old epoch",
            issued_e,
            boundary + 5400,
            None,
        ),
        (
            "cred-invalid-P5-logged-old-epoch-three-hours-after",
            "issued three hours after B with the old epoch",
            issued_e,
            boundary + 10800,
            "P5",
        ),
        (
            "cred-present-logged-edge-old-epoch-B-plus-7199",
            "later verifier: old epoch at issued = B + 7199",
            issued_e,
            boundary + 7199,
            None,
        ),
        (
            "cred-invalid-P5-logged-edge-old-epoch-B-plus-7200",
            "later verifier: old epoch at issued = B + 7200",
            issued_e,
            boundary + 7200,
            "P5",
        ),
        (
            "cred-present-logged-edge-new-epoch-B-minus-3600",
            "later verifier: new epoch at issued = B - 3600",
            issued_e + 1,
            boundary - 3600,
            None,
        ),
        (
            "cred-invalid-P5-logged-edge-new-epoch-B-minus-3601",
            "later verifier: new epoch at issued = B - 3601",
            issued_e + 1,
            boundary - 3601,
            "P5",
        ),
    ]:
        logged_case(
            suffix, desc, approved_card(epoch, suffix), issued, rule=rule, extra={"B": boundary}
        )
    # the log's own check at submission (clock T)
    for suffix, desc, epoch, log_now, issued, accept in [
        (
            "log-old-epoch-T-plus-1800",
            "old epoch at T = B + 1800",
            issued_e,
            boundary + 1800,
            boundary + 1800,
            True,
        ),
        (
            "log-old-epoch-T-plus-3660",
            "old epoch at T = B + 3660",
            issued_e,
            boundary + 3660,
            boundary + 3660,
            False,
        ),
        (
            "log-issued-T-plus-7200",
            "issued = T + 7200",
            issued_e + 1,
            boundary + 9000,
            boundary + 16200,
            False,
        ),
        (
            "log-issued-T-plus-3600",
            "issued = T + 3600",
            issued_e + 1,
            boundary + 9000,
            boundary + 12600,
            True,
        ),
        (
            "log-issued-two-hours-behind",
            "issued two hours behind the log's clock",
            issued_e + 1,
            boundary + 9000,
            boundary + 1800,
            False,
        ),
    ]:
        reason = cr.log_submission_check(epoch, V, log_now, issued)
        assert (reason is None) == accept, suffix
        name = ("cred-present-" if accept else "cred-invalid-P5-") + suffix
        inputs = {
            "card_epoch": epoch,
            "V": V,
            "log_clock_T": log_now,
            "issued": issued,
            "B": boundary,
        }
        if accept:
            f.add(name, "At the log: " + desc, "Validity", inputs, {"accepted": True})
        else:
            f.add(
                name,
                "At the log: " + desc,
                "Validity",
                inputs,
                rejection={"step": None, "check": "log-submission", "rule": "P5", "reason": reason},
            )
    # P3 (logged): kid removed at a log index above or below the object's
    removed = issuers()
    removed[DISTRICT].kids.discard(KID_D0)
    removed[DISTRICT].kids_removed_at[KID_D0] = 500
    old_kid = cr.Presentation(
        [card(DISTRICT, KID_D0, 4, {0: issued_e, 2: 1}, "old-kid-logged")], [], CONTEXT_VERSION
    )
    for suffix, desc, position, rule in [
        (
            "cred-present-logged-kid-removed-after",
            "kid removed from issuerKeys at log index 500; the object is at index 400 (valid)",
            400,
            None,
        ),
        (
            "cred-invalid-P3-logged-kid-removed-before",
            "kid removed from issuerKeys at log index 500; the object is at index 600",
            600,
            "P3",
        ),
    ]:
        logged_case(
            suffix,
            desc,
            old_kid,
            NOW,
            position,
            rule=rule,
            policy=area_leaf,
            issuers=removed,
            extra={"kid_removed_at": 500},
        )
    # P3 (logged): an attribute appended mid-epoch with fromEpoch = the next epoch
    appended = issuers()
    appended[DISTRICT].attributes.append(("block", issued_e + 1))
    for suffix, desc, length, rule in [
        (
            "cred-present-logged-old-len-after-append",
            "block appended with fromEpoch = E + 1; an object logged after it in epoch E "
            "carries the old len 4 (valid)",
            4,
            None,
        ),
        (
            "cred-invalid-P3-logged-new-len-in-old-epoch",
            "the same object with the new len 5 in epoch E",
            5,
            "P3",
        ),
    ]:
        logged_case(
            suffix,
            desc,
            cr.Presentation(
                [card(DISTRICT, KID_D1, length, {0: issued_e, 2: 1}, suffix)], [], CONTEXT_VERSION
            ),
            NOW,
            rule=rule,
            policy=area_leaf,
            issuers=appended,
            extra={"attributes": [list(a) for a in appended[DISTRICT].attributes]},
        )
    # P3: an authority has one verifier lineage (verifier.md rule 31)
    lineage_a, lineage_b = cid(b"district verifier v1"), cid(b"district verifier v1 again")
    by_auth = issuers()
    by_auth[DISTRICT].lineage = lineage_a
    infos = list(by_auth.values())
    assert cr.issuers_by_authority(infos)[DISTRICT].lineage == lineage_a
    twin = issuer_info(DISTRICT, "person", [KID_D1], [("area", 0), ("ward", 0)], {})
    twin.lineage = lineage_b
    try:
        cr.issuers_by_authority(infos + [twin])
        raise AssertionError("two lineages accepted")
    except cr.PresentationError as e:
        assert e.rule == "P3"
        f.add(
            "cred-invalid-P3-two-lineages-one-authority",
            "Two logged verifier lineages under the district authority: no card from it "
            "resolves (P3; verifier.md rule 31)",
            "Verification rules",
            {
                "authority": hexify(DISTRICT),
                "lineages": [hexify(lineage_a), hexify(lineage_b)],
                "logged_lineages_per_authority": 2,
            },
            rejection={"step": None, "check": "presentation", "rule": "P3", "reason": e.reason},
        )
    # Log of record (credentials.md, "in force"; services.md, "What the log runs")
    record, second = cid(b"log of record keyset"), cid(b"second log keyset")
    logs = [record, second]
    for suffix, desc, kw, expect in [
        (
            "cred-invalid-log-of-record-second-log-only",
            "An object present only in the context's second log: a phone treats it as not "
            "logged, whatever that log's proof says",
            {"proof_logs": [second]},
            "phone",
        ),
        (
            "cred-invalid-log-of-record-issuer-lineage-absent",
            "At the log of record: the issuer's verifier lineage is not in this log's history",
            {"this_log": record, "issuer_lineage_in_history": False, "log_now": NOW + 60},
            "refused",
        ),
        (
            "cred-invalid-log-of-record-stale-issued-no-proof",
            "At the second log: a three-hour-old issued with no proof from the log of record",
            {"this_log": second, "log_now": NOW + 10800},
            "refused",
        ),
        (
            "cred-present-second-log-accepts-on-record-proof",
            "At the second log: the same three-hour-old issued accepted because the bundle "
            "proves inclusion in the log of record; the later-verifier rule then applies",
            {"this_log": second, "log_now": NOW + 10800, "proof_logs": [record]},
            "accepted",
        ),
    ]:
        inputs = {
            "logs": [hexify(record), hexify(second)],
            "log_of_record": hexify(record),
            "proof_logs": [hexify(x) for x in kw.get("proof_logs", [])],
            "issued": NOW,
            "card_epoch": issued_e,
            "V": V,
        }
        if expect == "phone":
            ok = cr.object_in_log_of_record(logs, kw["proof_logs"])
            assert not ok
            f.add(
                suffix,
                desc,
                "Verification rules",
                inputs,
                rejection={
                    "step": None,
                    "check": "log-of-record",
                    "rule": "in force",
                    "reason": "object is not in the context's log of record",
                },
            )
            continue
        inputs.update({"this_log": hexify(kw["this_log"]), "log_clock_T": kw["log_now"]})
        inputs["issuer_lineage_in_history"] = kw.get("issuer_lineage_in_history", True)
        reason = cr.log_accepts_logged_object(
            this_log=kw["this_log"],
            logs=logs,
            proof_logs=kw.get("proof_logs", []),
            issuer_lineage_in_history=kw.get("issuer_lineage_in_history", True),
            card_epoch=issued_e,
            v=V,
            log_now=kw["log_now"],
            issued=NOW,
        )
        assert (reason is None) == (expect == "accepted"), suffix
        if reason is None:
            f.add(suffix, desc, "Verification rules", inputs, {"accepted": True})
        else:
            f.add(
                suffix,
                desc,
                "Verification rules",
                inputs,
                rejection={"step": None, "check": "log-submission", "rule": "P5", "reason": reason},
            )
    return f


def issuance_file() -> File:
    f = File(
        SPEC,
        "issuance",
        "Issuance request and response plaintexts, the host's epoch decisions, the nym-share "
        "derivation and the phone's checks. HPKE sealing and BBS blind signatures are pending.",
    )
    manifest = cid(b"district verifier manifest v2")
    keys = [(KID_D0, 0), (KID_D1, 4)]
    e_now = cr.epoch_now(NOW, V)
    kid = cr.key_of_epoch(keys, e_now)
    commit = fixed_bytes("commitment-with-proof", 200)
    req = cr.issuance_request(manifest, kid, [commit], [1])
    host_secret = fixed_bytes("host-secret")
    share = cr.nym_share(host_secret, req, e_now)
    resp_item = {
        0: 1,
        1: kid,
        2: {1: 2},
        3: [{0: e_now, 1: kid, 2: fixed_bytes("blind-signature", 80), 3: share}],
    }
    resp = cbor.encode(resp_item)
    declared = {1: {1, 2, 3}, 2: {1, 2}}
    cr.check_issuance_response(
        resp_item, request_kid=kid, keys=keys, now=NOW, v=V, declared=declared, approved={1}
    )
    f.add(
        "cred-issue-district",
        "A district card with area left unapproved (absent); request and response plaintexts",
        "Issuance",
        {
            "manifest": hexify(manifest),
            "kid": hexify(kid),
            "commits": [hexify(commit)],
            "approved": [1],
            "host_secret": hexify(host_secret),
            "now": NOW,
            "V": V,
        },
        {
            "request": hexify(req),
            "response": hexify(resp),
            "nym_share": hexify(share),
            "phone_checks": "pass",
            "hpke_info": hexify(b"hum/issue/1" + DISTRICT),
            "hpke_response_export_labels": [
                "hum/issue-response/1 key",
                "hum/issue-response/1 nonce",
            ],
            "hpke_response_aad": "the 16-byte session ID",
            "evidence_aad": "the 16-byte session ID ‖ SHA-256(this request plaintext), 48 "
            "bytes; the phone builds this request before sealing any evidence item "
            "(verifier/evidence)",
            "evidence_request_hash": hexify(hashlib.sha256(req).digest()),
            "sealed_request": "pending HPKE",
            "signature": "pending BBS",
        },
    )
    hand_now = (e_now * V + V - 1) * cr.PERIOD + 10  # last period of the epoch
    for name, rows_, now, expect in [
        (
            "cred-issue-handover",
            [],
            hand_now,
            {"issue": [e_now, e_now + 1], "retry": False, "refuse": False, "last_epoch": e_now + 1},
        ),
        (
            "cred-issue-renewal",
            [cr.DedupRow(e_now, kid, fixed_bytes("other-request-hash"))],
            hand_now,
            {"issue": [e_now + 1], "retry": False, "refuse": False, "last_epoch": e_now + 1},
        ),
        (
            "cred-issue-retry",
            [cr.DedupRow(e_now, kid, hashlib.sha256(req).digest())],
            NOW,
            {"issue": [], "retry": True, "refuse": False, "last_epoch": e_now},
        ),
        (
            "cred-issue-no-row",
            [],
            NOW,
            {"issue": [e_now], "retry": False, "refuse": False, "last_epoch": e_now},
        ),
        (
            "cred-issue-stale-row",
            [cr.DedupRow(e_now - 1, kid, fixed_bytes("h"))],
            NOW,
            {"issue": [e_now], "retry": False, "refuse": False, "last_epoch": e_now},
        ),
        (
            "cred-issue-removed-kid-counts-as-no-row",
            [cr.DedupRow(e_now, b"gone0000", fixed_bytes("h"))],
            NOW,
            {"issue": [e_now], "retry": False, "refuse": False, "last_epoch": e_now},
        ),
        (
            "cred-issue-largest-last-epoch-governs",
            [
                cr.DedupRow(e_now - 1, kid, fixed_bytes("h")),
                cr.DedupRow(e_now, kid, fixed_bytes("h2")),
            ],
            NOW,
            {"issue": [], "retry": False, "refuse": True, "last_epoch": e_now},
        ),
    ]:
        got = cr.decide_issuance(rows_, now, V, hashlib.sha256(req).digest(), {KID_D0, KID_D1})
        assert got == expect, (name, got)
        f.add(
            name,
            name,
            "Issuance",
            {
                "rows": [
                    {
                        "lastEpoch": r.last_epoch,
                        "kid": hexify(r.kid),
                        "request_hash": hexify(r.request_hash),
                    }
                    for r in rows_
                ],
                "now": now,
                "V": V,
                "request_hash": hashlib.sha256(req).hexdigest(),
            },
            got,
        )
    for name, rows_, now in [
        (
            "cred-issue-refuse-same-epoch-outside-handover",
            [cr.DedupRow(e_now, kid, fixed_bytes("h"))],
            NOW,
        ),
        (
            "cred-issue-refuse-next-epoch-already-issued",
            [cr.DedupRow(e_now + 1, kid, fixed_bytes("h"))],
            hand_now,
        ),
        (
            "cred-issue-refuse-different-request-spent-row",
            [cr.DedupRow(e_now, kid, fixed_bytes("other"))],
            NOW,
        ),
    ]:
        got = cr.decide_issuance(rows_, now, V, hashlib.sha256(req).digest(), {KID_D0, KID_D1})
        assert got["refuse"], name
        f.add(
            name,
            name,
            "Issuance",
            {
                "rows": [
                    {
                        "lastEpoch": r.last_epoch,
                        "kid": hexify(r.kid),
                        "request_hash": hexify(r.request_hash),
                    }
                    for r in rows_
                ],
                "now": now,
                "V": V,
            },
            rejection={
                "step": None,
                "check": "issuance",
                "rule": "dedup",
                "reason": "refused with the dedup code, masked per verifier-runtime.md",
            },
        )

    def bad_response(name, desc, item, **kw):
        args = dict(request_kid=kid, keys=keys, now=NOW, v=V, declared=declared, approved={1})
        args.update(kw)
        try:
            cr.check_issuance_response(item, **args)
            raise AssertionError(name)
        except cr.PresentationError as e:
            f.add(
                name,
                desc,
                "Issuance",
                {"response": hexify(cbor.encode(item)), "now": args["now"]},
                rejection={
                    "step": None,
                    "check": "issuance-response",
                    "rule": "phone",
                    "reason": e.reason,
                },
            )

    bad_response(
        "cred-issue-reject-kid-not-epoch-key",
        "kid is not the epoch's key",
        {**resp_item, 3: [{**resp_item[3][0], 1: KID_D0}]},
    )
    bad_response(
        "cred-issue-reject-next-epoch-outside-handover",
        "epoch E_now + 1 outside handover",
        {**resp_item, 3: [{**resp_item[3][0], 0: e_now + 1}]},
    )
    bad_response(
        "cred-issue-reject-previous-epoch",
        "epoch E_now − 1",
        {**resp_item, 3: [{**resp_item[3][0], 0: e_now - 1}]},
    )
    bad_response(
        "cred-issue-reject-value-undeclared",
        "a value outside the declared set",
        {**resp_item, 2: {1: 9}},
    )
    bad_response(
        "cred-issue-reject-unapproved-present",
        "an unapproved attribute present",
        {**resp_item, 2: {1: 2, 2: 1}},
    )
    bad_response(
        "cred-issue-reject-signature",
        "a signature that fails (flag)",
        resp_item,
        signature_valid=False,
    )
    return f


def backup_file() -> File:
    f = File(
        SPEC,
        "backup",
        "Backup and chat-only export plaintexts. The sealed-blob wrap, Argon2id and the HPKE wrap "
        "under hum/backup/1 are pending; no dependency was added.",
    )
    cards = [
        {
            "issuer": DISTRICT,
            "kid": KID_D1,
            "len": 4,
            "messages": [fixed_bytes("m1", 8), fixed_bytes("m2", 8)],
            "signature": fixed_bytes("sig", 80),
            "nym_secret": fixed_bytes("nym"),
        }
    ]
    contexts = [
        {"lineage": CONTEXT_LINEAGE},
        {"lineage": cid(b"left context"), "left": NOW - 86_400},
    ]
    plain = cr.write_backup(fixed_bytes("chat-key"), fixed_bytes("edit-root"), cards, contexts, NOW)
    f.add(
        "cred-backup-roundtrip",
        "Backup plaintext with one left context (wrap pending)",
        "The sealed backup",
        {
            "chat_key": hexify(fixed_bytes("chat-key")),
            "edit_root": hexify(fixed_bytes("edit-root")),
            "written": NOW,
        },
        {
            "plaintext": hexify(plain),
            "view": jsonable(cbor.decode(plain)),
            "chat_only_export": hexify(
                cr.write_chat_export(fixed_bytes("chat-key"), fixed_bytes("edit-root"))
            ),
        },
    )
    for name, extra, desc in [
        ("cred-invalid-backup-unknown-key", {6: b"x"}, "a plaintext with an unknown key"),
        (
            "cred-invalid-backup-hand-key",
            {"hand": b"x"},
            "a plaintext carrying a hand key; the writer refuses",
        ),
    ]:
        try:
            cr.write_backup(
                fixed_bytes("chat-key"), fixed_bytes("edit-root"), cards, contexts, NOW, extra=extra
            )
            raise AssertionError
        except ValueError as e:
            f.add(
                name,
                desc,
                "The sealed backup",
                {"extra_keys": [str(k) for k in extra]},
                rejection={
                    "step": None,
                    "check": "backup-writer",
                    "rule": "backup",
                    "reason": str(e),
                },
            )
    f.add(
        "cred-backup-pending",
        "Wrong phrase and tampered ciphertext cases",
        "The sealed backup",
        {},
        {
            "pending": "Argon2id (RFC 9106) and HPKE are not in the reference; no dependency was added"
        },
    )
    return f


def generate() -> list[File]:
    return [epochs_file(), layout_file(), presentations_file(), issuance_file(), backup_file()]
