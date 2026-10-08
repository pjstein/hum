"""The deterministic test world behind the manifest and log vectors.

One log with its own keyset, two witnesses with keysets, one authority that
rotates once, a context and a deck with three versions, plus entries a
misbehaving log appended that a phone must reject. Every key comes from a
fixed label, so building the world twice gives identical bytes.

Log positions:

0. keyset of the log itself (key `log`, 1-of-1 sign, separate rotate key `log-rotate`)
1. keyset A v1 (keys a1 a2 a3, sign 2-of-3, rotate 2-of-3, commits to b1 b2 b3)
2. context v1 (signed a1 a2)
3. deck v1 (signed a1 a3, refs context)
4. deck v2 (signed a2 a3)
5. deck X v1 (signed a1 a3): rejected later, because a3 is revoked from here
6. keyset A v2 (rotation signed a1 a2; keys b1 b2 b3; revokes a3 from position 5)
7. deck v3 (signed b1 b2)
8. keyset B v1 (c1 sign 1-of-1, c2 rotate 1-of-1)

Entries a misbehaving log appended (an honest log runs steps 1-6 and 8 first):

9. deck v2' (fork: same lineage and version as position 4, logged later)
10. deck "orphan" v2 (prev is a CID nobody has)
11. deck "skip" v3 (prev is deck v1, so the version is not one higher)
12. deck "hijack" v2 (prev is deck v1, authority is B, signed by c1)
13. keyset D v1 (commits to e1 e2) and 14. keyset D v2 (keys f1 f2, breaking the commitment)
15. keyset E v1 (sign threshold 3 with two sign keys)
16. deck "dangling" v1 (refs a CID nobody has)
17. deck "bad-ref" v1 (refs deck X, which fails step 6)
18. context chain: 18 contexts, chain-0 up to chain-17, each naming the previous as
    its parent (positions 18-35), for the reference-depth rule

The two witnesses' keysets are built (to derive their authority CIDs and so their
names) but not logged: a phone holds only their keys.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from . import manifest as m
from .cid import cid as compute_cid
from .keys import SigningKey, key_from_label

ISSUED = 1_791_259_200  # 2026-10-06T00:00:00Z, informational only
EXPIRES = 1_792_800_000
NOW = ISSUED + 3600
CHAIN_LEN = 18
REVOKE_A3_FROM = 5

KEY_LABELS = [
    "log", "log-rotate", "w1", "w1-rotate", "w2", "w2-rotate",
    "a1", "a2", "a3", "b1", "b2", "b3", "c1", "c2", "d1", "e1", "e2", "f1", "f2",
]  # fmt: skip


@dataclass
class Fixture:
    world: m.World
    keys: dict[str, SigningKey]
    named: dict[str, m.Bundle] = field(default_factory=dict)
    witness_keysets: dict[bytes, bytes] = field(default_factory=dict)  # authority -> envelope

    def __getattr__(self, name: str) -> m.Bundle:
        try:
            return self.named[name]
        except KeyError as e:
            raise AttributeError(name) from e

    @property
    def authority_a(self) -> bytes:
        return self.named["keyset_a1"].cid


def kk(name: str, key: SigningKey, *roles: str) -> m.KeysetKey:
    return m.KeysetKey(name.encode(), key.public, tuple(roles))


def service_keyset(sign: str, rotate: str, keys: dict[str, SigningKey]) -> dict:
    """A one-key service keyset: ``sign`` signs, a separate ``rotate`` key rotates."""
    return m.envelope(
        "keyset",
        m.build_keyset_body(
            [kk(sign, keys[sign], "sign"), kk(rotate, keys[rotate], "rotate")], 1, 1
        ),
        authority=None,
        issued=ISSUED,
    )


def fixed_bytes(label: str, n: int = 32) -> bytes:
    """Deterministic opaque bytes (group ids, keys that are never used to sign)."""
    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(f"hum-vectors/bytes/{label}/{counter}".encode()).digest()
        counter += 1
    return out[:n]


def context_body(fx: Fixture, authority: bytes) -> dict:
    """A valid, minimal context: open entry, vote and nullifier on a direct issuer."""
    from .bodies import context as c

    w = fx.world
    helper = compute_cid(b"helper aggregator keyset placeholder")
    store = compute_cid(b"blob store keyset placeholder")
    delivery = compute_cid(b"delivery keyset placeholder")
    issuer = compute_cid(b"approved-list verifier keyset placeholder")
    return c.body(
        name="Test context",
        sealed=False,
        entry=[c.NODE_TRUE],
        vote=c.attr([c.SRC_ISSUER, 0], "unique", [c.PRED_PRESENT]),
        nullifier=[[c.SRC_ISSUER, 0], "unique"],
        issuers=[issuer],
        perms={c.P_CARDS: 2, c.P_RESULTS: 0, c.P_MEMBER_LIST: 1},
        floors_=c.floors(),
        logs=[{c.L_LOG: w.log_authority, c.L_WITNESSES: w.witness_keys()}],
        aggregators=[authority, helper],
        stores=[store],
        storage=c.storage_policy(),
        chat=c.chat_ids(
            fixed_bytes("all-members"),
            fixed_bytes("organizers"),
            delivery,
            fixed_bytes("greeting"),
            (fixed_bytes("issuer-key-0", 49), fixed_bytes("issuer-key-1", 49)),
        ),
        mix_global=False,
    )


def build(held_size: int = 0) -> Fixture:
    keys = {n: key_from_label(n) for n in KEY_LABELS}
    log_ks_env = service_keyset("log", "log-rotate", keys)
    log_authority = compute_cid(m.encode_envelope(log_ks_env))
    witness_keysets = {}
    witnesses = {}
    for w in ("w1", "w2"):
        env = m.encode_envelope(service_keyset(w, f"{w}-rotate", keys))
        witness_keysets[compute_cid(env)] = env
        witnesses[compute_cid(env)] = keys[w]
    world = m.World(log_authority=log_authority, log_key=keys["log"], witnesses=witnesses)
    fx = Fixture(world, keys, witness_keysets=witness_keysets)
    named = fx.named

    def signers(*names: str) -> list[tuple[bytes, SigningKey]]:
        return [(n.encode(), keys[n]) for n in names]

    named["keyset_log"] = world.append(log_ks_env, signers("log-rotate"))
    assert named["keyset_log"].cid == log_authority

    a_keys = [kk(n, keys[n], "sign", "rotate") for n in ("a1", "a2", "a3")]
    b_keys = [kk(n, keys[n], "sign", "rotate") for n in ("b1", "b2", "b3")]

    ks1 = world.append(
        m.envelope(
            "keyset",
            m.build_keyset_body(a_keys, 2, 2, next_keys=b_keys),
            authority=None,
            issued=ISSUED,
        ),
        signers("a1", "a2"),
    )
    named["keyset_a1"] = ks1
    a = ks1.cid

    ctx = world.append(
        m.envelope("context", context_body(fx, a), authority=a, issued=ISSUED),
        signers("a1", "a2"),
    )
    named["context_v1"] = ctx

    def deck_body(closes_offset: int, title: str = "Fall check-in") -> dict:
        """A valid vote deck: one statement-blob card, a tallies-only plan (R = 0)."""
        from .bodies import deck as dk

        return dk.body(
            title=title,
            opens=ISSUED + 100,
            closes=ISSUED + 10 * 86_400 + closes_offset,
            topics=["General"],
            cards=[dk.card(dk.CARD_BLOB, 0)],
            plan_=dk.plan_tallies_only(18),
        )

    statement = world.put_blob(b"Statement text behind card 0.")

    def deck(body, *, version=1, lineage=None, prev=None, issued=ISSUED, refs=None, authority=a):
        return m.envelope(
            "deck",
            body,
            authority=authority,
            version=version,
            lineage=lineage,
            prev=prev,
            issued=issued,
            expires=EXPIRES,
            refs={"context": ctx.cid, "card/0": statement} if refs is None else refs,
        )

    deck1 = world.append(deck(deck_body(0)), signers("a1", "a3"))
    named["deck_v1"] = deck1
    deck2 = world.append(
        deck(
            deck_body(86_400),
            version=2,
            lineage=deck1.cid,
            prev=deck1.cid,
            issued=ISSUED + 60,
        ),
        signers("a2", "a3"),
    )
    named["deck_v2"] = deck2
    named["deck_x"] = world.append(
        deck(deck_body(0, "Deck X"), issued=ISSUED + 90), signers("a1", "a3")
    )
    assert named["deck_x"].proof.position == REVOKE_A3_FROM
    ks2 = world.append(
        m.envelope(
            "keyset",
            m.build_keyset_body(b_keys, 2, 2, revocations=[(b"a3", REVOKE_A3_FROM)]),
            authority=a,
            version=2,
            lineage=a,
            prev=a,
            issued=ISSUED + 120,
        ),
        signers("a1", "a2"),
    )
    named["keyset_a2"] = ks2
    deck3 = world.append(
        deck(
            deck_body(2 * 86_400),
            version=3,
            lineage=deck1.cid,
            prev=deck2.cid,
            issued=ISSUED + 180,
        ),
        signers("b1", "b2"),
    )
    named["deck_v3"] = deck3
    ksb = world.append(service_keyset("c1", "c2", keys), signers("c2"))
    named["keyset_b1"] = ksb

    # ---- entries a misbehaving log appended
    named["deck_v2_fork"] = world.append(
        deck(
            deck_body(3 * 86_400),
            version=2,
            lineage=deck1.cid,
            prev=deck1.cid,
            issued=ISSUED + 61,
        ),
        signers("b1", "b2"),
    )
    nobody = compute_cid(b"nobody has these bytes")
    named["deck_orphan"] = world.append(
        deck(deck_body(0, "Orphan"), version=2, lineage=nobody, prev=nobody, issued=ISSUED + 200),
        signers("b1", "b2"),
    )
    named["deck_skip"] = world.append(
        deck(
            deck_body(4 * 86_400),
            version=3,
            lineage=deck1.cid,
            prev=deck1.cid,
            issued=ISSUED + 201,
        ),
        signers("b1", "b2"),
    )
    named["deck_hijack"] = world.append(
        deck(
            deck_body(86_400, "Hijack"),
            version=2,
            lineage=deck1.cid,
            prev=deck1.cid,
            issued=ISSUED + 202,
            authority=ksb.cid,
        ),
        signers("c1"),
    )
    d_keys = [kk("d1", keys["d1"], "sign", "rotate")]
    e_keys = [kk("e1", keys["e1"], "sign", "rotate"), kk("e2", keys["e2"], "sign", "rotate")]
    f_keys = [kk("f1", keys["f1"], "sign", "rotate"), kk("f2", keys["f2"], "sign", "rotate")]
    ksd1 = world.append(
        m.envelope(
            "keyset",
            m.build_keyset_body(d_keys, 1, 1, next_keys=e_keys),
            authority=None,
            issued=ISSUED,
        ),
        signers("d1"),
    )
    named["keyset_d1"] = ksd1
    named["keyset_d2_broken_commitment"] = world.append(
        m.envelope(
            "keyset",
            m.build_keyset_body(f_keys, 1, 1),
            authority=ksd1.cid,
            version=2,
            lineage=ksd1.cid,
            prev=ksd1.cid,
            issued=ISSUED + 10,
        ),
        signers("d1"),
    )
    named["keyset_e_threshold"] = world.append(
        m.envelope("keyset", m.build_keyset_body(e_keys, 3, 1), authority=None, issued=ISSUED),
        signers("e1", "e2"),
    )
    named["deck_dangling"] = world.append(
        deck(
            deck_body(0, "Dangling"),
            refs={"context": ctx.cid, "card/0": statement, "statements": nobody},
            issued=ISSUED + 203,
        ),
        signers("b1", "b2"),
    )
    named["deck_bad_ref"] = world.append(
        deck(
            deck_body(0, "Bad ref"),
            refs={"context": ctx.cid, "card/0": statement, "other": named["deck_x"].cid},
            issued=ISSUED + 204,
        ),
        signers("b1", "b2"),
    )
    prev_cid = None
    for i in range(CHAIN_LEN):
        # Reference-depth chain: contexts linked through ``parent`` refs (each its own lineage,
        # equal floors, so context.md C13 holds at every hop).
        refs = {"parent": prev_cid} if prev_cid else {}
        cb = context_body(fx, a)
        cb[0] = f"chain {i}"
        b = world.append(
            m.envelope("context", cb, authority=a, issued=ISSUED + 300 + i, refs=refs),
            signers("b1", "b2"),
        )
        named[f"chain_{i}"] = b
        prev_cid = b.cid

    world.finalize(held_size)
    return fx
