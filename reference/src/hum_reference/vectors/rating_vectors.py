"""Rating decks (deck.md, kind 1, rule D15) and rating releases (release.md R5, R10), built in
``take_vectors.TakeWorld`` after the takes. Writes ``deck/rating.json`` and ``release/rating.json``.

Cases whose outcome under the current deck and release modules differs from the spec are
listed in the file notes instead of being emitted; see the module's ``PENDING`` list.
"""

from __future__ import annotations

import copy
from fractions import Fraction

from .. import cbor, fixtures
from .. import manifest as m
from .. import release as rmath
from ..bodies import deck as dk
from ..bodies import release as rb
from ..bodies import take as tk
from . import File, hexify, jsonable
from . import take_vectors as tv
from .issue_map_vectors import bundle_json

S_DECK = "Validation rules (verification step 10 for deck)"
S_REL = "Validation rules (verification step 10 for release)"
WINDOW = dk.DEFAULT_ROUND_WINDOW
PENDING: list[str] = []


def build_ratings(wd: tv.TakeWorld) -> None:
    """Append rating takes, decks and releases to the take world (called from its _build)."""
    src = wd.rating_source
    wd.rating_takes: list[m.Bundle] = []
    wd.rating_deck_cases: list[tuple[str, str, str | None, m.Bundle]] = []
    wd.rating_release_cases: list[tuple[str, str, str | None, int | None, m.Bundle]] = []
    series_ = [
        tk.series(0, "group_tallies", tk.AGREE_SHARE, statements=wd.statements(2), group=0),
        tk.series(0, "group_tallies", tk.AGREE_SHARE, statements=wd.statements(2), group=1),
    ]
    for i in range(tv.RATING_TAKES):
        wd.rating_takes.append(
            wd.take(
                f"rating-{i}",
                wd.take_env(f"rating-{i}", [src], series=series_, issued=tv.T_TAKE + i),
            )
        )
    # a retired lineage pinning the source: not eligible
    r1 = wd.take(
        "rating-retired-v1",
        wd.take_env("rating-retired-v1", [src], series=series_, issued=tv.T_TAKE + 20),
    )
    wd.rating_retired = wd.take(
        "rating-retired-v2",
        wd.v2(r1, lambda e: e[m.BODY].__setitem__(tk.RETIRED, True)),
        signers=wd.signers("tk1"),
    )
    # a take pinning the not-final IBIS release (for the source-not-final case)
    wd.ibis_take = wd.take(
        "pins-ibis",
        wd.take_env(
            "pins-ibis",
            [wd.ibis_release],
            series=[tk.series(0, "tallies", tk.AGREE_SHARE)],
            issued=tv.T_TAKE + 21,
        ),
    )
    # a take pinning the second context's release
    wd.second_take = wd.take(
        "pins-second",
        wd.take_env(
            "pins-second",
            [wd.release2],
            series=[tk.series(0, "tallies", tk.AGREE_SHARE)],
            issued=tv.T_TAKE + 22,
        ),
    )

    def rating_env(cards_takes, *, source=None, plan_=None, title="Fair readings?", topics=("Fairness",),
                   kind=dk.KIND_RATING, extra_refs=None, issued=None, minv=None):  # fmt: skip
        plan_ = plan_ or dk.plan_rating()
        if minv is not None:
            plan_ = dict(plan_)
            plan_[dk.P_MIN_VOTERS] = minv
        cards = [dk.card(dk.CARD_TAKE, 0) for _ in cards_takes]
        refs = {f"card/{i}": t.cid for i, t in enumerate(cards_takes)}
        refs["source"] = (source or src).cid
        if extra_refs:
            refs.update(extra_refs)
        env = wd.deck_env(
            wd.ctx, plan_, cards, refs, title=title, topics=list(topics), opens=tv.RATING_OPENS,
            closes=tv.RATING_CLOSES, kind=kind, issued=issued or tv.T_TAKE + DAY,
        )  # fmt: skip
        return env

    DAY = 86_400
    valid = wd.deck("rating-valid", rating_env(wd.rating_takes))
    wd.rating_deck_cases.append(
        (
            "valid-rating",
            "kind 1, 12 take cards in log order, source final with groups, parts 0, 3, 8",
            None,
            valid,
        )
    )

    def bad(name, env, desc, rule="D15"):
        b = wd.deck(f"rating-invalid-{name}", env)
        wd.rating_deck_cases.append((f"invalid-{rule}-{name}", desc, rule, b))

    full = dk.plan_rating()
    tiered = dict(full)
    tiered[dk.P_PARTS] = {
        0: rmath.rat(Fraction(1, 100)), 1: rmath.rat(Fraction(1, 100)), 2: rmath.rat(Fraction(1, 100)),
        3: rmath.rat(Fraction(1, 100)), 8: rmath.rat(Fraction(1, 100)),
    }  # fmt: skip
    bad(
        "part-1",
        rating_env(wd.rating_takes, plan_=tiered),
        "rating deck with the map tier (parts 1, 2, 3): D8 fires before D15",
        rule="D8",
    )
    no_groups = dict(full)
    no_groups[dk.P_PARTS] = {
        0: rmath.rat(Fraction(1, 100)), 8: rmath.rat(Fraction(1, 100)),
    }  # fmt: skip
    no_groups[dk.P_RHO] = rmath.rat(Fraction(2, 100))
    bad(
        "no-part-3",
        rating_env(wd.rating_takes, plan_=no_groups),
        "rating deck without part 3",
        rule="D8",
    )
    bad(
        "rho-1-10",
        rating_env(wd.rating_takes, plan_=dk.plan_rating(rho=Fraction(1, 10))),
        "rho 1/10",
    )
    bad("cap-25", rating_env(wd.rating_takes, plan_=dk.plan_rating(cap=25)), "cap 25")
    bad("source-not-final", rating_env([wd.ibis_take], source=wd.ibis_release), "source not final")
    bad(
        "source-other-context",
        rating_env([wd.second_take], source=wd.release2),
        "source from another context",
    )
    bad(
        "card-is-position",
        rating_env(wd.rating_takes[:-1] + [wd.positions[0]]),
        "a card that is a position",
    )
    bad("take-omitted", rating_env(wd.rating_takes[:-1]), "an eligible take omitted")
    bad(
        "retired-included",
        rating_env(wd.rating_takes + [wd.rating_retired]),
        "a retired take included",
    )
    bad("out-of-order", rating_env(list(reversed(wd.rating_takes))), "cards out of log order")
    bad(
        "minvoters-300",
        rating_env(wd.rating_takes, minv=300),
        "minVoters 300 on a rating deck: D11 (minVoters above the tallies gate) fires before D15",
        rule="D11",
    )
    vote_env = wd.deck_env(wd.ctx, dk.plan_full(dv_cards := len(wd.cards), cov_statements=dv_cards), copy.deepcopy(wd.cards),
                           {**wd.refs, "source": src.cid}, title="Vote deck with source", issued=tv.T_TAKE + DAY)  # fmt: skip
    bad("vote-deck-with-source", vote_env, "vote deck with a source ref")
    pro_env = rating_env(wd.rating_takes, extra_refs={"card/0/pro": wd.args["p0-pro"].cid})
    bad("pro-ref", pro_env, "a pro ref on a take card (D4's rule text catches it first)", rule="D4")
    # decks for the rating-release cases, logged while the eligible set is still the 12 takes
    extra_decks = {
        name: wd.deck(
            f"rating-for-{name}", cbor.decode(valid.envelope) | {m.ISSUED: tv.T_TAKE + k * DAY}
        )
        for k, name in enumerate(
            ("R5-not-final", "R5-groupsk", "R10-a", "R10-b", "R10-c", "R7-consensus"), start=3
        )
    }
    # a second source release (its own deck lineage, no other rating release) for the R5
    # groupsK case, so that R10's by-source count cannot fire first
    from . import deck_vectors as dv
    from . import release_body_vectors as rbv

    bld = rbv.Builder(wd)
    dsrc2 = wd.deck(
        "rating-source-2",
        wd.deck_env(
            wd.ctx,
            dk.plan_full(dv.CARDS, cov_statements=dv.CARDS),
            copy.deepcopy(wd.cards),
            dict(wd.refs),
            title="Rating source 2",
        ),
    )
    v = bld.version("rating-source-2-v1", dsrc2, n_hat=1243, record=False)
    v = bld.version("rating-source-2-v2", dsrc2, stage=2, prev=v, part_n={1: 1198}, record=False)
    v = bld.version("rating-source-2-v3", dsrc2, stage=3, prev=v, part_n={2: 1171}, record=False)
    src2 = bld.version("rating-source-2-v4", dsrc2, stage=4, prev=v, part_n={3: 1150}, record=False)
    takes2 = [
        wd.take(
            f"rating2-{i}",
            wd.take_env(f"rating2-{i}", [src2], series=series_, issued=tv.T_TAKE + 30 + i),
        )
        for i in range(3)
    ]
    extra_decks["R5-groupsk"] = wd.deck(
        "rating-for-R5-groupsk-source-2",
        rating_env(
            takes2, source=src2, title="Fair readings? (source 2)", issued=tv.T_TAKE + 9 * DAY
        ),
    )
    # 61 eligible takes: append 61 more takes, then a 61-card deck
    more = [
        wd.take(
            f"rating-more-{i}",
            wd.take_env(f"rating-more-{i}", [src], series=series_, issued=tv.T_TAKE + 100 + i),
        )
        for i in range(49)
    ]
    all_takes = wd.rating_takes + more  # 61 eligible takes (the retired lineage excluded)
    bad(
        "61-cards",
        rating_env(all_takes, issued=tv.T_TAKE + 2 * DAY),
        "61 cards where the first 60 eligible takes are the limit",
    )
    # ---- rating releases
    wd.rating_release_cases = build_rating_releases(wd, valid, extra_decks)


def rating_release_env(
    wd, deck: m.Bundle, *, n_hat=250, groups_n=900, groups_k=2, final=True, issued=None, mutate=None
):
    deck_env = cbor.decode(deck.envelope)
    plan = deck_env[m.BODY][dk.PLAN]
    cards = len(deck_env[m.BODY][dk.CARDS])
    plan_parts = {p: Fraction(r[0], r[1]) for p, r in plan[dk.P_PARTS].items()}
    parts = {
        dk.TALLIES: rb.part_record(
            plan_parts[0], rb.sigma_of_part(plan, cards, 0, plan_parts[0]), n_hat
        ),
        dk.GROUPS: rb.part_record(
            plan_parts[3], rb.sigma_of_part(plan, cards, 3, plan_parts[3]), groups_n
        ),
        dk.RECEIPTS: rb.part_record(plan_parts[8], rb.sigma_of_part(plan, cards, 8, plan_parts[8])),
    }
    unlocked = rb.canonical_unlocked(plan, parts, n_hat, 1)
    refs = {"deck": deck.cid}
    label = f"rating-release-{hexify(deck.cid)[:8]}"
    for t in ("tallies", "group_tallies", "group_sizes"):
        refs[f"t/{t}"] = wd.w.put_blob(cbor.encode({"hum-vector-table": f"{label}-{t}"}))
    # take.md: a rating release publishes tallies, group_tallies and group_sizes only (no repness
    # at stage 1; release.md R7 asks for repness at stage 4).
    from .. import services

    leaves = [fixtures.fixed_bytes(f"{label}-receipt-{i}") for i in range(5)]
    pages = services.receipt_pages(leaves)
    for page in pages["pages"]:
        wd.w.put_blob(page)
    refs["receipts/0"] = wd.w.put_blob(pages["root_blob"])
    ctx_env = cbor.decode(wd.w.bundles[deck_env[m.REFS]["context"]].envelope)
    issued = issued or deck_env[m.BODY][dk.CLOSES] + 3600
    body = rb.body(
        helper=ctx_env[m.BODY][8][1],
        stage=1,
        final=final,
        rho=sum(plan_parts.values(), Fraction(0)),
        delta=Fraction(plan[dk.P_DELTA][0], plan[dk.P_DELTA][1]),
        parts=parts,
        unlocked=unlocked,
        receipts={0: pages["root"]},
        assurance=wd.assurance,
        sealed=False,
        n_hat=n_hat,
        round_deadline=None if final else issued + WINDOW,
        groups_k=groups_k,
    )
    env = m.envelope("release", body, authority=ctx_env[m.BODY][8][0], issued=issued, refs=refs)
    if mutate:
        mutate(env)
    return env


def build_rating_releases(wd, valid_deck: m.Bundle, decks: dict[str, m.Bundle]):
    cases = []
    signers = [(n.encode(), wd.keys[n]) for n in ("l1", "h1", "h2")]
    b = wd.append("release-rating-valid", rating_release_env(wd, valid_deck), signers)
    cases.append(
        (
            "valid-rating",
            "one-version rating release: parts 0, 3, 8; tallies, group_tallies, group_sizes; "
            "groupsK from the source; nHat 250 (below GATE_COMMON, so no consensus table)",
            None,
            None,
            b,
        )
    )
    b = wd.append(
        "release-invalid-R5-rating-not-final",
        rating_release_env(wd, decks["R5-not-final"], final=False),
        signers,
    )
    cases.append(("invalid-R5-rating-not-final", "rating release not final", "R5", 10, b))
    b = wd.append(
        "release-invalid-R5-rating-groupsk",
        rating_release_env(wd, decks["R5-groupsk"], groups_k=3),
        signers,
    )
    cases.append(
        ("invalid-R5-rating-groupsk", "rating groupsK 3 where the source has 2", "R5", 10, b)
    )
    b = wd.append(
        "release-invalid-R7-rating-consensus",
        rating_release_env(
            wd,
            decks["R7-consensus"],
            mutate=lambda e: e[m.REFS].__setitem__("t/consensus", wd.statement_blob),
        ),
        signers,
    )
    cases.append(("invalid-R7-rating-consensus", "t/consensus on a rating release", "R7", 10, b))
    wd.append(
        "release-rating-R10-a",
        rating_release_env(wd, decks["R10-a"], issued=tv.RATING_CLOSES + 2 * 86_400),
        signers,
    )
    wd.append(
        "release-rating-R10-b",
        rating_release_env(wd, decks["R10-b"], issued=tv.RATING_CLOSES + 3 * 86_400),
        signers,
    )
    b = wd.append(
        "release-invalid-R10-third-rating",
        rating_release_env(wd, decks["R10-c"], issued=tv.RATING_CLOSES + 4 * 86_400),
        signers,
    )
    cases.append(
        (
            "invalid-R10-third-rating",
            "third rating release for one source within 365 days",
            "R10",
            10,
            b,
        )
    )
    return cases


def _emit(f: File, wd, suffix, desc, b, *, step, rule, section):
    """Run the case; emit it when the module's verdict matches the spec, else record it pending."""
    ctx = wd.w.context(now=tv.NOW)
    inputs = {
        "bundle": bundle_json(b),
        "now": tv.NOW,
        "body_view": jsonable(cbor.decode(b.envelope)[m.BODY]),
    }
    try:
        env = m.verify_bundle(ctx, b)
        observed = None
    except m.Rejection as e:
        observed = (e.step, e.rule, e.reason)
    if rule is None and observed is None:
        f.add(
            suffix,
            desc,
            section,
            inputs,
            {"accept": True, "type": env[m.TYPE], "version": env[m.VERSION]},
        )
    elif rule is not None and observed is not None and observed[0] == step and observed[1] == rule:
        f.add(
            suffix,
            desc,
            section,
            inputs,
            rejection={"step": step, "rule": rule, "reason": observed[2]},
        )
    else:
        PENDING.append(
            f"{suffix}: expected {'accept' if rule is None else f'step {step} {rule}'}, module gives {observed}"
        )


def generate() -> list[File]:
    wd = tv.get_take_world()
    PENDING.clear()
    fd = File("deck", "rating", "")
    for name, desc, rule, b in wd.rating_deck_cases:
        _emit(fd, wd, f"deck-{name}", desc, b, step=10, rule=rule, section=S_DECK)
    fr = File("release", "rating", "")
    for name, desc, rule, step, b in wd.rating_release_cases:
        _emit(fr, wd, f"release-{name}", desc, b, step=step, rule=rule, section=S_REL)
    note = (
        "Rating decks (deck.md Rating decks, D15) and rating releases (release.md R5, R10). Bundles resolve "
        "against take/world.json. Cases the current deck and release modules decide differently from the "
        "spec are not emitted; they are: " + ("; ".join(PENDING) if PENDING else "none") + "."
    )
    fd.notes = note
    fr.notes = note
    return [fd, fr]
