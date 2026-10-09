"""Vectors for docs/specs/release.md manifests, built on deck_vectors' world.

Tables are opaque placeholder blobs (no Parquet in this run), so R15 is pending; the keybox
is a placeholder public blob because the HPKE seal needs a library (pending). Noise is an
input: nHat, each part's n and the receipt padding draws are fixed numbers.
"""

from __future__ import annotations

import copy
import hashlib
import random
from fractions import Fraction
from typing import Any

from .. import cbor, cose, fixtures, services, storage
from .. import manifest as m
from .. import release as rmath
from ..bodies import context as c
from ..bodies import deck as dk
from ..bodies import release as rb
from ..cid import cid as compute_cid
from . import File, hexify, jsonable
from .manifest_vectors import bundle_json

SPEC = "release"
S_RULES = "Validation rules (verification step 10 for release)"
S_LOG = "Validation rules (R13's clock half, at the ledger)"
DAY = 86_400
WINDOW = dk.DEFAULT_ROUND_WINDOW
NOW = fixtures.NOW
SEALED_KEY = bytes.fromhex("5ea1ed5ea1ed5ea1ed5ea1ed5ea1ed00")


# ---------------------------------------------------------------- building release versions


class Builder:
    """Builds canonical release versions for a deck in a world (deck_vectors.World)."""

    def __init__(self, wd) -> None:
        self.wd = wd
        self.cases: list[tuple[str, str, str | None, m.Bundle]] = []  # (name, desc, rule, b)
        self.extra: dict[str, dict] = {}
        # deck cases this builder creates (D16's clock-free half): (suffix, desc, rule, bundle)
        self.deck_cases: list[tuple[str, str, str, m.Bundle]] = []
        # releases logged only in the context's second log (R10): (named key, env, signers)
        # and their cases (suffix, desc, named key)
        self.second_log_pending: list[tuple[str, dict, list]] = []
        self.second_log_cases: list[tuple[str, str, str]] = []
        # (name, desc, bundle, log_now): cases for the ledger's clock check (R13, log_check)
        self.log_cases: list[tuple[str, str, m.Bundle, int]] = []

    def signers(self, names=("l1", "h1", "h2")):
        return [(n.encode(), self.wd.keys[n]) for n in names]

    def table_blob(self, label: str, sealed: bool) -> bytes:
        data = cbor.encode({"hum-vector-table": label})
        if sealed:
            data = storage.seal(data, SEALED_KEY)
        return self.wd.w.put_blob(data)

    def receipt_root(self, label: str, count: int = 5) -> tuple[bytes, bytes]:
        leaves = [fixtures.fixed_bytes(f"receipt-{label}-{i}") for i in range(count)]
        pages = services.receipt_pages(leaves)
        for page in pages["pages"]:
            self.wd.w.put_blob(page)
        return pages["root"], self.wd.w.put_blob(pages["root_blob"])

    def version(
        self,
        name: str,
        deck: m.Bundle,
        *,
        stage: int = 1,
        prev: m.Bundle | None = None,
        n_hat: int | None = None,
        part_n: dict[int, int] | None = None,
        count_total: int | None = None,
        issued: int | None = None,
        final: bool | None = None,
        mutate=None,
        signers=None,
        desc: str | None = None,
        rule: str | None = None,
        record: bool = True,
        log=None,
    ) -> m.Bundle:
        wd = self.wd
        deck_env = cbor.decode(deck.envelope)
        dbody = deck_env[m.BODY]
        plan = dbody[dk.PLAN]
        cards = len(dbody[dk.CARDS])
        ctx_env = cbor.decode(wd.w.bundles[deck_env[m.REFS]["context"]].envelope)
        cbody = ctx_env[m.BODY]
        sealed = cbody[c.PERMS][c.P_RESULTS] != 0
        plan_parts = {p: Fraction(r[0], r[1]) for p, r in plan[dk.P_PARTS].items()}
        part_n = dict(part_n or {})
        prev_env = cbor.decode(prev.envelope) if prev is not None else None
        prev_body = prev_env[m.BODY] if prev_env else None
        if n_hat is None and prev_body is not None:
            n_hat = prev_body.get(rb.N_HAT)  # frozen across versions (R8)
        # absorb decision (stage 1 only, from the daily count total)
        absorbed = False
        if prev_body is not None:
            absorbed = prev_body[rb.ABSORBED]
        elif plan.get(dk.P_ABSORB, False) and count_total is not None:
            absorbed = count_total < dk.effective_gate(plan, dk.COVARIANCE)
        # parts
        parts: dict[int, dict] = dict(prev_body[rb.PARTS]) if prev_body else {}
        if stage == 1:
            below = n_hat is None or n_hat < plan[dk.P_MIN_VOTERS]
            for p in (dk.TALLIES, dk.COUNT, dk.MOVEMENT, dk.RATINGS, dk.BREAKDOWN, dk.RECEIPTS):
                if p not in plan_parts:
                    continue
                if below and p not in (dk.TALLIES, dk.COUNT):
                    continue  # ADR 0103: below the minimum only parts 0 and 4 are noised
                rho_p = plan_parts[p]
                if p == dk.TALLIES and absorbed:
                    rho_p = sum(
                        (plan_parts.get(q, Fraction(0)) for q in (dk.TALLIES, *dk.TIER)),
                        Fraction(0),
                    )
                n = n_hat if (p == dk.TALLIES and not below) else None
                parts[p] = rb.part_record(rho_p, rb.sigma_of_part(plan, cards, p, rho_p), n)
        else:
            p = rb.STAGE_PART[stage]
            parts[p] = rb.part_record(
                plan_parts[p], rb.sigma_of_part(plan, cards, p, plan_parts[p]), part_n[p]
            )
        n_hat_eff = None if (n_hat is None or n_hat < plan[dk.P_MIN_VOTERS]) else n_hat
        unlocked = rb.canonical_unlocked(plan, parts, n_hat_eff, stage)
        gate1 = dk.effective_gate(plan, dk.COVARIANCE)
        if final is None:
            if stage == 1:
                final = (
                    dk.COVARIANCE not in plan_parts
                    or absorbed
                    or n_hat_eff is None
                    or n_hat_eff < gate1
                    or not unlocked
                )
            elif stage == 4:
                final = True
            else:
                final = part_n[rb.STAGE_PART[stage]] < gate1
        window = plan.get(dk.P_ROUND_WINDOW, WINDOW)
        if issued is None:
            issued = dbody[dk.CLOSES] + 3600 if prev_env is None else prev_env[m.ISSUED] + 2 * DAY
        # refs: tables, receipts, keybox
        refs: dict[str, bytes] = {"deck": deck.cid}
        if prev_env:
            for k, v in prev_env[m.REFS].items():
                if k.startswith("t/") or k.startswith("receipts/"):
                    refs[k] = v
        must, _may = rb.required_tables(plan, unlocked, n_hat_eff, stage, final)
        for t in sorted(must):
            if f"t/{t}" not in refs:
                refs[f"t/{t}"] = self.table_blob(f"{name}-{t}", sealed)
        receipts: dict[int, bytes] = dict(prev_body[rb.RECEIPTS]) if prev_body else {}
        for r in range(stage if unlocked else 0):  # no receipt tree below the minimum
            if r not in receipts:
                root, root_cid = self.receipt_root(f"{name}-round-{r}")
                receipts[r] = root
                refs[f"receipts/{r}"] = root_cid
        if sealed:
            refs["keybox"] = wd.w.put_blob(
                b"\x01"
                + fixtures.fixed_bytes(f"enc-{name}")
                + fixtures.fixed_bytes(f"ct-{name}", 80)
            )
        groups_k = 2 if (stage >= 3 and not (stage == 3 and final)) else None
        body = rb.body(
            helper=cbody[c.AGGREGATORS][1],
            stage=stage,
            final=final,
            rho=sum(
                (Fraction(rec[rb.PR_RHO][0], rec[rb.PR_RHO][1]) for rec in parts.values()),
                Fraction(0),
            ),
            delta=Fraction(plan[dk.P_DELTA][0], plan[dk.P_DELTA][1]),
            parts=parts,
            unlocked=unlocked,
            receipts=receipts,
            assurance=wd.assurance,
            sealed=sealed,
            absorbed=absorbed,
            n_hat=n_hat_eff,
            results_epoch=cbody.get(c.RESULTS_EPOCH) if sealed else None,
            round_deadline=None if final else issued + window,
            groups_k=groups_k,
        )
        env = m.envelope(
            "release",
            body,
            authority=cbody[c.AGGREGATORS][0],
            version=stage,
            lineage=prev_env.get(m.LINEAGE, prev.cid) if prev_env else None,
            prev=prev.cid if prev else None,
            issued=issued,
            refs=refs,
        )
        if mutate is not None:
            mutate(env)
        if log is not None:
            # logged only in the context's second log, after the world is complete: the second
            # log mirrors every entry of the ledger of record and then holds this release
            self.second_log_pending.append((f"release-{name}", env, signers or self.signers()))
            return None
        b = wd.append(f"release-{name}", env, signers or self.signers())
        if record:
            self.cases.append((name, desc or name, rule, b))
        return b

    def unlogged(self, name: str, base: m.Bundle, *, signers, desc: str, rule: str) -> None:
        """A re-signed copy with a borrowed proof: for step-6 (R9) failures only."""
        env = cbor.decode(base.envelope)
        data = cbor.encode(env)
        cid = compute_cid(data)
        sigs = [cose.sign_cid(k, kid, cid) for kid, k in signers]
        b = m.Bundle(data, cose.encode_cose_sign(sigs), cid, copy.deepcopy(base.proof))
        self.cases.append((name, desc, rule, b))


# ---------------------------------------------------------------- the release scenarios


def build_releases(wd) -> Builder:
    """Append every release (valid first, then the invalid ones) to the world."""
    bld = Builder(wd)
    cards, refs = wd.cards, wd.refs

    def deck(name, ctx=None, plan_=None, **kw):
        # Positions live in the main context; decks elsewhere pin statement blobs instead.
        if ctx is None or ctx is wd.ctx:
            cs, rs = copy.deepcopy(cards), dict(refs)
        else:
            cs, rs = wd.blob_cards(CARDS_)
        return wd.deck(
            f"for-release-{name}",
            wd.deck_env(
                ctx or wd.ctx,
                plan_ or dk.plan_full(CARDS_, cov_statements=CARDS_),
                cs,
                rs,
                title=f"deck for {name}",
                **kw,
            ),
        )

    CARDS_ = len(cards)
    tallies_plan = dk.plan_tallies_only(CARDS_)
    # ---- valid
    d = deck("stage1-final-tallies-only", plan_=tallies_plan)
    bld.version(
        "valid-stage1-final-tallies-only",
        d,
        n_hat=350,
        desc="tallies-only plan; version 1 final with tallies, count, consensus",
    )
    d = deck("below-minimum", plan_=tallies_plan)
    bld.version(
        "valid-below-minimum",
        d,
        n_hat=80,
        desc="nHat 80 under minVoters 100: final, unlocked empty, no tables, nHat absent, "
        "receipts empty and no receipts/0 ref, parts holding 0 and 4 only (no part 8; ADR 0103)",
    )
    d = deck("below-minimum-ibis", plan_=dk.plan_ibis(CARDS_, count=True))
    bld.version(
        "valid-below-minimum-ibis",
        d,
        n_hat=80,
        desc="an IBIS plan with parts 5 and 6 and the daily count, below the minimum: parts "
        "holding 0 and 4 only, no receipts, no tables",
    )
    d = deck("R13-below-minimum-receipt-root", plan_=tallies_plan)

    def add_root(e):
        root, root_cid = bld.receipt_root("below-minimum-root")
        e[m.BODY][rb.RECEIPTS] = {0: root}
        e[m.REFS]["receipts/0"] = root_cid

    bld.version(
        "invalid-R13-below-minimum-receipt-root",
        d,
        n_hat=80,
        mutate=add_root,
        desc="a below-minimum version 1 that carries a receipts/0 root: nothing is published "
        "below the minimum, a padded leaf count included",
        rule="R13",
    )
    d = deck("absorbed", plan_=dk.plan_full(CARDS_, cov_statements=CARDS_, absorb=True))
    bld.version(
        "valid-absorbed",
        d,
        n_hat=410,
        count_total=420,
        desc="absorb plan, count total 420: final, absorbed, tallies sigma from the summed rho",
    )
    d4 = deck("four-stages", ctx=wd.ctx_sealed)
    v1 = bld.version(
        "valid-four-stages-v1",
        d4,
        n_hat=1243,
        desc="four stages (sealed context): version 1, tallies",
    )
    v2 = bld.version(
        "valid-four-stages-v2",
        d4,
        stage=2,
        prev=v1,
        part_n={1: 1198},
        desc="version 2: covariance and axes",
    )
    v3 = bld.version(
        "valid-four-stages-v3",
        d4,
        stage=3,
        prev=v2,
        part_n={2: 1171},
        desc="version 3: map and centroids, groupsK 2",
    )
    bld.version(
        "valid-four-stages-v4",
        d4,
        stage=4,
        prev=v3,
        part_n={3: 1150},
        desc="version 4: group tables, repness, consensus; final",
    )
    bld.extra["valid-four-stages-v4"] = phone_computations()
    dd = deck("dropout-final-at-3")
    w1 = bld.version("valid-dropout-v1", dd, n_hat=1243, desc="dropout: version 1")
    w2 = bld.version(
        "valid-dropout-v2", dd, stage=2, prev=w1, part_n={1: 1198}, desc="dropout: version 2"
    )
    bld.version(
        "valid-dropout-final-at-3",
        dd,
        stage=3,
        prev=w2,
        part_n={2: 790},
        desc="round 2's n falls to 790: version 3 final with map and no centroids",
    )
    dp = deck("public")
    p1 = bld.version(
        "valid-public-v1",
        dp,
        n_hat=1243,
        desc="public context: version 1, public tables, no keybox",
    )
    p2 = bld.version(
        "valid-public-v2", dp, stage=2, prev=p1, part_n={1: 1198}, desc="public: version 2"
    )
    p3 = bld.version(
        "valid-public-v3", dp, stage=3, prev=p2, part_n={2: 1171}, desc="public: version 3"
    )
    bld.version(
        "valid-public-v4", dp, stage=4, prev=p3, part_n={3: 1150}, desc="public: version 4 final"
    )
    di = deck("ibis", plan_=dk.plan_ibis(CARDS_))
    bld.version(
        "valid-ibis",
        di,
        n_hat=900,
        desc="IBIS plan: movement, moved, ratings at nHat 900; not final",
    )

    # ---- invalid: R1 to R9 as mutations on fresh decks (logged after the valid releases)
    def bad(rule, name, desc, *, plan_=tallies_plan, ctx=None, n_hat=350, mutate=None, **kw):
        d = deck(f"{rule}-{name}", ctx=ctx, plan_=plan_)
        return bld.version(
            f"invalid-{rule}-{name}", d, n_hat=n_hat, mutate=mutate, desc=desc, rule=rule, **kw
        )

    body = lambda e: e[m.BODY]  # noqa: E731

    def drop_part(e, p):
        """Remove a part record and keep rho equal to the remaining sum (so R4 still holds)."""
        body(e)[rb.PARTS].pop(p)
        total = sum(
            (Fraction(r[rb.PR_RHO][0], r[rb.PR_RHO][1]) for r in body(e)[rb.PARTS].values()),
            Fraction(0),
        )
        body(e)[rb.RHO] = rmath.rat(total)

    bad(
        "R1",
        "stage-not-version",
        "stage 2 on version 1",
        mutate=lambda e: body(e).__setitem__(rb.STAGE, 2),
    )
    bad(
        "R1",
        "unlocked-unsorted",
        "unlocked unsorted",
        mutate=lambda e: body(e).__setitem__(rb.UNLOCKED, [8, 4, 0]),
    )
    bad(
        "R1",
        "assurance-unsorted",
        "assurance unsorted",
        mutate=lambda e: body(e).__setitem__(rb.ASSURANCE, list(reversed(body(e)[rb.ASSURANCE]))),
    )
    other_auth = wd.named["keyset-trust"].cid
    bad(
        "R2",
        "helper-not-contexts",
        "helper is not the context's",
        mutate=lambda e: body(e).__setitem__(rb.HELPER, other_auth),
        signers=bld.signers(("l1", "ts")),
    )
    # deck ref not the highest pre-close version: pin version 1 of the extended lineage
    bld.version(
        "invalid-R2-deck-not-highest",
        wd.decks["valid-v2-extend-v1"],
        n_hat=350,
        desc="deck ref is version 1 while version 2 was logged",
        rule="R2",
    )
    ds = deck("R2-shared-key", ctx=wd.ctx_shared, plan_=tallies_plan)
    bld.version(
        "invalid-R2-shared-key",
        ds,
        n_hat=350,
        desc="a key in both aggregator keysets",
        rule="R2",
        signers=[(b"l1", wd.keys["l1"]), (b"l1-shared", wd.keys["l1"])],
    )
    bad("R3", "mechanism-1", "mechanism 1", mutate=lambda e: body(e).__setitem__(rb.MECHANISM, 1))

    def sigma_off(e):
        b = body(e)
        rec = b[rb.PARTS][dk.TALLIES]
        rho_t = Fraction(rec[rb.PR_RHO][0], rec[rb.PR_RHO][1])
        rp = dk.to_release_plan(tallies_plan, CARDS_)
        wrong = rmath.sigma_micro_binary64(rmath.delta_squared(dk.TALLIES, rp, CARDS_), rho_t)
        rec[rb.PR_SIGMA] = wrong if wrong != rec[rb.PR_SIGMA] else rec[rb.PR_SIGMA] - 1

    bad("R4", "sigma-not-rounded-up",
        "tallies sigma computed from σ instead of σ_r (binary64 round(σ × 10⁶)), a few "
        "micro-units below round(σ_r × 10⁶)", mutate=sigma_off)  # fmt: skip
    bad(
        "R4",
        "part-not-in-plan",
        "a part not in the plan",
        mutate=lambda e: body(e)[rb.PARTS].__setitem__(
            dk.MOVEMENT, rb.part_record(Fraction(1, 1000), 1, None)
        ),
    )
    bad(
        "R4",
        "absorbed-without-absorb",
        "absorbed without plan.absorb",
        mutate=lambda e: body(e).__setitem__(rb.ABSORBED, True),
    )
    bad(
        "R4",
        "rho-above-plan",
        "rho above plan.rho",
        mutate=lambda e: body(e).__setitem__(rb.RHO, [3, 10]),
    )
    full = dk.plan_full(CARDS_, cov_statements=CARDS_)
    bad(
        "R5",
        "stage1-not-final",
        "version 1 not final though nHat 500 < 800 and no absorb",
        plan_=full,
        n_hat=500,
        final=False,
    )
    dv = deck("R5-after-final")
    f1 = bld.version("lineage-R5-after-final-v1", dv, n_hat=500, record=False)
    bld.version(
        "invalid-R5-version-after-final",
        dv,
        stage=2,
        prev=f1,
        part_n={1: 1000},
        desc="version 2 after a final version 1",
        rule="R5",
    )

    def four(label, stop, ctx=None):
        d = deck(label, ctx=ctx)
        vs = [bld.version(f"lineage-{label}-v1", d, n_hat=1243, record=False)]
        if stop >= 2:
            vs.append(
                bld.version(
                    f"lineage-{label}-v2", d, stage=2, prev=vs[-1], part_n={1: 1198}, record=False
                )
            )
        if stop >= 3:
            vs.append(
                bld.version(
                    f"lineage-{label}-v3", d, stage=3, prev=vs[-1], part_n={2: 1171}, record=False
                )
            )
        return d, vs

    d, vs = four("R5-missing-part-2", 2)
    bld.version(
        "invalid-R5-stage3-missing-part-2",
        d,
        stage=3,
        prev=vs[-1],
        part_n={2: 1171},
        mutate=lambda e: drop_part(e, dk.MAP),
        desc="stage 3 missing part 2",
        rule="R5",
    )
    d, vs = four("R5-stage4-not-final", 3)
    bld.version(
        "invalid-R5-stage4-not-final",
        d,
        stage=4,
        prev=vs[-1],
        part_n={3: 1150},
        final=False,
        desc="stage 4 not final",
        rule="R5",
    )
    d, vs = four("R5-final-at-2", 1)
    bld.version(
        "invalid-R5-final-at-stage-2",
        d,
        stage=2,
        prev=vs[-1],
        part_n={1: 900},
        final=True,
        desc="final at stage 2 with n 900",
        rule="R5",
    )
    bad(
        "R6",
        "part0-unlocked-nhat-90",
        "part 0 in unlocked with nHat 90",
        n_hat=90,
        mutate=lambda e: (
            body(e).__setitem__(rb.N_HAT, 90),
            body(e)[rb.PARTS][0].__setitem__(rb.PR_N, 90),
            body(e).__setitem__(rb.UNLOCKED, [0, 4, 8]),
        ),
    )
    bad(
        "R6",
        "part4-unlocked-below-floor",
        "part 4 unlocked below the floor",
        n_hat=90,
        mutate=lambda e: body(e).__setitem__(rb.UNLOCKED, [4]),
    )
    bad(
        "R6",
        "part5-unlocked-at-250",
        "part 5 unlocked at nHat 250",
        plan_=dk.plan_ibis(CARDS_),
        n_hat=250,
        mutate=lambda e: body(e).__setitem__(rb.UNLOCKED, [0, 5, 8]),
    )
    d, vs = four("R6-part1-n-700", 1)
    bld.version(
        "invalid-R6-part1-unlocked-n-700",
        d,
        stage=2,
        prev=vs[-1],
        part_n={1: 700},
        mutate=lambda e: body(e).__setitem__(rb.UNLOCKED, sorted(set(body(e)[rb.UNLOCKED]) | {1})),
        desc="part 1 unlocked with n 700",
        rule="R6",
    )
    bad(
        "R6",
        "nhat-absent-part0-unlocked",
        "nHat absent with part 0 unlocked",
        n_hat=90,
        mutate=lambda e: body(e).__setitem__(rb.UNLOCKED, [0, 4, 8]),
    )
    d, vs = four("R7-group-tallies-at-2", 1)
    bld.version(
        "invalid-R7-group-tallies-at-stage-2",
        d,
        stage=2,
        prev=vs[-1],
        part_n={1: 1198},
        mutate=lambda e: e[m.REFS].__setitem__("t/group_tallies", wd.statement_blob),
        desc="t/group_tallies present at stage 2",
        rule="R7",
    )
    bad(
        "R7",
        "consensus-missing",
        "t/consensus missing at nHat 400",
        n_hat=400,
        mutate=lambda e: e[m.REFS].pop("t/consensus"),
    )
    d, vs = four("R7-groupsk-at-2", 1)
    bld.version(
        "invalid-R7-groupsk-at-stage-2",
        d,
        stage=2,
        prev=vs[-1],
        part_n={1: 1198},
        mutate=lambda e: body(e).__setitem__(rb.GROUPS_K, 2),
        desc="groupsK at stage 2",
        rule="R7",
    )

    def r8(name, desc, mutate):
        d, vs = four(f"R8-{name}", 1)
        bld.version(
            f"invalid-R8-{name}",
            d,
            stage=2,
            prev=vs[-1],
            part_n={1: 1198},
            mutate=mutate,
            desc=desc,
            rule="R8",
        )

    r8("nhat-changed", "version 2 changes nHat", lambda e: body(e).__setitem__(rb.N_HAT, 1244))
    # "version 2 changes helper" (spec's R8 list): R2 compares helper with the pinned context's
    # aggregators on every version, so under numbered rule order R2 fires before R8.
    d, vs = four("R2-helper-changed", 1)
    leader_id = cbor.decode(wd.ctx.envelope)[m.BODY][c.AGGREGATORS][0]
    bld.version(
        "invalid-R2-helper-changed",
        d,
        stage=2,
        prev=vs[-1],
        part_n={1: 1198},
        mutate=lambda e: body(e).__setitem__(rb.HELPER, leader_id),
        desc="version 2 changes helper (R2 fires before R8: helper is not the context's)",
        rule="R2",
    )

    def receipt0(e):
        body(e)[rb.RECEIPTS][0] = bytes(32)

    r8("receipts-0-changed", "version 2 changes receipts[0]", receipt0)

    def n_prior(e):
        # a prior part's n is frozen by R8 alone (a prior sigma change is the R4 case below)
        body(e)[rb.PARTS][dk.TALLIES][rb.PR_N] += 1

    r8("prior-n-changed", "version 2 changes a prior part's n", n_prior)
    r8(
        "prior-table-changed",
        "version 2 replaces a prior t/* (dropping it is the R7 case)",
        lambda e: e[m.REFS].__setitem__("t/tallies", wd.statement_blob),
    )
    # version 2 changes a prior part's sigma: R4 (sigma is not the rounding) fires before R8
    d, vs = four("R4-prior-sigma-changed", 1)

    def sigma_prior(e):
        body(e)[rb.PARTS][dk.TALLIES][rb.PR_SIGMA] += 1

    bld.version(
        "invalid-R4-prior-sigma-changed",
        d,
        stage=2,
        prev=vs[-1],
        part_n={1: 1198},
        mutate=sigma_prior,
        desc="version 2 changes a prior part's sigma (R4 fires before R8)",
        rule="R4",
    )
    # version 2 drops a prior t/*: R7 (missing table) fires before R8
    d, vs = four("R7-prior-table-dropped", 1)
    bld.version(
        "invalid-R7-prior-table-dropped",
        d,
        stage=2,
        prev=vs[-1],
        part_n={1: 1198},
        mutate=lambda e: e[m.REFS].pop("t/tallies"),
        desc="version 2 drops a prior t/* (R7 fires before R8)",
        rule="R7",
    )

    def lower_rho(e):
        drop_part(e, dk.TALLIES)

    r8("rho-lowered", "version 2 lowers rho", lower_rho)
    r8(
        "assurance-changed",
        "version 2 changes assurance",
        lambda e: body(e).__setitem__(rb.ASSURANCE, [[wd.vd_auth, 2]]),
    )
    # R9: step 6, so unlogged copies of a valid release with fewer signatures
    valid_tallies = bld.cases[0][3]
    bld.unlogged(
        "invalid-R9-leader-only",
        valid_tallies,
        signers=bld.signers(("l1",)),
        desc="Leader signatures only",
        rule="R9",
    )
    bld.unlogged(
        "invalid-R9-helper-below-threshold",
        valid_tallies,
        signers=bld.signers(("l1", "h1")),
        desc="Helper below its 2-of-2 threshold",
        rule="R9",
    )
    # R10: a second lineage for the deck of the first valid release
    bld.version(
        "invalid-R10-second-lineage",
        wd.decks["for-release-stage1-final-tallies-only"],
        n_hat=350,
        issued=CLOSES_() + 7200,
        desc="second release lineage for the same deck",
        rule="R10",
    )
    # R11: own decks
    bad(
        "R11",
        "sealed-context-public-tables",
        "sealed context with public tables",
        ctx=wd.ctx_sealed,
        mutate=lambda e: (
            body(e).__setitem__(rb.SEALED, False),
            body(e).pop(rb.RESULTS_EPOCH),
            e[m.REFS].pop("keybox"),
        ),
    )
    bad(
        "R11",
        "public-context-keybox",
        "public context with a keybox",
        mutate=lambda e: e[m.REFS].__setitem__("keybox", wd.statement_blob),
    )
    bad(
        "R11",
        "wrong-results-epoch",
        "wrong resultsEpoch",
        ctx=wd.ctx_sealed,
        mutate=lambda e: body(e).__setitem__(rb.RESULTS_EPOCH, 2),
    )
    bad(
        "R11",
        "sealed-without-keybox",
        "sealed without keybox",
        ctx=wd.ctx_sealed,
        mutate=lambda e: e[m.REFS].pop("keybox"),
    )
    # R12
    bad(
        "R12",
        "missing-issuer",
        "assurance missing an issuer",
        mutate=lambda e: body(e).__setitem__(rb.ASSURANCE, [[wd.vd_auth, 2]]),
    )
    bad(
        "R12",
        "wrong-level",
        "wrong assurance level",
        mutate=lambda e: body(e).__setitem__(
            rb.ASSURANCE, [[a, 1] for a, _ in sorted(wd.assurance)]
        ),
    )
    bad(
        "R12",
        "entry-only-issuer",
        "including the entry-only issuer",
        mutate=lambda e: body(e).__setitem__(
            rb.ASSURANCE, [[a, lvl] for a, lvl in sorted(wd.assurance + [(wd.va_auth, 1)])]
        ),
    )
    # R13
    bad(
        "R13",
        "deadline-on-final",
        "roundDeadline on a final version",
        mutate=lambda e: body(e).__setitem__(rb.ROUND_DEADLINE, e[m.ISSUED] + WINDOW),
    )
    bad(
        "R13",
        "deadline-wrong",
        "roundDeadline not issued + window",
        plan_=full,
        n_hat=1243,
        mutate=lambda e: body(e).__setitem__(rb.ROUND_DEADLINE, e[m.ISSUED] + WINDOW + 1),
    )
    bad(
        "R13",
        "issued-40-days-late",
        "version 1 issued 40 days after closes",
        issued=CLOSES_() + 40 * DAY,
    )
    bad(
        "R13",
        "receipts-missing-round",
        "receipts missing a round",
        mutate=lambda e: body(e)[rb.RECEIPTS].pop(0),
    )
    # R13, expires: every version is issued by E, the pinned deck version's expires
    expires_of = lambda d: cbor.decode(d.envelope)[m.EXPIRES]  # noqa: E731
    d = deck("R13-v3-after-expires", plan_=full)
    e1 = bld.version("valid-R13-v3-after-expires-v1", d, n_hat=1243, desc="version 1, in time")
    e2 = bld.version(
        "valid-R13-v3-after-expires-v2", d, stage=2, prev=e1, part_n={1: 1198},
        desc="version 2, in time",
    )  # fmt: skip
    bld.version(
        "invalid-R13-issued-after-expires", d, stage=3, prev=e2, part_n={2: 1171},
        issued=expires_of(d) + 1, desc="version 3 issued one second after the deck's expires",
        rule="R13",
    )  # fmt: skip
    bad(
        "R13",
        "no-room-for-rounds",
        "non-final version 1 issued with less than three roundWindows left before expires",
        plan_=full,
        n_hat=1243,
        issued=CLOSES_() + WINDOW + 1,
    )
    d = deck("R13-ledger-clock")
    clock = bld.version(
        "valid-R13-ledger-clock", d, n_hat=350,
        desc="a version with a valid issued (the ledger-clock cases submit this bundle)",
    )  # fmt: skip
    bld.log_cases.append((
        "invalid-R13-ledger-clock-after-expires",
        "a version with a valid issued, submitted when the ledger's clock is past expires",
        clock, expires_of(d) + 1,
    ))  # fmt: skip
    bld.log_cases.append((
        "valid-R13-ledger-clock-at-expires",
        "the same version submitted when the ledger's clock reads exactly expires: admitted",
        clock, expires_of(d),
    ))  # fmt: skip
    d = deck("R13-final-at-expires")
    bld.version(
        "valid-R13-final-at-expires", d, n_hat=350, issued=expires_of(d),
        desc="a final version issued exactly at expires",
    )  # fmt: skip
    # a later deck version does not move E: release version 1 pins deck version 1 (R8 freezes
    # the ref), the log then holds a deck version 2 with a later expires, and release version 2
    # is issued after version 1's expires and before version 2's
    d = deck("R13-pinned", plan_=full)
    pin1 = bld.version(
        "valid-R13-pinned-v1", d, n_hat=1243, desc="version 1 pinning deck version 1"
    )
    e_v1 = expires_of(d)
    d_v2 = wd.deck(
        "for-release-R13-pinned-v2",
        wd.extend(d, closes=CLOSES_() + 2 * DAY, expires=e_v1 + 2 * DAY),
    )
    assert expires_of(d_v2) > e_v1 + 1
    bld.version(
        "invalid-R13-v2-after-pinned-expires", d, stage=2, prev=pin1, part_n={1: 1198},
        issued=e_v1 + 1, rule="R13",
        desc="version 2 issued after the pinned deck version's expires and before a later deck "
        "version's expires",
    )  # fmt: skip
    # D16, the clock-free half: a deck version 2 logged after release version 1 of its lineage
    d = deck("D16-after-release", plan_=tallies_plan)
    bld.version("valid-D16-after-release-v1", d, n_hat=350, desc="version 1 of the release "
                "whose deck is extended afterwards; valid on its own")  # fmt: skip
    from .deck_vectors import CLOSES as _CLOSES

    d2 = wd.deck(
        "for-release-D16-after-release-v2",
        wd.extend(d, closes=_CLOSES + DAY, expires=_CLOSES + WINDOW + DAY),
    )
    bld.deck_cases.append((
        "deck-invalid-D16-after-release",
        "deck version 2 logged after release version 1 of the same lineage: invalid for every "
        "verifier, with no clock (ADR 0103 item 2)",
        "D16",
        d2,
    ))  # fmt: skip
    # step 7: a release present only in the context's second log (not in the ledger of record)
    d = deck("step7-second-log", ctx=wd.ctx_two_logs, plan_=tallies_plan)
    bld.version("step7-not-in-ledger-of-record", d, n_hat=350, record=False, log=wd.w2)
    bld.second_log_cases.append((
        "release-invalid-step7-not-in-ledger-of-record",
        "a release logged only in the context's second listed log (which mirrors every entry "
        "of the ledger of record), verified by a phone that accepted that log: for release and "
        "deck manifests step 7's inclusion proof must be against the ledger of record (the "
        "first entry of logs) whichever log the bundle came from, so it fails at step 7 before "
        "R10 is reached; a phone following the ledger of record fails step 7 too (the proof is "
        "not from its accepted log). One expected result: step 7",
        "release-step7-not-in-ledger-of-record",
    ))  # fmt: skip
    # R14: four releases at rho 1/4 fit rhoYear 1; the fifth does not
    quarter = dk.plan_tallies_only(CARDS_, rho=Fraction(1, 4))
    for i in range(4):
        d = deck(f"R14-{i}", ctx=wd.ctx_year, plan_=quarter)
        bld.version(
            f"valid-rho-year-{i}", d, n_hat=350, desc=f"release {i + 1} of 4 that fit rhoYear 1"
        )
    d = deck("R14-fifth", ctx=wd.ctx_year, plan_=quarter)
    bld.version(
        "invalid-R14-fifth-release",
        d,
        n_hat=350,
        desc="fifth release of the year over rhoYear",
        rule="R14",
    )
    return bld


def CLOSES_() -> int:
    from .deck_vectors import CLOSES

    return CLOSES


# ---------------------------------------------------------------- phone computations (inputs and outputs)


def phone_computations() -> dict[str, Any]:
    rng = random.Random(20261006)
    cards = 18
    tallies = []
    for _ in range(cards):
        n = rng.choice([300, 450, 600, 800, 900])
        a = rng.random()
        tallies.append(
            (
                round(n * a) + rng.randint(-8, 8),
                round(n * (1 - a) * 0.8) + rng.randint(-8, 8),
                round(n * (1 - a) * 0.2) + rng.randint(-8, 8),
            )
        )
    sel, mu = rmath.sel_and_mu([(float(a), float(b), float(u)) for a, b, u in tallies], cards)
    hands = {
        "full": {j: rng.choice([1, -1, 0]) for j in range(cards)},
        "sparse": {0: 1, 5: -1, 9: 0},
        "half-point": {0: 1},
    }
    pc1 = [((j * 7) % 11 - 5) / 10 for j in range(cards)]
    n1 = sum(x * x for x in pc1) ** 0.5
    pc1 = [x / n1 for x in pc1]
    pc2 = [((j * 5) % 13 - 6) / 10 for j in range(cards)]
    d = sum(a * b for a, b in zip(pc1, pc2, strict=True))
    pc2 = [b - d * a for a, b in zip(pc1, pc2, strict=True)]
    n2 = sum(x * x for x in pc2) ** 0.5
    pc2 = [x / n2 for x in pc2]
    half_x, half_y, grid = 2.4, 1.9, 24
    centroids = [(-0.8, 0.2), (0.9, -0.1)]
    out = {
        "inputs": {
            "tallies": [
                {"card": j, "agree": t[0], "disagree": t[1], "unsure": t[2]}
                for j, t in enumerate(tallies)
            ],
            "M": cards,
            "covScale": 65536,
            "hands": {k: {str(a): b for a, b in v.items()} for k, v in hands.items()},
            "axes": {"pc1": pc1, "pc2": pc2, "half_x": half_x, "half_y": half_y, "grid": grid},
            "centroids": centroids,
        },
        "outputs": {"sel": sel, "mu": mu, "round1": {}, "round2": {}, "round3": {}},
    }
    for name, hand in hands.items():
        v = rmath.round1_vector(hand, sel, mu, 65536)
        out["outputs"]["round1"][name] = (
            None
            if v is None
            else {
                "entries": v["entries"],
                "norm_squared": v["norm_squared"],
                "delta_cov": v["delta_cov"],
            }
        )
        out["outputs"]["round2"][name] = rmath.round2_cell(
            hand, sel, mu, pc1, pc2, half_x, half_y, grid
        )
        out["outputs"]["round3"][name] = rmath.round3_group(hand, sel, mu, pc1, pc2, centroids)
    return out


# ---------------------------------------------------------------- files


def manifests_file(wd, bld: Builder) -> File:
    from .deck_vectors import run

    f = File(
        SPEC,
        "manifests",
        "Release manifests (release.md Vectors): the valid scenarios and one invalid case per "
        "rule sub-condition. Tables are placeholder blobs (R15 pending Parquet); the keybox is a "
        "placeholder public blob (HPKE pending). Rating releases and R10's rating case are pending "
        "the take module. Invalid releases other than R9's were appended by a misbehaving log.",
    )
    for name, desc, rule, b in bld.cases:
        env = cbor.decode(b.envelope)
        extra = {"deck": hexify(env[m.REFS]["deck"]), "body_view": jsonable(env[m.BODY])}
        if name in bld.extra:
            extra["phone_computations"] = bld.extra[name]
        if rule is None:
            run(f, wd, f"release-{name}", desc, b, extra=extra, section=S_RULES)
        else:
            step = 6 if rule == "R9" else 10
            run(
                f,
                wd,
                f"release-{name}",
                desc,
                b,
                step=step,
                rule=rule,
                extra=extra,
                section=S_RULES,
            )
    # step 7: a release only in the second log. The phone accepted the second log, which holds
    # every entry of the ledger of record (at index + 1, after its own keyset) and then this
    # release; it resolves everything from that log and fails step 7 (services.md, "Submitting
    # a manifest"; release.md R10; conformance.md disagreement 21).
    for suffix, desc, key in bld.second_log_cases:
        b = wd.named[key]
        env = cbor.decode(b.envelope)
        ctx2 = wd.w2.context(now=NOW)
        deck_env = cbor.decode(wd.w.bundles[env[m.REFS]["deck"]].envelope)
        cbody = cbor.decode(wd.w.bundles[deck_env[m.REFS]["context"]].envelope)[m.BODY]
        inputs = {
            "bundle": bundle_json(b),
            "now": NOW,
            "deck": hexify(env[m.REFS]["deck"]),
            "body_view": jsonable(env[m.BODY]),
            "context_logs": [hexify(e[c.L_LOG]) for e in cbody[c.LOGS]],
            "ledger_of_record": hexify(cbody[c.LOGS][0][c.L_LOG]),
            "accepted_log": hexify(wd.w2.log_authority),
            "accepted_log_keyset": bundle_json(wd.w2_keyset),
            "accepted_log_public_key": hexify(wd.w2.log_public),
            "accepted_log_entries": "the accepted log's keyset at index 0, then every entry "
            "of deck/world.json at its index + 1 (same envelope, signatures and authorship), "
            "then this release; resolve references against that log with its checkpoint",
            "accepted_log_checkpoint": wd.w2.note().text(),
        }
        try:
            m.verify_bundle(ctx2, b)
            raise AssertionError(f"{suffix}: accepted")
        except m.Rejection as e:
            assert (e.step, e.rule) == (7, None), (suffix, str(e))
            f.add(f"{suffix}", desc, "Verification step 7, the ledger of record", inputs,
                  rejection={"step": 7, "reason": e.reason})  # fmt: skip
    # R13's clock half: the ledger refuses a submission once its own clock is past expires
    for name, desc, b, log_now in bld.log_cases:
        env = cbor.decode(b.envelope)
        deck_env = cbor.decode(wd.w.bundles[env[m.REFS]["deck"]].envelope)
        inputs = {
            "log_now": log_now,
            "bundle": bundle_json(b),
            "deck_expires": deck_env[m.EXPIRES],
        }
        result = rb.log_check(env, deck_env, log_now)
        if result is None:
            assert name.startswith("valid-"), name
            f.add(f"release-{name}", desc, S_LOG, inputs, {"admitted": True})
        else:
            assert name.startswith("invalid-"), name
            rule, reason = result
            f.add(f"release-{name}", desc, S_LOG, inputs,
                  rejection={"step": None, "check": "log-admission", "rule": rule,
                             "reason": reason})  # fmt: skip
    return f


def receipts_file() -> File:
    f = File(
        SPEC,
        "receipts",
        "Receipt padding (release.md Receipts): integer ⌈σ_8⌉ from the exact rational σ², "
        "Y_r = 6·⌈σ_8⌉ + Z_r clamped at 0 with Z_r an input, and a padded tree with its pages. Dummy leaves "
        "here are fixed bytes; a real aggregator draws them. The keybox seal is pending an HPKE library; only "
        "its info and aad bytes are given.",
    )
    for d2, rho in (
        (4, Fraction(1, 200)),
        (1, Fraction(1, 200)),
        (4, Fraction(1, 400)),
        (2, Fraction(3, 1000)),
    ):
        sigma_sq = Fraction(d2 * rho.denominator, 2 * rho.numerator)
        f.add("ceil-sigma", f"⌈σ_8⌉ for Δ² {d2}, ρ {rho}", "Receipts",
              {"delta_squared": d2, "rho": {"num": rho.numerator, "den": rho.denominator}},
              {"sigma_squared": {"num": sigma_sq.numerator, "den": sigma_sq.denominator}, "ceil_sigma": rb.ceil_sigma(sigma_sq)})  # fmt: skip
    sigma_sq = Fraction(4 * 200, 2)
    for z in (0, 17, -40, -1000):
        f.add("padding", f"Y_r for Z_r {z} at σ_8² {sigma_sq}", "Receipts",
              {"sigma_squared": {"num": sigma_sq.numerator, "den": sigma_sq.denominator}, "z_r": z},
              {"y_r": rb.receipt_padding(sigma_sq, z)})  # fmt: skip
    real = [hashlib.sha256(f"real receipt {i}".encode()).digest() for i in range(7)]
    y_r = 3
    dummies = [hashlib.sha256(f"dummy {i}".encode()).digest() for i in range(y_r)]
    pages = services.receipt_pages(real + dummies)
    f.add("padded-tree", "Seven real leaves padded with Y_r = 3 dummies, sorted bytewise, one page", "Receipts",
          {"real_leaves": [hexify(x) for x in real], "dummy_leaves": [hexify(x) for x in dummies], "y_r": y_r},
          {"sorted_leaves": [hexify(x) for x in pages["sorted"]], "k": pages["k"], "root": hexify(pages["root"]),
           "page_cids": [hexify(x) for x in pages["page_cids"]], "root_blob": hexify(pages["root_blob"])})  # fmt: skip
    deck_cid = compute_cid(b"a deck")
    info, aad = rb.keybox_info(deck_cid)
    f.add("keybox-layout", "HPKE info and aad for the keybox (the seal itself is pending)", "Members-only results",
          {"deck_cid": hexify(deck_cid)}, {"info": hexify(info), "aad": hexify(aad), "pending": "HPKE seal needs a library"})  # fmt: skip
    return f


def generate() -> list[File]:
    from .deck_vectors import get_world

    wd = get_world()
    return [manifests_file(wd, wd.releases), receipts_file()]
