"""Vectors for docs/specs/take.md, and the world that rating_vectors reuses.

``TakeWorld`` extends the deck world (``deck_vectors.World``) in its own instance: a second
public context with a release, a four-stage "rating source" release, take authorities, the
valid and invalid takes, and (for rating_vectors) the rating decks and releases. It never
touches ``deck_vectors.get_world()``, so the deck and release vectors keep their bytes.
"""

from __future__ import annotations

import copy
import functools

from .. import cbor, cose, fixtures, storage
from .. import manifest as m
from ..bodies import agent_sponsor as sp
from ..bodies import context as c
from ..bodies import deck as dk
from ..bodies import issue_map as im
from ..bodies import take as tk
from ..cid import cid as compute_cid
from ..keys import key_from_label
from . import File, hexify, jsonable
from . import deck_vectors as dv
from .issue_map_vectors import bundle_json

SPEC = "take"
S_RULES = "Validation rules"
DAY = 86_400
T_TAKE = fixtures.ISSUED + 40 * DAY
NOW = fixtures.NOW
EPOCH_SECRET = fixtures.fixed_bytes("results-epoch-3", 16)
RATING_TAKES = 12
RATING_OPENS = T_TAKE + 2 * DAY
RATING_CLOSES = RATING_OPENS + 7 * DAY


class TakeWorld(dv.World):
    """The deck world plus everything takes and rating decks need."""

    def _build(self) -> None:
        super()._build()  # builds and finalizes the deck world; we extend and refinalize
        from . import release_body_vectors as rbv

        w = self.w
        self.takes: dict[str, m.Bundle] = {}
        self.take_cases: list[tuple[str, str, str | None, int | None, m.Bundle]] = []
        tlrefs = {"tl/0": self.tl.cid}
        # a second public context with one final release
        self.ctx2 = self.context(
            "take-second", self.context_body({c.NAME: "Second context"}), tlrefs
        )
        cs, rs = self.blob_cards(6)
        d2 = self.deck(
            "take-second", self.deck_env(self.ctx2, dk.plan_tallies_only(6), cs, rs, title="Second")
        )
        bld = rbv.Builder(self)
        self.release2 = bld.version("take-second", d2, n_hat=350, record=False)
        # a four-stage public release in the main context, the source of the rating decks
        cards, refs = copy.deepcopy(self.cards), dict(self.refs)
        dsrc = self.deck(
            "rating-source",
            self.deck_env(
                self.ctx,
                dk.plan_full(dv.CARDS, cov_statements=dv.CARDS),
                cards,
                refs,
                title="Rating source",
            ),
        )
        v = bld.version("rating-source-v1", dsrc, n_hat=1243, record=False)
        v = bld.version("rating-source-v2", dsrc, stage=2, prev=v, part_n={1: 1198}, record=False)
        v = bld.version("rating-source-v3", dsrc, stage=3, prev=v, part_n={2: 1171}, record=False)
        self.rating_source = bld.version(
            "rating-source-v4", dsrc, stage=4, prev=v, part_n={3: 1150}, record=False
        )
        self.rating_source_deck = dsrc
        self.public_release = self.named["release-valid-public-v4"]
        self.public_deck = self.decks["for-release-public"]
        self.sealed_release = self.named["release-valid-four-stages-v4"]
        self.ibis_release = self.named["release-valid-ibis"]
        # take authorities
        self.ks_author = self.keyset("take-author", ["tk1"], "tkr")
        self.ks_author2 = self.keyset("take-author-2", ["tk2"], "tkr2")
        self.ks_fork = self.keyset("take-fork-author", ["tkf"], "tkfr")
        self.agent = key_from_label("take-agent")
        self.ks_sponsor = self.keyset("take-sponsor", ["sp1"], "spr")
        self.sponsor = self._sponsor("take-sponsor", self.ks_sponsor, tier=1, runtime=3, caps=[4])
        self.ks_sponsor_nocap = self.keyset("take-sponsor-nocap", ["sp2"], "spr2")
        self.sponsor_nocap = self._sponsor(
            "take-sponsor-nocap",
            self.ks_sponsor_nocap,
            tier=0,
            runtime=1,
            caps=[0, 3],
            signer="sp2",
        )
        self._build_takes()
        from . import rating_vectors as rv

        rv.build_ratings(self)
        w.finalize()

    # -- helpers
    def _sponsor(self, name, ks, *, tier, runtime, caps, signer="sp1") -> m.Bundle:
        body = sp.body(
            agent_key=self.agent.public,
            tier=tier,
            runtime=runtime,
            capabilities=caps,
            label="studio-agent",
            description="Writes takes over public releases.",
            sponsor_kind=1,
        )
        env = m.envelope(
            "agent-sponsor",
            body,
            authority=ks.cid,
            issued=fixtures.ISSUED,
            expires=fixtures.ISSUED + 80 * DAY,
        )
        return self.append(name, env, self.signers(signer))

    def text_blob(
        self, label: str, labels: list[str], *, prose: str | None = None, sealed=False
    ) -> bytes:
        data = tk.encode_text_blob(
            f"Take: {label}",
            "millbrook.weekly",
            labels,
            prose if prose is not None else f"Prose of {label}.",
        )
        if sealed:
            salt = fixtures.fixed_bytes(f"take-salt-{label}", 16)
            data = storage.seal_keyring(data, EPOCH_SECRET, salt)
        return self.w.put_blob(data)

    def statements(self, n: int = 3) -> list[bytes]:
        return [self.positions[i].cid for i in range(n)]

    def take_env(
        self,
        label: str,
        releases: list[m.Bundle],
        *,
        series: list[dict] | None = None,
        compare: int = 0,
        author: int = tk.AUTHORITY,
        sealed: bool = False,
        epoch: int | None = None,
        authority: bytes | None = None,
        chart: dict | None = None,
        text: bytes | None = None,
        extra_refs: dict | None = None,
        version: int = 1,
        lineage: bytes | None = None,
        prev: bytes | None = None,
        issued: int | None = None,
        retired: bool | None = None,
        labels: list[str] | None = None,
        body_extra: dict | None = None,
    ) -> dict:
        if series is None:
            # statements only when the first release's deck pins the main positions
            stmts = self.statements() if releases and releases[0] is self.public_release else []
            series = [
                tk.series(0, "group_tallies", tk.AGREE_SHARE, statements=stmts, group=0),
                tk.series(0, "group_tallies", tk.AGREE_SHARE, statements=stmts, group=1),
            ]
        body = tk.body(
            author=author,
            query_=tk.query(series, compare),
            chart_=chart or tk.chart(),
            sealed=sealed,
            epoch=epoch,
            retired=retired,
        )
        if body_extra:
            body.update(body_extra)
        refs = {f"release/{i}": r.cid for i, r in enumerate(releases)}
        refs["text"] = (
            text
            if text is not None
            else self.text_blob(
                label,
                labels
                if labels is not None
                else ["A", "B"][: len(series)] + ["C"] * max(0, len(series) - 2),
                sealed=sealed,
            )
        )
        if extra_refs:
            refs.update(extra_refs)
        return m.envelope(
            "take",
            body,
            authority=authority or self.ks_author.cid,
            version=version,
            lineage=lineage,
            prev=prev,
            issued=issued if issued is not None else T_TAKE,
            refs=refs,
        )

    def take(
        self, name: str, env: dict, *, signers=None, agent=None, desc=None, rule=None, step=None
    ) -> m.Bundle:
        if agent is not None:
            b = self.w.append(
                env,
                None,
                authorship=lambda cid_: im.Authorship(3, sig=im.sign_author(agent, cid_)).encode(),
            )
            self.named[f"take-{name}"] = b
        else:
            b = self.append(f"take-{name}", env, signers or self.signers("tk1"))
        self.takes[name] = b
        if desc is not None:
            self.take_cases.append((name, desc, rule, step, b))
        return b

    def v2(
        self, v1: m.Bundle, mutate=None, *, version: int = 2, prev: m.Bundle | None = None
    ) -> dict:
        prev = prev or v1
        env = copy.deepcopy(cbor.decode(prev.envelope))
        env[m.VERSION] = version
        env[m.LINEAGE] = v1.cid
        env[m.PREV] = prev.cid
        env[m.ISSUED] = env[m.ISSUED] + DAY
        if mutate is not None:
            mutate(env)
        return env

    # -- the takes
    def _build_takes(self) -> None:
        pub, sealed_r, two = self.public_release, self.sealed_release, self.release2
        # valid
        one = self.take(
            "ok-one-release",
            self.take_env("ok-one-release", [pub]),
            desc="one public release, two group series",
        )
        self.take(
            "ok-two-contexts",
            self.take_env(
                "ok-two-contexts",
                [pub, two],
                series=[
                    tk.series(0, "tallies", tk.AGREE_SHARE),
                    tk.series(1, "tallies", tk.AGREE_SHARE),
                ],
                compare=2,
            ),
            desc="compare 2 over two public releases of two contexts",
        )
        sealed_t = self.take(
            "ok-sealed",
            self.take_env("ok-sealed", [sealed_r], sealed=True, epoch=3),
            desc="sealed take over a sealed release: body carries no prose, blob is keyring form",
        )
        self.take(
            "ok-agent",
            self.take_env(
                "ok-agent",
                [pub],
                author=tk.AGENT,
                authority=self.ks_sponsor.cid,
                extra_refs={"sponsor": self.sponsor.cid},
            ),
            agent=self.agent,
            desc="agent take under its sponsor's authority with an hum/author/1 signature",
        )
        self.take(
            "ok-fork",
            self.take_env(
                "ok-fork", [pub], authority=self.ks_fork.cid, extra_refs={"forkOf": one.cid}
            ),
            signers=self.signers("tkf"),
            desc="a fork under another authority with forkOf",
        )
        self.take(
            "ok-prose-edit",
            self.v2(
                one,
                lambda e: e[m.REFS].__setitem__(
                    "text", self.text_blob("ok-prose-edit", ["A", "B"])
                ),
            ),
            desc="version 2 with new prose and the same queryHash",
        )
        retire_v1 = self.take(
            "retire-v1",
            self.take_env("retire-v1", [pub], authority=self.ks_author2.cid),
            signers=self.signers("tk2"),
        )
        retired = self.take(
            "ok-retire",
            self.v2(retire_v1, lambda e: e[m.BODY].__setitem__(tk.RETIRED, True)),
            signers=self.signers("tk2"),
            desc="version 2 retiring the lineage",
        )

        # invalid, one per rule sub-condition (logged by a misbehaving log; step 6 cases unlogged)
        def bad(name, env, rule, desc, *, step=10, signers=None, agent=None):
            self.take(name, env, signers=signers, agent=agent, desc=desc, rule=rule, step=step)

        bad("bad-no-release", self.take_env("bad-no-release", []), "TK-1", "no release ref")
        env = self.take_env("bad-release-gap", [pub])
        env[m.REFS]["release/2"] = two.cid
        bad("bad-release-gap", env, "TK-1", "release/0 and release/2 with no release/1")
        env = self.take_env("bad-ref-not-release", [pub])
        env[m.REFS]["release/0"] = self.public_deck.cid
        bad("bad-ref-not-release", env, "TK-1", "release/0 names a deck")
        bad(
            "bad-text-long",
            self.take_env(
                "bad-text-long",
                [pub],
                text=self.text_blob("bad-text-long", ["A", "B"], prose="x" * 16_001),
            ),
            "TK-2",
            "prose of 16,001 bytes",
        )
        bad(
            "bad-labels-count",
            self.take_env("bad-labels-count", [pub], labels=["A"]),
            "TK-2",
            "one label for two series",
        )
        bad(
            "bad-sealed-no-epoch",
            self.take_env(
                "bad-sealed-no-epoch",
                [sealed_r],
                sealed=True,
                text=self.text_blob("bad-sealed-no-epoch", ["A", "B"], sealed=True),
            ),
            "TK-2",
            "sealed without epoch",
        )
        bad(
            "bad-sealed-title-in-body",
            self.take_env(
                "bad-sealed-title-in-body",
                [sealed_r],
                sealed=True,
                epoch=3,
                body_extra={8: "The headline"},
            ),
            "TK-2",
            "an unknown body key carrying text",
        )
        bad(
            "bad-public-over-sealed",
            self.take_env("bad-public-over-sealed", [sealed_r]),
            "TK-3",
            "public take over sealed data",
        )
        bad(
            "bad-sealed-two-contexts",
            self.take_env(
                "bad-sealed-two-contexts",
                [sealed_r, two],
                sealed=True,
                epoch=3,
                series=[
                    tk.series(0, "tallies", tk.AGREE_SHARE),
                    tk.series(1, "tallies", tk.AGREE_SHARE),
                ],
            ),
            "TK-3",
            "sealed take pinning releases of two contexts",
        )
        bad(
            "bad-table-unknown",
            self.take_env(
                "bad-table-unknown", [pub], series=[tk.series(0, "votes", tk.AGREE_SHARE)]
            ),
            "TK-4",
            "unknown table",
        )
        bad(
            "bad-release-index",
            self.take_env(
                "bad-release-index", [pub], series=[tk.series(1, "tallies", tk.AGREE_SHARE)]
            ),
            "TK-4",
            "series release index 1 with one release",
        )
        bad(
            "bad-statement-foreign",
            self.take_env(
                "bad-statement-foreign",
                [pub],
                series=[
                    tk.series(0, "tallies", tk.AGREE_SHARE, statements=[self.positions[17].cid])
                ],
            ),
            "TK-4",
            "a statement the release's deck does not pin",
        )
        many = [compute_cid(b"statement %d" % i) for i in range(257)]
        bad(
            "bad-statements-too-many",
            self.take_env(
                "bad-statements-too-many",
                [pub],
                series=[tk.series(0, "tallies", tk.AGREE_SHARE, statements=many)],
            ),
            "TK-4",
            "257 statements",
        )
        bad(
            "bad-group-on-tallies",
            self.take_env(
                "bad-group-on-tallies",
                [pub],
                series=[tk.series(0, "tallies", tk.AGREE_SHARE, group=0)],
            ),
            "TK-4",
            "group on the tallies table",
        )
        # TK-5 (step 6)
        env = self.take_env("bad-sig", [pub])
        data = cbor.encode(env)
        cid = compute_cid(data)
        sigs = cose.encode_cose_sign([cose.sign_cid(self.keys["tk2"], b"tk2", cid)])
        self.take_cases.append(
            (
                "bad-sig",
                "signed by another authority's key",
                "TK-5",
                6,
                m.Bundle(data, sigs, cid, copy.deepcopy(one.proof)),
            )
        )
        bad(
            "bad-agent-authority-mismatch",
            self.take_env(
                "bad-agent-authority-mismatch",
                [pub],
                author=tk.AGENT,
                authority=self.ks_author.cid,
                extra_refs={"sponsor": self.sponsor.cid},
            ),
            "TK-5",
            "agent take under an authority that is not the sponsor's",
            step=6,
            agent=self.agent,
        )
        bad(
            "bad-agent-capability",
            self.take_env(
                "bad-agent-capability",
                [pub],
                author=tk.AGENT,
                authority=self.ks_sponsor_nocap.cid,
                extra_refs={"sponsor": self.sponsor_nocap.cid},
            ),
            "TK-5",
            "sponsor without the take capability",
            step=6,
            agent=self.agent,
        )
        # TK-6
        bad(
            "bad-sponsor-missing",
            self.take_env(
                "bad-sponsor-missing", [pub], author=tk.AGENT, authority=self.ks_sponsor.cid
            ),
            "TK-6",
            "agent take without a sponsor ref",
            step=6,
            agent=self.agent,
        )
        bad(
            "bad-sponsor-on-person",
            self.take_env("bad-sponsor-on-person", [pub], extra_refs={"sponsor": self.sponsor.cid}),
            "TK-6",
            "sponsor ref on an authority-authored take",
        )
        # TK-7
        bad(
            "bad-interval",
            self.take_env("bad-interval", [pub], chart=tk.chart(interval=50)),
            "TK-7",
            "interval 50",
        )
        # TK-8
        agent_take = self.takes["ok-agent"]
        bad(
            "bad-author-swap",
            self.v2(
                agent_take,
                lambda e: (
                    e[m.BODY].__setitem__(tk.AUTHOR, tk.AUTHORITY),
                    e[m.REFS].pop("sponsor"),
                ),
            ),
            "TK-8",
            "version 2 swaps author 3 for 0 (signed by the sponsor authority's keyset)",
            signers=self.signers("sp1"),
        )
        bad(
            "bad-after-retire",
            self.v2(retire_v1, version=3, prev=retired),
            "TK-8",
            "version 3 after a retired version 2",
            signers=self.signers("tk2"),
        )
        # TK-9
        sf1 = self.take(
            "selffork-v1",
            self.take_env("selffork-v1", [pub], authority=self.ks_author2.cid),
            signers=self.signers("tk2"),
        )
        bad(
            "bad-self-fork",
            self.v2(sf1, lambda e: e[m.REFS].__setitem__("forkOf", sf1.cid)),
            "TK-9",
            "version 2 forking its own version 1",
            signers=self.signers("tk2"),
        )
        bad(
            "bad-fork-unsealed",
            self.take_env(
                "bad-fork-unsealed",
                [pub],
                authority=self.ks_fork.cid,
                extra_refs={"forkOf": sealed_t.cid},
            ),
            "TK-9",
            "public fork of a sealed take",
            signers=self.signers("tkf"),
        )


@functools.lru_cache(maxsize=1)
def get_take_world() -> TakeWorld:
    return TakeWorld()


# ---------------------------------------------------------------- files


def run(
    f: File,
    wd: TakeWorld,
    suffix: str,
    desc: str,
    bundle: m.Bundle,
    *,
    step=None,
    rule=None,
    extra=None,
):
    ctx = wd.w.context(now=NOW)
    inputs = {"bundle": bundle_json(bundle), "now": NOW}
    if extra:
        inputs.update(extra)
    try:
        env = m.verify_bundle(ctx, bundle)
    except m.Rejection as e:
        if step is None or e.step != step or (rule is not None and e.rule != rule):
            raise AssertionError(
                f"{suffix} {desc!r}: expected step {step} {rule}, got {e} ({e.rule})"
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
        raise AssertionError(
            f"{suffix} {desc!r}: expected rejection at step {step} {rule}, accepted"
        )
    f.add(
        suffix,
        desc,
        S_RULES,
        inputs,
        {"accept": True, "type": env[m.TYPE], "version": env[m.VERSION]},
    )


def manifests_file(wd: TakeWorld) -> File:
    f = File(
        SPEC,
        "manifests",
        "Valid takes and one invalid take per rule sub-condition (take.md Vectors). Invalid takes "
        "other than the step-6 ones were appended by a misbehaving log. Bundles resolve against "
        "world.json here and the deck vectors' world.",
    )
    for name, desc, rule, step, b in wd.take_cases:
        env = cbor.decode(b.envelope)
        extra = {
            "body_view": jsonable(env[m.BODY]),
            "query_hash": hexify(tk.query_hash(env[m.BODY][tk.QUERY], env[m.BODY][tk.CHART])),
        }
        run(f, wd, f"tk-{name}", desc, b, step=step, rule=rule, extra=extra)
    return f


def world_file(wd: TakeWorld) -> File:
    f = File(
        SPEC,
        "world",
        "Bundles beyond the deck vectors' world: the second context and its release, the rating "
        "source release, take authorities, sponsors, takes, rating decks and rating releases. "
        "Note: this world re-finalizes the deck world's log, so proofs here differ from deck/world.json; "
        "resolve the base bundles by CID from either file and use the checkpoint given here.",
    )
    base = {b.cid for b in dv.get_world().w.bundles.values()}
    names = {b.cid: n for n, b in wd.named.items()}
    bundles = [
        {"name": names.get(b.cid, "?"), **bundle_json(b), "view": jsonable(cbor.decode(b.envelope))}
        for b in wd.w.bundles.values()
        if b.cid not in base
    ]
    import hashlib

    f.add(
        "world",
        "Bundles, blobs, checkpoint",
        "Vectors",
        {
            "keys": {
                n: {"seed": hexify(k.seed), "public": hexify(k.public)}
                for n, k in wd.keys.items()
                if n not in fixtures.KEY_LABELS
            },
            "agent_seed": hexify(wd.agent.seed),
            "sealed_text_epoch_secret": hexify(EPOCH_SECRET),
        },
        {
            "checkpoint": wd.w.note().text(),
            "entries": [hexify(x) for x in wd.w.leaves],
            "blobs": {
                hexify(k): (
                    hexify(v) if len(v) <= 4096 else {"sha256": hashlib.sha256(v).hexdigest()}
                )
                for k, v in wd.w.blobs.items()
            },
            "bundles": bundles,
        },
    )
    return f


def numeric_file() -> File:
    f = File(
        SPEC,
        "numeric",
        "Noise math, measures, queryHash and gallery ranking (take.md). Floats are binary64 printed "
        "with Python's shortest repr; compare to six decimals.",
    )
    sec = "Noise math"
    sigma = 18.3869
    r = tk.share([412.0, 240.0, 61.0], sigma, 3)
    f.add(
        "take-noise-share",
        "agree share with m = 3 at σ 18.3869",
        sec,
        {"counts": [412.0, 240.0, 61.0], "sigma": sigma, "m": 3},
        {
            **r,
            "interval_90": tk.interval(r["p"], r["sigma_p"], 90),
            "interval_80": tk.interval(r["p"], r["sigma_p"], 80),
            "interval_95": tk.interval(r["p"], r["sigma_p"], 95),
        },
    )
    r = tk.share([300.0, 190.0], 19.0, 2)
    f.add(
        "take-noise-ratio",
        "fair share with m = 2 (a take's fairness)",
        sec,
        {"counts": [300.0, 190.0], "sigma": 19.0, "m": 2},
        {**r, "f_low_90": r["p"] - tk.Z[90] * r["sigma_p"]},
    )
    a = tk.share([412.0, 240.0, 61.0], sigma, 3)
    b = tk.share([380.0, 260.0, 70.0], sigma, 3)
    c_ = tk.share([200.0, 400.0, 100.0], sigma, 3)
    f.add(
        "take-noise-diff",
        "two shares within the noise and one beyond it, at each z",
        sec,
        {
            "a": [412.0, 240.0, 61.0],
            "b": [380.0, 260.0, 70.0],
            "c": [200.0, 400.0, 100.0],
            "sigma": sigma,
        },
        {
            "p": [a["p"], b["p"], c_["p"]],
            "sigma_p": [a["sigma_p"], b["sigma_p"], c_["sigma_p"]],
            "ab_within": {
                str(z): tk.within_noise(a["p"], a["sigma_p"], b["p"], b["sigma_p"], z)
                for z in (80, 90, 95)
            },
            "ac_within": {
                str(z): tk.within_noise(a["p"], a["sigma_p"], c_["p"], c_["sigma_p"], z)
                for z in (80, 90, 95)
            },
        },
    )
    f.add(
        "take-noise-too-few",
        "N below 10σ renders as too few votes",
        sec,
        {"counts": [90.0, 60.0, 20.0], "sigma": sigma},
        tk.share([90.0, 60.0, 20.0], sigma, 3),
    )
    f.add(
        "take-noise-negative-n",
        "a negative N fails the gap test",
        sec,
        {"counts": [-20.0, 5.0, 3.0], "sigma": sigma},
        tk.share([-20.0, 5.0, 3.0], sigma, 3),
    )
    d = tk.difference(412.0, 240.0, 61.0, sigma)
    f.add(
        "take-noise-agree-minus-disagree",
        "agreeMinusDisagree with σ_d",
        sec,
        {"agree": 412.0, "disagree": 240.0, "unsure": 61.0, "sigma": sigma},
        d,
    )
    f.add(
        "take-noise-pooled",
        "pooled σ over three releases",
        sec,
        {"sigmas": [18.3869, 19.0, 10.3376]},
        {"pooled_sigma": tk.pooled_sigma([18.3869, 19.0, 10.3376])},
    )
    # measures
    sec = "Query spec"
    movement = [
        {"first": i, "second": j, "n": n}
        for (i, j), n in zip(
            [(a_, b_) for a_ in range(3) for b_ in range(3)],
            [120.0, 30.0, 25.0, 40.0, 90.0, 15.0, 22.0, 18.0, 60.0],
            strict=True,
        )
    ]
    for meas, name in (
        (tk.MOVED_TOWARD, "toward"),
        (tk.MOVED_AWAY, "away"),
        (tk.UNCHANGED, "unchanged"),
    ):
        f.add(
            "take-measure-moved",
            f"moved{name.capitalize() if name != 'unchanged' else ''} over a fixed movement table ({name})",
            sec,
            {"movement_rows": movement, "sigma": 7.5, "measure": meas},
            tk.measure(meas, movement, 7.5),
        )
    mapt = [{"x": x, "y": y, "n": float((x * 7 + y * 3) % 11)} for x in range(4) for y in range(4)]
    f.add(
        "take-measure-mapcell",
        "mapCell at [2, 3]",
        sec,
        {"map_rows": mapt, "sigma": 3.6227, "cell": [2, 3]},
        tk.measure(tk.MAP_CELL, mapt, 3.6227, cell=[2, 3]),
    )
    row = {"agree": 412.0, "disagree": 240.0, "unsure": 61.0}
    for meas in (tk.AGREE_SHARE, tk.DISAGREE_SHARE, tk.UNSURE_SHARE, tk.AGREE_MINUS_DISAGREE):
        f.add(
            "take-measure",
            f"measure {meas} on a tallies row",
            sec,
            {"row": row, "sigma": sigma, "measure": meas},
            tk.measure(meas, [row], sigma),
        )
    f.add(
        "take-measure",
        "measure 4 (count) of column disagree",
        sec,
        {"row": row, "sigma": sigma, "measure": 4, "column": "disagree"},
        tk.measure(tk.COUNT, [row], sigma, column="disagree"),
    )
    f.add(
        "take-measure",
        "measure 5 (participants) from nHat",
        sec,
        {"n_hat": 1243, "sigma": sigma, "measure": 5},
        tk.measure(tk.PARTICIPANTS, [{"n": 0}], sigma, n_hat=1243),
    )
    f.add(
        "take-measure",
        "measure 5 (participants) from a group_sizes row",
        sec,
        {"row": {"group": 1, "n": 601}, "sigma": 10.3376, "measure": 5},
        tk.measure(tk.PARTICIPANTS, [{"group": 1, "n": 601}], 10.3376),
    )
    rrow = {"moves": 210.0, "neutral": 90.0, "against": 50.0}
    for meas in (tk.MOVES_ME, tk.AGAINST):
        f.add(
            "take-measure",
            f"measure {meas} on a ratings row",
            sec,
            {"row": rrow, "sigma": 9.1, "measure": meas},
            tk.measure(meas, [rrow], 9.1),
        )
    f.add(
        "take-measure",
        "measure 11 (consensusScore)",
        sec,
        {"row": {"score": 0.4231}, "measure": 11},
        tk.measure(tk.CONSENSUS_SCORE, [{"score": 0.4231}], 0.0),
    )
    f.add(
        "take-measure",
        "measure 12 (repnessScore), not significant",
        sec,
        {"row": {"metric": 1.73, "significant": False}, "measure": 12},
        tk.measure(tk.REPNESS_SCORE, [{"metric": 1.73, "significant": False}], 0.0),
    )
    # queryHash
    sec = "Ratings and versions"
    q = tk.query(
        [tk.series(0, "group_tallies", tk.AGREE_SHARE, statements=[compute_cid(b"s1")], group=0)]
    )
    ch = tk.chart()
    ch2 = tk.chart(type_=1)
    f.add(
        "take-queryhash",
        "queryHash is over [query, chart]; a prose edit keeps it, a chart edit changes it",
        sec,
        {"query": jsonable(q), "chart": jsonable(ch), "chart_edited": jsonable(ch2)},
        {
            "query_hash": hexify(tk.query_hash(q, ch)),
            "query_hash_after_prose_edit": hexify(tk.query_hash(q, ch)),
            "query_hash_after_chart_edit": hexify(tk.query_hash(q, ch2)),
            "hashed_bytes": hexify(tk.QUERY_HASH_DOMAIN + cbor.encode([q, ch])),
        },
    )
    # ranking
    sec = "Gallery ranking"
    cells = [(300.0, 190.0, 19.0, 650.0), (240.0, 260.0, 19.0, 480.0), (120.0, 40.0, 19.0, 200.0)]
    f.add(
        "take-rank-min-group",
        "score is the lowest f_low over groups at or above GATE_CELL (the third group is below the gate)",
        sec,
        {"group_cells": cells, "overall": (660.0, 490.0, 19.0)},
        tk.gallery_score(cells, (660.0, 490.0, 19.0)),
    )
    f.add(
        "take-rank-overall-only",
        "no group past GATE_CELL: score from the overall row, hasGroupScore false",
        sec,
        {"group_cells": [(120.0, 40.0, 19.0, 200.0)], "overall": (660.0, 490.0, 19.0)},
        tk.gallery_score([(120.0, 40.0, 19.0, 200.0)], (660.0, 490.0, 19.0)),
    )
    pooled = tk.pooled_sigma([19.0, 19.0])
    f.add(
        "take-rank-pooled",
        "two rating releases pooled: counts summed, σ combined",
        sec,
        {"release_a": [(300.0, 190.0, 19.0, 650.0)], "release_b": [(280.0, 200.0, 19.0, 610.0)]},
        {"pooled_sigma": pooled, **tk.gallery_score([(580.0, 390.0, pooled, 1260.0)], None)},
    )
    takes = [
        {
            "name": "A",
            "rated": True,
            "hasGroupScore": True,
            "score": 0.5712,
            "forkCount": 2,
            "logIndex": 10,
        },
        {
            "name": "B",
            "rated": True,
            "hasGroupScore": True,
            "score": 0.5712,
            "forkCount": 7,
            "logIndex": 12,
        },
        {
            "name": "C",
            "rated": True,
            "hasGroupScore": False,
            "score": 0.9,
            "forkCount": 0,
            "logIndex": 3,
        },
        {
            "name": "D",
            "rated": False,
            "hasGroupScore": False,
            "score": None,
            "forkCount": 0,
            "logIndex": 20,
        },
        {
            "name": "E",
            "rated": False,
            "hasGroupScore": False,
            "score": None,
            "forkCount": 5,
            "logIndex": 25,
        },
        {
            "name": "F",
            "rated": True,
            "hasGroupScore": True,
            "score": 0.5712004,
            "forkCount": 0,
            "logIndex": 30,
        },
    ]
    f.add(
        "take-rank-unrated-last",
        "sort key (rated, hasGroupScore, score to 6 decimals, forkCount, -logIndex) descending; unrated last, newest first",
        sec,
        {"takes": takes},
        {
            "order": [t["name"] for t in tk.rank(takes)],
            "keys": {
                t["name"]: list(
                    tk.sort_key(
                        t["rated"], t["hasGroupScore"], t["score"], t["forkCount"], t["logIndex"]
                    )
                )
                for t in takes
            },
        },
    )
    f.add(
        "take-render-gap",
        "a series over an unreleased tier is valid and renders as a gap (no numbers)",
        "Query spec",
        {
            "series": jsonable(tk.series(0, "group_tallies", tk.AGREE_SHARE, group=0)),
            "unlocked": [0, 4, 8],
        },
        {"renders": "not released at this size", "valid": True},
    )
    return f


def generate() -> list[File]:
    wd = get_take_world()
    return [world_file(wd), manifests_file(wd), numeric_file()]
