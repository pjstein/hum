import hashlib
import math

import pytest

from hum_reference import cbor
from hum_reference import manifest as m
from hum_reference.bodies import take as tk
from hum_reference.cid import cid


def test_query_hash_covers_query_and_chart():
    q = tk.query([tk.series(0, "tallies", tk.AGREE_SHARE)])
    ch = tk.chart()
    assert (
        tk.query_hash(q, ch) == hashlib.sha256(b"hum/take-query/1" + cbor.encode([q, ch])).digest()
    )
    assert tk.query_hash(q, ch) != tk.query_hash(q, tk.chart(type_=1))


def test_text_blob_limits():
    data = tk.encode_text_blob("T", "b", ["A"], "p")
    assert tk.decode_text_blob(data)["labels"] == ["A"]
    from hum_reference.bodies import TypeRule

    with pytest.raises(TypeRule) as e:
        tk.decode_text_blob(tk.encode_text_blob("T", "b", ["A"], "x" * 16_001))
    assert e.value.rule == "TK-2"


def test_share_and_difference_formulas():
    r = tk.share([412.0, 240.0, 61.0], 18.0, 3)
    n = 713.0
    p = 412.0 / n
    assert math.isclose(r["p"], p)
    assert math.isclose(r["sigma_p"], (18.0 / n) * math.sqrt((1 - p) ** 2 + 2 * p * p))
    assert tk.share([90.0, 60.0, 20.0], 18.0, 3)["too_few"]
    assert tk.share([-5.0, 2.0, 1.0], 1.0, 3)["too_few"]
    d = tk.difference(412.0, 240.0, 61.0, 18.0)
    dd = (412.0 - 240.0) / n
    assert math.isclose(
        d["sigma_d"], (18.0 / n) * math.sqrt((1 - dd) ** 2 + (1 + dd) ** 2 + dd * dd)
    )
    lo, hi = tk.interval(0.98, 0.05, 95)
    assert hi == 1.0 and math.isclose(lo, 0.98 - 1.96 * 0.05)
    assert tk.within_noise(0.50, 0.03, 0.52, 0.03, 90)
    assert not tk.within_noise(0.50, 0.03, 0.70, 0.03, 90)
    assert math.isclose(tk.pooled_sigma([3.0, 4.0]), 5.0)


def test_movement_measures_use_release_direction_rule():
    rows = [{"first": i, "second": j, "n": 10.0} for i in range(3) for j in range(3)]
    toward = tk.measure(tk.MOVED_TOWARD, rows, 1.0)
    away = tk.measure(tk.MOVED_AWAY, rows, 1.0)
    same = tk.measure(tk.UNCHANGED, rows, 1.0)
    assert math.isclose(toward["p"], 1 / 3) and math.isclose(away["p"], 1 / 3)
    assert math.isclose(same["p"], 1 / 3)
    # σ per bucket is σ√3 before the share formula
    assert math.isclose(toward["sigma_p"], tk.share([30.0, 30.0, 30.0], math.sqrt(3), 3)["sigma_p"])


def test_gallery_score_and_sort():
    cells = [(300.0, 190.0, 19.0, 650.0), (240.0, 260.0, 19.0, 480.0), (120.0, 40.0, 19.0, 200.0)]
    s = tk.gallery_score(cells, (660.0, 490.0, 19.0))
    assert s["rated"] and s["hasGroupScore"]
    f = tk.fair_share(240.0, 260.0, 19.0)
    assert math.isclose(s["score"], f["f_low"])
    only = tk.gallery_score([(120.0, 40.0, 19.0, 200.0)], (660.0, 490.0, 19.0))
    assert only["rated"] and not only["hasGroupScore"]
    assert not tk.gallery_score([], None)["rated"]
    order = tk.rank(
        [
            {
                "name": "rated",
                "rated": True,
                "hasGroupScore": True,
                "score": 0.4,
                "forkCount": 0,
                "logIndex": 1,
            },
            {
                "name": "new-unrated",
                "rated": False,
                "hasGroupScore": False,
                "score": None,
                "forkCount": 0,
                "logIndex": 9,
            },
            {
                "name": "old-unrated",
                "rated": False,
                "hasGroupScore": False,
                "score": None,
                "forkCount": 0,
                "logIndex": 2,
            },
        ]
    )
    assert [t["name"] for t in order] == ["rated", "new-unrated", "old-unrated"]  # newest first


def test_measure_table_compatibility():
    assert tk.MAP_CELL in tk.MEASURE_TABLES["map"]
    assert tk.AGREE_SHARE not in tk.MEASURE_TABLES["map"]
    assert tk.PARTICIPANTS in tk.MEASURE_TABLES["group_sizes"]
    assert tk.measure(tk.PARTICIPANTS, [{"n": 7}], 1.0, n_hat=1243)["value"] == 1243
    with pytest.raises(ValueError):
        tk.measure(tk.MAP_CELL, [{"x": 0, "y": 0, "n": 1}], 1.0, cell=[3, 3])


def test_schema_rejects_bad_shapes():
    from hum_reference.bodies import TypeRule

    good = tk.body(
        author=0, query_=tk.query([tk.series(0, "tallies", 0)]), chart_=tk.chart(), sealed=False
    )
    env = m.envelope("take", good, authority=cid(b"a"), issued=1, refs={})
    tk.schema(env)
    bad = dict(good)
    bad[tk.CHART] = tk.chart(interval="90")
    with pytest.raises(TypeRule) as e:
        tk.schema(m.envelope("take", bad, authority=cid(b"a"), issued=1, refs={}))
    assert e.value.rule == "TK-7"


def test_take_world_cases_and_determinism():
    from hum_reference.vectors import rating_vectors as rv
    from hum_reference.vectors import take_vectors as tv

    files = tv.generate()
    by_name = {f.name: f for f in files}
    ids = {c["id"].split("/")[-1].rsplit("-", 1)[0] for c in by_name["manifests"].cases}
    for want in (
        "tk-ok-one-release",
        "tk-ok-agent",
        "tk-bad-sig",
        "tk-bad-self-fork",
        "tk-bad-fork-unsealed",
    ):
        assert want in ids
    rules = {c["rejection"]["rule"] for c in by_name["manifests"].cases if "rejection" in c}
    assert rules == {f"TK-{i}" for i in range(1, 10)}
    rating = rv.generate()
    assert {f.spec for f in rating} == {"deck", "release"}
    import json

    first = json.dumps([f.cases for f in files + rating], sort_keys=True)
    tv.get_take_world.cache_clear()
    second = json.dumps([f.cases for f in tv.generate() + rv.generate()], sort_keys=True)
    assert first == second
