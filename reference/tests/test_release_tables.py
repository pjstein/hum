"""R15 contracts and sealed transport; manifest verification is tested separately."""

import copy
from fractions import Fraction
from types import SimpleNamespace

import pytest

from hum_reference import cbor, hpke, storage
from hum_reference import manifest as m
from hum_reference.bodies import deck as dk
from hum_reference.bodies import release as rb
from hum_reference.cid import cid
from hum_reference.parquet_tables import TableError, encode_table
from hum_reference.release_tables import (
    _metadata,
    contract_for,
    open_verified_release,
    rating_fixture_tables,
    rating_group_rows,
    validate_opened_tables,
)


def fixture():
    deck = {
        m.BODY: {dk.CARDS: [0, 1], dk.PLAN: {}, dk.OPENS: 0, dk.CLOSES: 86400},
        m.REFS: {f"card/{i}": cid(bytes([i])) for i in range(2)},
    }
    deck_cid = cid(cbor.encode(deck))
    body = {
        rb.STAGE: 1,
        rb.GROUPS_K: 2,
        rb.UNLOCKED: [0, 3],
        rb.N_HAT: 599,
        rb.SEALED: False,
        rb.PARTS: {
            0: rb.part_record(Fraction(1, 2), 1000000, 599),
            3: rb.part_record(Fraction(1, 2), 1000000, 599),
        },
    }
    tables = rating_fixture_tables(deck_cid, deck, body, [299, 300])
    release = {
        m.TYPE: "release",
        m.BODY: body,
        m.REFS: {"deck": deck_cid, **{f"t/{n}": cid(v) for n, v in tables.items()}},
    }
    return deck_cid, deck, release, tables


def test_manifest_derived_contracts_and_cell_floor():
    dc, deck, release, tables = fixture()
    rows = validate_opened_tables(dc, deck, release, tables)
    assert len(rows["group_tallies"]) == 4
    assert [r["group"] for r in rating_group_rows(rows)] == [1, 1]
    assert all(r["agree"] == -2 for r in rows["tallies"])
    for replacement in ({}, {**tables, "other": tables["tallies"]}):
        with pytest.raises(TableError, match="opened table"):
            validate_opened_tables(dc, deck, release, replacement)
    for key, value in [("hum.deck", "wrong"), ("hum.n_hat", "600"), ("hum.rho", "1/3")]:
        bad = encode_table("tallies", rows["tallies"], {**_metadata(tables["tallies"]), key: value})
        with pytest.raises(TableError, match="metadata"):
            validate_opened_tables(dc, deck, release, {**tables, "tallies": bad})
    bad = encode_table(
        "group_tallies", rows["group_tallies"][:-1], _metadata(tables["group_tallies"])
    )
    with pytest.raises(TableError, match="row count"):
        validate_opened_tables(dc, deck, release, {**tables, "group_tallies": bad})


def test_covariance_selection_uses_clamped_ns_and_card_tie_order():
    dc, deck, release, _ = fixture()
    deck[m.BODY][dk.PLAN][dk.P_COV_STATEMENTS] = 1
    release[m.BODY][rb.UNLOCKED].append(1)
    release[m.BODY][rb.PARTS][1] = release[m.BODY][rb.PARTS][0]
    # Both ns values are one, so card 0 wins despite its negative raw count.
    decoded = {
        "tallies": [
            {"agree": -5, "disagree": 0, "unsure": 0},
            {"agree": 1, "disagree": 0, "unsure": 0},
        ]
    }
    contract = contract_for("covariance", dc, deck, release[m.BODY], decoded, {})
    assert contract.expected_keys == ((0, 0),)


def test_public_and_sealed_opening_reject_tampering_before_return(monkeypatch):
    dc, deck, release, tables = fixture()
    ctx = SimpleNamespace(resolver={dc: deck}, blobs={cid(v): v for v in tables.values()})
    verified = []

    def verify(context, bundle):
        verified.append(bundle)
        return bundle

    monkeypatch.setattr(m, "verify_bundle", verify)
    expected = open_verified_release(ctx, release)
    assert verified == [release, deck]
    first = release[m.REFS]["t/tallies"]
    ctx.blobs[first] += b"x"
    with pytest.raises(TableError, match="CID"):
        open_verified_release(ctx, release)
    refs = []
    for index, name in enumerate(sorted(tables)):
        ref, sealed = storage.SealedReference.direct(
            tables[name], bytes([index + 1]) * 16, "application/vnd.apache.parquet"
        )
        refs.append(ref.to_item())
        release[m.REFS][f"t/{name}"] = ref.cid
        ctx.blobs[ref.cid] = sealed
    release[m.BODY][rb.SEALED] = True
    private = bytes([7]) * 32

    def keybox(items):
        raw = hpke.seal_keybox(
            hpke.public_key(private), dc, cbor.encode(items), ephemeral_private=bytes([8]) * 32
        )
        ctx.blobs[cid(raw)] = raw
        release[m.REFS]["keybox"] = cid(raw)

    keybox(refs)
    assert open_verified_release(ctx, release, results_private=private) == expected
    with pytest.raises(TableError, match="private key"):
        open_verified_release(ctx, release)
    keybox(list(reversed(refs)))
    with pytest.raises(TableError, match="binding"):
        open_verified_release(ctx, release, results_private=private)
    keybox(refs[:-1])
    with pytest.raises(TableError, match="count"):
        open_verified_release(ctx, release, results_private=private)
    bad = copy.deepcopy(refs)
    bad[0][storage.REF_MEDIA] = "application/octet-stream"
    keybox(bad)
    with pytest.raises(TableError, match="binding"):
        open_verified_release(ctx, release, results_private=private)


def test_actual_signed_rating_world_opens_real_parquet():
    from hum_reference.vectors import take_vectors as tv

    world = tv.get_take_world()
    bundle = next(case[-1] for case in world.rating_release_cases if case[0] == "valid-rating")
    tables = open_verified_release(world.w.context(now=tv.NOW), bundle)
    assert set(tables) == {"tallies", "group_tallies", "group_sizes"}
    assert len(tables["group_sizes"]) == 2


def test_breakdown_domains_are_sorted_independently_of_declared_value_order():
    dc, deck, release, _ = fixture()
    deck[m.BODY][dk.PLAN][dk.P_BREAKDOWN] = {dk.BD_NAME: "ward", dk.BD_VALUES: [2, 1]}
    release[m.BODY][rb.UNLOCKED].append(7)
    release[m.BODY][rb.PARTS][7] = release[m.BODY][rb.PARTS][0]
    contract = contract_for("breakdown_cells", dc, deck, release[m.BODY], {}, {})
    assert contract.expected_keys == ((1,), (2,))


def test_signed_public_and_sealed_stages_open_without_placeholder_blobs():
    from hum_reference import fixtures
    from hum_reference.bodies import context as cx
    from hum_reference.vectors import deck_vectors as dv

    world = dv.get_world()
    private, _ = cx.results_key(fixtures.fixed_bytes("results-epoch-3", 16))
    checked = set()
    for name, _, rule, bundle in world.releases.cases:
        if name.startswith(("valid-four-stages-v", "valid-public-v")) and rule is None:
            tables = open_verified_release(
                world.w.context(now=fixtures.NOW), bundle, results_private=private
            )
            assert tables["tallies"][0]["agree"] == -2
            checked.add(name)
    assert len(checked) == 8


def test_group_part_total_binds_opened_group_sizes():
    dc, deck, release, tables = fixture()
    rows = validate_opened_tables(dc, deck, release, tables)
    rows["group_sizes"][0]["n"] += 1
    bad = encode_table("group_sizes", rows["group_sizes"], _metadata(tables["group_sizes"]))
    with pytest.raises(TableError, match="part total"):
        validate_opened_tables(dc, deck, release, {**tables, "group_sizes": bad})


def test_all_sixteen_contracts_use_complete_plan_domains():
    from hum_reference.parquet_tables import SCHEMAS
    from hum_reference.release_tables import fixture_tables

    dc, deck, release, _ = fixture()
    deck[m.BODY][dk.PLAN].update(
        {
            dk.P_COV_STATEMENTS: 2,
            dk.P_GRID: 2,
            dk.P_BREAKDOWN: {dk.BD_NAME: "ward", dk.BD_VALUES: [2, 1]},
        }
    )
    for index in range(2):
        for side in ("pro", "con"):
            deck[m.REFS][f"card/{index}/{side}"] = cid(f"{index}/{side}".encode())
    release[m.BODY][rb.STAGE] = 4
    release[m.BODY][rb.UNLOCKED] = list(range(9))
    release[m.BODY][rb.PARTS] = {
        p: rb.part_record(Fraction(1, 100), 1000000, 599) for p in range(9)
    }
    tables = fixture_tables(dc, deck, release[m.BODY], SCHEMAS)
    release[m.REFS] = {"deck": dc, **{f"t/{name}": cid(data) for name, data in tables.items()}}
    rows = validate_opened_tables(dc, deck, release, tables)
    assert set(rows) == set(SCHEMAS)
    assert len(rows["movement"]) == 18
    assert len(rows["moved"]) == len(rows["ratings"]) == 4
    assert len(rows["group_ratings"]) == 8
    assert len(rows["covariance"]) == 3
    assert len(rows["map"]) == 4
    assert [r["value"] for r in rows["breakdown"]] == [2, 2]
    assert [r["published"] for r in rows["breakdown_cells"]] == [False, True]
