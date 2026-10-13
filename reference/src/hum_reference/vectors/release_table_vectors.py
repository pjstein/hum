"""R15 after full signed-manifest verification, with real rating Parquet blobs."""

from .. import fixtures
from .. import manifest as m
from ..bodies import context as cx
from ..parquet_tables import TableError, encode_table
from ..release_tables import (
    _metadata,
    open_verified_release,
    rating_group_rows,
    validate_opened_tables,
)
from . import File, jsonable
from . import deck_vectors as dv
from . import take_vectors as tv


def row_json(row):
    # Parquet doubles are JSON numbers; they are not Hum CBOR data items.
    return {
        name: jsonable(value) if isinstance(value, bytes) else value for name, value in row.items()
    }


def rows_json(tables):
    return {name: [row_json(row) for row in rows] for name, rows in tables.items()}


def generate():
    world = tv.get_take_world()
    output = File(
        "release",
        "opened-tables",
        notes=[
            "Real signed rating manifests and Parquet blobs. Row-wise expectations are normative; "
            "writer bytes are transport fixtures. No noise-generation or numerical oracle claim.",
            "Mutation cases begin after successful signature/log/manifest verification and test R15 "
            "on opened tables; they are not new logged release manifests.",
        ],
    )
    for label in ("valid-rating", "valid-rating-nhat-400"):
        bundle = next(case[-1] for case in world.rating_release_cases if case[0] == label)
        ctx = world.w.context(now=tv.NOW)
        release = m.verify_bundle(ctx, bundle)
        dc = release[m.REFS]["deck"]
        deck = m.verify_bundle(ctx, ctx.resolver[dc])
        tables = {
            name[2:]: ctx.blobs[value]
            for name, value in release[m.REFS].items()
            if name.startswith("t/")
        }
        rows = open_verified_release(ctx, bundle)
        common = {
            "verified_deck_cid": dc,
            "verified_deck": deck,
            "verified_release": release,
            "tables": tables,
        }
        output.add(
            label,
            "Signed rating release opens all tables; group shares apply GATE_CELL",
            "Validation rules / R15",
            jsonable(common),
            expected={
                "rows": rows_json(rows),
                "eligible_group_rows": [row_json(row) for row in rating_group_rows(rows)],
            },
        )
        if label != "valid-rating":
            continue
        for key, value in [("hum.deck", "wrong"), ("hum.n_hat", "251")]:
            bad = encode_table(
                "tallies", rows["tallies"], {**_metadata(tables["tallies"]), key: value}
            )
            changed = {**tables, "tallies": bad}
            try:
                validate_opened_tables(dc, deck, release, changed)
            except TableError:
                pass
            else:
                raise AssertionError("R15 mutation accepted")
            output.add(
                key.replace(".", "-"),
                "Opened table metadata disagrees with verified manifest",
                "Validation rules / R15",
                jsonable({**common, "tables": changed}),
                rejection={"rule": "R15", "reason": "metadata"},
            )
    staged = dv.get_world()
    private, _ = cx.results_key(fixtures.fixed_bytes("results-epoch-3", 16))
    for label, _, rule, bundle in staged.releases.cases:
        if not label.startswith(("valid-four-stages-v", "valid-public-v")) or rule is not None:
            continue
        ctx = staged.w.context(now=fixtures.NOW)
        release = m.verify_bundle(ctx, bundle)
        deck_cid = release[m.REFS]["deck"]
        rows = open_verified_release(ctx, bundle, results_private=private)
        transport = {
            name: ctx.blobs[value]
            for name, value in release[m.REFS].items()
            if name.startswith("t/") or name == "keybox"
        }
        output.add(
            label,
            "Full signed staged release opens public or HPKE-sealed Parquet",
            "Validation rules / R15",
            jsonable(
                {
                    "verified_release": release,
                    "verified_deck_cid": deck_cid,
                    "verified_deck": m.verify_bundle(ctx, ctx.resolver[deck_cid]),
                    "blobs_by_reference": transport,
                    "results_private_fixture_only": private if "keybox" in transport else None,
                }
            ),
            expected={"rows": rows_json(rows)},
        )
    return [output]
