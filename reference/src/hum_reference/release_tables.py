"""Phone/Helper R15 after manifest verification, including sealed keyboxes.

Contracts come from verified manifests and already validated dependency tables.
Derived numerical outputs remain conveniences, not evidence of correct computation.
"""

from __future__ import annotations

from decimal import Decimal
from fractions import Fraction

import pyarrow as pa
import pyarrow.parquet as pq

from . import cbor, hpke, storage
from . import manifest as m
from .bodies import context as cx
from .bodies import deck as dk
from .bodies import release as rb
from .cid import cid, cid_text
from .parquet_tables import DERIVED, EXTRA, PARTS, Contract, TableError, validate_table


def _metadata(data):
    try:
        return {
            k.decode(): v.decode()
            for k, v in (pq.ParquetFile(pa.BufferReader(data)).schema_arrow.metadata or {}).items()
        }
    except (pa.ArrowException, UnicodeError, OSError) as error:
        raise TableError("invalid Parquet metadata") from error


def contract_for(name, deck_cid, deck, release, decoded, metadata):
    """Derive domains and binding metadata; callers cannot supply row-count overrides."""
    body, plan = deck[m.BODY], deck[m.BODY][dk.PLAN]
    cards = tuple(deck[m.REFS][f"card/{i}"] for i in range(len(body[dk.CARDS])))
    n, k = len(cards), release.get(rb.GROUPS_K, 0)
    part = 3 if name == "consensus" and release[rb.STAGE] == 4 else min(PARTS[name])
    if part not in release[rb.UNLOCKED]:
        raise TableError("table part is locked")
    record = release[rb.PARTS][part]
    extras = {}
    arguments = sorted(
        (i, deck[m.REFS][f"card/{i}/{side}"], s)
        for i in range(n)
        for s, side in enumerate(("pro", "con"))
        if f"card/{i}/{side}" in deck[m.REFS]
    )
    argument_keys = sorted({(i, argument) for i, argument, _ in arguments})
    selection = []
    if name in {"covariance", "axes"}:
        size = plan.get(dk.P_COV_STATEMENTS, min(60, n))
        tallies = decoded["tallies"]
        selection = sorted(
            sorted(
                range(n),
                key=lambda i: (
                    -max(1, sum(max(0, tallies[i][x]) for x in ("agree", "disagree", "unsure"))),
                    i,
                ),
            )[:size]
        )
    if name == "tallies":
        keys = [(i,) for i in range(n)]
        extras["hum.n_hat"] = str(release[rb.N_HAT])
    elif name == "count":
        keys = [(d,) for d in range((body[dk.CLOSES] - body[dk.OPENS]) // 86400 + 1)]
    elif name == "movement":
        keys = [(i, a, b) for i in range(n) for a in range(3) for b in range(3)]
    elif name == "moved":
        keys = arguments
    elif name == "ratings":
        keys = argument_keys
    elif name == "breakdown_cells":
        keys = [(v,) for v in sorted(plan[dk.P_BREAKDOWN][dk.BD_VALUES])]
        extras["hum.attribute"] = plan[dk.P_BREAKDOWN][dk.BD_NAME]
    elif name == "breakdown":
        keys = [
            (row["value"], i)
            for row in decoded["breakdown_cells"]
            if row["published"]
            for i in range(n)
        ]
    elif name == "covariance":
        keys = [(i, j) for i in selection for j in selection if i <= j]
        extras.update(
            {
                "hum.cov_scale": str(plan.get(dk.P_COV_SCALE, dk.DEFAULT_COV_SCALE)),
                "hum.n": str(record[rb.PR_N]),
            }
        )
    elif name == "axes":
        keys = [(i,) for i in selection]
        extras.update(
            {"hum.m": str(len(selection)), "hum.grid": str(plan.get(dk.P_GRID, dk.DEFAULT_GRID))}
        )
    elif name == "map":
        grid = plan.get(dk.P_GRID, dk.DEFAULT_GRID)
        keys = [(x, y) for x in range(grid) for y in range(grid)]
    elif name in {"centroids", "group_sizes"}:
        keys = [(g,) for g in range(k)]
        if name == "centroids":
            extras.update(
                {"hum.k": str(k), "hum.blur": str(float(Fraction(*plan.get(dk.P_BLUR, [1, 1]))))}
            )
    elif name == "group_tallies":
        keys = [(g, i) for g in range(k) for i in range(n)]
    elif name == "group_ratings":
        keys = [(g, i, argument) for g in range(k) for i, argument in argument_keys]
    elif name in {"repness", "consensus"}:
        # Rank lengths depend on numerical post-processing. Validate bounds and
        # contiguous ranks after the generic table checks; no expected numeric result.
        keys = None
    else:
        raise TableError("unknown table")
    if name in DERIVED:
        extras["hum.noise_sd"] = str(Decimal(record[rb.PR_SIGMA]) / 1_000_000)
    # These derived annotations have no corresponding manifest field. Require
    # finite numeric annotations; do not claim to verify their oracle computation.
    for key in EXTRA.get(name, set()) - extras.keys():
        try:
            value = Decimal(metadata[key])
            if not value.is_finite() or (
                key in {"hum.half_x", "hum.half_y", "hum.threshold_sigma"} and value <= 0
            ):
                raise ValueError()
        except (KeyError, ArithmeticError, ValueError) as error:
            raise TableError("invalid derived metadata") from error
        extras[key] = metadata[key]
    rows = (
        len(keys)
        if keys is not None
        else pq.ParquetFile(pa.BufferReader(decoded["_raw"])).metadata.num_rows
    )
    return Contract(
        name,
        cid_text(deck_cid),
        part,
        Fraction(*record[rb.PR_RHO]),
        record[rb.PR_SIGMA],
        rows,
        extras,
        tuple(keys) if keys is not None else None,
        cards,
    )


def validate_opened_tables(deck_cid, deck, release, tables):
    """Validate every opened file against already verified deck/release envelopes."""
    body = release[m.BODY]
    if release[m.REFS]["deck"] != deck_cid:
        raise TableError("wrong deck binding")
    expected = {name[2:] for name in release[m.REFS] if name.startswith("t/")}
    if set(tables) != expected:
        raise TableError("missing or unexpected opened table")
    decoded = {}
    order = ["tallies", "breakdown_cells"] + sorted(expected - {"tallies", "breakdown_cells"})
    for name in order:
        if name not in expected:
            continue
        raw = tables[name]
        decoded["_raw"] = raw
        contract = contract_for(name, deck_cid, deck, body, decoded, _metadata(raw))
        rows = validate_table(raw, contract)
        if name == "breakdown_cells" and any(
            r["published"] != (r["n"] >= cx.GATE_CELL) for r in rows
        ):
            raise TableError("breakdown suppression disagrees with cell floor")
        if name == "group_sizes" and sum(r["n"] for r in rows) != body[rb.PARTS][3][rb.PR_N]:
            raise TableError("group sizes disagree with released part total")
        if name in {"consensus", "repness"}:
            groups = range(body[rb.GROUPS_K]) if name == "repness" else [None]
            if name == "repness" and any(r["group"] not in groups for r in rows):
                raise TableError("invalid ranking group")
            for group in groups:
                ranks = [r["rank"] for r in rows if group is None or r["group"] == group]
                if len(ranks) > 15 or ranks != list(range(len(ranks))):
                    raise TableError("ranking bounds or noncontiguous ranks")
        decoded[name] = rows
    decoded.pop("_raw", None)
    return decoded


def open_verified_release(ctx, bundle, *, results_private=None):
    """Verify signatures/log/rules first, then content CIDs, keybox and R15.

    No table is returned if any table fails. No blob resolution is added to the ledger.
    """
    release = m.verify_bundle(ctx, bundle)
    if release[m.TYPE] != "release":
        raise TableError("not a release")
    deck_cid = release[m.REFS]["deck"]
    deck = m.verify_bundle(ctx, ctx.resolver[deck_cid])
    refs = {name[2:]: value for name, value in release[m.REFS].items() if name.startswith("t/")}

    def fetch(value):
        data = ctx.blobs[value]
        if cid(data) != value:
            raise TableError("blob CID mismatch")
        return data

    opened = {}
    if release[m.BODY][rb.SEALED]:
        if results_private is None:
            raise TableError("results private key required")
        items = cbor.decode(
            hpke.open_keybox(results_private, deck_cid, fetch(release[m.REFS]["keybox"]))
        )
        if not isinstance(items, list) or len(items) != len(refs):
            raise TableError("keybox table count")
        for name, item in zip(sorted(refs), items, strict=True):
            reference = storage.SealedReference.decode(cbor.encode(item))
            if (
                reference.cid != refs[name]
                or reference.format != 1
                or reference.key is None
                or reference.media != "application/vnd.apache.parquet"
            ):
                raise TableError("keybox table binding or format")
            opened[name] = reference.open(fetch(refs[name]))
    else:
        opened = {name: fetch(value) for name, value in refs.items()}
    return validate_opened_tables(deck_cid, deck, release, opened)


def rating_group_rows(tables):
    """Reader post-processing: publish group shares only at GATE_CELL (take.md).

    Physical group tables retain the k*cards / k rows required by release.md.
    This returns only rows eligible for a group share, without clamping raw sums.
    """
    eligible = {row["group"] for row in tables["group_sizes"] if row["n"] >= cx.GATE_CELL}
    return [row for row in tables["group_tallies"] if row["group"] in eligible]


def rating_fixture_tables(deck_cid, deck, body, group_sizes=None):
    """Synthetic noised sum fixture for a rating release; never a noise sampler."""
    from .parquet_tables import encode_table

    n, k = len(deck[m.BODY][dk.CARDS]), body[rb.GROUPS_K]
    if group_sizes is None:
        q, r = divmod(body[rb.PARTS][3][rb.PR_N], k)
        group_sizes = [q + (g < r) for g in range(k)]
    if len(group_sizes) != k or sum(group_sizes) != body[rb.PARTS][3][rb.PR_N]:
        raise ValueError("group fixture does not match the released total")
    cards = [deck[m.REFS][f"card/{i}"] for i in range(n)]
    rows = {
        "tallies": [
            {"card": i, "statement": cards[i], "agree": -2, "disagree": 12, "unsure": 0}
            for i in range(n)
        ],
        "group_sizes": [{"group": g, "n": group_sizes[g]} for g in range(k)],
        "group_tallies": [
            {"group": g, "card": i, "statement": cards[i], "agree": -2, "disagree": 12, "unsure": 0}
            for g in range(k)
            for i in range(n)
        ],
    }
    return {
        name: encode_table(
            name, values, contract_for(name, deck_cid, deck, body, {}, {}).required_metadata()
        )
        for name, values in rows.items()
    }


def fixture_tables(deck_cid, deck, body, names):
    """Complete synthetic table transports; derived values are not oracle fixtures.

    Counts are supplied test inputs. This helper draws no noise and makes no claim
    that its arbitrary derived columns were computed by an aggregator.
    """
    from .parquet_tables import KEYS, SCHEMAS, encode_table

    output, decoded = {}, {}
    order = ["tallies", "breakdown_cells"] + sorted(set(names) - {"tallies", "breakdown_cells"})
    for name in order:
        if name not in names:
            continue
        metadata = {key: "1" for key in EXTRA.get(name, set())}
        decoded["_raw"] = encode_table(name, [], {})
        contract = contract_for(name, deck_cid, deck, body, decoded, metadata)
        rows = []
        for index, key in enumerate(contract.expected_keys or ()):
            row = {
                column: (
                    False
                    if pa.types.is_boolean(dtype)
                    else b"\x01" + bytes(32)
                    if pa.types.is_fixed_size_binary(dtype)
                    else 0.0
                    if pa.types.is_floating(dtype)
                    else 0
                )
                for column, dtype in SCHEMAS[name]
            }
            row.update(zip(KEYS[name], key, strict=True))
            if "statement" in row:
                row["statement"] = contract.card_cids[row["card"]]
            if name in {"tallies", "group_tallies", "breakdown"}:
                row.update(agree=-2, disagree=12, unsure=0)
            if name == "breakdown_cells":
                row.update(n=299 + index % 2, published=bool(index % 2))
            if name == "group_sizes":
                q, r = divmod(body[rb.PARTS][3][rb.PR_N], body[rb.GROUPS_K])
                row["n"] = q + (index < r)
            if name == "map" and index == 0:
                row["n"] = body[rb.PARTS][2][rb.PR_N]
            if name == "covariance" and index == 0:
                row["s"] = float(body[rb.PARTS][1][rb.PR_N])
            rows.append(row)
        output[name] = encode_table(name, rows, contract.required_metadata())
        decoded[name] = rows
    return output
