"""Decoded-row release-table validation (release.md Tables and R15).

Parquet bytes are generated for transport tests only. Cross-implementation comparison
uses decoded rows, logical types and metadata, never writer-specific bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

I32, I64, I8, F64, CID, BOOL = (
    pa.int32(),
    pa.int64(),
    pa.int8(),
    pa.float64(),
    pa.binary(33),
    pa.bool_(),
)
TALLY = [("card", I32), ("statement", CID), ("agree", I64), ("disagree", I64), ("unsure", I64)]
RATING = [("card", I32), ("argument", CID), ("moves", I64), ("neutral", I64), ("against", I64)]
# Repeated column names retain the type of their definition in the Tables section.
SCHEMAS = {
    "tallies": TALLY,
    "count": [("day", I32), ("ballots", I64)],
    "movement": [("card", I32), ("statement", CID), ("first", I8), ("second", I8), ("n", I64)],
    "moved": [("card", I32), ("argument", CID), ("side", I8), ("n", I64)],
    "ratings": RATING,
    "breakdown_cells": [("value", I64), ("n", I64), ("published", BOOL)],
    "breakdown": [("value", I64)] + TALLY,
    "covariance": [("i", I32), ("j", I32), ("s", F64)],
    "axes": [("card", I32), ("mu", F64), ("pc1", F64), ("pc2", F64)],
    "map": [("x", I32), ("y", I32), ("n", I64)],
    "centroids": [("group", I32), ("x", F64), ("y", F64)],
    "group_tallies": [("group", I32)] + TALLY,
    "group_sizes": [("group", I32), ("n", I64)],
    "group_ratings": [("group", I32)] + RATING,
    "repness": [
        ("group", I32),
        ("rank", I32),
        ("card", I32),
        ("statement", CID),
        ("direction", I8),
        ("metric", F64),
        ("significant", BOOL),
    ],
    "consensus": [("rank", I32), ("card", I32), ("statement", CID), ("score", F64)],
}
KEYS = {
    "tallies": ("card",),
    "count": ("day",),
    "movement": ("card", "first", "second"),
    "moved": ("card", "argument", "side"),
    "ratings": ("card", "argument"),
    "breakdown_cells": ("value",),
    "breakdown": ("value", "card"),
    "covariance": ("i", "j"),
    "axes": ("card",),
    "map": ("x", "y"),
    "centroids": ("group",),
    "group_tallies": ("group", "card"),
    "group_sizes": ("group",),
    "group_ratings": ("group", "card", "argument"),
    "repness": ("group", "rank"),
    "consensus": ("rank",),
}
EXTRA = {
    "tallies": {"hum.n_hat"},
    "breakdown_cells": {"hum.attribute"},
    "covariance": {"hum.cov_scale", "hum.n"},
    "axes": {"hum.lambda1", "hum.lambda2", "hum.half_x", "hum.half_y", "hum.grid", "hum.m"},
    "centroids": {"hum.k", "hum.blur", "hum.threshold_sigma"},
}
DERIVED = {"axes", "centroids", "repness", "consensus"}
PARTS = {
    "tallies": {0},
    "count": {4},
    "movement": {5},
    "moved": {5},
    "ratings": {6},
    "breakdown_cells": {7},
    "breakdown": {7},
    "covariance": {1},
    "axes": {1},
    "map": {2},
    "centroids": {2},
    "group_tallies": {3},
    "group_sizes": {3},
    "group_ratings": {3},
    "repness": {3},
    "consensus": {0, 3},
}


class TableError(ValueError):
    """A decoded table fails R15."""


@dataclass(frozen=True)
class Contract:
    """Expected values derived by the caller from a verified release and pinned deck.

    expected_keys is the complete expected domain (not a sample); use it when the
    plan fixes card/group/grid coordinates. Extra metadata must be supplied from
    the plan/body or verified sum tables, not copied from the untrusted file.
    """

    name: str
    deck: str
    part: int
    rho: Fraction
    sigma_micro: int
    rows: int
    metadata: dict[str, str] = field(default_factory=dict)
    expected_keys: tuple[tuple, ...] | None = None
    card_cids: tuple[bytes, ...] | None = None

    def required_metadata(self) -> dict[str, str]:
        return {
            **self.metadata,
            "hum.spec": "release/1",
            "hum.deck": self.deck,
            "hum.part": str(self.part),
            "hum.rho": f"{self.rho.numerator}/{self.rho.denominator}",
            "hum.sigma": str(Decimal(self.sigma_micro) / 1_000_000),
        }


def encode_table(name: str, rows: list[dict[str, Any]], metadata: dict[str, str]) -> bytes:
    """Reference writer; decoded content rather than these bytes is normative."""
    schema = pa.schema(
        SCHEMAS[name], metadata={k.encode(): v.encode() for k, v in sorted(metadata.items())}
    )
    table = pa.Table.from_pylist(rows, schema=schema)
    out = pa.BufferOutputStream()
    pq.write_table(table, out, compression="NONE", use_dictionary=False, version="2.6")
    return out.getvalue().to_pybytes()


def validate_table(data: bytes, contract: Contract) -> list[dict[str, Any]]:
    """Validate an opened table against its trusted, explicit R15 contract."""
    if contract.name not in SCHEMAS or contract.part not in PARTS[contract.name]:
        raise TableError("table or part is not defined")
    try:
        table = pq.read_table(pa.BufferReader(data))
        md = {k.decode(): v.decode() for k, v in (table.schema.metadata or {}).items()}
    except (pa.ArrowException, UnicodeError, OSError) as e:
        raise TableError("invalid Parquet or metadata") from e
    if [(f.name, f.type) for f in table.schema] != SCHEMAS[contract.name]:
        raise TableError("columns or logical types differ")
    if table.num_rows != contract.rows or any(col.null_count for col in table.columns):
        raise TableError("row count or null cell")
    expected = contract.required_metadata()
    extra = EXTRA.get(contract.name, set()) | (
        {"hum.noise_sd"} if contract.name in DERIVED else set()
    )
    if not extra <= contract.metadata.keys():
        raise TableError("trusted contract is missing table-specific metadata")
    required = set(expected) | extra
    if not required <= md.keys():
        raise TableError("required metadata missing")
    for key, value in expected.items():
        if key in {
            "hum.sigma",
            "hum.noise_sd",
            "hum.n_hat",
            "hum.n",
            "hum.grid",
            "hum.m",
            "hum.k",
            "hum.cov_scale",
            "hum.blur",
        }:
            try:
                same = Decimal(md[key]) == Decimal(value) and Decimal(md[key]).is_finite()
            except InvalidOperation:
                same = False
        else:
            same = md.get(key) == value
        if not same:
            raise TableError(f"metadata mismatch: {key}")
    rows = table.to_pylist()
    keys = [tuple(row[k] for k in KEYS[contract.name]) for row in rows]
    if keys != sorted(keys) or len(set(keys)) != len(keys):
        raise TableError("key order or duplicate key")
    if contract.expected_keys is not None and tuple(keys) != contract.expected_keys:
        raise TableError("row coordinates differ from plan")
    for row in rows:
        if contract.card_cids is not None and "statement" in row:
            card = row["card"]
            if (
                not 0 <= card < len(contract.card_cids)
                or row["statement"] != contract.card_cids[card]
            ):
                raise TableError("statement differs from the pinned card")
        for name in ("statement", "argument"):
            if name in row and row[name][0] != 1:
                raise TableError("invalid CID algorithm")
        for name, limit in (("first", 2), ("second", 2), ("side", 1), ("direction", 1)):
            if name in row and not 0 <= row[name] <= limit:
                raise TableError("invalid categorical value")
        if contract.name == "covariance" and row["i"] > row["j"]:
            raise TableError("covariance is not upper triangular")
    return rows
