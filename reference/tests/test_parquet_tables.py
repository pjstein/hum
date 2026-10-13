from dataclasses import replace
from fractions import Fraction

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from hum_reference.parquet_tables import (
    DERIVED,
    EXTRA,
    PARTS,
    SCHEMAS,
    Contract,
    TableError,
    encode_table,
    validate_table,
)


def example(name="tallies", count=1):
    meta = {key: "1" for key in EXTRA.get(name, set())}
    if name in DERIVED:
        meta["hum.noise_sd"] = "1"
    cards = tuple(b"\x01" + bytes([i]) * 32 for i in range(count))
    rows = []
    for i in range(count):
        row = {}
        for column, dtype in SCHEMAS[name]:
            row[column] = (
                cards[i]
                if pa.types.is_fixed_size_binary(dtype)
                else False
                if pa.types.is_boolean(dtype)
                else 0.25
                if pa.types.is_floating(dtype)
                else 0
            )
        if "card" in row:
            row["card"] = i
        if "agree" in row:
            row["agree"] = -2
        rows.append(row)
    contract = Contract(
        name,
        "btest-deck",
        min(PARTS[name]),
        Fraction(1, 20),
        1_000_000,
        count,
        meta,
        card_cids=cards,
    )
    return rows, contract


@pytest.mark.parametrize("name", SCHEMAS)
def test_all_declared_schemas_round_trip_without_clamping(name):
    rows, contract = example(name)
    assert validate_table(encode_table(name, rows, contract.required_metadata()), contract) == rows


def test_r15_eighteen_card_tallies_and_bad_metadata():
    rows, contract = example(count=18)
    raw = encode_table("tallies", rows, contract.required_metadata())
    assert len(validate_table(raw, contract)) == 18
    for key, wrong in (
        ("hum.deck", "wrong"),
        ("hum.sigma", "1.000001"),
        ("hum.rho", "1/19"),
        ("hum.part", "3"),
        ("hum.n_hat", "2"),
    ):
        bad = encode_table("tallies", rows, {**contract.required_metadata(), key: wrong})
        with pytest.raises(TableError, match="metadata"):
            validate_table(bad, contract)
    with pytest.raises(TableError, match="row count"):
        validate_table(encode_table("tallies", rows[:-1], contract.required_metadata()), contract)


def test_order_duplicate_null_cid_and_truncation():
    rows, contract = example(count=2)
    for changed in (
        list(reversed(rows)),
        [rows[0], rows[0]],
        [{**rows[0], "agree": None}, rows[1]],
        [{**rows[0], "statement": b"\x01" + b"x" * 32}, rows[1]],
    ):
        with pytest.raises(TableError):
            validate_table(encode_table("tallies", changed, contract.required_metadata()), contract)
    with pytest.raises(TableError):
        validate_table(b"not parquet", contract)


def test_alternate_writer_encodings_and_required_columns_are_not_rejected():
    rows, contract = example()
    schema = pa.schema(
        [pa.field(n, t, nullable=False) for n, t in SCHEMAS["tallies"]],
        metadata={k.encode(): v.encode() for k, v in contract.required_metadata().items()},
    )
    out = pa.BufferOutputStream()
    pq.write_table(pa.Table.from_pylist(rows, schema=schema), out, compression="snappy")
    assert validate_table(out.getvalue().to_pybytes(), contract) == rows


def test_wrong_logical_type_and_expected_coordinate_domain():
    rows, contract = example()
    table = pa.Table.from_pylist(rows)
    out = pa.BufferOutputStream()
    pq.write_table(table, out)
    with pytest.raises(TableError, match="logical types"):
        validate_table(out.getvalue().to_pybytes(), contract)
    raw = encode_table("tallies", rows, contract.required_metadata())
    with pytest.raises(TableError, match="coordinates"):
        validate_table(raw, replace(contract, expected_keys=((1,),)))


def test_reference_writer_metadata_order_is_stable_across_hash_seeds():
    import os
    import subprocess
    import sys

    script = """
import hashlib
from hum_reference.parquet_tables import encode_table
metadata = {key: "1" for key in {
    "hum.lambda1", "hum.lambda2", "hum.half_x", "hum.half_y", "hum.grid", "hum.m"
}}
print(hashlib.sha256(encode_table("axes", [], metadata)).hexdigest())
"""
    outputs = [
        subprocess.check_output(
            [sys.executable, "-c", script],
            env={**os.environ, "PYTHONHASHSEED": seed},
            text=True,
        )
        for seed in ("1", "2")
    ]
    assert outputs[0] == outputs[1]
