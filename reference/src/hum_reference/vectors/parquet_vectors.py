"""R15 decoded tables against a trusted eighteen-card contract."""

from __future__ import annotations

from fractions import Fraction

from ..parquet_tables import Contract, TableError, encode_table, validate_table
from . import File, jsonable


def generate() -> list[File]:
    f = File(
        "release",
        "parquet",
        "Parquet bytes are transport examples, not canonical bytes. Compare decoded rows, logical types and metadata. This standalone R15 helper requires a trusted complete contract; release-world integration remains pending.",
    )
    cards = tuple(b"\x01" + bytes([i]) * 32 for i in range(18))
    rows = [
        {"card": i, "statement": cards[i], "agree": -2, "disagree": 12, "unsure": 0}
        for i in range(18)
    ]
    contract = Contract(
        "tallies",
        "btest-deck",
        0,
        Fraction(1, 20),
        1_000_000,
        18,
        {"hum.n_hat": "10"},
        tuple((i,) for i in range(18)),
        cards,
    )
    metadata = contract.required_metadata()
    domain = {
        "name": "tallies",
        "rows": 18,
        "metadata": metadata,
        "keys": [[i] for i in range(18)],
        "card_cids": [x.hex() for x in cards],
    }

    def add(suffix, candidate_rows, md, accepted=False):
        raw = encode_table("tallies", candidate_rows, md)
        inputs = {"parquet": raw.hex(), "contract": domain}
        if accepted:
            decoded = validate_table(raw, contract)
            f.add(
                suffix,
                "Eighteen cards; negative noised sums remain unchanged",
                "R15; Tables",
                inputs,
                expected={"rows": jsonable(decoded), "metadata": md},
            )
        else:
            try:
                validate_table(raw, contract)
            except TableError as error:
                f.add(
                    suffix,
                    str(error),
                    "R15; Tables",
                    inputs,
                    rejection={"step": 10, "check": "R15", "reason": str(error)},
                )
            else:
                raise AssertionError("bad table accepted")

    add("valid", rows, metadata, True)
    add("seventeen-rows", rows[:-1], metadata)
    for key, value in (
        ("hum.deck", "wrong"),
        ("hum.sigma", "1.000001"),
        ("hum.rho", "1/19"),
        ("hum.part", "3"),
        ("hum.n_hat", "11"),
    ):
        add("wrong-" + key[4:], rows, {**metadata, key: value})
    add("missing-metadata", rows, {k: v for k, v in metadata.items() if k != "hum.spec"})
    add("unsorted", list(reversed(rows)), metadata)
    add("duplicate", [rows[0]] + rows[:-1], metadata)
    add("null", [{**rows[0], "agree": None}] + rows[1:], metadata)
    add("wrong-statement", [{**rows[0], "statement": cards[1]}] + rows[1:], metadata)
    return [f]
