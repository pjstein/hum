"""Type bodies: the per-type schema (verification step 4) and type rules (step 10).

Every body module exposes two callables and registers them with ``manifest``:

- ``schema(env)``: the type's shape rules that read the envelope alone. Raises
  ``TypeRule`` with the spec's rule id. Run at step 4 after the envelope shape.
- ``rules(view)``: the type's step-10 rules. ``view`` is a ``manifest.Resolved``:
  the envelope, the previous version, the log position, the resolver and the
  blobs the phone holds. Raises ``TypeRule``.

Helpers here are the conventions ``context.md`` fixes for every W0-01 body and
that the other body specs adopt: ``rat``, text limits (UTF-8, NFC, no control
characters, byte limits), CIDs, times, enumerations.
"""

from __future__ import annotations

import math
import re
import unicodedata
from fractions import Fraction
from typing import Any

from ..cid import parse_cid

__all__ = [
    "TypeRule",
    "check_cid",
    "check_rat",
    "check_text",
    "is_bytes",
    "is_cid",
    "is_rat",
    "is_text",
    "is_uint",
    "no_unknown_keys",
    "rat_value",
    "require",
    "require_keys",
]

LANG_RE = re.compile(r"^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$")
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")


class TypeRule(Exception):
    """A type rule failed. ``rule`` is the spec's id (``C3``, ``D12``, ``IM-7``, ``20a``)."""

    def __init__(self, rule: str, reason: str) -> None:
        super().__init__(f"{rule}: {reason}")
        self.rule = rule
        self.reason = reason


def require(cond: bool, rule: str, reason: str) -> None:
    if not cond:
        raise TypeRule(rule, reason)


# ---------------------------------------------------------------- predicates


def is_uint(v: Any, lo: int = 0, hi: int | None = None) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= lo and (hi is None or v <= hi)


def is_bytes(v: Any, n: int | None = None, lo: int | None = None, hi: int | None = None) -> bool:
    if not isinstance(v, bytes):
        return False
    if n is not None:
        return len(v) == n
    if lo is not None and len(v) < lo:
        return False
    return not (hi is not None and len(v) > hi)


def is_cid(v: Any) -> bool:
    if not isinstance(v, bytes):
        return False
    try:
        parse_cid(v)
        return True
    except ValueError:
        return False


def is_text(v: Any, limit: int, *, min_bytes: int = 0, pattern: re.Pattern | None = None) -> bool:
    if not isinstance(v, str):
        return False
    b = v.encode("utf-8")
    if not min_bytes <= len(b) <= limit:
        return False
    if not unicodedata.is_normalized("NFC", v):
        return False
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in v):
        return False
    return pattern is None or bool(pattern.match(v))


def is_rat(v: Any) -> bool:
    """A ``rat``: ``[num, den]`` of uints below 2^64, ``den >= 1``, in lowest terms."""
    if not (isinstance(v, list) and len(v) == 2 and all(is_uint(x) for x in v)):
        return False
    num, den = v
    if den < 1 or num >= 1 << 64 or den >= 1 << 64:
        return False
    return math.gcd(num, den) == 1


def rat_value(v: list[int]) -> Fraction:
    return Fraction(v[0], v[1])


# ---------------------------------------------------------------- checks that name a rule


def check_text(v: Any, limit: int, rule: str, what: str, **kw) -> str:
    require(
        is_text(v, limit, **kw), rule, f"{what}: not text within {limit} bytes, NFC, no controls"
    )
    return v


def check_cid(v: Any, rule: str, what: str) -> bytes:
    require(is_cid(v), rule, f"{what}: not a CID")
    return v


def check_rat(v: Any, rule: str, what: str) -> Fraction:
    require(is_rat(v), rule, f"{what}: not a rat in lowest terms")
    return rat_value(v)


def require_keys(body: Any, required: set[int], rule: str, what: str = "body") -> None:
    require(isinstance(body, dict), rule, f"{what} must be a map")
    missing = sorted(k for k in required if k not in body)
    require(not missing, rule, f"{what} missing keys {missing}")


def no_unknown_keys(body: dict, allowed: set[int], rule: str, what: str = "body") -> None:
    unknown = sorted(k for k in body if k not in allowed)
    require(not unknown, rule, f"{what} has unknown keys {unknown}")
