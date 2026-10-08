"""Deterministic CBOR, RFC 8949 section 4.2.1 (core deterministic encoding).

Written on purpose rather than taken from a library: the canonical-form rule
(manifest spec, verification step 2) is a thing under test, and a strict
decoder that names the exact violation is what the failing vectors need.

Supported data model, which is all the specs use:

- unsigned and negative integers (major types 0 and 1), any size up to 64 bits
- byte strings and text strings (major types 2 and 3), definite length only
- arrays and maps (major types 4 and 5), definite length only
- ``False``, ``True`` and ``None`` (simple values 20, 21, 22)
- tags (major type 6), used only for COSE structures

No floats: the manifest spec forbids floating point in signed content.

Map keys are sorted by their encoded bytes (bytewise lexicographic), which is
the RFC 8949 rule, not the older RFC 7049 length-first rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["CborError", "Tag", "decode", "dumps", "encode", "is_canonical", "loads"]


class CborError(ValueError):
    """Raised when bytes are not well-formed, not deterministic, or out of the model."""


@dataclass(frozen=True)
class Tag:
    """A tagged value (major type 6)."""

    tag: int
    value: Any


# ---------------------------------------------------------------- encoding


def _head(major: int, arg: int) -> bytes:
    """Encode a major type and its argument in shortest form."""
    if arg < 0:
        raise CborError("negative argument")
    if arg < 24:
        return bytes([(major << 5) | arg])
    if arg < 0x100:
        return bytes([(major << 5) | 24, arg])
    if arg < 0x10000:
        return bytes([(major << 5) | 25]) + arg.to_bytes(2, "big")
    if arg < 0x1_0000_0000:
        return bytes([(major << 5) | 26]) + arg.to_bytes(4, "big")
    if arg < 0x1_0000_0000_0000_0000:
        return bytes([(major << 5) | 27]) + arg.to_bytes(8, "big")
    raise CborError("integer does not fit in 64 bits")


def encode(value: Any) -> bytes:
    """Encode ``value`` deterministically. Raises ``CborError`` for anything outside the model."""
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        if value >= 0:
            return _head(0, value)
        return _head(1, -1 - value)
    if isinstance(value, bytes | bytearray | memoryview):
        b = bytes(value)
        return _head(2, len(b)) + b
    if isinstance(value, str):
        b = value.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(value, list | tuple):
        return _head(4, len(value)) + b"".join(encode(v) for v in value)
    if isinstance(value, dict):
        items = [(encode(k), encode(v)) for k, v in value.items()]
        keys = [k for k, _ in items]
        if len(set(keys)) != len(keys):
            raise CborError("duplicate map key")
        items.sort(key=lambda kv: kv[0])
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    if isinstance(value, Tag):
        return _head(6, value.tag) + encode(value.value)
    if isinstance(value, float):
        raise CborError("floating point is not allowed in signed content")
    raise CborError(f"cannot encode {type(value).__name__}")


dumps = encode


# ---------------------------------------------------------------- decoding


class _Decoder:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def _take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise CborError("truncated")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def _arg(self, info: int) -> int:
        """Read the argument and check it uses the shortest form."""
        if info < 24:
            return info
        if info == 24:
            v = self._take(1)[0]
            if v < 24:
                raise CborError("integer not in shortest form")
            return v
        if info == 25:
            v = int.from_bytes(self._take(2), "big")
            if v < 0x100:
                raise CborError("integer not in shortest form")
            return v
        if info == 26:
            v = int.from_bytes(self._take(4), "big")
            if v < 0x10000:
                raise CborError("integer not in shortest form")
            return v
        if info == 27:
            v = int.from_bytes(self._take(8), "big")
            if v < 0x1_0000_0000:
                raise CborError("integer not in shortest form")
            return v
        if info == 31:
            raise CborError("indefinite length is not allowed")
        raise CborError(f"reserved additional information {info}")

    def item(self) -> Any:
        start = self.pos
        initial = self._take(1)[0]
        major, info = initial >> 5, initial & 0x1F
        if major == 0:
            return self._arg(info)
        if major == 1:
            return -1 - self._arg(info)
        if major == 2:
            return self._take(self._arg(info))
        if major == 3:
            raw = self._take(self._arg(info))
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as e:
                raise CborError("text string is not valid UTF-8") from e
        if major == 4:
            n = self._arg(info)
            return [self.item() for _ in range(n)]
        if major == 5:
            n = self._arg(info)
            out: dict[Any, Any] = {}
            prev: bytes | None = None
            for _ in range(n):
                kstart = self.pos
                key = self.item()
                kbytes = self.data[kstart : self.pos]
                if prev is not None:
                    if kbytes == prev:
                        raise CborError("duplicate map key")
                    if kbytes < prev:
                        raise CborError("map keys not in bytewise order")
                prev = kbytes
                if isinstance(key, list | dict):
                    raise CborError("map key must be a scalar")
                out[key] = self.item()
            return out
        if major == 6:
            return Tag(self._arg(info), self.item())
        # major 7
        if info == 20:
            return False
        if info == 21:
            return True
        if info == 22:
            return None
        if info in (25, 26, 27):
            raise CborError("floating point is not allowed")
        if info == 31:
            raise CborError("break outside indefinite item")
        raise CborError(f"unsupported simple value at offset {start}")


def decode(data: bytes) -> Any:
    """Decode one deterministic CBOR item. Rejects trailing bytes and any non-canonical form."""
    d = _Decoder(bytes(data))
    value = d.item()
    if d.pos != len(d.data):
        raise CborError("trailing bytes after item")
    return value


loads = decode


def is_canonical(data: bytes) -> bool:
    """True when ``data`` decodes and re-encodes to exactly the same bytes."""
    try:
        return encode(decode(data)) == bytes(data)
    except CborError:
        return False
