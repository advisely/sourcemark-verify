"""Deterministic CBOR, written from `spec/canonicalization.md` clause 2.

This is an independent implementation. It shares no code with the emitter,
which is the point: two implementations that agree because they call the same
function agree about nothing. Where it and the emitter disagree, the
specification decides, and one of them has a bug.

The decoder is strict in exactly one direction. Anything a conforming encoder
would never emit is refused rather than accepted and normalized -- indefinite
lengths, non-shortest arguments, out-of-order or duplicate map keys, unknown
tags, trailing bytes. A verifier is handed bytes chosen by whoever wants it to
be wrong; leniency here is not kindness, it is the vulnerability.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import struct
from typing import Any

__all__ = ["encode", "decode", "Tagged", "CborError", "MAX_DEPTH"]

MAX_DEPTH = 64


class CborError(ValueError):
    """The bytes are outside the clause 2 profile. Always MALFORMED."""


class Tagged:
    __slots__ = ("tag", "value")

    def __init__(self, tag: int, value: Any) -> None:
        self.tag, self.value = tag, value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Tagged) and (self.tag, self.value) == (other.tag, other.value)


# --------------------------------------------------------------------------
# Encoding -- only what a verifier needs: hash preimages and Sig_structure
# --------------------------------------------------------------------------


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    for info, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (width * 8):
            return bytes([(major << 5) | info]) + n.to_bytes(width, "big")
    raise CborError(f"argument {n} exceeds 64 bits")


def encode(value: Any, _depth: int = 0) -> bytes:
    if _depth > MAX_DEPTH:
        raise CborError(f"nesting deeper than {MAX_DEPTH}")
    if value is None:
        return b"\xf6"
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -value - 1)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise CborError(f"{value!r} has no canonical encoding")
        return b"\xfb" + struct.pack(">d", value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(encode(v, _depth + 1) for v in value)
    if isinstance(value, dict):
        items = sorted((encode(k, _depth + 1), encode(v, _depth + 1)) for k, v in value.items())
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    if isinstance(value, Tagged):
        return _head(6, value.tag) + encode(value.value, _depth + 1)
    raise CborError(f"{type(value).__name__} has no encoding in this profile")


# --------------------------------------------------------------------------
# Decoding
# --------------------------------------------------------------------------

_MIN_FOR_INFO = {24: 24, 25: 0x100, 26: 0x10000, 27: 0x100000000}


def decode(data: bytes) -> Any:
    """Decode exactly one value. Trailing bytes are an error."""
    value, offset = _at(data, 0, 0)
    if offset != len(data):
        raise CborError(f"{len(data) - offset} trailing byte(s) after the top-level value")
    return value


def _need(data: bytes, offset: int, n: int) -> None:
    if offset + n > len(data):
        raise CborError("truncated: input ends inside a value")


def _at(data: bytes, offset: int, depth: int) -> tuple[Any, int]:
    if depth > MAX_DEPTH:
        raise CborError(f"nesting deeper than {MAX_DEPTH}")
    _need(data, offset, 1)
    initial = data[offset]
    major, info = initial >> 5, initial & 0x1F

    if major == 7:
        offset += 1
        if info == 20:
            return False, offset
        if info == 21:
            return True, offset
        if info == 22:
            return None, offset
        if info == 27:
            _need(data, offset, 8)
            return struct.unpack(">d", data[offset : offset + 8])[0], offset + 8
        if info in (25, 26):
            raise CborError("float16/float32; clause 2.6 requires float64")
        raise CborError(f"simple value {info} is not defined in this profile")

    offset += 1
    if info < 24:
        n = info
    elif info == 31:
        raise CborError("indefinite length; clause 2.3 forbids it")
    elif info > 27:
        raise CborError(f"reserved additional information {info}")
    else:
        width = 1 << (info - 24)
        _need(data, offset, width)
        n = int.from_bytes(data[offset : offset + width], "big")
        offset += width
        if n < _MIN_FOR_INFO[info]:
            raise CborError(f"non-shortest argument: {n} in {width} byte(s)")

    if major == 0:
        return n, offset
    if major == 1:
        return -1 - n, offset
    if major in (2, 3):
        _need(data, offset, n)
        raw = data[offset : offset + n]
        if major == 2:
            return raw, offset + n
        try:
            return raw.decode("utf-8"), offset + n
        except UnicodeDecodeError as exc:
            raise CborError(f"text string is not valid UTF-8: {exc}") from exc
    if major == 4:
        out = []
        for _ in range(n):
            item, offset = _at(data, offset, depth + 1)
            out.append(item)
        return out, offset
    if major == 5:
        out_map: dict[Any, Any] = {}
        previous: bytes | None = None
        for _ in range(n):
            start = offset
            key, offset = _at(data, offset, depth + 1)
            encoded = data[start:offset]
            if previous is not None and encoded <= previous:
                raise CborError(
                    "duplicate map key" if encoded == previous
                    else "map keys are not in strictly increasing encoded order"
                )
            previous = encoded
            value, offset = _at(data, offset, depth + 1)
            try:
                out_map[key] = value
            except TypeError:
                raise CborError(f"map key of type {type(key).__name__} is not hashable") from None
        return out_map, offset
    # major == 6
    if n != 18:
        raise CborError(f"tag {n} is not defined in this profile")
    inner, offset = _at(data, offset, depth + 1)
    return Tagged(n, inner), offset
