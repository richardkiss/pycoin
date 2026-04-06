from __future__ import annotations

from typing import IO

from .satoshi_int import parse_satoshi_int, stream_satoshi_int


def parse_satoshi_string(f: IO[bytes]) -> bytes:
    size = parse_satoshi_int(f)
    return f.read(size)


def stream_satoshi_string(f: IO[bytes], v: bytes) -> None:
    stream_satoshi_int(f, len(v))
    f.write(v)
