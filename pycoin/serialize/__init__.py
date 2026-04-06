from __future__ import annotations

import io
from typing import Callable, IO


def stream_to_bytes(stream_f: Callable[[IO[bytes]], None]) -> bytes:
    f = io.BytesIO()
    stream_f(f)
    return f.getvalue()
