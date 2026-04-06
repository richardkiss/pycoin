from __future__ import annotations

import io
from typing import Any, Callable, IO


class Streamer(object):
    def __init__(self) -> None:
        self.parse_lookup: dict[str, Any] = {}
        self.stream_lookup: dict[str, Any] = {}

    def register_functions(self, lookup: Any) -> None:
        for c, v in lookup:
            parse_f, stream_f = v
            self.parse_lookup[c] = parse_f
            self.stream_lookup[c] = stream_f

    def register_array_count_parse(
        self, array_count_parse_f: Callable[[IO[bytes]], int]
    ) -> None:
        self.array_count_parse_f = array_count_parse_f

    def parse_struct(self, fmt: str, f: IO[bytes]) -> tuple[Any, ...]:
        items: list[Any] = []
        i = 0
        while i < len(fmt):
            c = fmt[i]
            if c == "[":
                end = fmt.find("]", i)
                if end < 0:
                    raise ValueError("no closing ] character")
                subfmt = fmt[i + 1 : end]
                count = self.array_count_parse_f(f)
                array = []
                for j in range(count):
                    if len(subfmt) == 1:
                        array.append(self.parse_struct(subfmt, f)[0])
                    else:
                        array.append(self.parse_struct(subfmt, f))
                items.append(tuple(array))
                i = end
            else:
                items.append(self.parse_lookup[c](f))
            i += 1
        return tuple(items)

    def parse_as_dict(
        self, attribute_list: list[str], pack_list: str, f: IO[bytes]
    ) -> dict[str, Any]:
        return dict(list(zip(attribute_list, self.parse_struct(pack_list, f))))

    def stream_struct(self, fmt: str, f: IO[bytes], *args: Any) -> None:
        for c, v in zip(fmt, args):
            self.stream_lookup[c](f, v)

    def unpack_struct(self, fmt: str, b: bytes) -> tuple[Any, ...]:
        return self.parse_struct(fmt, io.BytesIO(b))

    def pack_struct(self, fmt: str, *args: Any) -> bytes:
        b = io.BytesIO()
        self.stream_struct(fmt, b, *args)
        return b.getvalue()
