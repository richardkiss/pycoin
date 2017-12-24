
if hasattr(int, "to_bytes"):
    def to_bytes_32(v):
        return v.to_bytes(32, byteorder="big")

    def from_bytes_32(v):
        return int.from_bytes(v, byteorder="big")
else:
    from .base_conversion import from_long, to_long
    from ..intbytes import byte2int

    def to_bytes_32(v):
        v = from_long(v, 0, 256, lambda x: x)
        if len(v) > 32:
            raise ValueError("input to to_bytes_32 is too large")
        return ((b'\0' * 32) + v)[-32:]

    def from_bytes_32(v):
        if len(v) > 32:
            raise OverflowError("int too big to convert")
        return to_long(256, byte2int, v)[0]


"""
Various utilities useful for converting one Bitcoin format to another, including some
the human-transcribable format hashed_base58.


The MIT License (MIT)

Copyright (c) 2013 by Richard Kiss

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
