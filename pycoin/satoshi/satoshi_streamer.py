import struct

from pycoin.encoding.hexbytes import bytes_as_revhex
from pycoin.serialize.streamer import Streamer

from .satoshi_int import parse_satoshi_int, stream_satoshi_int
from .satoshi_string import parse_satoshi_string, stream_satoshi_string


STREAMER_FUNCTIONS = {
    "I": (parse_satoshi_int, stream_satoshi_int),
    "S": (parse_satoshi_string, stream_satoshi_string),
    "h": (lambda f: struct.unpack("!H", f.read(2))[0], lambda f, v: f.write(struct.pack("!H", v))),
    "L": (lambda f: struct.unpack("<L", f.read(4))[0], lambda f, v: f.write(struct.pack("<L", v))),
    "Q": (lambda f: struct.unpack("<Q", f.read(8))[0], lambda f, v: f.write(struct.pack("<Q", v))),
    "#": (lambda f: bytes_as_revhex(f.read(32)), lambda f, v: f.write(v[:32])),
    "@": (lambda f: f.read(16), lambda f, v: f.write(v[:16])),
    "b": (lambda f: struct.unpack("?", f.read(1))[0], lambda f, b: f.write(struct.pack("?", b))),
}

SATOSHI_STREAMER = Streamer()
SATOSHI_STREAMER.register_array_count_parse(parse_satoshi_int)
SATOSHI_STREAMER.register_functions(STREAMER_FUNCTIONS.items())
