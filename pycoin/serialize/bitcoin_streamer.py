
import struct

from .streamer import Streamer


def parse_bc_int(f):
    v = ord(f.read(1))
    if v == 253:
        v = struct.unpack("<H", f.read(2))[0]
    elif v == 254:
        v = struct.unpack("<L", f.read(4))[0]
    elif v == 255:
        v = struct.unpack("<Q", f.read(8))[0]
    return v


def parse_bc_string(f):
    size = parse_bc_int(f)
    return f.read(size)


def stream_bc_int(f, v):
    if v < 253:
        f.write(struct.pack("<B", v))
    elif v <= 65535:
        f.write(b'\xfd' + struct.pack("<H", v))
    elif v <= 0xffffffff:
        f.write(b'\xfe' + struct.pack("<L", v))
    else:
        f.write(b'\xff' + struct.pack("<Q", v))


def stream_bc_string(f, v):
    stream_bc_int(f, len(v))
    f.write(v)

STREAMER_FUNCTIONS = {
    "I": (parse_bc_int, stream_bc_int),
    "S": (parse_bc_string, stream_bc_string),
    "h": (lambda f: struct.unpack("!H", f.read(2))[0], lambda f, v: f.write(struct.pack("!H", v))),
    "L": (lambda f: struct.unpack("<L", f.read(4))[0], lambda f, v: f.write(struct.pack("<L", v))),
    "Q": (lambda f: struct.unpack("<Q", f.read(8))[0], lambda f, v: f.write(struct.pack("<Q", v))),
    "#": (lambda f: f.read(32), lambda f, v: f.write(v[:32])),
    "@": (lambda f: f.read(16), lambda f, v: f.write(v[:16])),
    "b": (lambda f: struct.unpack("?", f.read(1))[0], lambda f, b: f.write(struct.pack("?", b))),
}

BITCOIN_STREAMER = Streamer()
BITCOIN_STREAMER.register_array_count_parse(parse_bc_int)
BITCOIN_STREAMER.register_functions(STREAMER_FUNCTIONS.items())

parse_struct = BITCOIN_STREAMER.parse_struct
parse_as_dict = BITCOIN_STREAMER.parse_as_dict
stream_struct = BITCOIN_STREAMER.stream_struct
pack_struct = BITCOIN_STREAMER.pack_struct
