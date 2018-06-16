import struct


def parse_satoshi_int(f, v=None):
    if v is None:
        v = ord(f.read(1))
    if v == 253:
        v = struct.unpack("<H", f.read(2))[0]
    elif v == 254:
        v = struct.unpack("<L", f.read(4))[0]
    elif v == 255:
        v = struct.unpack("<Q", f.read(8))[0]
    return v


def stream_satoshi_int(f, v):
    if v < 253:
        f.write(struct.pack("<B", v))
    elif v <= 65535:
        f.write(b'\xfd' + struct.pack("<H", v))
    elif v <= 0xffffffff:
        f.write(b'\xfe' + struct.pack("<L", v))
    else:
        f.write(b'\xff' + struct.pack("<Q", v))
