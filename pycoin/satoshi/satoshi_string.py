from .satoshi_int import parse_satoshi_int, stream_satoshi_int


def parse_satoshi_string(f):
    size = parse_satoshi_int(f)
    return f.read(size)


def stream_satoshi_string(f, v):
    stream_satoshi_int(f, len(v))
    f.write(v)
