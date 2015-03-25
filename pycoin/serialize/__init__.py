
import io
import binascii


def h2b(h):
    """
    A version of binascii.unhexlify that accepts unicode. This is
    no longer necessary as of Python 3.3. But it doesn't hurt.
    """
    return binascii.unhexlify(h.encode("ascii"))


def h2b_rev(h):
    return binascii.unhexlify(h.encode("utf8"))[::-1]


def b2h(the_bytes):
    return binascii.hexlify(the_bytes).decode("utf8")


def b2h_rev(the_bytes):
    return binascii.hexlify(bytearray(reversed(the_bytes))).decode("utf8")


def stream_to_bytes(stream_f):
    f = io.BytesIO()
    stream_f(f)
    return f.getvalue()
