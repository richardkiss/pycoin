
import io
import binascii


def h2b(h):
    """
    A version of binascii.unhexlify that accepts unicode. This is
    no longer necessary as of Python 3.3. But it doesn't hurt.

    Raises a ValueError on failure (unlike binascii.unhexlify, which
    raises a TypeError in Python 2 and a binascii.Error in Python 3).
    """
    try:
        return binascii.unhexlify(h.encode("ascii"))
    except Exception:
        raise ValueError("h2b failed on %s" % h)


def h2b_rev(h):
    return h2b(h)[::-1]


def b2h(the_bytes):
    return binascii.hexlify(the_bytes).decode("utf8")


def b2h_rev(the_bytes):
    return b2h(bytearray(reversed(the_bytes)))


def stream_to_bytes(stream_f):
    f = io.BytesIO()
    stream_f(f)
    return f.getvalue()


class bytes_as_revhex(bytes):
    def __str__(self):
        return "<%s>" % b2h_rev(self)

    def __repr__(self):
        return "<%s>" % b2h_rev(self)


class bytes_as_hex(bytes):
    def __str__(self):
        return "<%s>" % b2h(self)

    def __repr__(self):
        return "<%s>" % b2h(self)
