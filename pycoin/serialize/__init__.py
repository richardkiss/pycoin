import io

# BRAIN DAMAGE
from pycoin.encoding.hexbytes import b2h, h2b, b2h_rev, h2b_rev


def stream_to_bytes(stream_f):
    f = io.BytesIO()
    stream_f(f)
    return f.getvalue()
