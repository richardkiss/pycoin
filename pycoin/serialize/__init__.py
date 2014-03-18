
import io
import binascii

def b2h(the_bytes):
    return binascii.hexlify(the_bytes).decode("utf8")

def b2h_rev(the_bytes):
    return binascii.hexlify(bytearray(reversed(the_bytes))).decode("utf8")

def h2b_rev(h):
    return binascii.unhexlify(h)[::-1]

def stream_to_bytes(stream_f):
    f = io.BytesIO()
    stream_f(f)
    return f.getvalue()
