
import binascii

def h2b(the_hex):
    return binascii.unhexlify(the_hex)

def h2b_rev(the_hex):
    return bytes(reversed(binascii.unhexlify(the_hex)))

def b2h(the_bytes):
    return binascii.hexlify(the_bytes).decode("utf8")

def b2h_rev(the_bytes):
    return binascii.hexlify(bytes(reversed(the_bytes))).decode("utf8")
