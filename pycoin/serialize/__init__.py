
import binascii

def b2h(the_bytes):
    return binascii.hexlify(the_bytes).decode("utf8")

def b2h_rev(the_bytes):
    return binascii.hexlify(bytearray(reversed(the_bytes))).decode("utf8")
