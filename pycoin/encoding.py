import binascii
import hashlib

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BASE58_BASE = len(BASE58_ALPHABET)
BASE58_LOOKUP = dict((c, i) for i, c in enumerate(BASE58_ALPHABET))

def to_long(base, lookup_f, s):
    prefix = 0
    v = 0
    for c in s:
        v *= base
        v += lookup_f(c)
        if v == 0:
            prefix += 1
    return v, prefix

def from_long(v, prefix, base, charset):
    l = []
    while v > 0:
        v, mod = divmod(v, base)
        l.append(charset(mod))
    l += [charset(0)] * prefix
    return bytes(reversed(l))

def b2a_base58(s):
    v, prefix = to_long(256, lambda x: x, s)
    s = from_long(v, prefix, BASE58_BASE, lambda v: v)
    return ''.join(BASE58_ALPHABET[x] for x in s)

def a2b_base58(s):
    v, prefix = to_long(BASE58_BASE, lambda c: BASE58_LOOKUP[c], s)
    return from_long(v, prefix, 256, lambda x: x)

def b2a_hashed_base58(data):
    return b2a_base58(data + double_sha256(data)[:4])

def a2b_hashed_base58(s):
    data = a2b_base58(s)
    data, the_hash = data[:-4], data[-4:]
    if double_sha256(data)[:4] == the_hash:
        return data

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def ripemd160_sha(data):
    h = hashlib.new("ripemd160")
    h.update(hashlib.sha256(data).digest())
    return h.digest()

def wif_to_tuple_of_secret_exponent_compressed(wif):
    decoded = a2b_hashed_base58(wif)
    if decoded:
        header80, private_key = decoded[0], decoded[1:]
        if header80 == 128:
            compressed = len(private_key) > 32
            return int.from_bytes(private_key[:32], byteorder="big"), compressed

def wif_to_secret_exponent(wif):
    v = wif_to_tuple_of_secret_exponent_compressed(wif)
    if v: return v[0]

def is_valid_wif(wif):
    return wif_to_secret_exponent(wif) is not None

def secret_exponent_to_wif(secret_exp, compressed=True):
    d = b'\x80' + secret_exp.to_bytes(32, byteorder="big")
    if compressed: d += b'\01'
    return b2a_hashed_base58(d)

def public_pair_to_ripemd160_sha_sec(public_pair, compressed=True):
    return ripemd160_sha(public_pair_to_sec(public_pair, compressed=compressed))

def public_pair_to_bitcoin_address(public_pair, compressed=True):
    return b2a_hashed_base58(b"\x00" + public_pair_to_ripemd160_sha_sec(public_pair, compressed=compressed))

def bitcoin_address_to_ripemd160_sha_sec(bitcoin_address):
    version_sr160 = a2b_hashed_base58(bitcoin_address)
    if version_sr160 and len(version_sr160) == 21:
        return version_sr160[1:]

def is_valid_bitcoin_address(bitcoin_address):
    return bitcoin_address_to_ripemd160_sha_sec(bitcoin_address) is not None

def is_hashed_base58_valid(base58):
    return a2b_hashed_base58(base58) is not None

def public_pair_to_sec(public_pair, compressed=True):
    x_str = public_pair[0].to_bytes(32, byteorder="big")
    if compressed:
        return bytes([(2 + (public_pair[1] & 1))]) + x_str
    y_str = public_pair[1].to_bytes(32, byteorder="big")
    return bytes([4]) + x_str + y_str

def public_pair_from_sec(b):
    x = int.from_bytes(b[1:33], byteorder="big")
    if b[0] == 4:
        y = int.from_bytes(b[33:65], byteorder="big")
        # TODO: verify this is on the curve
        return (x, y)
    if b[0] in (2, 3):
        from .ecdsa import public_pair_for_x, generator_secp256k1
        return public_pair_for_x(generator_secp256k1, x, is_even=(b[0]==2))
    raise Exception("bad sec encoding for public key")

def is_sec_compressed(b):
    return b[0] in (2,3)
