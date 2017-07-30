from ctypes import (
    cdll, byref, c_byte, c_int, c_uint, c_char_p, c_size_t, c_void_p, create_string_buffer, CFUNCTYPE, POINTER
)
import os
import platform

from ..Group import Group

from pycoin.encoding import from_bytes_32, to_bytes_32



SECP256K1_FLAGS_TYPE_MASK = ((1 << 8) - 1)
SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0)
SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1)
# /** The higher bits contain the actual data. Do not use directly. */
SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8)
SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9)
SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8)

# /** Flags to pass to secp256k1_context_create. */
SECP256K1_CONTEXT_VERIFY = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
SECP256K1_CONTEXT_SIGN = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
SECP256K1_CONTEXT_NONE = (SECP256K1_FLAGS_TYPE_CONTEXT)

SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8)
SECP256K1_EC_COMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION)
SECP256K1_EC_UNCOMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION)



def load_library():
    try:
        SO_EXT = 'dylib' if platform.system() == 'Darwin' else 'so'

        secp256k1 = cdll.LoadLibrary('libsecp256k1.%s' % SO_EXT)

        secp256k1.secp256k1_context_create.argtypes = [c_uint]
        secp256k1.secp256k1_context_create.restype = c_void_p

        secp256k1.secp256k1_context_randomize.argtypes = [c_void_p, c_char_p]
        secp256k1.secp256k1_context_randomize.restype = c_int

        secp256k1.secp256k1_ec_pubkey_create.argtypes = [c_void_p, c_void_p, c_char_p]
        secp256k1.secp256k1_ec_pubkey_create.restype = c_int

        secp256k1.secp256k1_ecdsa_sign.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p, c_void_p, c_void_p]
        secp256k1.secp256k1_ecdsa_sign.restype = c_int

        secp256k1.secp256k1_ecdsa_verify.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
        secp256k1.secp256k1_ecdsa_verify.restype = c_int

        secp256k1.secp256k1_ec_pubkey_parse.argtypes = [c_void_p, c_char_p, c_char_p, c_int]
        secp256k1.secp256k1_ec_pubkey_parse.restype = c_int

        secp256k1.secp256k1_ec_pubkey_serialize.argtypes = [c_void_p, c_char_p, c_void_p, c_char_p, c_uint]
        secp256k1.secp256k1_ec_pubkey_serialize.restype = c_int

        secp256k1.secp256k1_ecdsa_signature_parse_compact.argtypes = [c_void_p, c_char_p, c_char_p]
        secp256k1.secp256k1_ecdsa_signature_parse_compact.restype = c_int

        secp256k1.secp256k1_ecdsa_signature_serialize_compact.argtypes = [c_void_p, c_char_p, c_char_p]
        secp256k1.secp256k1_ecdsa_signature_serialize_compact.restype = c_int
        secp256k1.ctx = secp256k1.secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
        r = secp256k1.secp256k1_context_randomize(secp256k1.ctx, os.urandom(32))
        return secp256k1
    except OSError:
        return None



LibSECP256K1GroupBestClass = None

libsecp256k1 = load_library()

if libsecp256k1:
    secp256k1 = libsecp256k1
    class LibSECP256K1Group(Group):

        def __mul__(self, e):
            if e == 0:
                return self._infinity
            pubkey = create_string_buffer(65)
            secp256k1.secp256k1_ec_pubkey_create(libsecp256k1.ctx, pubkey, c_char_p(to_bytes_32(e)))
            pubkey_size = c_size_t(65)
            pubkey_serialized = create_string_buffer(65)
            secp256k1.secp256k1_ec_pubkey_serialize(
                libsecp256k1.ctx, pubkey_serialized, byref(pubkey_size), pubkey, SECP256K1_EC_UNCOMPRESSED)
            x = from_bytes_32(pubkey_serialized[1:33])
            y = from_bytes_32(pubkey_serialized[33:])
            return self.Point(x, y)

        def sign(self, secret_exponent, val, gen_k=None):
            nonce_function = None
            if gen_k is not None:
                def adaptor(nonce32_p, msg32_p, key32_p, algo16_p, data, attempt):
                    r = gen_k(self.order(), secret_exponent, val)
                    for _, b in enumerate(to_bytes_32(r)):
                        # BRAIN DAMAGE: this seem lame
                        nonce32_p.contents[_] = b
                    return 1
                p_b32 = POINTER(c_byte*32)
                nonce_function = CFUNCTYPE(c_int, p_b32, p_b32, p_b32, POINTER(c_byte*16), c_void_p, c_uint)(adaptor)

            sig = create_string_buffer(64)
            sig_hash_bytes = to_bytes_32(val)
            secp256k1.secp256k1_ecdsa_sign(libsecp256k1.ctx, sig, sig_hash_bytes, to_bytes_32(secret_exponent), nonce_function, None)
            compact_signature = create_string_buffer(64)
            secp256k1.secp256k1_ecdsa_signature_serialize_compact(libsecp256k1.ctx, compact_signature, sig)
            r = from_bytes_32(compact_signature[:32])
            s = from_bytes_32(compact_signature[32:])
            return self.Point(r, s)

        def verify(self, public_pair, val, signature_pair):
            sig = create_string_buffer(64)
            input64 = to_bytes_32(signature_pair[0]) + to_bytes_32(signature_pair[1])
            r = secp256k1.secp256k1_ecdsa_signature_parse_compact(libsecp256k1.ctx, sig, input64)
            assert r
            r = secp256k1.secp256k1_ecdsa_signature_normalize(libsecp256k1.ctx, sig, sig)

            public_pair_bytes = b'\4' + to_bytes_32(public_pair[0]) + to_bytes_32(public_pair[1])
            pubkey = create_string_buffer(64)
            r = secp256k1.secp256k1_ec_pubkey_parse(libsecp256k1.ctx, pubkey, public_pair_bytes, len(public_pair_bytes))
            assert r

            return 1 == secp256k1.secp256k1_ecdsa_verify(libsecp256k1.ctx, sig, to_bytes_32(val), pubkey)

