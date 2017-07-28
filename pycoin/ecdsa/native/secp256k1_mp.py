from ctypes import cdll, byref, c_int, c_uint, c_char_p, c_void_p, create_string_buffer
import os
import platform

from pycoin.encoding import sec_to_public_pair, from_bytes_32, to_bytes_32, public_pair_to_sec
from pycoin.tx.script import der


SO_EXT = 'dylib' if platform.system() == 'Darwin' else 'so'


libsecp256k1 = None

import pdb


SECP256K1_FLAGS_TYPE_MASK = ((1 << 8) - 1)
SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0)
SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1)
#/** The higher bits contain the actual data. Do not use directly. */
SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8)
SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9)
SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8)

#/** Flags to pass to secp256k1_context_create. */
SECP256K1_CONTEXT_VERIFY = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
SECP256K1_CONTEXT_SIGN = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
SECP256K1_CONTEXT_NONE = (SECP256K1_FLAGS_TYPE_CONTEXT)


try:
    #pdb.set_trace()
    secp256k1 = cdll.LoadLibrary('libsecp256k1.%s' % SO_EXT)

    SECP256K1_START_VERIFY = 1
    SECP256K1_START_SIGN = 2
    secp256k1.secp256k1_context_create.argtypes = [c_uint]
    secp256k1.secp256k1_context_create.restype = c_void_p
    ctx = secp256k1.secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
    seed = os.urandom(32)
    secp256k1.secp256k1_context_randomize.argtypes = [c_void_p, c_char_p]
    secp256k1.secp256k1_context_randomize.restype = c_int
    r = secp256k1.secp256k1_context_randomize(ctx, seed)

    secp256k1.secp256k1_ec_pubkey_create.argtypes = [c_void_p, c_void_p, c_char_p]
    secp256k1.secp256k1_ec_pubkey_create.restype = c_int

    secp256k1.secp256k1_ecdsa_sign.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p, c_void_p, c_void_p]
    secp256k1.secp256k1_ecdsa_sign.restype = c_int

    class libsecp256k1(object):
        def _public_pair_for_secret_exponent(secexp):
            out = create_string_buffer(64)
            secp256k1.secp256k1_ec_pubkey_create(ctx, out, c_char_p(to_bytes_32(secexp)))
            out = out[::-1]
            x = from_bytes_32(out[32:])
            y = from_bytes_32(out[:32])
            return (x, y)

        """
            const secp256k1_context* ctx,
            secp256k1_ecdsa_signature *sig,
            const unsigned char *msg32,
            const unsigned char *seckey,
            secp256k1_nonce_function noncefp,
            const void *ndata
        """

        def _sign(secexp, signature_hash, gen_k):
            pdb.set_trace()
            msg_char_p = c_char_p(to_bytes_32(signature_hash))
            sec_char_p = c_char_p(to_bytes_32(secexp))
            out = create_string_buffer(128)
            secp256k1.secp256k1_ecdsa_sign(ctx, out, msg_char_p, sec_char_p, None, None)
            x = from_bytes_32(out[:32])
            y = from_bytes_32(out[32:64])
            return (x, y)

        def _verify(public_pair, signature_hash, signature):
            pdb.set_trace()
            msg_char_p = c_char_p(to_bytes_32(signature_hash))
            sig_str = der.sigencode_der(*signature)
            sig_char_p = c_char_p(sig_str)
            pub_str = public_pair_to_sec(public_pair)
            pub_char_p = c_char_p(pub_str)
            return 1 == secp256k1.secp256k1_ecdsa_verify(
                ctx, msg_char_p, sig_char_p, len(sig_str), pub_char_p, len(pub_str))

except OSError:
    libsecp256k1 = None
