import logging


from pycoin.encoding import sec_to_public_pair, to_bytes_32, public_pair_to_sec
from pycoin.tx.script import der

from ctypes import cdll, byref, c_int, c_char_p, create_string_buffer
import platform, os

SO_EXT = 'dylib' if platform.system() == 'Darwin' else 'so'

try:
    secp256k1 = cdll.LoadLibrary('libsecp256k1.' + SO_EXT)
except OSError:
    log.debug("Not using libsecp256k1.")
else:
    log.debug("Using libsecp256k1.")

    SECP256K1_START_VERIFY = 1
    SECP256K1_START_SIGN = 2
    ctx = secp256k1.secp256k1_context_create(SECP256K1_START_VERIFY | SECP256K1_START_SIGN)
    seed = os.urandom(32)
    assert secp256k1.secp256k1_context_randomize(ctx, seed)

    def _public_pair_for_secret_exponent(secexp):
        out = create_string_buffer(128)
        out_s = byref(c_int(128))
        secp256k1.secp256k1_ec_pubkey_create(ctx, out, out_s, c_char_p(to_bytes_32(secexp)), 0)
        return sec_to_public_pair(out.raw[:out_s._obj.value])

    def _sign(secexp, signature_hash):
        msg_char_p = c_char_p(to_bytes_32(signature_hash))
        sec_char_p = c_char_p(to_bytes_32(secexp))
        out = create_string_buffer(128)
        out_s = byref(c_int(128))
        secp256k1.secp256k1_ecdsa_sign(ctx, msg_char_p, out, out_s, sec_char_p, None, None)

        return der.sigdecode_der(out.raw[:out_s._obj.value])

    def _verify(public_pair, signature_hash, signature):
        msg_char_p = c_char_p(to_bytes_32(signature_hash))
        sig_str = der.sigencode_der(*signature)
        sig_char_p = c_char_p(sig_str)
        pub_str = public_pair_to_sec(public_pair)
        pub_char_p = c_char_p(pub_str)
        return 1 == secp256k1.secp256k1_ecdsa_verify(ctx, msg_char_p, sig_char_p, len(sig_str), pub_char_p, len(pub_str))


    import pycoin.ecdsa
    _orig_sign = pycoin.ecdsa.sign
    _orig_public_pair_for_secret_exponent = pycoin.ecdsa.public_pair_for_secret_exponent
    _orig_verify = pycoin.ecdsa.verify

    def _patched_sign(generator, secexp, val):
        if generator is pycoin.ecdsa.generator_secp256k1:
            return _sign(secexp, val)
        else:
            return _orig_sign(generator, secexp, val)
    pycoin.ecdsa.sign = _patched_sign

    def _patched_public_pair_for_secret_exponent(generator, secexp):
        if generator is pycoin.ecdsa.generator_secp256k1:
            return _public_pair_for_secret_exponent(secexp)
        else:
            return _orig_public_pair_for_secret_exponent(generator, secexp)
    pycoin.ecdsa.public_pair_for_secret_exponent = _patched_public_pair_for_secret_exponent

    def _patched_verify(generator, public_pair, signature_hash, signature):
        if generator is pycoin.ecdsa.generator_secp256k1:
            return _verify(public_pair, signature_hash, signature)
        else:
            return _orig_verify(generator, public_pair, signature_hash, signature)
    pycoin.ecdsa.verify = _patched_verify
