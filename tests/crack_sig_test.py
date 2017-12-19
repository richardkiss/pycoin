import unittest

from pycoin.crack.ecdsa import crack_secret_exponent_from_k, crack_k_from_sigs
from pycoin.ecdsa.secp256k1 import secp256k1_generator


def make_gen_k_const(K):

    def gen_k(*args):
        return K
    return gen_k


class CrackSigTest(unittest.TestCase):
    def test_crack_secret_exponent_from_k(self):
        k = 105
        se = 181919191
        gen_k = make_gen_k_const(k)
        val = 488819181819384
        sig = secp256k1_generator.sign(se, val, gen_k=gen_k)
        cracked_se = crack_secret_exponent_from_k(secp256k1_generator, val, sig, k)
        self.assertEqual(cracked_se, se)

    def test_crack_k_from_sigs(self):
        k = 105
        se = 181919191
        gen_k = make_gen_k_const(k)
        val1 = 488819181819384
        val2 = 588819181819384
        sig1 = secp256k1_generator.sign(se, val1, gen_k=gen_k)
        sig2 = secp256k1_generator.sign(se, val2, gen_k=gen_k)
        cracked_k = crack_k_from_sigs(secp256k1_generator, sig1, val1, sig2, val2)
        self.assertEqual(cracked_k, k)
