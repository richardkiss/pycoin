import unittest

from pycoin.ecdsa.encrypt import generate_shared_public_key
from pycoin.ecdsa.secp256k1 import secp256k1_generator


class SharedPublicKeyTest(unittest.TestCase):
    def test_gen_shared(self):
        BASE_1 = 0x1111111111111111111111111111111111111111111111111111111111111111
        BASE_2 = 0x1111111111011111111111111110111111111111111111110111111110111111
        for factor_1 in range(1, 16):
            priv_1 = BASE_1 * factor_1
            pub_1 = secp256k1_generator * priv_1
            for factor_2 in range(1, 16):
                priv_2 = BASE_2 * factor_2
                pub_2 = secp256k1_generator * priv_2
                pk1 = generate_shared_public_key(priv_1, pub_2, secp256k1_generator)
                pk2 = generate_shared_public_key(priv_2, pub_1, secp256k1_generator)
                self.assertEqual(pk1, pk2)
