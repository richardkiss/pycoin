#!/usr/bin/env python

import unittest

from pycoin.ecdsa import generator_secp256k1

class SigningTest(unittest.TestCase):
    def test_sign(self):
        for se in ["47f7616ea6f9b923076625b4488115de1ef1187f760e65f89eb6f4f7ff04b012"] + [x * 64 for x in "123456789abcde"]:
            secret_exponent = int(se, 16)
            val = 28832970699858290 #int.from_bytes(b"foo bar", byteorder="big")
            sig = generator_secp256k1.sign(secret_exponent, val)

            public_pair = generator_secp256k1 * secret_exponent

            v = generator_secp256k1.verify(public_pair, val, sig)
            self.assertTrue(v)

            sig1 = (sig[0] + 1, sig[1])
            v = generator_secp256k1.verify(public_pair, val, sig1)
            self.assertFalse(v)

            public_pairs = generator_secp256k1.possible_public_pairs_for_signature(val, sig)
            self.assertIn(public_pair, public_pairs)
            print(se)

def main():
    unittest.main()

if __name__ == "__main__":
    main()
