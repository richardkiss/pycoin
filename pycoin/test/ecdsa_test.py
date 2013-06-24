#!/usr/bin/env python

import binascii
import unittest

from pycoin.ecdsa import generator_secp256k1, sign, verify, public_pair_for_secret_exponent

class ECDSATestCase(unittest.TestCase):

    def test_sign_verify(self):
        def do_test(secret_exponent, val_list):
            public_point = public_pair_for_secret_exponent(generator_secp256k1, secret_exponent)
            for v in val_list:
                signature = sign(generator_secp256k1, secret_exponent, v)
                r = verify(generator_secp256k1, public_point, v, signature)
                assert r == True
                signature = signature[0],signature[1]+1
                r = verify(generator_secp256k1, public_point, v, signature)
                assert r == False

        val_list = [100,20000,30000000,400000000000,50000000000000000,60000000000000000000000]

        do_test(0x1111111111111111111111111111111111111111111111111111111111111111, val_list)
        do_test(0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd, val_list)
        do_test(0x47f7616ea6f9b923076625b4488115de1ef1187f760e65f89eb6f4f7ff04b012, val_list)

if __name__ == '__main__':
    unittest.main()

