#!/usr/bin/env python

import hashlib
import unittest

from pycoin.ecdsa import generator_secp256k1, sign, verify, public_pair_for_secret_exponent, intbytes
from pycoin.ecdsa.ecdsa import deterministic_generate_k

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

    def test_deterministic_generate_k_A_1(self):
        """
        The example in http://tools.ietf.org/html/rfc6979#appendix-A.1
        """
        h = hashlib.sha256(b'sample').digest()
        val = intbytes.from_bytes(h)
        self.assertEqual(val, 0xAF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF)
        q = 0x4000000000000000000020108A2E0CC0D99F8A5EF
        x = 0x09A4D6792295A7F730FC3F2B49CBC0F62E862272F
        k = deterministic_generate_k(q, x, val)
        self.assertEqual(k, 0x23AF4074C90A02B3FE61D286D5C87F425E6BDD81B)

    def test_deterministic_generate_k_A_2_1(self):
        """
        The example in https://tools.ietf.org/html/rfc6979#appendix-A.2.3
        """
        hashes_values = (
            (hashlib.sha1, 0x37D7CA00D2C7B0E5E412AC03BD44BA837FDD5B28CD3B0021),
            (hashlib.sha224, 0x4381526B3FC1E7128F202E194505592F01D5FF4C5AF015D8),
            (hashlib.sha256, 0x32B1B6D7D42A05CB449065727A84804FB1A3E34D8F261496),
            (hashlib.sha384, 0x4730005C4FCB01834C063A7B6760096DBE284B8252EF4311),
            (hashlib.sha512, 0xA2AC7AB055E4F20692D49209544C203A7D1F2C0BFBC75DB1),
            )
        q = 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
        x = 0x6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4
        for h, v in hashes_values:
            v_sample = intbytes.from_bytes(h(b'sample').digest())
            k = deterministic_generate_k(q, x, v_sample, h)
            self.assertEqual(k, v)

        hashes_values = (
            (hashlib.sha1, 0xD9CF9C3D3297D3260773A1DA7418DB5537AB8DD93DE7FA25),
            (hashlib.sha224, 0xF5DC805F76EF851800700CCE82E7B98D8911B7D510059FBE),
            (hashlib.sha256, 0x5C4CE89CF56D9E7C77C8585339B006B97B5F0680B4306C6C),
            (hashlib.sha384, 0x5AFEFB5D3393261B828DB6C91FBC68C230727B030C975693),
            (hashlib.sha512, 0x0758753A5254759C7CFBAD2E2D9B0792EEE44136C9480527),
            )
        for h, v in hashes_values:
            v_sample = intbytes.from_bytes(h(b'test').digest())
            k = deterministic_generate_k(q, x, v_sample, h)
            self.assertEqual(k, v)

    def test_deterministic_generate_k_A_2_5(self):
        """
        The example in https://tools.ietf.org/html/rfc6979#appendix-A.2.5
        """
        h = hashlib.sha256(b'sample').digest()
        val = intbytes.from_bytes(h)
        self.assertEqual(val, 0xAF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF)
        generator_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
        secret_exponent = 0xF220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1
        k = deterministic_generate_k(generator_order, secret_exponent, val)
        self.assertEqual(k, 0xAD3029E0278F80643DE33917CE6908C70A8FF50A411F06E41DEDFCDC)


if __name__ == '__main__':
    unittest.main()

