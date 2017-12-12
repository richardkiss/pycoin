import unittest

from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.ecdsa.intstream import to_bytes, from_bytes


class ECDSATestCase(unittest.TestCase):

    def test_infinity(self):
        infinity = secp256k1_generator.infinity()
        self.assertEqual(secp256k1_generator * 0, infinity)
        self.assertEqual(0 * secp256k1_generator, infinity)
        for _ in range(0, 100, 10):
            self.assertEqual(_ * infinity, infinity)
            self.assertEqual(infinity * _, infinity)
        g2 = secp256k1_generator * 2
        g2_neg = secp256k1_generator * -2
        self.assertEqual(g2 + g2_neg, infinity)
        self.assertEqual(g2 + infinity, g2)
        self.assertEqual(g2_neg + infinity, g2_neg)
        self.assertEqual(-g2, g2_neg)

    def test_multiply(self):
        g2 = secp256k1_generator * 2
        g2p = g2 * 1
        self.assertEqual(g2p, g2)
        g4 = g2 * 2
        self.assertEqual(g4, secp256k1_generator * 4)
        g8 = g2 * 4
        self.assertEqual(g8, secp256k1_generator * 8)
        g24 = g8 * 3
        self.assertEqual(g24, secp256k1_generator * 24)
        g_big = g2 * (71 ** 41)
        self.assertEqual(g_big, secp256k1_generator * ((2 * 71 ** 41) % secp256k1_generator.order()))

    def test_add(self):
        G = secp256k1_generator
        a, b = 2, 3
        self.assertEqual(a * G + b * G, (a + b) * G)
        a, b = 200, 300
        self.assertEqual(a * G + b * G, (a + b) * G)
        a, b = 71**41, 41**47
        self.assertEqual(a * G + b * G, (a + b) * G)

    def test_sign_simple(self):
        secret_exponent = 1
        public_pair = secp256k1_generator * secret_exponent
        self.assertEqual(public_pair, (
            55066263022277343669578718895168534326250603453777594175500187360389116729240,
            32670510020758816978083085130507043184471273380659243275938904335757337482424)
        )
        hash_value = 1
        sig = secp256k1_generator.sign(secret_exponent, hash_value)
        r = secp256k1_generator.verify(public_pair, hash_value, sig)
        self.assertTrue(r)
        r = secp256k1_generator.verify(public_pair, hash_value, (sig[0], sig[1] ^ 1))
        self.assertFalse(r)
        self.assertEqual(sig[0], 46340862580836590753275244201733144181782255593078084106116359912084275628184)
        self.assertIn(sig[1], [
            81369331955758484632176499244870227132558660296342819670803726373940306621624,
            34422757281557710791394485763817680720278903982732084711801436767577854872713
        ])

    def test_verify_simple(self):
        public_pair = secp256k1_generator * 1
        self.assertEqual(public_pair, (
            55066263022277343669578718895168534326250603453777594175500187360389116729240,
            32670510020758816978083085130507043184471273380659243275938904335757337482424)
        )
        hash_value = 1
        sig = (46340862580836590753275244201733144181782255593078084106116359912084275628184,
               81369331955758484632176499244870227132558660296342819670803726373940306621624)
        r = secp256k1_generator.verify(public_pair, hash_value, sig)
        self.assertEqual(r, True)

    def test_sign_verify(self):
        def do_test(secret_exponent, val_list):
            public_point = secret_exponent * secp256k1_generator
            for v in val_list:
                signature = secp256k1_generator.sign(secret_exponent, v)
                r = secp256k1_generator.verify(public_point, v, signature)
                assert r is True
                inv_sig = (signature[0], secp256k1_generator.order() - signature[1])
                r = secp256k1_generator.verify(public_point, v, inv_sig)
                assert r is True
                signature = signature[0], signature[1]+1
                r = secp256k1_generator.verify(public_point, v, signature)
                assert r is False

        val_list = [100, 20000, 30000000, 400000000000, 50000000000000000, 60000000000000000000000]

        do_test(0x1111111111111111111111111111111111111111111111111111111111111111, val_list)
        do_test(0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd, val_list)
        do_test(0x47f7616ea6f9b923076625b4488115de1ef1187f760e65f89eb6f4f7ff04b012, val_list)

    def test_custom_k(self):
        secret_exponent = 1
        sig_hash = 1

        def gen_k(*args):
            return 1

        signature = secp256k1_generator.sign(secret_exponent, sig_hash, gen_k)
        self.assertEqual(signature, (
            55066263022277343669578718895168534326250603453777594175500187360389116729240,
            55066263022277343669578718895168534326250603453777594175500187360389116729241
        ))

    def test_inverse_mod(self):
        prime = secp256k1_generator.curve().p()
        order = secp256k1_generator.order()
        for v in range(70):
            n = int(float("1e%d" % v))
            i = secp256k1_generator.inverse_mod(n, prime)
            assert n * i % prime == 1
            i = secp256k1_generator.inverse_mod(n, order)
            assert n * i % order == 1

    def test_endian(self):
        for e in ("big", "little"):
            assert from_bytes(to_bytes(768, 2, e), e) == 768
            assert from_bytes(to_bytes(3, 1, e), e) == 3
            assert from_bytes(to_bytes(66051, 3, e), e) == 66051


if __name__ == '__main__':
    unittest.main()
