#!/usr/bin/env python

import unittest

from pycoin import encoding
from pycoin.serialize import h2b

class EncodingTestCase(unittest.TestCase):

    def test_to_from_long(self):
        def do_test(as_int, prefix, as_rep, base):
            self.assertEqual((as_int, prefix), encoding.to_long(base, encoding.byte_to_int, as_rep))
            self.assertEqual(as_rep, encoding.from_long(as_int, prefix, base, lambda v:v))

        do_test(10000101, 2, h2b("00009896e5"), 256)
        do_test(10000101, 3, h2b("0000009896e5"), 256)
        do_test(1460765565493402645157733592332121663123460211377, 1, b'\0\xff\xde\xfeOHu\xcf\x11\x9f\xc3\xd8\xf4\xa0\x9a\xe3~\xc4\xccB\xb1', 256)

    def test_to_bytes_32(self):
        for i in range(256):
            v = encoding.to_bytes_32(i)
            self.assertEqual(v, b'\0' * 31 + bytes(bytearray([i])))
        for i in range(256,512):
            v = encoding.to_bytes_32(i)
            self.assertEqual(v, b'\0' * 30 + bytes(bytearray([1, i&0xff])))

    def test_to_from_base58(self):
        def do_test(as_text, as_bin):
            self.assertEqual(as_bin, encoding.a2b_base58(as_text))
            self.assertEqual(as_text, encoding.b2a_base58(as_bin))

        do_test("1abcdefghijkmnpqrst", b'\x00\x01\x93\\|\xf2*\xb9\xbe\x19b\xae\xe4\x8c{')
        do_test("1CASrvcpMMTa4dz4DmYtAqcegCtdkhjvdn", b'\x00zr\xb6\xfac\xde6\xc4\xab\xc6\nh\xb5-\x7f3\xe3\xd7\xcd>\xc4\xba\xbd9')
        do_test("1111111111111111aaaa11aa",
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00CnzQ)\x0b')
        do_test("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
            b'\x00\x01\x11\xd3\x8e_\xc9\x07\x1f\xfc\xd2\x0bJv<\xc9\xaeO%+\xb4\xe4\x8f\xd6j\x83^%*\xda\x93\xffH\rm\xd4=\xc6*d\x11U\xa5')

    def test_to_from_hashed_base58(self):
        def do_test(as_text, as_bin):
            self.assertEqual(as_text, encoding.b2a_hashed_base58(as_bin))
            self.assertEqual(as_bin, encoding.a2b_hashed_base58(as_text))
            self.assertTrue(encoding.is_hashed_base58_valid(as_text))
            bogus_text = as_text[:-1] + chr(1+ord(as_text[-1]))
            self.assertFalse(encoding.is_hashed_base58_valid(bogus_text))

        do_test("14nr3dMd4VwNpFhFECU1A6imi", b'\x00\x01\x93\\|\xf2*\xb9\xbe\x19b\xae\xe4\x8c{')
        do_test("1CASrvcpMMTa4dz4DmYtAqcegCtdkhjvdn", b'\x00zr\xb6\xfac\xde6\xc4\xab\xc6\nh\xb5-\x7f3\xe3\xd7\xcd>')
        do_test("11111111111111114njGbaozZJui9o",
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00CnzQ)\x0b')
        do_test("1mLRia5CbfDB9752zxvtrpnkigecaYWUSQNLJGECA8641ywusqomjhfdb6EM7bXGj1Gb",
            b'\x00\x01\x11\xd3\x8e_\xc9\x07\x1f\xfc\xd2\x0bJv<\xc9\xaeO%+\xb4\xe4\x8f\xd6j\x83^%*\xda\x93\xffH\rm\xd4=\xc6*d\x11U\xa5aaaa')

    def test_double_sha256(self):
        def do_test(blob, expected_hash):
            self.assertEqual(encoding.double_sha256(blob), expected_hash)

        do_test(b"This is a test",
            b'\xea\xc6I\xd41\xaa?\xc2\xd5t\x9d\x1aP!\xbb\xa7\x81.\xc8;\x8aY\xfa\x84\x0b\xffu\xc1\x7f\x8af\\')
        do_test(b"The quick brown fox jumps over the lazy dogs",
            b'\x8a5e\x88yz\x90\x1a\x11\x03\x17y\xd4xz\xd0E~\xb0\x82\xc5k\xd9\xb6W\x15z\xcf1\xba\xe6\xc4')
        do_test(b'\x74' * 10000,
            b'nMw6\xaa7<G\x18\xee\xf2\xb9E(\xfe\xd5u\x19\xa0\xbd\xc3\xa8\xf40\n\xee7,\xbe\xde\xa9\xa0')

    def test_hash160(self):
        def do_test(blob, expected_hash):
            self.assertEqual(encoding.hash160(blob), expected_hash)

        do_test(b"This is a test",
            b'\x18\xac\x98\xfa*$\x12\xdd\xb7]\xe6\x04Y\xb5*\xcd\x98\xf2\xd9r')
        do_test(b"The quick brown fox jumps over the lazy dogs",
            b'v\xc9\xd1\xf3\xaaR&UN G_\x91\x9a\xad\xd1t\xf7\xe9\xb7')
        do_test(b'\x74' * 10000,
            b'\xa9a\x07\x02\x96gt\x01\xa5~\xae\r\x96\xd1MZ\x88\n,A')

    def test_wif_to_from_secret_exponent(self):
        def do_test(as_secret_exponent, as_wif, is_compressed):
            self.assertEqual(as_wif, encoding.secret_exponent_to_wif(as_secret_exponent, compressed=is_compressed))
            se, comp = encoding.wif_to_tuple_of_secret_exponent_compressed(as_wif)
            self.assertEqual(se, as_secret_exponent)
            self.assertEqual(comp, is_compressed)
            self.assertTrue(encoding.is_valid_wif(as_wif))

        WIF_LIST = [
            "5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC1115WWsh",
            "5J5KUK3VXP8HUefNVYPxwxVRokScZdWXpu1Tj8LfaAXMqHzMmbk",
            "5JCqR8LhFLuS5yJRDiNVsus5bpkTjsqFswUoUbz8EorifYA4TwJ",
            "5JLMMwdtyJgahHwTwtM2osEjPu4Jv89yvyx9E5dauTC5Vs6EjBA",
            "5JTsJkw6hGTjJcaWg4KZjpcPByNA6NUhz2RUyZH3a6XSL7vAYmy",
            "5JbPFaEJREEsuwDZQEJ6fmz2z3g1GcoS34tpj2vWEjroARtCMBF",
            "5JiuCPXW9C22XFrc8QGdbjMgn7yrSs8A67NAUWZxuPC9ziUizQP",
            "5JrR9Cphs9oB8aVeraFAXgjLaCHhd7St99qWDzDRa2XWq3RVw7d",
            "5Jyw627ub7aKju8hakDhTe6zNGbYoMmcCCJqyTrtEfrsfLDreVt",
            "5K7T2qR7K5MUMDmkJvCEPbUeALuPyc6LFEnBiwWLuKCEVdBp8qV",
            "5KExyeiK338cxYQo36AmKYrHxRDF9rR4JHFXUR9oZxXbKue7gdL",
            "5KNUvU1WkzumZs3qmG9JFWDwkVX6L6jnMKisDtoGEbrxACzxk6T",
            "5KVzsHJiUxgvBBgtVS7qBTbbYZpwWM4WQNCCyNSiuFCJzYMxg8H",
            "5KdWp6bvCvU4nWKwDc6N7QyFLe8ngbPETQfYir6BZtXfpsnSrGS",
        ]
        SE_LIST = [int(c * 64, 16) for c in "123456789abcde"]
        for se, wif in zip(SE_LIST, WIF_LIST):
            do_test(se, wif, is_compressed=False)

    def test_public_pair_to_sec(self):
        def do_test(as_public_pair, as_sec, is_compressed, as_hash160_sec, as_bitcoin_address):
            self.assertEqual(encoding.sec_to_public_pair(as_sec), as_public_pair)
            self.assertEqual(encoding.public_pair_to_sec(as_public_pair, compressed=is_compressed), as_sec)
            self.assertEqual(encoding.is_sec_compressed(as_sec), is_compressed)
            self.assertEqual(encoding.public_pair_to_hash160_sec(as_public_pair, compressed=is_compressed),
                             as_hash160_sec)
            self.assertEqual(encoding.hash160_sec_to_bitcoin_address(as_hash160_sec), as_bitcoin_address)
            self.assertEqual(encoding.public_pair_to_bitcoin_address(as_public_pair, compressed=is_compressed), as_bitcoin_address)
            self.assertTrue(encoding.is_valid_bitcoin_address(as_bitcoin_address))
            bad_address = as_bitcoin_address[:17] + chr(ord(as_bitcoin_address[17]) + 1) + as_bitcoin_address[18:]
            self.assertFalse(encoding.is_valid_bitcoin_address(bad_address))

        SEC_TEST_DATA = [
            ((35826991941973211494003564265461426073026284918572421206325859877044495085994,
                25491041833361137486709012056693088297620945779048998614056404517283089805761),
                "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                True,
                "fc7250a211deddc70ee5a2738de5f07817351cef",
                "1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9"
            ),
            ((31855367722742370537280679280108010854876607759940877706949385967087672770343,
                46659058944867745027460438812818578793297503278458148978085384795486842595210),
                "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27",
                True,
                "531260aa2a199e228c537dfa42c82bea2c7c1f4d",
                "18aF6pYXKDSXjXHpidt2G6okdVdBr8zA7z"
            ),
            ((27341391395138457474971175971081207666803680341783085051101294443585438462385,
                26772005640425216814694594224987412261034377630410179754457174380653265224672),
                "023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1",
                True,
                "3bc28d6d92d9073fb5e3adf481795eaf446bceed",
                "16Syw4SugWs4siKbK8cuxJXM2ukh2GKpRi"
            ),
            ((35826991941973211494003564265461426073026284918572421206325859877044495085994,
                25491041833361137486709012056693088297620945779048998614056404517283089805761),
                "044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"\
                  "385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1",
                False,
                "e4e517ee07984a4000cd7b00cbcb545911c541c4",
                "1MsHWS1BnwMc3tLE8G35UXsS58fKipzB7a"
            ),
            ((31855367722742370537280679280108010854876607759940877706949385967087672770343,
                46659058944867745027460438812818578793297503278458148978085384795486842595210),
                "04466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27"\
                  "6728176c3c6431f8eeda4538dc37c865e2784f3a9e77d044f33e407797e1278a",
                False,
                "b256082b934fe782adbacaafeadfca64c52a5384",
                "1HFxLkPTtMZeo5mDpZn6CF9sh4h2ycknwr"
            ),
            ((27341391395138457474971175971081207666803680341783085051101294443585438462385,
                26772005640425216814694594224987412261034377630410179754457174380653265224672),
                "043c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1"\
                  "3b306b0fe085665d8fc1b28ae1676cd3ad6e08eaeda225fe38d0da4de55703e0",
                False,
                "edf6bbd7ba7aad222c2b28e6d8d5001178e3680c",
                "1NhEipumt9Pug6pwTqMNRXhBG84K39Ebbi"
            ),
        ]

        for public_pair, sec, compressed, hash160_sec, bitcoin_address in SEC_TEST_DATA:
            do_test(public_pair, h2b(sec), compressed, h2b(hash160_sec), bitcoin_address)

if __name__ == '__main__':
    unittest.main()

