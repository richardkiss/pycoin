import unittest

from pycoin.encoding.b58 import a2b_base58, b2a_base58, a2b_hashed_base58, b2a_hashed_base58, is_hashed_base58_valid
from pycoin.encoding.base_conversion import from_long, to_long, EncodingError
from pycoin.encoding.bytes32 import to_bytes_32
from pycoin.encoding.hash import double_sha256, hash160
from pycoin.encoding.hexbytes import h2b
from pycoin.encoding.sec import is_sec_compressed, public_pair_to_hash160_sec, public_pair_to_sec, sec_to_public_pair
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.intbytes import iterbytes
from pycoin.symbols.btc import network


class EncodingTestCase(unittest.TestCase):

    def test_to_from_long(self):
        def do_test(as_int, prefix, as_rep, base):
            self.assertEqual((as_int, prefix), to_long(base, lambda v: v, iterbytes(as_rep)))
            self.assertEqual(as_rep, from_long(as_int, prefix, base, lambda v: v))

        do_test(10000101, 2, h2b("00009896e5"), 256)
        do_test(10000101, 3, h2b("0000009896e5"), 256)
        do_test(1460765565493402645157733592332121663123460211377, 1,
                h2b("00ffdefe4f4875cf119fc3d8f4a09ae37ec4cc42b1"), 256)

    def test_to_bytes_32(self):
        for i in range(256):
            v = to_bytes_32(i)
            self.assertEqual(v, b'\0' * 31 + bytes(bytearray([i])))
        for i in range(256, 512):
            v = to_bytes_32(i)
            self.assertEqual(v, b'\0' * 30 + bytes(bytearray([1, i & 0xff])))

    def test_to_from_base58(self):
        def do_test(as_text, as_bin):
            self.assertEqual(as_bin, a2b_base58(as_text))
            self.assertEqual(as_text, b2a_base58(as_bin))

        do_test("1abcdefghijkmnpqrst", h2b("0001935c7cf22ab9be1962aee48c7b"))
        do_test("1CASrvcpMMTa4dz4DmYtAqcegCtdkhjvdn",
                h2b("007a72b6fa63de36c4abc60a68b52d7f33e3d7cd3ec4babd39"))
        do_test("1111111111111111aaaa11aa",
                h2b("00000000000000000000000000000000436e7a51290b"))
        do_test("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
                h2b("000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6d"
                    "d43dc62a641155a5"))

    def test_to_from_hashed_base58(self):
        def do_test(as_text, as_bin):
            self.assertEqual(as_text, b2a_hashed_base58(as_bin))
            self.assertEqual(as_bin, a2b_hashed_base58(as_text))
            self.assertTrue(is_hashed_base58_valid(as_text))
            bogus_text = as_text[:-1] + chr(1+ord(as_text[-1]))
            self.assertFalse(is_hashed_base58_valid(bogus_text))

        do_test("14nr3dMd4VwNpFhFECU1A6imi", h2b("0001935c7cf22ab9be1962aee48c7b"))
        do_test("1CASrvcpMMTa4dz4DmYtAqcegCtdkhjvdn", h2b("007a72b6fa63de36c4abc60a68b52d7f33e3d7cd3e"))
        do_test("11111111111111114njGbaozZJui9o",
                h2b("00000000000000000000000000000000436e7a51290b"))
        do_test("1mLRia5CbfDB9752zxvtrpnkigecaYWUSQNLJGECA8641ywusqomjhfdb6EM7bXGj1Gb",
                h2b("000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6dd43dc62a641155a561616161"))

    def test_double_sha256(self):
        def do_test(blob, expected_hash):
            self.assertEqual(double_sha256(blob), expected_hash)

        do_test(b"This is a test",
                h2b("eac649d431aa3fc2d5749d1a5021bba7812ec83b8a59fa840bff75c17f8a665c"))
        do_test(b"The quick brown fox jumps over the lazy dogs",
                h2b("8a356588797a901a11031779d4787ad0457eb082c56bd9b657157acf31bae6c4"))
        do_test(b'\x74' * 10000,
                h2b("6e4d7736aa373c4718eef2b94528fed57519a0bdc3a8f4300aee372cbedea9a0"))

    def test_hash160(self):
        def do_test(blob, expected_hash):
            self.assertEqual(hash160(blob), expected_hash)

        do_test(b"This is a test", h2b("18ac98fa2a2412ddb75de60459b52acd98f2d972"))
        do_test(b"The quick brown fox jumps over the lazy dogs",
                h2b("76c9d1f3aa5226554e20475f919aadd174f7e9b7"))
        do_test(b'\x74' * 10000, h2b("a961070296677401a57eae0d96d14d5a880a2c41"))

    def test_wif_to_from_secret_exponent(self):
        def do_test(as_secret_exponent, as_wif, is_compressed):
            key = network.keys.private(as_secret_exponent, is_compressed=is_compressed)
            self.assertEqual(as_wif, key.wif())
            key = network.parse.wif(as_wif)
            se = key.secret_exponent()
            comp = key.is_compressed()
            self.assertEqual(se, as_secret_exponent)
            self.assertEqual(comp, is_compressed)

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
            self.assertEqual(sec_to_public_pair(as_sec, secp256k1_generator), as_public_pair)
            self.assertEqual(public_pair_to_sec(as_public_pair, compressed=is_compressed), as_sec)
            self.assertEqual(is_sec_compressed(as_sec), is_compressed)
            self.assertEqual(public_pair_to_hash160_sec(as_public_pair, compressed=is_compressed),
                             as_hash160_sec)

            self.assertEqual(network.address.for_p2pkh(as_hash160_sec), as_bitcoin_address)
            self.assertIsNotNone(network.parse.address(as_bitcoin_address))
            bad_address = as_bitcoin_address[:17] + chr(ord(as_bitcoin_address[17]) + 1) + as_bitcoin_address[18:]
            self.assertIsNone(network.parse.address(bad_address))

        SEC_TEST_DATA = [
            (
                (35826991941973211494003564265461426073026284918572421206325859877044495085994,
                 25491041833361137486709012056693088297620945779048998614056404517283089805761),
                "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                True,
                "fc7250a211deddc70ee5a2738de5f07817351cef",
                "1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9"
            ),
            (
                (31855367722742370537280679280108010854876607759940877706949385967087672770343,
                 46659058944867745027460438812818578793297503278458148978085384795486842595210),
                "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27",
                True,
                "531260aa2a199e228c537dfa42c82bea2c7c1f4d",
                "18aF6pYXKDSXjXHpidt2G6okdVdBr8zA7z"
            ),
            (
                (27341391395138457474971175971081207666803680341783085051101294443585438462385,
                 26772005640425216814694594224987412261034377630410179754457174380653265224672),
                "023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1",
                True,
                "3bc28d6d92d9073fb5e3adf481795eaf446bceed",
                "16Syw4SugWs4siKbK8cuxJXM2ukh2GKpRi"
            ),
            (
                (35826991941973211494003564265461426073026284918572421206325859877044495085994,
                 25491041833361137486709012056693088297620945779048998614056404517283089805761),
                "044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
                "385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1",
                False,
                "e4e517ee07984a4000cd7b00cbcb545911c541c4",
                "1MsHWS1BnwMc3tLE8G35UXsS58fKipzB7a"
            ),
            (
                (31855367722742370537280679280108010854876607759940877706949385967087672770343,
                 46659058944867745027460438812818578793297503278458148978085384795486842595210),
                "04466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27"
                "6728176c3c6431f8eeda4538dc37c865e2784f3a9e77d044f33e407797e1278a",
                False,
                "b256082b934fe782adbacaafeadfca64c52a5384",
                "1HFxLkPTtMZeo5mDpZn6CF9sh4h2ycknwr"
            ),
            (
                (27341391395138457474971175971081207666803680341783085051101294443585438462385,
                 26772005640425216814694594224987412261034377630410179754457174380653265224672),
                "043c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1"
                "3b306b0fe085665d8fc1b28ae1676cd3ad6e08eaeda225fe38d0da4de55703e0",
                False,
                "edf6bbd7ba7aad222c2b28e6d8d5001178e3680c",
                "1NhEipumt9Pug6pwTqMNRXhBG84K39Ebbi"
            ),
        ]

        for public_pair, sec, compressed, hash160_sec, bitcoin_address in SEC_TEST_DATA:
            do_test(public_pair, h2b(sec), compressed, h2b(hash160_sec), bitcoin_address)

    def test_sec(self):
        pair_blob = h2b("0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483a"
                        "da7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
        sec_to_public_pair(pair_blob, secp256k1_generator, strict=False)
        try:
            sec_to_public_pair(pair_blob, secp256k1_generator, strict=True)
            self.fail("sec_to_public_pair unexpectedly succeeded")
        except EncodingError:
            pass


if __name__ == '__main__':
    unittest.main()
