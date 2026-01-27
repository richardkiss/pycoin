import unittest

from pycoin.encoding.hexbytes import h2b
from pycoin.encoding.sec import (
    is_sec_compressed, public_pair_to_sec, sec_to_public_pair, public_pair_to_hash160_sec
)
from pycoin.symbols.stak import network


def secret_exponent_to_wif(se, compressed):
    return network.keys.private(se, compressed).wif()


def public_pair_to_stak_address(pair, compressed):
    return network.keys.public(pair, is_compressed=compressed).address()


def stak_address_to_hash160_sec(stak_address):
    return network.parse.address(stak_address).hash160()


class StakKeyTranslationTest(unittest.TestCase):
    """
    Test STRAKS mainnet key translation using test vectors.
    
    These test vectors are derived from well-known Bitcoin test vectors
    using the same secret exponents, but with STRAKS network parameters
    (WIF prefix: 0xcc, Address prefix: 0x3f, P2SH prefix: 0x05).
    """

    def test_translation(self):
        def do_test(exp_hex, wif, c_wif, public_pair_sec, c_public_pair_sec, address_b58, c_address_b58):
            secret_exponent = int(exp_hex, 16)
            sec = h2b(public_pair_sec)
            c_sec = h2b(c_public_pair_sec)

            self.assertEqual(secret_exponent_to_wif(secret_exponent, compressed=False), wif)
            self.assertEqual(secret_exponent_to_wif(secret_exponent, compressed=True), c_wif)

            key = network.parse.wif(wif)
            exponent = key.secret_exponent()
            compressed = key.is_compressed()
            self.assertEqual(exponent, secret_exponent)
            self.assertFalse(compressed)

            key = network.parse.wif(c_wif)
            exponent = key.secret_exponent()
            compressed = key.is_compressed()
            self.assertEqual(exponent, secret_exponent)
            self.assertTrue(compressed)

            public_pair = secret_exponent * key._generator

            pk_public_pair = sec_to_public_pair(sec, key._generator)
            compressed = is_sec_compressed(sec)
            self.assertEqual(pk_public_pair, public_pair)
            self.assertFalse(is_sec_compressed(sec))
            self.assertEqual(public_pair_to_sec(pk_public_pair, compressed=False), sec)

            pk_public_pair = sec_to_public_pair(c_sec, key._generator)
            compressed = is_sec_compressed(c_sec)
            self.assertEqual(pk_public_pair, public_pair)
            self.assertTrue(compressed)
            self.assertEqual(public_pair_to_sec(pk_public_pair, compressed=True), c_sec)

            bca = public_pair_to_stak_address(pk_public_pair, compressed=True)
            self.assertEqual(bca, c_address_b58)

            self.assertEqual(stak_address_to_hash160_sec(c_address_b58),
                             public_pair_to_hash160_sec(pk_public_pair, compressed=True))

            bca = public_pair_to_stak_address(pk_public_pair, compressed=False)
            self.assertEqual(bca, address_b58)

            self.assertEqual(stak_address_to_hash160_sec(address_b58),
                             public_pair_to_hash160_sec(pk_public_pair, compressed=False))

        # Test vector 1
        do_test("1111111111111111111111111111111111111111111111111111111111111111",
                "7qgNw7riZkkM7gBvfRbNWNgdcLwLnuEMaRvJX2yLTKhUWBUdZ14",
                "XBroosGSTa6KnTyDrbYhvehvazzrMbXwpYzGKZhesBXePig6zouV",
                "044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
                "385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1",
                "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                "SiAHYGnLXJYoaC7gfh2A2S1ziutkWChqd7",
                "SkJpFvhXzbRZMjPwxnaxjDGcgKKpq7ad5d")

        # Test vector 2
        do_test("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "7sEaGuR9FJ68RXrVPVHmfqAT9EdWus74CwaPWkirT3hnVr1WGiF",
                "XJiusCMZQ6RdmHBSJFs2APaiPMAB2L9j9htNNKyjFxw1ozBUMdsM",
                "04ed83704c95d829046f1ac27806211132102c34e9ac7ffa1b71110658e5b9d1bd"
                "edc416f5cefc1db0625cd0c75de8192d2b592d7e3b00bcfb4a0e860d880fd1fc",
                "02ed83704c95d829046f1ac27806211132102c34e9ac7ffa1b71110658e5b9d1bd",
                "SfGMMmASVDPc9SWsQGSVZkLRpQEvY7rxaE",
                "SicRjGtsGqTf6UT2xWyCjonixS7GMkeYUF")

        # Test vector 3
        do_test("47f7616ea6f9b923076625b4488115de1ef1187f760e65f89eb6f4f7ff04b012",
                "7r6ZGjf65SRpfqdTVzvmaC9p4njG9t2MyeTWWuX1utQvHwPqTmt",
                "XDhXSTH7QbEZQRduxzgKjWDtjiqXtCD1b2L1GzoV2RvaDbW6UpSk",
                "042596957532fc37e40486b910802ff45eeaa924548c0e1c080ef804e523ec3ed3"
                "ed0a9004acf927666eee18b7f5e8ad72ff100a3bb710a577256fd7ec81eb1cb3",
                "032596957532fc37e40486b910802ff45eeaa924548c0e1c080ef804e523ec3ed3",
                "Sje37gmBeJPRWvFmS9pHzomjEMaHKnnTnM",
                "SVukBL6LpgvUUivnr73HvFaAhs4ggrr3Q6")


if __name__ == '__main__':
    unittest.main()
