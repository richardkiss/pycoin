import unittest

from pycoin.encoding.hexbytes import h2b
from pycoin.encoding.sec import (
    is_sec_compressed, public_pair_to_sec, sec_to_public_pair, public_pair_to_hash160_sec
)
from pycoin.symbols.tstak import network


def secret_exponent_to_wif(se, compressed):
    return network.keys.private(se, compressed).wif()


def public_pair_to_tstak_address(pair, compressed):
    return network.keys.public(pair, is_compressed=compressed).address()


def tstak_address_to_hash160_sec(tstak_address):
    return network.parse.address(tstak_address).hash160()


class TStakKeyTranslationTest(unittest.TestCase):
    """
    Test STRAKS testnet key translation using test vectors.
    
    These test vectors are derived from well-known Bitcoin test vectors
    using the same secret exponents, but with STRAKS testnet network parameters
    (WIF prefix: 0xef, Address prefix: 0x7f, P2SH prefix: 0x13).
    """

    def test_translation_compressed(self):
        """Test compressed key translation for testnet."""
        def do_test(exp_hex, c_wif, c_public_pair_sec, c_address_b58):
            secret_exponent = int(exp_hex, 16)
            c_sec = h2b(c_public_pair_sec)

            self.assertEqual(secret_exponent_to_wif(secret_exponent, compressed=True), c_wif)

            key = network.parse.wif(c_wif)
            exponent = key.secret_exponent()
            compressed = key.is_compressed()
            self.assertEqual(exponent, secret_exponent)
            self.assertTrue(compressed)

            public_pair = secret_exponent * key._generator

            pk_public_pair = sec_to_public_pair(c_sec, key._generator)
            compressed = is_sec_compressed(c_sec)
            self.assertEqual(pk_public_pair, public_pair)
            self.assertTrue(compressed)
            self.assertEqual(public_pair_to_sec(pk_public_pair, compressed=True), c_sec)

            bca = public_pair_to_tstak_address(pk_public_pair, compressed=True)
            self.assertEqual(bca, c_address_b58)

            self.assertEqual(tstak_address_to_hash160_sec(c_address_b58),
                             public_pair_to_hash160_sec(pk_public_pair, compressed=True))

        # Test vector 1
        do_test("1111111111111111111111111111111111111111111111111111111111111111",
                "cN9spWsvaxA8taS7DFMxnk1yJD2gaF2PX1npuTpy3vuZFJdwavaw",
                "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                "tVwRGsmyS95dhUKVXduMmEgxxbpCH7u9hV")

        # Test vector 2
        do_test("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "cV1ysqy3XUVSsPeKeugH2Utm6ZC1EyeArAgvxE73SiJvfa6AJng7",
                "02ed83704c95d829046f1ac27806211132102c34e9ac7ffa1b71110658e5b9d1bd",
                "tUF2kDyJiP7jSDNaXNHbmqD5EibdnZpJxm")


if __name__ == '__main__':
    unittest.main()
