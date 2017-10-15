import unittest

from pycoin.coins.bitcoin.networks import BitcoinMainnet


class KeyParserTest(unittest.TestCase):

    def setUp(self):
        self._keyparser = BitcoinMainnet.keyparser

    def test_parse_bip32_prv(self):
        key = self._keyparser.key_from_text("xprv9s21ZrQH143K31AgNK5pyVvW23gHnkBq2wh5aEk6g1s496M8ZMjx"
                                            "ncCKZKgb5jZoY5eSJMJ2Vbyvi2hbmQnCuHBujZ2WXGTux1X2k9Krdtq")
        self.assertEqual(
            key.secret_exponent(), 0x91880b0e3017ba586b735fe7d04f1790f3c46b818a2151fb2def5f14dd2fd9c3)
        self.assertEqual(key.address(), "19Vqc8uLTfUonmxUEZac7fz1M5c5ZZbAii")
        self.assertEqual(key.address(use_uncompressed=True), "1MwkRkogzBRMehBntgcq2aJhXCXStJTXHT")
        subkey = key.subkey_for_path("0")
        self.assertEqual(subkey.address(), "1NV3j6NgeAkWBytXiQkWxMFLBtTdbef1rp")

    def test_parse_bip32_pub(self):
        key = self._keyparser.key_from_text("xpub661MyMwAqRbcFVF9ULcqLdsEa5WnCCugQAcgNd9iEMQ31tgH6u4"
                                            "DLQWoQayvtSVYFvXz2vPPpbXE1qpjoUFidhjFj82pVShWu9curWmb2zy")
        self.assertEqual(key.secret_exponent(), None)
        self.assertEqual(key.address(), "19Vqc8uLTfUonmxUEZac7fz1M5c5ZZbAii")
        self.assertEqual(key.address(use_uncompressed=True), "1MwkRkogzBRMehBntgcq2aJhXCXStJTXHT")
        subkey = key.subkey_for_path("0")
        self.assertEqual(subkey.address(), "1NV3j6NgeAkWBytXiQkWxMFLBtTdbef1rp")

    def test_parse_bad_bip32_prv(self):
        key = self._keyparser.key_from_text("xprv9s21ZrQH143K31AgNK5pyVvW23gHnkBq2wh5aEk6g1s496M8ZMjx"
                                            "ncCKZKgb5jZoY5eSJMJ2Vbyvi2hbmQnCuHBujZ2WXGTux1X2k9Krdtr")
        self.assertEqual(key, None)

    def test_parse_wif(self):
        key = self._keyparser.key_from_text("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
        self.assertEqual(key.secret_exponent(), 1)

    def test_parse_bad_wif(self):
        key = self._keyparser.key_from_text("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWo")
        self.assertEqual(key, None)

    def test_parse_address(self):
        key = self._keyparser.key_from_text("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
        self.assertEqual(key.address(), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")

    def test_parse_bad_address(self):
        key = self._keyparser.key_from_text("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMW")
        self.assertEqual(key, None)

    def test_parse_electrum_seed(self):
        key = self._keyparser.key_from_text("E:00000000000000000000000000000001")
        self.assertEqual(
            key.secret_exponent(), 0x2ccdb632d4630c8e5a417858f70876afe5585c15b1c0940771af9ac160201b1d)
        self.assertEqual(key.address(), "1L4sLh5R5MEyAQFSALJX8thcfGHeME5tTi")
        subkey = key.subkey("1")
        self.assertEqual(subkey.wif(), "5KYqyRxoMGnwsXfEFWtVifAKTzU9RcAZu1hme6GLMECKdWHybns")

    def test_parse_electrum_master_private(self):
        key = self._keyparser.key_from_text(
            "E:0000000000000000000000000000000000000000000000000000000000000001")
        self.assertEqual(key.secret_exponent(), 1)
