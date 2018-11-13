import unittest

from pycoin.symbols.btc import network


class ParseTest(unittest.TestCase):

    def test_parse_wif(self):
        WIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        k = network.parse.wif(WIF)
        self.assertEqual(k.secret_exponent(), 1)

    def test_parse_bip32_prv(self):
        HWIF = (
            "xprv9s21ZrQH143K31AgNK5pyVvW23gHnkBq2wh5aEk6g1s496M8ZMj"
            "xncCKZKgb5jZoY5eSJMJ2Vbyvi2hbmQnCuHBujZ2WXGTux1X2k9Krdtq")
        k = network.parse.bip32_prv(HWIF)
        self.assertEqual(k.as_text(as_private=True), HWIF)

    def test_parse_bip32_pub(self):
        HWIF = (
            "xpub661MyMwAqRbcFVF9ULcqLdsEa5WnCCugQAcgNd9iEMQ31tgH6u4DL"
            "QWoQayvtSVYFvXz2vPPpbXE1qpjoUFidhjFj82pVShWu9curWmb2zy")
        k = network.parse.bip32_pub(HWIF)
        self.assertEqual(k.as_text(), HWIF)

    def test_parse_bip32_seed(self):
        expected_hwif = (
            "xprv9s21ZrQH143K31AgNK5pyVvW23gHnkBq2wh5aEk6g1s496M8ZMjxn"
            "cCKZKgb5jZoY5eSJMJ2Vbyvi2hbmQnCuHBujZ2WXGTux1X2k9Krdtq")
        k = network.parse.bip32_seed("P:foo")
        self.assertEqual(k.as_text(as_private=True), expected_hwif)
        k = network.parse.bip32_seed("H:666f6f")
        self.assertEqual(k.as_text(as_private=True), expected_hwif)

    def test_parse_electrum_seed(self):
        E_INIT = "E:00000000000000000000000000000001"
        k = network.parse.electrum_seed(E_INIT)
        self.assertEqual(
            k.secret_exponent(),
            0x2ccdb632d4630c8e5a417858f70876afe5585c15b1c0940771af9ac160201b1d)

    def test_parse_electrum_prv(self):
        E_PRV = "E:0000000000000000000000000000000000000000000000000000000000000001"
        k = network.parse.electrum_prv(E_PRV)
        self.assertEqual(k.secret_exponent(), 1)

    def test_parse_electrum_pub(self):
        E_PUB = (
            "E:"
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
        k = network.parse.electrum_pub(E_PUB)
        self.assertEqual(k.address(), "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")

    def test_parse_address_p2pkh(self):
        address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
        k = network.parse.p2pkh(address)
        self.assertEqual(k.address(), address)

    def test_parse_address_p2sh(self):
        address = "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"
        k = network.parse.p2sh(address)
        self.assertEqual(k.address(), address)

    def test_parse_address_p2pkh_wit(self):
        address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        k = network.parse.p2pkh_segwit(address)
        self.assertEqual(k.address(), address)

    def test_parse_address_p2sh_wit(self):
        import hashlib
        address = network.address.for_p2sh_wit(hashlib.sha256(b'').digest())

        k = network.parse.p2sh_segwit(address)
        self.assertEqual(k.address(), address)

    def test_parse_script(self):
        k = network.parse.script("foo")
        self.assertEqual(k, None)
        k = network.parse.script("OP_CHECKSIG")
        self.assertEqual(k.disassemble(), "OP_CHECKSIG")
