import unittest


from pycoin.crack.bip32 import ascend_bip32, crack_bip32
from pycoin.symbols.btc import network


class CrackBIP32Test(unittest.TestCase):

    def setUp(self):
        self.bip32_key = network.keys.bip32_seed(b"foo")

    def test_crack_bip32(self):
        bip32_key = self.bip32_key
        bip32_pub = bip32_key.public_copy()
        secret_exponent_p0_1_7_9 = bip32_key.subkey_for_path("0/1/7/9").secret_exponent()
        cracked_bip32_node = crack_bip32(bip32_pub, secret_exponent_p0_1_7_9, "0/1/7/9")
        self.assertEqual(cracked_bip32_node.hwif(as_private=True), bip32_key.hwif(as_private=True))

    def test_ascend_bip32(self):
        bip32_key = self.bip32_key
        bip32_pub = bip32_key.public_copy()
        secret_exponent_p9 = bip32_key.subkey_for_path("9").secret_exponent()
        secret_exponent = ascend_bip32(bip32_pub, secret_exponent_p9, 9)
        self.assertEqual(secret_exponent, bip32_key.secret_exponent())
