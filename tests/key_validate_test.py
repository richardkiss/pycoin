import unittest

from pycoin.coins.bitcoin.networks import BitcoinMainnet, BitcoinTestnet
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.encoding.b58 import b2a_hashed_base58
from pycoin.key.Key import InvalidSecretExponentError
from pycoin.networks.registry import pay_to_script_prefix_for_netcode, network_codes
from pycoin.ui.key_from_text import key_from_text
from pycoin.ui.validate import is_address_valid, is_wif_valid, is_public_bip32_valid, is_private_bip32_valid

# BRAIN DAMAGE
Key = BitcoinMainnet.ui._key_class
XTNKey = BitcoinTestnet.ui._key_class
BIP32Node = BitcoinMainnet.ui._bip32node_class


def change_prefix(address, new_prefix):
    return b2a_hashed_base58(new_prefix + key_from_text(address).hash160())


PAY_TO_HASH_ADDRESSES = [
    "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
    "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP", "1LagHJk2FyCV2VzrNHVqg3gYG4TSYwDV4m",
    "1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb", "1NZUP3JAc9JkmbvmoTv7nVgZGtyJjirKV1"]

PAY_TO_SCRIPT_PREFIX = pay_to_script_prefix_for_netcode("BTC")

PAY_TO_SCRIPT_ADDRESSES = [change_prefix(t, PAY_TO_SCRIPT_PREFIX) for t in PAY_TO_HASH_ADDRESSES]


class KeyUtilsTest(unittest.TestCase):

    def test_address_valid_btc(self):
        for address in PAY_TO_HASH_ADDRESSES:
            self.assertEqual(is_address_valid(address), "BTC")
            a = address[:-1] + chr(ord(address[-1])+1)
            self.assertEqual(is_address_valid(a), None)

        for address in PAY_TO_HASH_ADDRESSES:
            self.assertEqual(is_address_valid(address, allowable_types=["p2sh"]), None)
            self.assertEqual(is_address_valid(address, allowable_types=["p2pkh"]), "BTC")

        for address in PAY_TO_SCRIPT_ADDRESSES:
            self.assertEqual(address[0], "3")
            self.assertEqual(is_address_valid(address, allowable_types=["p2sh"]), "BTC")
            self.assertEqual(is_address_valid(address, allowable_types=["p2pkh"]), None)

    def test_is_wif_valid(self):
        WIFS = ["KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
                "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf",
                "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74NMTptX4",
                "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAvUcVfH"]

        for wif in WIFS:
            self.assertEqual(is_wif_valid(wif), "BTC")
            a = wif[:-1] + chr(ord(wif[-1])+1)
            self.assertEqual(is_wif_valid(a), None)

        from pycoin.networks.registry import network_for_netcode
        NETWORK_NAMES = network_codes()
        for netcode in NETWORK_NAMES:
            network = network_for_netcode(netcode)
            if not getattr(network, "key", None):
                continue
            for se in range(1, 10):
                key = network.key(secret_exponent=se, generator=secp256k1_generator)
                for tv in [True, False]:
                    wif = key.wif(use_uncompressed=tv)
                    self.assertEqual(is_wif_valid(wif, allowable_netcodes=[netcode]), netcode)
                    a = wif[:-1] + chr(ord(wif[-1])+1)
                    self.assertEqual(is_wif_valid(a, allowable_netcodes=[netcode]), None)

    def test_is_public_private_bip32_valid(self):
        from pycoin.networks.registry import network_for_netcode
        NETWORK_NAMES = network_codes()
        WALLET_KEYS = ["foo", "1", "2", "3", "4", "5"]

        # not all networks support BIP32 yet
        for netcode in "BTC XTN DOGE".split():
            network = network_for_netcode(netcode)
            BIP32Node = network.ui._bip32node_class
            for wk in WALLET_KEYS:
                wallet = BIP32Node.from_master_secret(secp256k1_generator, wk.encode("utf8"))
                text = wallet.wallet_key(as_private=True)
                self.assertEqual(is_private_bip32_valid(text, allowable_netcodes=NETWORK_NAMES), netcode)
                self.assertEqual(is_public_bip32_valid(text, allowable_netcodes=NETWORK_NAMES), None)
                a = text[:-1] + chr(ord(text[-1])+1)
                self.assertEqual(is_private_bip32_valid(a, allowable_netcodes=NETWORK_NAMES), None)
                self.assertEqual(is_public_bip32_valid(a, allowable_netcodes=NETWORK_NAMES), None)
                text = wallet.wallet_key(as_private=False)
                self.assertEqual(is_private_bip32_valid(text, allowable_netcodes=NETWORK_NAMES), None)
                self.assertEqual(is_public_bip32_valid(text, allowable_netcodes=NETWORK_NAMES), netcode)
                a = text[:-1] + chr(ord(text[-1])+1)
                self.assertEqual(is_private_bip32_valid(a, allowable_netcodes=NETWORK_NAMES), None)
                self.assertEqual(is_public_bip32_valid(a, allowable_netcodes=NETWORK_NAMES), None)

    def test_key_limits(self):
        nc = 'BTC'
        cc = b'000102030405060708090a0b0c0d0e0f'
        order = secp256k1_generator.order()

        for k in -1, 0, order, order + 1:
            self.assertRaises(InvalidSecretExponentError, Key, secret_exponent=k, generator=secp256k1_generator)
            self.assertRaises(InvalidSecretExponentError, BIP32Node, secp256k1_generator, nc, cc, secret_exponent=k)

        for i in range(1, 512):
            Key(secret_exponent=i, generator=secp256k1_generator)
            BIP32Node(secp256k1_generator, cc, secret_exponent=i)

    def test_repr(self):
        key = XTNKey(secret_exponent=273, generator=secp256k1_generator)

        address = key.address()
        pub_k = key_from_text(address)
        self.assertEqual(repr(pub_k),  '<mhDVBkZBWLtJkpbszdjZRkH1o5RZxMwxca>')

        wif = key.wif()
        priv_k = key_from_text(wif)
        self.assertEqual(
            repr(priv_k),
            'private_for <XTNSEC:0264e1b1969f9102977691a40431b0b672055dcf31163897d996434420e6c95dc9>')


if __name__ == '__main__':
    unittest.main()
