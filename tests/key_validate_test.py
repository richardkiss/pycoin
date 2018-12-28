import unittest

from pycoin.encoding.b58 import a2b_hashed_base58, b2a_hashed_base58
from pycoin.key.Key import InvalidSecretExponentError
from pycoin.networks.registry import network_for_netcode
from pycoin.networks.registry import network_codes

NETCODES = "BTC XTN DOGE".split()


BitcoinMainnet = network_for_netcode("BTC")
BitcoinTestnet = network_for_netcode("XTN")

# BRAIN DAMAGE
BIP32Node = BitcoinMainnet.BIP32Node


def change_prefix(address, new_prefix):
    return b2a_hashed_base58(new_prefix + a2b_hashed_base58(address)[1:])


P2PKH_ADDRESSES = [
    "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
    "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP", "1LagHJk2FyCV2VzrNHVqg3gYG4TSYwDV4m",
    "1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb", "1NZUP3JAc9JkmbvmoTv7nVgZGtyJjirKV1"]

P2SH_ADDRESSES = [
    '3CNHUhP3uyB9EUtRLsmvFUmvGdjGdkTxJw', '3EyPVdtVrtMJ1XwPT9oiBrQysGpRY8LE9K',
    '32JNcZWZqMX72bpzzgFLhkX56WviowgUtS', '3MGhCrETosWs7fhHVPAS6g3UQakA7Xz3wb',
    '3DAP9jDzQ76R4B94qa2Q8CgQrbEXvUoghh', '3PFVJancA3d8rmdCvZaiD83VRRG2Em15Ge']


class KeyUtilsTest(unittest.TestCase):

    def test_address_valid_btc(self):
        for address in P2PKH_ADDRESSES:
            self.assertEqual(BitcoinMainnet.parse.p2pkh(address).address(), address)
            a = address[:-1] + chr(ord(address[-1])+1)
            self.assertIsNone(BitcoinMainnet.parse.address(a))

        for address in P2PKH_ADDRESSES:
            self.assertIsNone(BitcoinMainnet.parse.p2sh(address))
            self.assertEqual(BitcoinMainnet.parse.p2pkh(address).address(), address)

        for address in P2SH_ADDRESSES:
            self.assertEqual(address[0], "3")
            self.assertEqual(BitcoinMainnet.parse.p2sh(address).address(), address)
            self.assertIsNone(BitcoinMainnet.parse.p2pkh(address))

    def test_is_wif_valid(self):
        WIFS = ["KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
                "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf",
                "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74NMTptX4",
                "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAvUcVfH"]

        for wif in WIFS:
            self.assertEqual(BitcoinMainnet.parse.wif(wif).wif(), wif)
            a = wif[:-1] + chr(ord(wif[-1])+1)
            self.assertIsNone(BitcoinMainnet.parse.wif(a))

        NETWORK_NAMES = network_codes()
        for netcode in NETWORK_NAMES:
            network = network_for_netcode(netcode)
            if not getattr(network, "Key", None):
                continue
            for se in range(1, 10):
                key = network.Key(secret_exponent=se)
                for tv in [True, False]:
                    wif = key.wif(use_uncompressed=tv)
                    self.assertEqual(network.parse.wif(wif).wif(), wif)
                    a = wif[:-1] + chr(ord(wif[-1])+1)
                    self.assertIsNone(network.parse.wif(a))

    def test_is_public_private_bip32_valid(self):
        from pycoin.networks.registry import network_for_netcode
        WALLET_KEYS = ["foo", "1", "2", "3", "4", "5"]

        # not all networks support BIP32 yet
        for netcode in NETCODES:
            network = network_for_netcode(netcode)
            BIP32Node = network.BIP32Node
            for wk in WALLET_KEYS:
                wallet = BIP32Node.from_master_secret(wk.encode("utf8"))
                text = wallet.hwif(as_private=True)
                self.assertEqual(network.parse.bip32_prv(text).hwif(as_private=True), text)
                self.assertIsNone(network.parse.bip32_pub(text))
                a = text[:-1] + chr(ord(text[-1])+1)
                self.assertIsNone(network.parse.bip32_prv(a))
                self.assertIsNone(network.parse.bip32_pub(a))
                text = wallet.hwif(as_private=False)
                self.assertIsNone(network.parse.bip32_prv(text))
                self.assertEqual(network.parse.bip32_pub(text).hwif(), text)
                a = text[:-1] + chr(ord(text[-1])+1)
                self.assertIsNone(network.parse.bip32_prv(a))
                self.assertIsNone(network.parse.bip32_pub(a))

    def test_key_limits(self):
        nc = 'BTC'
        cc = b'000102030405060708090a0b0c0d0e0f'
        order = BitcoinMainnet.keys.private(1)._generator.order()

        for k in -1, 0, order, order + 1:
            self.assertRaises(InvalidSecretExponentError, BitcoinMainnet.keys.private, secret_exponent=k)
            self.assertRaises(InvalidSecretExponentError, BIP32Node, nc, cc, secret_exponent=k)

        for i in range(1, 512):
            BitcoinMainnet.keys.private(secret_exponent=i)
            BIP32Node(cc, secret_exponent=i)

    def test_repr(self):
        key = BitcoinTestnet.keys.private(secret_exponent=273)

        address = key.address()
        pub_k = BitcoinTestnet.parse(address)
        self.assertEqual(repr(pub_k),  '<mhDVBkZBWLtJkpbszdjZRkH1o5RZxMwxca>')

        wif = key.wif()
        priv_k = BitcoinTestnet.parse.wif(wif)
        self.assertEqual(
            repr(priv_k),
            'private_for <XTNSEC:0264e1b1969f9102977691a40431b0b672055dcf31163897d996434420e6c95dc9>')


if __name__ == '__main__':
    unittest.main()
