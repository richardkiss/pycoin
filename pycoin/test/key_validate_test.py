#!/usr/bin/env python

import unittest

from pycoin.block import Block
from pycoin.encoding import hash160_sec_to_bitcoin_address
from pycoin.key import Key
from pycoin.key.bip32 import Wallet
from pycoin.networks import pay_to_script_prefix_for_netcode, prv32_prefix_for_netcode, NETWORK_NAMES
from pycoin.serialize import b2h_rev, h2b

from pycoin.key.validate import is_address_valid, is_wif_valid, is_public_bip32_valid, is_private_bip32_valid

def change_prefix(address, new_prefix):
    return hash160_sec_to_bitcoin_address(Key.from_text(address).hash160(), address_prefix=new_prefix)


PAY_TO_HASH_ADDRESSES = ["1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
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
            self.assertEqual(is_address_valid(address, allowable_types=["pay_to_script"]), None)
            self.assertEqual(is_address_valid(address, allowable_types=["address"]), "BTC")

        for address in PAY_TO_SCRIPT_ADDRESSES:
            self.assertEqual(address[0], "3")
            self.assertEqual(is_address_valid(address, allowable_types=["pay_to_script"]), "BTC")
            self.assertEqual(is_address_valid(address, allowable_types=["address"]), None)


    def test_is_wif_valid(self):
        WIFS = ["KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
                "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf",
                "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74NMTptX4",
                "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAvUcVfH"]

        for wif in WIFS:
            self.assertEqual(is_wif_valid(wif), "BTC")
            a = wif[:-1] + chr(ord(wif[-1])+1)
            self.assertEqual(is_wif_valid(a), None)

        for netcode in NETWORK_NAMES:
            for se in range(1, 10):
                key = Key(secret_exponent=se, netcode=netcode)
                for tv in [True, False]:
                    wif = key.wif(use_uncompressed=tv)
                    self.assertEqual(is_wif_valid(wif, allowable_netcodes=[netcode]), netcode)
                    a = wif[:-1] + chr(ord(wif[-1])+1)
                    self.assertEqual(is_wif_valid(a, allowable_netcodes=[netcode]), None)


    def test_is_public_private_bip32_valid(self):
        WALLET_KEYS = ["foo", "1", "2", "3", "4", "5"]

        # not all networks support BIP32 yet
        for netcode in "BTC XTN DOGE".split():
            for wk in WALLET_KEYS:
                wallet = Wallet.from_master_secret(wk.encode("utf8"), netcode=netcode)
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
