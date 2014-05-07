#!/usr/bin/env python

import hashlib
import struct
import unittest

from pycoin.ecdsa import generator_secp256k1, public_pair_for_secret_exponent
from pycoin.encoding import public_pair_to_bitcoin_address, secret_exponent_to_wif

from pycoin.tx.Tx import BadSpendableError
from pycoin.tx.TxOut import standard_tx_out_script
from pycoin.tx.tx_utils import create_signed_tx
from pycoin.tx.Spendable import Spendable


BITCOIN_ADDRESSES = [public_pair_to_bitcoin_address(
    public_pair_for_secret_exponent(generator_secp256k1, i))
    for i in range(1, 21)]

WIFS = [secret_exponent_to_wif(i) for i in range(1, 21)]

FAKE_HASHES = [hashlib.sha256(struct.pack("Q", idx)).digest() for idx in range(100)]


class SpendTest(unittest.TestCase):

    def test_simple_spend(self):

        FEE = 10000

        # create a fake Spendable
        COIN_VALUE = 100000000
        spendables = [Spendable(COIN_VALUE, standard_tx_out_script(BITCOIN_ADDRESSES[0]), FAKE_HASHES[1], 0)]

        EXPECTED_IDS = [
            "d28bff6c4a8a0f9e7d5b7df0670d07b43c5613d8c9b14e84707b1e2c0154a978",
            "7afbe63b00171b18f806ebd48190ebc1c68cadf286a85489c06ebe43d146489e",
            "2b90c150ba1d080a0816952f5d9c2642d408989cbc4d4c540591c8c9241294bd",
            "17b0b5b22887081595c1a9ad153e903f63bb8682ae59d6082df018dc617e5e67",
            "dff1b34c243becb096ad2a2d6119973067a8137cc8bf95615e742bbf6f0944c1",
            "206bbfbb759a8f91901d86b62390d7587f6097a32994ece7752d143fc8a02cee",
            "7841412716ad35cbc9954e547ba85be89e5ed0b34ed5fb8d7594517318dc10d6",
            "8b7e643bf47db46ada7a75b8498990b111fe20917b5610ca6759b8b0078ccd5e",
            "5756f0a6d5a2bbb93a07f0729d3773aaafd21393ede3ec0e20b0b5219ca45548",
            "32dcbb34965ea72d2caa59eb1e907aa28bac2afea43214c1809f5d8ed360f30e",
        ]

        for count in range(1, 11):
            tx = create_signed_tx(spendables, BITCOIN_ADDRESSES[1:count+1], wifs=WIFS[:1])
            self.assertEqual(tx.bad_signature_count(), 0)
            self.assertEqual(tx.fee(), FEE)
            self.assertEqual(tx.id(), EXPECTED_IDS[count-1])
            for idx in range(1, count+1):
                self.assertEqual(tx.txs_out[idx-1].bitcoin_address(), BITCOIN_ADDRESSES[idx])
            # TODO: add check that s + s < generator for each signature
            for i in range(count):
                extra = (1 if i < ((COIN_VALUE - FEE) % count) else 0)
                self.assertEqual(tx.txs_out[i].coin_value, (COIN_VALUE - FEE)//count + extra)

    def test_confirm_input(self):
        FEE = 10000

        # create a fake Spendable
        COIN_VALUE = 100000000
        spendables = [Spendable(COIN_VALUE, standard_tx_out_script(BITCOIN_ADDRESSES[0]), FAKE_HASHES[1], 0)]

        tx_1 = create_signed_tx(spendables, BITCOIN_ADDRESSES[1:2], wifs=WIFS[:1])

        spendables = tx_1.tx_outs_as_spendable()

        tx_db = dict((tx.hash(), tx) for tx in [tx_1])

        tx_2 = create_signed_tx(spendables, BITCOIN_ADDRESSES[2:3], wifs=WIFS[:3])
        tx_2.validate_unspents(tx_db)

        tx_2 = create_signed_tx([s.as_dict() for s in spendables], BITCOIN_ADDRESSES[2:3], wifs=WIFS[:3])
        tx_2.validate_unspents(tx_db)

        tx_2 = create_signed_tx([s.as_text() for s in spendables], BITCOIN_ADDRESSES[2:3], wifs=WIFS[:3])
        tx_2.validate_unspents(tx_db)


    def test_confirm_input_raises(self):
        FEE = 10000

        # create a fake Spendable
        COIN_VALUE = 100000000
        spendables = [Spendable(COIN_VALUE, standard_tx_out_script(BITCOIN_ADDRESSES[0]), FAKE_HASHES[1], 0)]

        tx_1 = create_signed_tx(spendables, BITCOIN_ADDRESSES[1:2], wifs=WIFS[:1])
        spendables = tx_1.tx_outs_as_spendable()
        spendables[0].coin_value += 100

        tx_db = dict((tx.hash(), tx) for tx in [tx_1])
        tx_2 = create_signed_tx(spendables, BITCOIN_ADDRESSES[2:3], wifs=WIFS[:3])

        self.assertRaises(BadSpendableError, tx_2.validate_unspents, tx_db)


if __name__ == "__main__":
    unittest.main()
