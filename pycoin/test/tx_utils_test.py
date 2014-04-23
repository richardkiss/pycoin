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

        for count in range(1, 11):
            tx = create_signed_tx(spendables, BITCOIN_ADDRESSES[1:count+1], wifs=WIFS[:1])
            self.assertEqual(tx.bad_signature_count(), 0)
            self.assertEqual(tx.fee(), FEE)
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
