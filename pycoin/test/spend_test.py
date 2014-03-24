#!/usr/bin/env python

import hashlib
import struct
import unittest

from pycoin.ecdsa import generator_secp256k1, public_pair_for_secret_exponent
from pycoin.encoding import public_pair_to_bitcoin_address, secret_exponent_to_wif

from pycoin.tx.TxOut import standard_tx_out_script
from pycoin.tx.spend import create_and_sign_tx
from pycoin.tx.Spendable import Spendable


def fake_hash(idx):
    d = struct.pack("Q", idx)
    return hashlib.sha256(d).digest()


class SpendTest(unittest.TestCase):
    def test_simple_spend(self):

        FEE = 10000
        BITCOIN_ADDRESSES = [public_pair_to_bitcoin_address(
            public_pair_for_secret_exponent(generator_secp256k1, i))
            for i in range(1, 21)]

        WIFS = [secret_exponent_to_wif(i) for i in range(1, 21)]

        # create a fake Spendable
        COIN_VALUE = 100000000
        spendables = [Spendable(COIN_VALUE, standard_tx_out_script(BITCOIN_ADDRESSES[0]), fake_hash(1), 0)]

        for count in range(1, 11):
            tx = create_and_sign_tx(spendables, BITCOIN_ADDRESSES[1:count+1], wifs=WIFS[:1])
            self.assertEqual(tx.bad_signature_count(), 0)
            self.assertEqual(tx.fee(), FEE)
            for i in range(count):
                extra = (1 if i < ((COIN_VALUE - FEE) % count) else 0)
                self.assertEqual(tx.txs_out[i].coin_value, (COIN_VALUE - FEE)//count + extra)


if __name__ == "__main__":
    unittest.main()
