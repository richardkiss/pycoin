#!/usr/bin/env python

import argparse
import binascii
import decimal
import io
import itertools
import sys

from pycoin import ecdsa
from pycoin import encoding
from pycoin.convention import tx_fee, btc_to_satoshi, satoshi_to_btc
from pycoin.services import blockchain_info
from pycoin.tx import Tx, UnsignedTx, TxOut, SecretExponentSolver
from pycoin.wallet import Wallet

def main():
    parser = argparse.ArgumentParser(description="Create (bogus) coinbase transactions, for testing purposes.")
    parser.add_argument("wif/value", help='a WIF and coin count (usually 50) separated by a "/"', nargs="+")

    args = parser.parse_args()
    for wv in getattr(args, "wif/value"):
        wif, btc_amount = wv.split("/")
        satoshi_amount = btc_to_satoshi(btc_amount)
        secret_exponent, compressed = encoding.wif_to_tuple_of_secret_exponent_compressed(wif)
        public_pair = ecdsa.public_pair_for_secret_exponent(ecdsa.secp256k1.generator_secp256k1, secret_exponent)
        public_key_sec = encoding.public_pair_to_sec(public_pair, compressed=compressed)
        coinbase_tx = Tx.coinbase_tx(public_key_sec, satoshi_amount)

        tx_hash_hex = binascii.hexlify(coinbase_tx.hash())
        tx_output_index = 0
        tx_out_val = str(satoshi_to_btc(coinbase_tx.txs_out[tx_output_index].coin_value)).rstrip('0').rstrip('.')
        tx_out_script_hex = binascii.hexlify(coinbase_tx.txs_out[tx_output_index].script)
        # produce output in the form:
        #  tx_hash_hex/tx_output_index_decimal/tx_out_val/tx_out_script_hex
        # which can be used as a fake input to a later transaction
        print "/".join([tx_hash_hex, str(tx_output_index), tx_out_script_hex, tx_out_val])

if __name__ == '__main__':
    main()
