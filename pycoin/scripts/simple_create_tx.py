#!/usr/bin/env python

# Sample usage (with fake coinbase transaction):
# ./simple_create_tx.py INPUT_BITCOIN_ADDRESS OUTPUT_BITCOIN_ADDRESS output.file.name

import argparse
import codecs
import sys

from pycoin.convention import tx_fee, satoshi_to_mbtc
from pycoin.serialize import stream_to_bytes
from pycoin.services.blokrio import unspent_for_address
from pycoin.tx import Tx
from pycoin.tx.airgap import minimal_tx_db_for_unspents, stream_minimal_tx_db_for_tx
from pycoin.tx.TxIn import TxIn
from pycoin.tx.TxOut import TxOut, standard_tx_out_script


def check_fees(tx, tx_db):
    total_in, total_out = tx.total_in(tx_db), tx.total_out()
    actual_tx_fee = total_in - total_out
    recommended_tx_fee = tx_fee.recommended_fee_for_tx(tx)
    if actual_tx_fee > recommended_tx_fee:
        print("warning: transaction fee of %s exceeds expected value of %s mBTC" %
              (satoshi_to_mbtc(actual_tx_fee), satoshi_to_mbtc(recommended_tx_fee)))
    elif actual_tx_fee < 0:
        print("not enough source coins (%s mBTC) for destination (%s mBTC)."
              " Short %s mBTC" %
              (satoshi_to_mbtc(total_in),
               satoshi_to_mbtc(total_out), satoshi_to_mbtc(-actual_tx_fee)))
    elif actual_tx_fee < recommended_tx_fee:
        print("warning: transaction fee lower than (casually calculated)"
              " expected value of %s mBTC, transaction might not propogate" %
              satoshi_to_mbtc(recommended_tx_fee))
    return actual_tx_fee


EPILOG = 'Files are binary by default unless they end with the suffix ".hex".'


def main():
    parser = argparse.ArgumentParser(
        description="A simple example that creates an unsigned Bitcoin transaction moving all funds "
                    "from one address to another.", epilog=EPILOG)

    parser.add_argument("src_bitcoin_address", help='the source bitcoin address')
    parser.add_argument("dst_bitcoin_address", help='the destination bitcoin address')
    parser.add_argument("output_file", help='output file with unsigned transaction',
                        metavar="path-to-output-file", type=argparse.FileType('wb'))

    parser.add_argument("-f", "--fee", help='miner fee', type=int, default=tx_fee.TX_FEE_PER_THOUSAND_BYTES)

    args = parser.parse_args()

    unspents = unspent_for_address(args.src_bitcoin_address)

    txs_in = [TxIn(tx_out_info[0], tx_out_info[1]) for tx_out_info in unspents]
    coin_value = sum(tx_out_info[-1].coin_value for tx_out_info in unspents)

    script = standard_tx_out_script(args.dst_bitcoin_address)
    txs_out = [TxOut(coin_value - args.fee, script)]

    tx = Tx(version=1, txs_in=txs_in, txs_out=txs_out)

    tx_db = minimal_tx_db_for_unspents(tx, unspents)

    actual_tx_fee = check_fees(tx, tx_db)
    if actual_tx_fee < 0:
        sys.exit(1)
    print("transaction fee: %s mBTC" % satoshi_to_mbtc(actual_tx_fee))

    tx_bytes = stream_to_bytes(tx.stream)
    f = args.output_file
    if f:
        if f.name.endswith("hex"):
            f = codecs.getwriter("hex_codec")(f)
        # write the transaction
        f.write(tx_bytes)
        # write the info for the unspent TxOut, required for signing
        stream_minimal_tx_db_for_tx(tx_db, f, tx)
        f.close()

if __name__ == '__main__':
    main()
