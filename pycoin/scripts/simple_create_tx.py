#!/usr/bin/env python

# Sample usage (with fake coinbase transaction):
# ./simple_create_tx.py INPUT_BITCOIN_ADDRESS OUTPUT_BITCOIN_ADDRESS output.file.name

import argparse
import codecs

from pycoin.convention import tx_fee
from pycoin.serialize import stream_to_bytes
from pycoin.services.blokrio import spendables_for_address
from pycoin.tx import Tx
from pycoin.tx.TxIn import TxIn
from pycoin.tx.TxOut import TxOut, standard_tx_out_script


EPILOG = 'Files are binary by default unless they end with the suffix ".hex".' \
        ' Note that unsigned transactions are regular transactions followed by some additional data.'


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

    spendables = spendables_for_address(args.src_bitcoin_address)

    txs_in = [spendable.tx_in() for spendable in spendables]

    total_coin_value = sum(tx_out.coin_value for tx_out in spendables)

    script = standard_tx_out_script(args.dst_bitcoin_address)
    txs_out = [TxOut(total_coin_value - args.fee, script)]

    tx = Tx(version=1, txs_in=txs_in, txs_out=txs_out)

    tx.set_unspents(spendables)

    tx_bytes = stream_to_bytes(tx.stream)
    f = args.output_file
    if f:
        if f.name.endswith("hex"):
            f = codecs.getwriter("hex_codec")(f)
        # write the transaction
        f.write(tx_bytes)
        # write the info for the unspent TxOut, required for signing
        tx.stream_unspents(f)
        f.close()

if __name__ == '__main__':
    main()
