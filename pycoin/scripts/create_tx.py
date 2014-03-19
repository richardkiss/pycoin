#!/usr/bin/env python

# Sample usage (with fake coinbase transaction):
# ./create_unsigned_xfer_tx.py INPUT_BITCOIN_ADDRESS OUTPUT_BITCOIN_ADDRESS output.file.name

import argparse
import binascii
import codecs
import decimal
import sys

from pycoin.convention import tx_fee, satoshi_to_btc
from pycoin.serialize import stream_to_bytes, h2b_rev
from pycoin.tx import Tx
from pycoin.tx.airgap import minimal_tx_db_for_txs_out, stream_minimal_tx_db_for_tx
from pycoin.tx.TxIn import TxIn
from pycoin.tx.TxOut import TxOut, standard_tx_out_script


def check_fees(unsigned_tx, tx_db):
    total_in, total_out = unsigned_tx.total_in(tx_db), unsigned_tx.total_out()
    actual_tx_fee = total_in - total_out
    recommended_tx_fee = tx_fee.recommended_fee_for_tx(unsigned_tx)
    if actual_tx_fee > recommended_tx_fee:
        print("warning: transaction fee of %s exceeds expected value of %s BTC" %
              (satoshi_to_btc(actual_tx_fee), satoshi_to_btc(recommended_tx_fee)))
    elif actual_tx_fee < 0:
        print("not enough source coins (%s BTC) for destination (%s BTC)."
              " Short %s BTC" %
              (satoshi_to_btc(total_in),
               satoshi_to_btc(total_out), satoshi_to_btc(-actual_tx_fee)))
    elif actual_tx_fee < recommended_tx_fee:
        print("warning: transaction fee lower than (casually calculated)"
              " expected value of %s BTC, transaction might not propogate" %
              satoshi_to_btc(recommended_tx_fee))
    return actual_tx_fee


def get_unsigned_tx(parser):
    args = parser.parse_args()

    tx_db = {}
    outgoing_txs_out = []
    txs_in = []
    txs_out = []
    for txinfo in args.txinfo:
        if '/' in txinfo:
            parts = txinfo.split("/")
            if len(parts) == 2:
                # we assume it's an output
                address, amount = parts
                txs_out.append(TxOut(amount, standard_tx_out_script(address)))
            else:
                try:
                    # we assume it's an input of the form
                    #  tx_hash_hex/tx_output_index_decimal/tx_out_script_hex/tx_out_coin_val
                    tx_hash_hex, tx_output_index_decimal = parts[:2]
                    tx_out_script_hex, tx_out_coin_val = parts[2:]
                    tx_hash = h2b_rev(tx_hash_hex)
                    tx_output_index = int(tx_output_index_decimal)
                    txs_in.append(TxIn(tx_hash, tx_output_index))
                    tx_out_coin_val = decimal.Decimal(tx_out_coin_val)
                    tx_out_script = binascii.unhexlify(tx_out_script_hex)
                    outgoing_txs_out.append(TxOut(tx_out_coin_val, tx_out_script))
                except Exception:
                    parser.error("can't parse %s\n" % txinfo)

    unsigned_tx = Tx(version=1, txs_in=txs_in, txs_out=txs_out)
    tx_db = minimal_tx_db_for_txs_out(unsigned_tx, outgoing_txs_out)
    return unsigned_tx, tx_db


EPILOG = 'Files are binary by default unless they end with the suffix ".hex".'


def main():
    parser = argparse.ArgumentParser(
        description="Create an unsigned Bitcoin transaction moving funds "
                    "from one address to another.", epilog=EPILOG)

    parser.add_argument('-o', "--output-file", help='output file containing '
                        'unsigned transaction', metavar="path-to-output-file",
                        type=argparse.FileType('wb'), required=True)
    parser.add_argument("txinfo", help='a 4-tuple tx_id/tx_out_idx/script_hex/satoshi_count as an input'
                        ' or a "bitcoin_address/satoshi_count" pair as an output. The fetch_unspent tool'
                        ' can help generate inputs.', nargs="+")

    args = parser.parse_args()

    unsigned_tx, tx_db = get_unsigned_tx(parser)
    actual_tx_fee = check_fees(unsigned_tx, tx_db)
    if actual_tx_fee < 0:
        sys.exit(1)
    print("transaction fee: %s BTC" % satoshi_to_btc(actual_tx_fee))

    tx_bytes = stream_to_bytes(unsigned_tx.stream)
    f = args.output_file
    if f:
        if f.name.endswith("hex"):
            f = codecs.getwriter("hex_codec")(f)
        f.write(tx_bytes)
        stream_minimal_tx_db_for_tx(tx_db, f, unsigned_tx)
        f.close()

if __name__ == '__main__':
    main()
