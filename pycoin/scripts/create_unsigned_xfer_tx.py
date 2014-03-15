#!/usr/bin/env python

# Sample usage (with fake coinbase transaction):
# ./create_unsigned_xfer_tx.py INPUT_BITCOIN_ADDRESS OUTPUT_BITCOIN_ADDRESS output.file.name

import argparse
import binascii
import decimal
import sys

from pycoin.convention import tx_fee, satoshi_to_btc
from pycoin.serialize import stream_to_bytes
from pycoin.tx import UnsignedTx, TxOut


def check_fees(unsigned_tx):
    total_in, total_out = unsigned_tx.total_in(), unsigned_tx.total_out()
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

    coins_from = []
    coins_to = []
    for txinfo in args.txinfo:
        if '/' in txinfo:
            parts = txinfo.split("/")
            if len(parts) == 2:
                # we assume it's an output
                address, amount = parts
                coins_to.append((amount, address))
            else:
                try:
                    # we assume it's an input of the form
                    #  tx_hash_hex/tx_output_index_decimal/tx_out_script_hex/tx_out_coin_val
                    tx_hash_hex, tx_output_index_decimal = parts[:2]
                    tx_out_script_hex, tx_out_coin_val = parts[2:]
                    tx_hash = binascii.unhexlify(tx_hash_hex)
                    tx_output_index = int(tx_output_index_decimal)
                    tx_out_coin_val = decimal.Decimal(tx_out_coin_val)
                    tx_out_script = binascii.unhexlify(tx_out_script_hex)
                    tx_out = TxOut(tx_out_coin_val, tx_out_script)
                    coins_source = (tx_hash, tx_output_index, tx_out)
                    coins_from.append(coins_source)
                except Exception:
                    parser.error("can't parse %s\n" % txinfo)

    unsigned_tx = UnsignedTx.standard_tx(coins_from, coins_to)
    return unsigned_tx


EPILOG = "If you generate an unsigned transaction, the output is a hex dump" \
         " that can be used by this script on an air-gapped machine."


def main():
    parser = argparse.ArgumentParser(
        description="Create an unsigned Bitcoin transaction moving funds "
                    "from one address to another.", epilog=EPILOG)

    parser.add_argument('-o', "--output-file", help='output file containing '
                        'unsigned transaction', metavar="path-to-output-file",
                        type=argparse.FileType('wb'))
    parser.add_argument("txinfo", help='a 4-tuple from bu_unspent as an input'
                        ' or a "bitcoin_address/value" pair as an output', nargs="+")

    args = parser.parse_args()

    unsigned_tx = get_unsigned_tx(parser)
    actual_tx_fee = check_fees(unsigned_tx)
    if actual_tx_fee < 0:
        sys.exit(1)
    print("transaction fee: %s BTC" % satoshi_to_btc(actual_tx_fee))

    tx_bytes = stream_to_bytes(unsigned_tx.stream)
    tx_hex = binascii.hexlify(tx_bytes).decode("utf8")
    print(tx_hex)
    if args.output_file:
        args.output_file.write(tx_bytes)
        args.output_file.close()

if __name__ == '__main__':
    main()
