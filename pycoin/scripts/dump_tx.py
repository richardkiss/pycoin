#!/usr/bin/env python

import argparse
import datetime
import decimal

from pycoin.convention import satoshi_to_mbtc
from pycoin.serialize import b2h_rev, stream_to_bytes
from pycoin.tx import Tx

LOCKTIME_THRESHOLD = 500000000


def dump_tx(tx, is_testnet=False):
    tx_bin = stream_to_bytes(tx.stream)
    print("%d bytes   tx hash %s" % (len(tx_bin), tx.id()))
    print("TxIn count: %d; TxOut count: %d" % (len(tx.txs_in), len(tx.txs_out)))
    if tx.lock_time == 0:
        meaning = "valid anytime"
    elif tx.lock_time < LOCKTIME_THRESHOLD:
        meaning = "valid after block index %d" % tx.lock_time
    else:
        when = datetime.datetime.utcfromtimestamp(tx.lock_time)
        meaning = "valid on or after %s utc" % when.isoformat()
    print("Lock time: %d (%s)" % (tx.lock_time, meaning))
    print("Input%s:" % ('s' if len(tx.txs_in) != 1 else ''))
    for idx, tx_in in enumerate(tx.txs_in):
        address = tx_in.bitcoin_address(is_test=is_testnet)
        print("%3d: %34s from %s:%d" % (idx, address, b2h_rev(tx_in.previous_hash), tx_in.previous_index))
    print("Output%s:" % ('s' if len(tx.txs_out) != 1 else ''))
    for idx, tx_out in enumerate(tx.txs_out):
        amount_mbtc = satoshi_to_mbtc(tx_out.coin_value)
        address = tx_out.bitcoin_address(is_test=is_testnet)
        print("%3d: %34s receives %12.5f mBTC" % (idx, address, amount_mbtc))


def main():
    parser = argparse.ArgumentParser(description="Dump a transaction in human-readable form.")
    parser.add_argument("tx_bin", help='The file containing the binary transaction.', nargs="+", type=argparse.FileType('rb'))

    args = parser.parse_args()

    for f in args.tx_bin:
        tx = Tx.parse(f)
        dump_tx(tx, is_testnet=False)
        print('')

if __name__ == '__main__':
    main()
