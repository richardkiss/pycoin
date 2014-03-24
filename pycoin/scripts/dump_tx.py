#!/usr/bin/env python

import argparse
import codecs
import datetime
import decimal
import io
import re

from pycoin.convention import satoshi_to_mbtc
from pycoin.serialize import b2h_rev, h2b_rev, stream_to_bytes
from pycoin.services.tx_cache import tx_for_hash
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
    has_unspents = tx.has_unspents()
    for idx, tx_in in enumerate(tx.txs_in):
        suffix = ""
        if has_unspents:
            tx_out = tx.unspents[idx]
            sig_result = " sig ok" if tx.is_signature_ok(idx) else " BAD SIG"
            suffix = " %12.5f mBTC %s" % (satoshi_to_mbtc(tx_out.coin_value), sig_result)
            address = tx_out.bitcoin_address(is_test=is_testnet)
        else:
            address = tx_in.bitcoin_address(is_test=is_testnet)
        print("%3d: %34s from %s:%d%s" % (idx, address, b2h_rev(tx_in.previous_hash), tx_in.previous_index, suffix))
    print("Output%s:" % ('s' if len(tx.txs_out) != 1 else ''))
    for idx, tx_out in enumerate(tx.txs_out):
        amount_mbtc = satoshi_to_mbtc(tx_out.coin_value)
        address = tx_out.bitcoin_address(is_test=is_testnet)
        print("%3d: %34s receives %12.5f mBTC" % (idx, address, amount_mbtc))
    if tx.has_unspents():
        print("Total input  %12.5f mBTC" % satoshi_to_mbtc(tx.total_in()))
    print(    "Total output %12.5f mBTC" % satoshi_to_mbtc(tx.total_out()))
    if tx.has_unspents():
        print("Total fees   %12.5f mBTC" % satoshi_to_mbtc(tx.fee()))

def tx_db_for_tx(tx):
    tx_db = {}
    for h in set([tx_in.previous_hash for tx_in in tx.txs_in]):
        prior_tx = tx_for_hash(h)
        if prior_tx:
            tx_db[prior_tx.hash()] = prior_tx
    return tx_db

def main():
    parser = argparse.ArgumentParser(description="Dump a transaction in human-readable form.")
    parser.add_argument('-v', "--validate", action='store_true',
                        help='fetch inputs and validate signatures (may fetch source transactions from blockexplorer')
    parser.add_argument("tx_id_or_path", help='The transaction id or the path to the file containing the transaction.', nargs="+")

    args = parser.parse_args()

    TX_RE = re.compile(r"^[0-9a-fA-F]{64}$")

    for p in args.tx_id_or_path:
        if TX_RE.match(p):
            tx = tx_for_hash(h2b_rev(p))
            if not tx:
                parser.error("can't find Tx with id %s" % p)
        else:
            f = open(p, "rb")
            try:
                if f.name.endswith("hex"):
                    f = io.BytesIO(codecs.getreader("hex_codec")(f).read())
                tx = Tx.parse(f)
            except Exception:
                parser.error("can't parse %s" % f.name)
        tx_db = {}
        if args.validate:
            tx.unspents_from_db(tx_db_for_tx(tx))
        dump_tx(tx, is_testnet=False)
        print('')

if __name__ == '__main__':
    main()
