#!/usr/bin/env python

import argparse
import binascii
import codecs
import datetime
import decimal
import io
import re

from pycoin.convention import satoshi_to_mbtc
from pycoin.serialize import b2h_rev, h2b_rev, stream_to_bytes
from pycoin.services.tx_cache import tx_for_hash
from pycoin.tx import Tx

try:
    from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
except ImportError:
    print("This script depends upon python-bitcoinrpc.")
    print("pip install -e git+https://github.com/jgarzik/python-bitcoinrpc#egg=python_bitcoinrpc-master")
    raise


def tx_db_for_tx(tx):
    tx_db = {}
    for h in set([tx_in.previous_hash for tx_in in tx.txs_in]):
        prior_tx = tx_for_hash(h)
        if prior_tx:
            tx_db[prior_tx.hash()] = prior_tx
    return tx_db

def tx_out_to_dict(tx, tx_out_idx):
    return dict(
        txid=tx.id(),
        vout=tx_out_idx,
        scriptPubKey=binascii.hexlify(tx.txs_out[tx_out_idx].script).decode("utf8")
    )

def bitcoind_signrawtransaction(connection, tx, tx_lookup):
    tx_hex = binascii.hexlify(stream_to_bytes(tx.stream)).decode("utf8")
    unknown_tx_outs = [tx_out_to_dict(tx_lookup[tx_in.previous_hash], tx_in.previous_index) for tx_in in tx.txs_in]
    return connection.signrawtransaction(tx_hex, unknown_tx_outs, [])

def main():
    parser = argparse.ArgumentParser(description="Verify that pycoin's opinion matches bitcoind's about a transaction's validity.")
    parser.add_argument('-b', "--bitcoind-url", required=True,
                        help='URL to bitcoind instance to validate against (http://user:pass@host:port).')
    parser.add_argument("tx_path", help='The transaction id or the path to the file containing the transaction.', nargs="+")

    args = parser.parse_args()

    TX_RE = re.compile(r"[0-9a-fA-F]{64}")

    connection = AuthServiceProxy(args.bitcoind_url)

    for p in args.tx_path:
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
        tx_db = tx_db_for_tx(tx)
        signed = bitcoind_signrawtransaction(connection, tx, tx_db)
        is_ok = [tx.is_signature_ok(idx, tx_db) for idx in range(len(tx.txs_in))]
        if all(is_ok) == signed.get("complete"):
            print("interop test passed for %s" % tx.id())
        else:
            print("==> %s" % signed)
            print(is_ok)
        print('')

if __name__ == '__main__':
    main()
