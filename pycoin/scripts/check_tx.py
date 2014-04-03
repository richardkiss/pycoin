#!/usr/bin/env python

import argparse
import codecs
import io
import re

from pycoin.serialize import h2b_rev
from pycoin.services.tx_cache import tx_for_hash
from pycoin.services.bitcoind import bitcoind_agrees_on_transaction_validity
from pycoin.tx import Tx
from pycoin.tx.tx_utils import validate_unspents


class TxDB(object):
    def get(self, h):
        return tx_for_hash(h)


def main():
    parser = argparse.ArgumentParser(
        description="Verify that pycoin's opinion matches bitcoind's about a transaction's validity.")
    parser.add_argument('-b', "--bitcoind-url", required=True,
                        help='URL to bitcoind instance to validate against (http://user:pass@host:port).')
    parser.add_argument("tx_path", nargs="+",
                        help='The transaction id or the path to the file containing the transaction.')

    args = parser.parse_args()

    TX_RE = re.compile(r"[0-9a-fA-F]{64}")

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

        # populate the unspents
        tx_db = TxDB()
        tx.unspents_from_db(tx_db)
        validate_unspents(tx, tx_db)

        if bitcoind_agrees_on_transaction_validity(args.bitcoind_url, tx):
            print("interop test passed for %s" % tx.id())
        else:
            print("tx ==> %s FAILED interop test" % tx.id())
        print('')

if __name__ == '__main__':
    main()
