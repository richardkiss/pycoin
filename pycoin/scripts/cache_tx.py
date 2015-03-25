#!/usr/bin/env python

import argparse
import codecs
import io
import re

from pycoin.serialize import h2b_rev
from pycoin.services import get_tx_db
from pycoin.tx import Tx


def main():
    parser = argparse.ArgumentParser(description="Add a transaction to tx cache.")
    parser.add_argument("tx_id_or_path", nargs="+",
                        help='The id of the transaction to fetch from web services or the path to it.')

    args = parser.parse_args()

    TX_RE = re.compile(r"^[0-9a-fA-F]{64}$")

    tx_db = get_tx_db()

    for p in args.tx_id_or_path:
        if TX_RE.match(p):
            tx = tx_db.get(h2b_rev(p))
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

        tx_db[tx.hash()] = tx
        print("cached %s" % tx.id())

if __name__ == '__main__':
    main()
