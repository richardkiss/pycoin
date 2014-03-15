#!/usr/bin/env python

import argparse

from pycoin.services import blockexplorer


def main():
    parser = argparse.ArgumentParser(description="Fetch a binary transaction from blockexplorer.com.")
    parser.add_argument("tx_hash", help='The hash of the transaction.', nargs="+")

    args = parser.parse_args()

    for tx_hash in args.tx_hash:
        tx = blockexplorer.fetch_tx(tx_hash, is_testnet=False)
        with open("%s.bin" % tx.id(), "wb") as f:
            tx.stream(f)

if __name__ == '__main__':
    main()
