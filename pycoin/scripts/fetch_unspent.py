#!/usr/bin/env python

import argparse

from pycoin.services.blockchain_info import spendables_for_address

def main():
    parser = argparse.ArgumentParser(description="Create a hex dump of unspent TxOut items for Bitcoin addresses.")
    parser.add_argument("bitcoin_address", help='a bitcoin address', nargs="+")

    args = parser.parse_args()

    for address in args.bitcoin_address:
        print("looking up funds for %s from blockchain.info" % address)
        spendables = spendables_for_address(address)
        for spendable in spendables:
            t = spendable.as_text()
            print(t)

if __name__ == '__main__':
    main()
