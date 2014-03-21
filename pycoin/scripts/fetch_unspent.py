#!/usr/bin/env python

import argparse

from pycoin.serialize import b2h, b2h_rev
from pycoin.services import blockchain_info

def main():
    parser = argparse.ArgumentParser(description="Create a hex dump of unspent TxOut items for Bitcoin addresses.")
    parser.add_argument("bitcoin_address", help='a bitcoin address', nargs="+")

    args = parser.parse_args()

    for address in args.bitcoin_address:
        print("looking up funds for %s from blockchain.info" % address)
        coins_sources = blockchain_info.unspent_for_address(address)
        for tx_hash, tx_output_index, tx_out in coins_sources:
            s = "%s/%d/%s/%d" % (b2h_rev(tx_hash), tx_output_index, b2h(tx_out.script), tx_out.coin_value)
            print(s)

if __name__ == '__main__':
    main()
