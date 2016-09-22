#!/usr/bin/env python

import argparse

from pycoin.services import spendables_for_address
from pycoin.services.providers import message_about_spendables_for_address_env


def main():
    parser = argparse.ArgumentParser(
        description="Create a hex dump of unspent TxOut items for Bitcoin addresses.")
    parser.add_argument("bitcoin_address", help='a bitcoin address', nargs="+")

    args = parser.parse_args()
    netcode = None

    m = message_about_spendables_for_address_env(netcode)
    if m:
        print("warning: %s" % m)

    for address in args.bitcoin_address:
        spendables = spendables_for_address(address, netcode, format="text")
        for spendable in spendables:
            print(spendable)

if __name__ == '__main__':
    main()
