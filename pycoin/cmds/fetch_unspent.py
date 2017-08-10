#!/usr/bin/env python

import argparse

from pycoin.networks.default import get_current_netcode
from pycoin.services import spendables_for_address
from pycoin.services.providers import message_about_spendables_for_address_env


def create_parser():
    parser = argparse.ArgumentParser(
        description="Create a hex dump of unspent TxOut items for Bitcoin addresses.")
    parser.add_argument("bitcoin_address", help='a bitcoin address', nargs="+")
    return parser


def fetch_unspent(args):
    netcode = get_current_netcode()

    m = message_about_spendables_for_address_env(netcode)
    if m:
        print("warning: %s" % m)

    for address in args.bitcoin_address:
        spendables = spendables_for_address(address, netcode, format="text")
        for spendable in spendables:
            print(spendable)


def main():
    parser = create_parser()
    args = parser.parse_args()
    fetch_unspent(args)


if __name__ == '__main__':
    main()
