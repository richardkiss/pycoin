#!/usr/bin/env python

from __future__ import print_function

import argparse
import sqlite3

from pycoin.keychain.SQLKeychain import SQLKeychain
from pycoin.key.paths import path_iterator_for_path
from pycoin.networks.registry import (
    full_network_name_for_netcode, network_codes, network_for_netcode
)


def create_parser():
    codes = network_codes()
    parser = argparse.ArgumentParser(
        description='Cache look-up information into an SQLKeychain for use with tx.',
        epilog=('Known networks codes:\n  ' +
                ', '.join(['%s (%s)' % (i, full_network_name_for_netcode(i)) for i in codes]))
    )
    parser.add_argument('-n', "--netcode", help='specify network by netcode', choices=codes, default="BTC")
    parser.add_argument('keychain', help='the keychain file (SQLite3 formatted)')
    parser.add_argument('subkey_path', help='subkey path (example: 0H/2/15-20)')
    parser.add_argument('key', nargs="+", help='a hierarchical wallet key string (public suffices)')
    return parser


def keychain(args, parser):
    parse = network_for_netcode(args.netcode).ui.parse

    new_keys = total_paths = 0
    keychain = SQLKeychain(sqlite3.connect(args.keychain))
    for key_text in args.key:
        key = parse(key_text, types=["electrum", "bip32"])
        if not key:
            raise ValueError("can't parse %s" % key_text)
        total = keychain.add_key_paths(key, path_iterator_for_path(args.subkey_path))
        total_paths += total
    print("%d total paths" % total_paths)


def main():
    parser = create_parser()
    args = parser.parse_args()
    keychain(args, parser)


if __name__ == '__main__':
    main()
