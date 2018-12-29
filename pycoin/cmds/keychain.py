#!/usr/bin/env python

from __future__ import print_function

import argparse
import sqlite3
import sys

from pycoin.key.subpaths import subpaths_for_path_range
from pycoin.networks.registry import (
    network_codes, network_for_netcode
)


def create_parser():
    codes = network_codes()
    parser = argparse.ArgumentParser(
        description=(
            'Cache look-up information into a Keychain for use with tx. '
            'Useful for hiearchical keys with many children.'),
        epilog=('Known networks codes:\n  ' +
                ', '.join(['%s (%s)' % (i, network_for_netcode(i).full_name()) for i in codes]))
    )
    parser.add_argument('-n', "--netcode", help='specify network by netcode', choices=codes, default="BTC")
    parser.add_argument('-m', "--multisig", metavar="sigcount", type=int,
                        help='multisig, with this many signatures need to unencumber the funds')
    parser.add_argument('keychain', help='the keychain file (SQLite3 formatted)')
    parser.add_argument('subkey_paths', help='subkey paths (example: 0H/2/15-20)')
    parser.add_argument('key', nargs="+", help='a hierarchical wallet key string (public suffices)')
    return parser


def keychain(args, parser):
    network = network_for_netcode(args.netcode)

    parse = network.ui.parse

    keychain = network.keychain(sqlite3.connect(args.keychain))

    keys = []
    for _ in args.key:
        key = parse(_, types=["electrum", "bip32"])
        if not key:
            raise ValueError("can't parse %s" % _)
        keys.append(key)

    subkey_paths = args.subkey_paths

    m = args.multisig
    if m and m > len(keys):
        raise ValueError("not enough keys for %d signatures" % m)

    total_paths = 0

    for path in subpaths_for_path_range(subkey_paths):
        if m:
            secs = sorted([_.subkey_for_path(path).sec() for _ in keys])
            script = network.contract.for_multisig(m, secs)
            keychain.add_p2s_script(script)
            print(network.ui.address_for_p2s(script))
        total_paths += keychain.add_keys_path(keys, path)
    keychain.commit()
    print("%d total paths" % total_paths, file=sys.stderr)


def main():
    parser = create_parser()
    args = parser.parse_args()
    keychain(args, parser)


if __name__ == '__main__':
    main()
