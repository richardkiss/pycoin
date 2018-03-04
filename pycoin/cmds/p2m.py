#!/usr/bin/env python

from __future__ import print_function

import argparse
import sys

from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.key import Key
from pycoin.networks.registry import (
    full_network_name_for_netcode, network_codes, network_for_netcode
)
from pycoin.serialize import b2h, h2b


def key_from_sec_hex(sec_hex):
    # BRAIN DAMAGE: generator hard-coded
    return Key.from_sec(h2b(sec_hex), generator=secp256k1_generator).sec()


def create_parser():
    codes = network_codes()
    parser = argparse.ArgumentParser(
        description='Create an address for pay-to-multisig.',
        epilog=('Known networks codes:\n  ' +
                ', '.join(['%s (%s)' % (i, full_network_name_for_netcode(i)) for i in codes]))
    )
    parser.add_argument('-n', "--network", help='specify network (default: BTC = Bitcoin)',
                        default='BTC', choices=codes)

    parser.add_argument("m", help="number of signatures required", type=int)
    parser.add_argument("sec", nargs="+", help="sec of a valid public key in the multisig address",
                        type=key_from_sec_hex)
    return parser


def p2m(args, parser):
    network = network_for_netcode(args.network)

    # BRAIN DAMAGE: drilling down to _script_info
    script = network.ui._script_info.script_for_multisig(args.m, args.sec)
    address_1 = network.ui.address_for_p2s(script)
    address_2 = network.ui.address_for_p2s_wit(script)

    print(address_1)
    print(b2h(network.ui.script_for_address(address_1)))
    print()
    print(address_2)
    print(b2h(network.ui.script_for_address(address_2)))
    print()
    print(b2h(script))


def main():
    parser = create_parser()
    args = parser.parse_args()
    return p2m(args, parser)


if __name__ == '__main__':
    sys.exit(main())
