#!/usr/bin/env python

import argparse
from pycoin.networks.registry import full_network_name_for_netcode, network_codes
from pycoin.networks.registry import network_for_netcode
from pycoin.networks.default import get_current_netcode
from pycoin.serialize import b2h


def create_parser():
    codes = network_codes()
    EPILOG = ('Known networks codes:\n  ' +
              ', '.join(['%s (%s)' % (i, full_network_name_for_netcode(i)) for i in codes]))

    parser = argparse.ArgumentParser(
        description="Compile or disassemble scripts.",
        epilog=EPILOG)

    parser.add_argument('-n', "--network", default=get_current_netcode(), choices=codes,
                        help=('Network code (environment variable PYCOIN_DEFAULT_NETCODE '
                              'or "BTC"=Bitcoin mainnet if unset'))

    parser.add_argument('-f', "--file", metavar="path-to-file", type=argparse.FileType('r'),
                        help='file containing a transaction, or hex to disassemble, or text to compile')

    parser.add_argument("argument", nargs="*", help='generic argument: can be a hex transaction id '
                        '(exactly 64 characters) to be fetched from cache or a web service;'
                        ' a transaction as a hex string; a path name to a transaction to be loaded;'
                        ' a spendable 4-tuple of the form tx_id/tx_out_idx/script_hex/satoshi_count '
                        'to be added to TxIn list; an address/satoshi_count to be added to the TxOut '
                        'list; an address to be added to the TxOut list and placed in the "split'
                        ' pool".')

    return parser


def coinc(args, parser):
    network = network_for_netcode(args.network)
    script_tools = network.extras.ScriptTools

    for arg in args.argument:
        compiled_script = script_tools.compile(arg)
        print(b2h(compiled_script))

        address_p2s = network.ui.address_for_p2s(compiled_script)
        print(address_p2s)
        print(b2h(network.ui.script_for_address(address_p2s)))

        address_p2s_wit = network.ui.address_for_p2s_wit(compiled_script)
        print(address_p2s_wit)
        print(b2h(network.ui.script_for_address(address_p2s_wit)))


def main():
    parser = create_parser()
    args = parser.parse_args()
    coinc(args, parser)


if __name__ == '__main__':
    main()
