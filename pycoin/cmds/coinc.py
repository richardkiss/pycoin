#!/usr/bin/env python

import argparse
from pycoin.encoding.hexbytes import b2h
from pycoin.networks.registry import network_codes, network_for_netcode
from pycoin.networks.default import get_current_netcode


def create_parser():
    codes = network_codes()
    EPILOG = ('Known networks codes:\n  ' +
              ', '.join(['%s (%s)' % (i, network_for_netcode(i).full_name()) for i in codes]))

    parser = argparse.ArgumentParser(
        description="Compile or disassemble scripts.",
        epilog=EPILOG)

    parser.add_argument('-n', "--network", default=get_current_netcode(), choices=codes,
                        help=('Network code (environment variable PYCOIN_DEFAULT_NETCODE '
                              'or "BTC"=Bitcoin mainnet if unset)'))

    parser.add_argument("argument", nargs="+", help='script to compile. To dump hex, prefix with 0x')

    return parser


def coinc(args, parser):
    network = network_for_netcode(args.network)

    for arg in args.argument:
        info = info_for_arg(arg, network)
        for k in ("compiled_script_hex address_p2s preimage_p2s_hex "
                  "address_p2s_wit underlying_script disassembled_script").split():
            print(info[k])


def info_for_arg(arg, network):
    d = {}
    compiled_script = network.script.compile(arg)
    d["compiled_script_hex"] = "0x%s" % b2h(compiled_script)

    address_p2s = network.address.for_p2s(compiled_script)
    d["address_p2s"] = address_p2s
    d["preimage_p2s_hex"] = b2h(network.contract.for_address(address_p2s))

    address_p2s_wit = network.address.for_p2s_wit(compiled_script)
    d["address_p2s_wit"] = address_p2s_wit
    d["underlying_script"] = b2h(network.contract.for_address(address_p2s_wit))

    d["disassembled_script"] = network.script.disassemble(compiled_script)
    return d


def main():
    parser = create_parser()
    args = parser.parse_args()
    coinc(args, parser)


if __name__ == '__main__':
    main()
