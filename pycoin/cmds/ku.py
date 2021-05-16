#!/usr/bin/env python

from __future__ import print_function

import argparse
import json
import re
import subprocess
import sys

from pycoin.encoding.hexbytes import h2b
from pycoin.key.BIP32Node import BIP32Node
from pycoin.networks.default import get_current_netcode
from pycoin.networks.registry import network_codes, network_for_netcode


HASH160_RE = re.compile(r"^([0-9a-fA-F]{40})$")


def gpg_entropy():
    try:
        output = subprocess.Popen(
            ["gpg", "--gen-random", "2", "64"], stdout=subprocess.PIPE).communicate()[0]
        return output
    except OSError:
        sys.stderr.write("warning: can't open gpg, can't use as entropy source\n")
    return b''


def get_entropy():
    entropy = bytearray()
    try:
        entropy.extend(gpg_entropy())
    except Exception:
        print("warning: can't use gpg as entropy source", file=sys.stdout)
    try:
        entropy.extend(open("/dev/random", "rb").read(64))
    except Exception:
        print("warning: can't use /dev/random as entropy source", file=sys.stdout)
    entropy = bytes(entropy)
    if len(entropy) < 64:
        raise OSError("can't find sources of entropy")
    return entropy


def create_output(item, key, output_key_set, subkey_path=None):
    output_dict = {}
    output_order = []

    def add_output(json_key, value=None, human_readable_key=None):
        if output_key_set and json_key not in output_key_set:
            return
        if human_readable_key is None:
            human_readable_key = json_key.replace("_", " ")
        if value:
            if human_readable_key == "legacy":
                output_dict[json_key.strip()] = value
            else:
                output_dict[json_key.strip().lower()] = value
                output_order.append((json_key.lower(), human_readable_key))

    full_network_name = "%s %s" % (key._network.network_name, key._network.subnet_name)
    add_output("input", item)
    add_output("network", full_network_name)
    add_output("symbol", key._network.symbol)

    if subkey_path:
        add_output("subkey_path", subkey_path)

    for k, v, text in key.ku_output():
        add_output(k, v, text)

    return output_dict, output_order


def dump_output(output_dict, output_order):
    print('')
    max_length = max(len(v[1]) for v in output_order)
    for key, hr_key in output_order:
        space_padding = ' ' * (1 + max_length - len(hr_key))
        val = output_dict.get(key)
        if val is None:
            print(hr_key)
        else:
            if len(val) > 80:
                val = "%s\\\n%s%s" % (val[:66], ' ' * (5 + max_length), val[66:])
            print("%s%s: %s" % (hr_key, space_padding, val))


def create_parser():
    codes = network_codes()
    parser = argparse.ArgumentParser(
        description='Crypto coin utility ku ("key utility") to show'
        ' information about Bitcoin or other cryptocoin data structures.',
        epilog=('Known networks codes:\n  ' +
                ', '.join(['%s (%s)' % (i, network_for_netcode(i).full_name()) for i in codes]))
    )
    parser.add_argument('-w', "--wallet", help='show just Bitcoin wallet key', action='store_true')
    parser.add_argument('-W', "--wif", help='show just Bitcoin WIF', action='store_true')
    parser.add_argument('-a', "--address", help='show just Bitcoin address', action='store_true')
    parser.add_argument(
        '-u', "--uncompressed", help='show output in uncompressed form', action='store_true')
    parser.add_argument(
        '-P', "--public", help='only show public version of wallet keys', action='store_true')

    parser.add_argument('-j', "--json", help='output as JSON', action='store_true')

    parser.add_argument('-b', "--brief", nargs="*", help='brief output; display a single field')

    parser.add_argument('-s', "--subkey", help='subkey path (example: 0H/2/15-20)', default="")
    parser.add_argument('-n', "--network", help='specify network', choices=codes)
    parser.add_argument(
        "--override-network", help='override detected network type', default=None, choices=codes)

    parser.add_argument(
        'item', nargs="*", help='a BIP0032 wallet key string;'
        ' a WIF;'
        ' a bitcoin address;'
        ' an SEC (ie. a 66 hex chars starting with 02, 03 or a 130 hex chars starting with 04);'
        ' the literal string "create" to create a new wallet key using strong entropy sources;'
        ' P:wallet passphrase (NOT RECOMMENDED);'
        ' H:wallet passphrase in hex (NOT RECOMMENDED);'
        ' E:electrum value (either a master public, master private, or initial data);'
        ' secret_exponent (in decimal or hex);'
        ' x,y where x,y form a public pair (y is a number or one of the strings "even" or "odd");'
        ' hash160 (as 40 hex characters).'
        ' If this argument is missing, input data will be read from stdin.')
    return parser


def _create_bip32(network):
    max_retries = 64
    for _ in range(max_retries):
        try:
            return network.keys.bip32_seed(get_entropy())
        except ValueError as e:
            continue
    # Probably a bug if we get here
    raise RuntimeError("can't create BIP32 key")


def parse_key(item, networks):
    default_network = networks[0]
    if item == 'create':
        return _create_bip32(default_network)

    if HASH160_RE.match(item):
        # BRAIN DAMAGE: lame hack for now
        item = default_network.address.for_p2pkh(h2b(item))

    item = default_network.str(item)

    for network in networks:
        for f in "hierarchical_key private_key public_key address".split():
            v = getattr(network.parse, f)(item)
            if v:
                return v

    return None


def generate_output(args, output_dict, output_order):
    if args.json:
        # the python2 version of json.dumps puts an extra blank prior to the end of each line
        # the "replace" is a hack to make python2 produce the same output as python3
        print(json.dumps(output_dict, indent=3, sort_keys=True).replace(" \n", "\n"))
        return

    if len(output_order) == 0:
        print("no output: use -j option to see keys")
    elif len(output_dict) == 1:
        print(output_dict[output_order[0][0]])
    else:
        dump_output(output_dict, output_order)


def ku(args, parser):
    fallback_network = network_for_netcode(args.network or get_current_netcode())
    parse_networks = [fallback_network] + [network_for_netcode(netcode) for netcode in network_codes()]
    if args.network:
        parse_networks = [network_for_netcode(args.network)]

    override_network = None
    if args.override_network:
        # Override the network value, so we can take the same xpubkey and view what
        # the values would be on each other network type.
        override_network = network_for_netcode(args.override_network)

    def parse_stdin():
        return [item for item in sys.stdin.readline().strip().split(' ') if len(item) > 0]

    output_key_set = set(args.brief or [])
    if args.wallet:
        output_key_set.add("wallet_key")
    elif args.wif:
        output_key_set.add("wif_uncompressed" if args.uncompressed else "wif")
    elif args.address:
        output_key_set.add("address" + ("_uncompressed" if args.uncompressed else ""))

    items = args.item if len(args.item) > 0 else parse_stdin()

    for item in items:
        key = parse_key(item, parse_networks)
        if key is None:
            print("can't parse %s" % item, file=sys.stderr)
            continue

        if override_network:
            key = key.override_network(override_network)

        display_network = override_network or key._network or fallback_network

        if hasattr(key, "subkeys"):
            key_iter = key.subkeys(args.subkey)
        else:
            key_iter = [key]
        for key in key_iter:
            if args.public:
                key = key.public_copy()

            output_dict, output_order = create_output(item, key, output_key_set)

            generate_output(args, output_dict, output_order)


def main():
    parser = create_parser()
    args = parser.parse_args()
    ku(args, parser)


if __name__ == '__main__':
    main()
