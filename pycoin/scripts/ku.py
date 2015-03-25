#!/usr/bin/env python

from __future__ import print_function

import argparse
import json
import re
import subprocess
import sys

from pycoin import encoding
from pycoin.ecdsa import is_public_pair_valid, generator_secp256k1, public_pair_for_x, secp256k1
from pycoin.serialize import b2h, h2b
from pycoin.key import Key
from pycoin.key.BIP32Node import BIP32Node
from pycoin.networks import full_network_name_for_netcode, network_name_for_netcode, NETWORK_NAMES


SEC_RE = re.compile(r"^(0[23][0-9a-fA-F]{64})|(04[0-9a-fA-F]{128})$")
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


def parse_as_number(s):
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return int(s, 16)
    except ValueError:
        pass


def parse_as_secret_exponent(s):
    v = parse_as_number(s)
    if v and v < secp256k1._r:
        return v


def parse_as_public_pair(s):
    for c in ",/":
        if c in s:
            s0, s1 = s.split(c, 1)
            v0 = parse_as_number(s0)
            if v0:
                if s1 in ("even", "odd"):
                    return public_pair_for_x(generator_secp256k1, v0, is_even=(s1 == 'even'))
                v1 = parse_as_number(s1)
                if v1:
                    if not is_public_pair_valid(generator_secp256k1, (v0, v1)):
                        sys.stderr.write("invalid (x, y) pair\n")
                        sys.exit(1)
                    return (v0, v1)


def create_output(item, key, subkey_path=None):
    output_dict = {}
    output_order = []

    def add_output(json_key, value=None, human_readable_key=None):
        if human_readable_key is None:
            human_readable_key = json_key.replace("_", " ")
        if value:
            output_dict[json_key.strip().lower()] = value
        output_order.append((json_key.lower(), human_readable_key))

    network_name = network_name_for_netcode(key._netcode)
    full_network_name = full_network_name_for_netcode(key._netcode)
    add_output("input", item)
    add_output("network", full_network_name)
    add_output("netcode", key._netcode)

    if hasattr(key, "wallet_key"):
        if subkey_path:
            add_output("subkey_path", subkey_path)

        add_output("wallet_key", key.wallet_key(as_private=key.is_private()))
        if key.is_private():
            add_output("public_version", key.wallet_key(as_private=False))

        child_number = key.child_index()
        if child_number >= 0x80000000:
            wc = child_number - 0x80000000
            child_index = "%dH (%d)" % (wc, child_number)
        else:
            child_index = "%d" % child_number
        add_output("tree_depth", "%d" % key.tree_depth())
        add_output("fingerprint", b2h(key.fingerprint()))
        add_output("parent_fingerprint", b2h(key.parent_fingerprint()), "parent f'print")
        add_output("child_index", child_index)
        add_output("chain_code", b2h(key.chain_code()))

        add_output("private_key", "yes" if key.is_private() else "no")

    secret_exponent = key.secret_exponent()
    if secret_exponent:
        add_output("secret_exponent", '%d' % secret_exponent)
        add_output("secret_exponent_hex", '%x' % secret_exponent, " hex")
        add_output("wif", key.wif(use_uncompressed=False))
        add_output("wif_uncompressed", key.wif(use_uncompressed=True), " uncompressed")

    public_pair = key.public_pair()

    if public_pair:
        add_output("public_pair_x", '%d' % public_pair[0])
        add_output("public_pair_y", '%d' % public_pair[1])
        add_output("public_pair_x_hex", '%x' % public_pair[0], " x as hex")
        add_output("public_pair_y_hex", '%x' % public_pair[1], " y as hex")
        add_output("y_parity", "odd" if (public_pair[1] & 1) else "even")

        add_output("key_pair_as_sec", b2h(key.sec(use_uncompressed=False)))
        add_output("key_pair_as_sec_uncompressed", b2h(key.sec(use_uncompressed=True)), " uncompressed")

    hash160_c = key.hash160(use_uncompressed=False)
    if hash160_c:
        add_output("hash160", b2h(hash160_c))
    hash160_u = key.hash160(use_uncompressed=True)
    if hash160_u:
        add_output("hash160_uncompressed", b2h(hash160_u), " uncompressed")

    if hash160_c:
        address = key.address(use_uncompressed=False)
        add_output("address", address, "%s address" % network_name)
        output_dict["%s_address" % key._netcode] = address

    if hash160_u:
        address = key.address(use_uncompressed=True)
        add_output("address_uncompressed", address, "%s address uncompressed" % network_name)
        output_dict["%s_address_uncompressed" % key._netcode] = address

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


def main():
    networks = "MTLD"
    parser = argparse.ArgumentParser(
        description='Crypto coin utility ku ("key utility") to show'
        ' information about Bitcoin or other cryptocoin data structures.',
        epilog='Known networks codes:\n  ' \
                + ', '.join(['%s (%s)'%(i, full_network_name_for_netcode(i)) for i in NETWORK_NAMES])
    )
    parser.add_argument('-w', "--wallet", help='show just Bitcoin wallet key', action='store_true')
    parser.add_argument('-W', "--wif", help='show just Bitcoin WIF', action='store_true')
    parser.add_argument('-a', "--address", help='show just Bitcoin address', action='store_true')
    parser.add_argument(
        '-u', "--uncompressed", help='show output in uncompressed form',
        action='store_true')
    parser.add_argument(
        '-P', "--public", help='only show public version of wallet keys',
        action='store_true')

    parser.add_argument('-j', "--json", help='output as JSON', action='store_true')

    parser.add_argument('-s', "--subkey", help='subkey path (example: 0H/2/15-20)')
    parser.add_argument('-n', "--network", help='specify network (default: BTC = Bitcoin)',
                                default='BTC', choices=NETWORK_NAMES)
    parser.add_argument("--override-network", help='override detected network type',
                                default=None, choices=NETWORK_NAMES)

    parser.add_argument(
        'item', nargs="+", help='a BIP0032 wallet key string;'
        ' a WIF;'
        ' a bitcoin address;'
        ' an SEC (ie. a 66 hex chars starting with 02, 03 or a 130 hex chars starting with 04);'
        ' the literal string "create" to create a new wallet key using strong entropy sources;'
        ' P:wallet passphrase (NOT RECOMMENDED);'
        ' H:wallet passphrase in hex (NOT RECOMMENDED);'
        ' secret_exponent (in decimal or hex);'
        ' x,y where x,y form a public pair (y is a number or one of the strings "even" or "odd");'
        ' hash160 (as 40 hex characters)')

    args = parser.parse_args()

    if args.override_network:
        # force network arg to match override, but also will override decoded data below.
        args.network = args.override_network

    PREFIX_TRANSFORMS = (
        ("P:", lambda s:
            BIP32Node.from_master_secret(s.encode("utf8"), netcode=args.network)),
        ("H:", lambda s:
            BIP32Node.from_master_secret(h2b(s), netcode=args.network)),
        ("create", lambda s:
            BIP32Node.from_master_secret(get_entropy(), netcode=args.network)),
    )

    for item in args.item:
        key = None
        for k, f in PREFIX_TRANSFORMS:
            if item.startswith(k):
                try:
                    key = f(item[len(k):])
                    break
                except Exception:
                    pass
        else:
            try:
                key = Key.from_text(item)
            except encoding.EncodingError:
                pass
        if key is None:
            secret_exponent = parse_as_secret_exponent(item)
            if secret_exponent:
                key = Key(secret_exponent=secret_exponent, netcode=args.network)

        if SEC_RE.match(item):
            key = Key.from_sec(h2b(item))

        if key is None:
            public_pair = parse_as_public_pair(item)
            if public_pair:
                key = Key(public_pair=public_pair, netcode=args.network)

        if HASH160_RE.match(item):
            key = Key(hash160=h2b(item), netcode=args.network)

        if key is None:
            print("can't parse %s" % item, file=sys.stderr)
            continue

        if args.override_network:
            # Override the network value, so we can take the same xpubkey and view what
            # the values would be on each other network type.
            # XXX public interface for this is needed...
            key._netcode = args.override_network

        for key in key.subkeys(args.subkey or ""):
            if args.public:
                key = key.public_copy()

            output_dict, output_order = create_output(item, key)

            if args.json:
                print(json.dumps(output_dict, indent=3, sort_keys=True))
            elif args.wallet:
                print(output_dict["wallet_key"])
            elif args.wif:
                print(output_dict["wif_uncompressed" if args.uncompressed else "wif"])
            elif args.address:
                print(output_dict["address" + ("_uncompressed" if args.uncompressed else "")])
            else:
                dump_output(output_dict, output_order)

if __name__ == '__main__':
    main()
