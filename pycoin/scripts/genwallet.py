#!/usr/bin/env python

import argparse
import binascii
import json
import subprocess
import sys

from pycoin.key.BIP32Node import BIP32Node, PublicPrivateMismatchError
from pycoin.networks import full_network_name_for_netcode

def gpg_entropy():
    output = subprocess.Popen(["gpg", "--gen-random", "2", "64"], stdout=subprocess.PIPE).communicate()[0]
    return output

def dev_random_entropy():
    return open("/dev/random", "rb").read(64)

def b2h(b):
    return binascii.hexlify(b).decode("utf8")

def main():
    parser = argparse.ArgumentParser(description="Generate a private wallet key. WARNING: obsolete. Use ku instead.")

    parser.add_argument('-a', "--address", help='show as Bitcoin address', action='store_true')
    parser.add_argument('-i', "--info", help='show metadata', action='store_true')
    parser.add_argument('-j', "--json", help='output metadata as JSON', action='store_true')
    parser.add_argument('-w', "--wif", help='show as Bitcoin WIF', action='store_true')
    parser.add_argument('-f', "--wallet-key-file", help='initial wallet key', type=argparse.FileType('r'))
    parser.add_argument('-k', "--wallet-key", help='initial wallet key')
    parser.add_argument('-g', "--gpg", help='use gpg --gen-random to get additional entropy', action='store_true')
    parser.add_argument('-u', "--dev-random", help='use /dev/random to get additional entropy', action='store_true')
    parser.add_argument('-n', "--uncompressed", help='show in uncompressed form', action='store_true')
    parser.add_argument('-p', help='generate wallet key from passphrase. NOT RECOMMENDED', metavar='passphrase')
    parser.add_argument('-s', "--subkey", help='subkey path (example: 0p/2/1)')
    parser.add_argument('-t', help='generate test key', action="store_true")
    parser.add_argument('inputfile', help='source of entropy. stdin by default', type=argparse.FileType(mode='r+b'), nargs='?')
    args = parser.parse_args()

    # args.inputfile doesn't like binary when "-" is passed in. Deal with this.
    if args.inputfile == sys.stdin and hasattr(sys.stdin, "buffer"):
        args.inputfile = sys.stdin.buffer

    network = 'XTN' if args.t else 'BTC'

    entropy = bytearray()
    if args.gpg:
        entropy.extend(gpg_entropy())
    if args.dev_random:
        entropy.extend(dev_random_entropy())
    if args.inputfile:
        entropy.extend(args.inputfile.read())
    if args.p:
        entropy.extend(args.p.encode("utf8"))
    if len(entropy) == 0 and not args.wallet_key and not args.wallet_key_file:
        parser.error("you must specify at least one source of entropy")
    if args.wallet_key and len(entropy) > 0:
        parser.error("don't specify both entropy and a wallet key")
    if args.wallet_key_file:
        wallet = BIP32Node.from_wallet_key(args.wallet_key_file.readline()[:-1])
    elif args.wallet_key:
        wallet = BIP32Node.from_wallet_key(args.wallet_key)
    else:
        wallet = BIP32Node.from_master_secret(bytes(entropy), netcode=network)
    try:
        if args.subkey:
            wallet = wallet.subkey_for_path(args.subkey)
        if wallet.child_index() >= 0x80000000:
            wc = wallet.child_index() - 0x80000000
            child_index = "%dp (%d)" % (wc, wallet.child_index())
        else:
            child_index = "%d" % wallet.child_index()
        if args.json:
            d = dict(
                wallet_key=wallet.wallet_key(as_private=wallet.is_private),
                public_pair_x=wallet.public_pair[0],
                public_pair_y=wallet.public_pair[1],
                tree_depth=wallet.depth,
                fingerprint=b2h(wallet.fingerprint()),
                parent_fingerprint=b2h(wallet.parent_fingerprint),
                child_index=child_index,
                chain_code=b2h(wallet.chain_code),
                bitcoin_addr=wallet.bitcoin_address(),
                bitcoin_addr_uncompressed=wallet.bitcoin_address(compressed=False),
                network="test" if wallet.is_test else "main",
            )
            if wallet.is_private:
                d.update(dict(
                    key="private",
                    secret_exponent=wallet.secret_exponent,
                    WIF=wallet.wif(),
                    WIF_uncompressed=wallet.wif(compressed=False)
                ))
            else:
                d.update(dict(key="public"))
            print(json.dumps(d, indent=3))
        elif args.info:
            print(wallet.wallet_key(as_private=wallet.is_private))
            print(full_network_name_for_netcode(wallet.netcode))
            if wallet.is_private:
                print("private key")
                print("secret exponent: %d" % wallet.secret_exponent)
            else:
                print("public key only")
            print("public pair x:   %d\npublic pair y:   %d" % wallet.public_pair)
            print("tree depth:      %d" % wallet.depth)
            print("fingerprint:     %s" % b2h(wallet.fingerprint()))
            print("parent f'print:  %s" % b2h(wallet.parent_fingerprint))
            print("child index:     %s" % child_index)
            print("chain code:      %s" % b2h(wallet.chain_code))
            if wallet.is_private:
                print("WIF:             %s" % wallet.wif())
                print("  uncompressed:  %s" % wallet.wif(compressed=False))
            print("Bitcoin address: %s" % wallet.bitcoin_address())
            print("  uncompressed:  %s" % wallet.bitcoin_address(compressed=False))
        elif args.address:
            print(wallet.bitcoin_address(compressed=not args.uncompressed))
        elif args.wif:
            print(wallet.wif(compressed=not args.uncompressed))
        else:
            print(wallet.wallet_key(as_private=wallet.is_private))
    except PublicPrivateMismatchError as ex:
        print(ex.args[0])


if __name__ == '__main__':
    main()
