#!/usr/bin/env python

import argparse
import subprocess
import sys

from pycoin.wallet import Wallet, PublicPrivateMismatchError

def gpg_entropy():
    output = subprocess.Popen(["gpg", "--gen-random", "2", "64"], stdout=subprocess.PIPE).communicate()[0]
    return output

def dev_random_entropy():
    return open("/dev/urandom", "rb").read(64)

def main():
    parser = argparse.ArgumentParser(description="Generate a private wallet key.")

    parser.add_argument('-a', "--address", help='show as Bitcoin address', action='store_true')
    parser.add_argument('-w', "--wif", help='show as Bitcoin WIF', action='store_true')
    parser.add_argument('-f', "--wallet-key-file", help='initial wallet key', type=argparse.FileType('r'))
    parser.add_argument('-k', "--wallet-key", help='initial wallet key')
    parser.add_argument('-g', "--gpg", help='use gpg --gen-random to get additional entropy', action='store_true')
    parser.add_argument('-u', "--dev-random", help='use /dev/urandom to get additional entropy', action='store_true')
    parser.add_argument('-n', "--uncompressed", help='show in uncompressed form', action='store_true')
    parser.add_argument('-p', help='generate wallet key from passphrase. NOT RECOMMENDED', metavar='passphrase')
    parser.add_argument('-s', "--subkey", help='subkey path (example: 0p/2/1)')
    parser.add_argument('-t', help='generate test key', action="store_true")
    parser.add_argument('inputfile', help='source of entropy. stdin by default', type=argparse.FileType(mode='r+b'), nargs='?')
    args = parser.parse_args()

    # args.inputfile doesn't like binary when "-" is passed in. Deal with this.
    if args.inputfile == sys.stdin:
        args.inputfile = sys.stdin.buffer

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
        wallet = Wallet.from_wallet_key(args.wallet_key_file.readline()[:-1])
    elif args.wallet_key:
        wallet = Wallet.from_wallet_key(args.wallet_key)
    else:
        wallet = Wallet.from_master_secret(bytes(entropy), is_test=args.t)
    try:
        if args.subkey:
            wallet = wallet.subkey_for_path(args.subkey)
        if args.address:
            print(wallet.bitcoin_address(compressed=not args.uncompressed))
        elif args.wif:
            print(wallet.wif(compressed=not args.uncompressed))
        else:
            print(wallet.wallet_key(as_private=wallet.is_private))
    except PublicPrivateMismatchError as ex:
        print(ex.args[0])


if __name__ == '__main__':
    main()
