#!/usr/bin/env python

import argparse
import binascii
import sys

from pycoin import ecdsa, encoding
from pycoin.serialize import b2h, h2b
from pycoin.ecdsa import secp256k1

def parse_as_number(s):
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return int(s, 16)
    except ValueError:
        pass

def parse_as_private_key(s):
    v = parse_as_number(s)
    if v and v < secp256k1._r:
        return v
    try:
        v = encoding.wif_to_secret_exponent(s)
        return v
    except encoding.EncodingError:
        pass

def parse_as_public_pair(s):
    try:
        if s[:2] in (["02", "03", "04"]):
            return encoding.sec_to_public_pair(h2b(s))
    except (encoding.EncodingError, binascii.Error):
        pass
    for c in ",/":
        if c in s:
            s0, s1 = s.split(c, 1)
            v0 = parse_as_number(s0)
            if v0:
                if s1 in ("even", "odd"):
                    return ecdsa.public_pair_for_x(ecdsa.generator_secp256k1, v0, is_even=(s1=='even'))
                v1 = parse_as_number(s1)
                if v1:
                    if not ecdsa.is_public_pair_valid(ecdsa.generator_secp256k1, (v0, v1)):
                        sys.stderr.write("invalid (x, y) pair\n")
                        sys.exit(1)
                    return (v0, v1)

def parse_as_address(s):
    try:
        return encoding.bitcoin_address_to_hash160_sec(s)
    except encoding.EncodingError:
        pass
    try:
        v = h2b(s)
        if len(v) == 20:
            return v
    except binascii.Error:
        pass

def main():
    parser = argparse.ArgumentParser(description="Bitcoin utilities. WARNING: obsolete. Use ku instead.")

    parser.add_argument('-a', "--address", help='show as Bitcoin address', action='store_true')
    parser.add_argument('-1', "--hash160", help='show as hash 160', action='store_true')
    parser.add_argument('-v', "--verbose", help='dump all information available', action='store_true')
    parser.add_argument('-w', "--wif", help='show as Bitcoin WIF', action='store_true')
    parser.add_argument('-n', "--uncompressed", help='show in uncompressed form', action='store_true')
    parser.add_argument('item', help='a WIF, secret exponent, X/Y public pair, SEC (as hex), hash160 (as hex), Bitcoin address', nargs="+")
    args = parser.parse_args()

    for c in args.item:
        # figure out what it is:
        #  - secret exponent
        #  - WIF
        #  - X/Y public key (base 10 or hex)
        #  - sec
        #  - hash160
        #  - Bitcoin address
        secret_exponent = parse_as_private_key(c)
        if secret_exponent:
            public_pair = ecdsa.public_pair_for_secret_exponent(secp256k1.generator_secp256k1, secret_exponent)
            print("secret exponent: %d" % secret_exponent)
            print("  hex:           %x" % secret_exponent)
            print("WIF:             %s" % encoding.secret_exponent_to_wif(secret_exponent, compressed=True))
            print("  uncompressed:  %s" % encoding.secret_exponent_to_wif(secret_exponent, compressed=False))
        else:
            public_pair = parse_as_public_pair(c)
        if public_pair:
            bitcoin_address_uncompressed = encoding.public_pair_to_bitcoin_address(public_pair, compressed=False)
            bitcoin_address_compressed = encoding.public_pair_to_bitcoin_address(public_pair, compressed=True)
            print("public pair x:   %d" % public_pair[0])
            print("public pair y:   %d" % public_pair[1])
            print("  x as hex:      %x" % public_pair[0])
            print("  y as hex:      %x" % public_pair[1])
            print("y parity:        %s" % "odd" if (public_pair[1] & 1) else "even")
            print("key pair as sec: %s" % b2h(encoding.public_pair_to_sec(public_pair, compressed=True)))
            s = b2h(encoding.public_pair_to_sec(public_pair, compressed=False))
            print("  uncompressed:  %s\\\n                   %s" % (s[:66], s[66:]))
            hash160 = encoding.public_pair_to_hash160_sec(public_pair, compressed=True)
            hash160_unc = encoding.public_pair_to_hash160_sec(public_pair, compressed=False)
        else:
            hash160 = parse_as_address(c)
            hash160_unc = None
        if not hash160:
            sys.stderr.write("can't decode input %s\n" % c)
            sys.exit(1)
        print("hash160:         %s" % b2h(hash160))
        if hash160_unc:
            print("  uncompressed:  %s" % b2h(hash160_unc))
        print("Bitcoin address: %s" % encoding.hash160_sec_to_bitcoin_address(hash160))
        if hash160_unc:
            print("  uncompressed:  %s" % encoding.hash160_sec_to_bitcoin_address(hash160_unc))

#   - hash 160 (hex), Bitcoin address


if __name__ == '__main__':
    main()
