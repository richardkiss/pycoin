#!/usr/bin/env python

from __future__ import print_function

import argparse

from pycoin.encoding.b58 import a2b_base58, b2a_base58, a2b_hashed_base58, b2a_hashed_base58
from pycoin.encoding.hexbytes import b2h, h2b


def create_parser():
    parser = argparse.ArgumentParser(description='Convert b58 to hex or back')
    parser.add_argument('-b', help='force b58 input (rather than best guess)', action="store_true")
    parser.add_argument('input', nargs="+", help='hex or base58')
    return parser


def parse_arg(arg, force_b58):
    is_hex_input = False
    blob = None
    if not force_b58:
        try:
            blob = h2b(arg)
            is_hex_input = True
        except Exception:
            pass
    if blob is None:
        try:
            blob = a2b_base58(arg)
        except KeyError:
            pass
    if blob is None:
        raise argparse.ArgumentTypeError("can't parse %s" % arg)
    return blob, is_hex_input


def b58(args, parser):
    for arg in args.input:
        blob, is_hex_input = parse_arg(arg, args.b)

        if is_hex_input:
            print(b2h(blob))
            print(b2a_base58(blob))
            print(b2a_hashed_base58(blob))
        else:
            print(b2h(blob))
            print(b2a_base58(blob))
            try:
                blob = a2b_hashed_base58(arg)
                print("valid hashed b58")
                print("contents: ", b2h(blob))
            except Exception:
                print("not hashed b58")


def main():
    parser = create_parser()
    args = parser.parse_args()
    b58(args, parser)


if __name__ == '__main__':
    main()
