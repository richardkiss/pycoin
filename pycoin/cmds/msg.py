#!/usr/bin/env python

from __future__ import print_function

import argparse
import sys

from pycoin.encoding.exceptions import EncodingError
from pycoin.encoding.sec import public_pair_to_hash160_sec
from pycoin.networks.registry import network_for_netcode, network_codes

from .ku import parse_key


def add_read_msg_arguments(parser, operation):
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-i', "--input", type=argparse.FileType('r'), default=sys.stdin,
                       help='file containing the message to be %s, instead of stdin' % operation)
    group.add_argument('-m', "--message", help='the message to be %s' % operation)


def create_parser():
    codes = network_codes()
    parser = argparse.ArgumentParser(
        description='Create or verify a text signature using bitcoin standards',
        epilog=('Known networks codes:\n  ' +
                ', '.join(['%s (%s)' % (i, network_for_netcode(i).full_name()) for i in codes]))
    )
    parser.add_argument('-n', "--network", help='specify network (default: BTC = Bitcoin)',
                        default='BTC', choices=codes)

    subparsers = parser.add_subparsers(dest="command")

    sign = subparsers.add_parser('sign', help='sign a message with a private key')
    sign.add_argument('WIF', help='the WIF to sign the message with')
    add_read_msg_arguments(sign, "signed")

    verify = subparsers.add_parser('verify')
    verify.add_argument('signature', help='the signature to verify')
    verify.add_argument('address', nargs="?", help='the address to verify against')
    add_read_msg_arguments(verify, "verified")

    return parser


def get_message_hash(args, message_signer):
    message = args.message
    if message is None:
        message = args.input.read()
    return message_signer.hash_for_signing(message)


def msg_sign(args, parser):
    network = network_for_netcode(args.network)
    message_signer = network.msg
    message_hash = get_message_hash(args, message_signer)
    key = parse_key(args.WIF, [network])
    is_compressed = key.is_compressed()
    sig = message_signer.signature_for_message_hash(
        key.secret_exponent(), msg_hash=message_hash, is_compressed=is_compressed)
    print(sig)


def msg_verify(args, parser):
    network = network_for_netcode(args.network)
    message_signer = network.msg
    message_hash = get_message_hash(args, message_signer)
    try:
        pair, is_compressed = message_signer.pair_for_message_hash(args.signature, msg_hash=message_hash)
    except EncodingError:
        pass
    ta = network.address.for_p2pkh(public_pair_to_hash160_sec(pair, compressed=is_compressed))
    if args.address:
        if ta == args.address:
            print("signature ok")
            return 0
        else:
            print("bad signature, matches %s" % ta)
            return 1
    else:
        print(ta)


def msg(args, parser):
    command_lookup = {
        "sign": msg_sign,
        "verify": msg_verify
    }
    f = command_lookup.get(args.command)
    if f is None:
        parser.error("no subcommand given: %s" % ' '.join(sorted(command_lookup.keys())))
    f(args, parser)


def main():
    parser = create_parser()
    args = parser.parse_args()
    return msg(args, parser)


if __name__ == '__main__':
    sys.exit(main())
