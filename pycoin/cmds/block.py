#!/usr/bin/env python

import argparse
import datetime

from .dump import dump_tx
from pycoin.encoding.hexbytes import b2h, b2h_rev
from pycoin.networks.default import get_current_netcode
from pycoin.networks.registry import network_for_netcode
from pycoin.serialize import stream_to_bytes


def dump_block(output, block, network):
    blob = stream_to_bytes(block.stream)
    output.append("%d bytes   block hash %s" % (len(blob), block.id()))
    output.append("version %d" % block.version)
    output.append("prior block hash %s" % b2h_rev(block.previous_block_hash))
    output.append("merkle root %s" % b2h(block.merkle_root))
    output.append("timestamp %s" % datetime.datetime.utcfromtimestamp(block.timestamp).isoformat())
    output.append("difficulty %d" % block.difficulty)
    output.append("nonce %s" % block.nonce)
    output.append("%d transaction%s" % (len(block.txs), "s" if len(block.txs) != 1 else ""))
    for idx, tx in enumerate(block.txs):
        output.append("Tx #%d:" % idx)
        dump_tx(
            output, tx, network=network, verbose_signature=False, disassembly_level=0, do_trace=False, use_pdb=False)
    output.append("")


def create_parser():
    parser = argparse.ArgumentParser(description="Dump a block in human-readable form.")
    parser.add_argument('-n', "--network", default=get_current_netcode(), type=network_for_netcode,
                        help=('Default network code (environment variable PYCOIN_DEFAULT_NETCODE '
                              'or "BTC"=Bitcoin mainnet if unset'))
    parser.add_argument("block_file", nargs="+", type=argparse.FileType('rb'),
                        help='The file containing the binary block.')
    return parser


def block(args, parser):
    network = args.network
    for f in args.block_file:
        block = network.block.parse(f)
        output = []
        dump_block(output, block, network)

        for line in output:
            print(line)


def main():
    parser = create_parser()
    args = parser.parse_args()
    block(args, parser)


if __name__ == '__main__':
    main()
