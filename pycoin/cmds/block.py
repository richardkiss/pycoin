#!/usr/bin/env python

from __future__ import annotations

import argparse
import datetime
from typing import Any

from .dump import dump_tx
from pycoin.encoding.hexbytes import b2h, b2h_rev
from pycoin.networks.default import get_current_netcode
from pycoin.networks.registry import network_for_netcode
from pycoin.serialize import stream_to_bytes


def dump_block(output: list[str], block: Any, network: Any) -> None:
    blob = stream_to_bytes(block.stream)
    output.append("%d bytes   block hash %s" % (len(blob), block.id()))
    output.append("version %d" % block.version)
    output.append("prior block hash %s" % b2h_rev(block.previous_block_hash))
    output.append("merkle root %s" % b2h(block.merkle_root))
    output.append(
        "timestamp %s"
        % datetime.datetime.fromtimestamp(block.timestamp, datetime.timezone.utc).isoformat()
    )
    output.append("difficulty %d" % block.difficulty)
    output.append("nonce %s" % block.nonce)
    output.append(
        "%d transaction%s" % (len(block.txs), "s" if len(block.txs) != 1 else "")
    )
    for idx, tx in enumerate(block.txs):
        output.append("Tx #%d:" % idx)
        dump_tx(
            output,
            tx,
            network=network,
            verbose_signature=False,
            disassembly_level=0,
            do_trace=False,
            use_pdb=False,
        )
    output.append("")


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Dump a block in human-readable form.")
    parser.add_argument(
        "-n",
        "--network",
        default=get_current_netcode(),
        type=network_for_netcode,
        help=(
            "Default network code (environment variable PYCOIN_DEFAULT_NETCODE "
            'or "BTC"=Bitcoin mainnet if unset'
        ),
    )
    parser.add_argument(
        "block_file",
        nargs="+",
        help="The file containing the binary block.",
    )
    return parser


def block(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    network = args.network
    for path in args.block_file:
        with open(path, "rb") as f:
            block = network.block.parse(f)
        output: list[str] = []
        dump_block(output, block, network)

        for line in output:
            print(line)


def main() -> None:
    parser = create_parser()
    args = parser.parse_args()
    block(args, parser)


if __name__ == "__main__":
    main()
