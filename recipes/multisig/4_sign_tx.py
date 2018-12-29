#!/usr/bin/env python

import sys

from pycoin.encoding.hexbytes import h2b
from pycoin.symbols.btc import network


def main():
    if len(sys.argv) != 4:
        print("usage: %s tx-hex-file-path wif-file-path p2sh-file-path" % sys.argv[0])
        sys.exit(-1)

    # get the tx
    with open(sys.argv[1], "r") as f:
        tx_hex = f.readline().strip()
    tx = network.tx.from_hex(tx_hex)

    # get the WIF
    with open(sys.argv[2], "r") as f:
        wif = f.readline().strip()
    assert network.parse.wif(wif) is not None

    # create the p2sh_lookup
    with open(sys.argv[3], "r") as f:
        p2sh_script_hex = f.readline().strip()
    p2sh_script = h2b(p2sh_script_hex)

    # build a dictionary of script hashes to scripts
    p2sh_lookup = network.tx.solve.build_p2sh_lookup([p2sh_script])

    # sign the transaction with the given WIF
    network.tx_utils.sign_tx(tx, wifs=[wif], p2sh_lookup=p2sh_lookup)

    bad_solution_count = tx.bad_solution_count()
    print("tx %s now has %d bad solution(s)" % (tx.id(), bad_solution_count))

    include_unspents = (bad_solution_count > 0)
    print("Here is the tx as hex:\n%s" % tx.as_hex(include_unspents=include_unspents))


if __name__ == '__main__':
    main()
