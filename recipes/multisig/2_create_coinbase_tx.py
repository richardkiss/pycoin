#!/usr/bin/env python

# This script creates a fake coinbase transaction to an address of your
# choosing so you can test code that spends this output.

import sys

from pycoin.symbols.btc import network


def main():
    if len(sys.argv) != 2:
        print("usage: %s address" % sys.argv[0])
        sys.exit(-1)

    # validate the address
    address = sys.argv[1]
    assert network.parse.address(address) is not None

    print("creating coinbase transaction to %s" % address)

    tx_in = network.tx.TxIn.coinbase_tx_in(script=b'')
    tx_out = network.tx.TxOut(50*1e8, network.contract.for_address(address))
    tx = network.tx(1, [tx_in], [tx_out])
    print("Here is the tx as hex:\n%s" % tx.as_hex())


if __name__ == '__main__':
    main()
