#!/usr/bin/env python

# This script creates a fake coinbase transaction to an address of your
# choosing so you can test code that spends this output.

import sys

from pycoin.key.validate import is_address_valid
from pycoin.tx.Tx import Tx, TxIn, TxOut
from pycoin.ui import script_for_address


def main():
    if len(sys.argv) != 2:
        print("usage: %s address" % sys.argv[0])
        sys.exit(-1)

    # validate the address
    address = sys.argv[1]
    assert is_address_valid(address)

    print("creating coinbase transaction to %s" % address)

    tx_in = TxIn.coinbase_tx_in(script=b'')
    tx_out = TxOut(50*1e8, script_for_address(address))
    tx = Tx(1, [tx_in], [tx_out])
    print("Here is the tx as hex:\n%s" % tx.as_hex())


if __name__ == '__main__':
    main()
