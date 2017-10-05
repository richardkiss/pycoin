#!/usr/bin/env python

import sys

from pycoin.key.validate import is_wif_valid
from pycoin.serialize import h2b
from pycoin.solve.utils import build_p2sh_lookup
from pycoin.tx.Tx import Tx
from pycoin.tx.tx_utils import sign_tx


def main():
    if len(sys.argv) != 4:
        print("usage: %s tx-hex-file-path wif-file-path p2sh-file-path" % sys.argv[0])
        sys.exit(-1)

    # get the tx
    with open(sys.argv[1], "r") as f:
        tx_hex = f.readline().strip()
    tx = Tx.from_hex(tx_hex)

    # get the WIF
    with open(sys.argv[2], "r") as f:
        wif = f.readline().strip()
    assert is_wif_valid(wif)

    # create the p2sh_lookup
    with open(sys.argv[3], "r") as f:
        p2sh_script_hex = f.readline().strip()
    p2sh_script = h2b(p2sh_script_hex)

    # build a dictionary of script hashes to scripts
    p2sh_lookup = build_p2sh_lookup([p2sh_script])

    # sign the transaction with the given WIF
    sign_tx(tx, wifs=[wif], p2sh_lookup=p2sh_lookup)

    bad_signature_count = tx.bad_signature_count()
    print("tx %s now has %d bad signature(s)" % (tx.id(), bad_signature_count))

    include_unspents = (bad_signature_count > 0)
    print("Here is the tx as hex:\n%s" % tx.as_hex(include_unspents=include_unspents))


if __name__ == '__main__':
    main()
