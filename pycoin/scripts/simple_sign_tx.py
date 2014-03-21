#!/usr/bin/env python

# Sample usage
# ./simple_sign_tx.py unsigned_tx.bin KxwGdpvzjzD5r6Qwg5Ev7gAv2Wn53tmSFfingBThhJEThQFcWPdj

import argparse
import codecs
import io

from pycoin.encoding import wif_to_secret_exponent
from pycoin.serialize import stream_to_bytes
from pycoin.tx import Tx
from pycoin.tx.airgap import parse_minimal_tx_db_for_tx
from pycoin.tx.script.solvers import build_hash160_lookup_db


def get_unsigned_tx(f):
    if f.name.endswith("hex"):
        f = codecs.getreader("hex_codec")(f)
        f = io.BytesIO(f.read())
    tx = Tx.parse(f)
    tx_db = parse_minimal_tx_db_for_tx(f, tx)
    return tx, tx_db

EPILOG = 'Files are binary by default unless they end with the suffix ".hex".'


def main():
    parser = argparse.ArgumentParser(description="Sign a Bitcoin transaction.", epilog=EPILOG)

    parser.add_argument("input_file", help='path to the unsigned transaction',
                        type=argparse.FileType('rb'))
    parser.add_argument("output_file", help='output file with signed transaction',
                        type=argparse.FileType('wb'))
    parser.add_argument("private_key", help='WIF or BIP0032 private key', type=str, nargs="+")

    args = parser.parse_args()

    try:
        unsigned_tx, tx_db = get_unsigned_tx(args.input_file)
    except Exception:
        parser.error("can't parse extended info... is this an airgapped transaction?")

    secret_exponent_lookup = build_hash160_lookup_db(wif_to_secret_exponent(pk) for pk in args.private_key)

    unsigned_before = unsigned_tx.bad_signature_count(tx_db)
    new_tx = unsigned_tx.sign(secret_exponent_lookup, tx_db)
    unsigned_after = unsigned_tx.bad_signature_count(tx_db)

    print("%d newly signed TxOut object(s) (%d unsigned before and %d unsigned now)" %
          (unsigned_before-unsigned_after, unsigned_before, unsigned_after))
    if unsigned_after == len(new_tx.txs_in):
        print("signing complete")

    tx_bytes = stream_to_bytes(new_tx.stream)
    f = args.output_file
    if f.name.endswith("hex"):
        f = codecs.getwriter("hex_codec")(f)
    f.write(tx_bytes)
    f.close()

if __name__ == '__main__':
    main()
