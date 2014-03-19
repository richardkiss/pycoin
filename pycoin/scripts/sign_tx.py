#!/usr/bin/env python

# Sample usage
# ./sign_tx.py -p KxwGdpvzjzD5r6Qwg5Ev7gAv2Wn53tmSFfingBThhJEThQFcWPdj

import argparse
import binascii
import codecs
import io
import itertools
import sys

from pycoin import encoding
from pycoin.convention import tx_fee, satoshi_to_btc
from pycoin.serialize import stream_to_bytes
from pycoin.tx import Tx
from pycoin.tx.airgap import parse_minimal_tx_db_for_tx
from pycoin.tx.script.solvers import build_hash160_lookup_db
from pycoin.wallet import Wallet

try:
    advance_iterator = next
except NameError:
    def advance_iterator(it):
        return it.next()

def roundrobin(*iterables):
    "roundrobin('ABC', 'D', 'EF') --> A D E B F C"
    # Recipe credited to George Sakkis
    pending = len(iterables)
    iterables = [iter(it) for it in iterables]
    nexts = itertools.cycle((lambda: advance_iterator(it)) for it in iterables)
    while pending:
        try:
            for n in nexts:
                yield n()
        except StopIteration:
            pending -= 1
            nexts = itertools.cycle(itertools.islice(nexts, pending))

def secret_exponents_iterator(wif_files, private_keys):
    def private_key_iterator(pk):
        try:
            wallet = Wallet.from_wallet_key(pk)
            return (w.secret_exponent for w in wallet.children(max_level=50, start_index=0))
        except (encoding.EncodingError, TypeError):
            try:
                exp = encoding.wif_to_secret_exponent(pk)
                return [exp]
            except encoding.EncodingError:
                sys.stderr.write('bad value: "%s"\n' % pk)
                sys.exit(1)

    iterables = []
    if wif_files:
        for wif_file in wif_files:
            for l in wif_file:
                iterables.append(private_key_iterator(l[:-1]))
    if private_keys:
        for pk in private_keys:
            iterables.append(private_key_iterator(pk))
    for v in roundrobin(*iterables):
        yield v


def check_fee(unsigned_tx, tx_db):
    actual_tx_fee = unsigned_tx.fee(tx_db)
    recommended_tx_fee = tx_fee.recommended_fee_for_tx(unsigned_tx)
    if actual_tx_fee > recommended_tx_fee:
        print("warning: transaction fee of exceeds expected value of %s BTC" %
              satoshi_to_btc(recommended_tx_fee))
    elif actual_tx_fee < 0:
        print("not enough source coins (%s BTC) for destination (%s BTC)."
              " Short %s BTC" % (
                  satoshi_to_btc(unsigned_tx.total_in()),
                  satoshi_to_btc(unsigned_tx.total_out()), satoshi_to_btc(-actual_tx_fee)))
    elif actual_tx_fee < recommended_tx_fee:
        print("warning: transaction fee lower than (casually calculated)"
              " expected value of %s BTC, transaction might not propogate" %
              satoshi_to_btc(recommended_tx_fee))
    return actual_tx_fee


def get_unsigned_tx(parser):
    args = parser.parse_args()
    f = args.input_file
    if f:
        if f.name.endswith("hex"):
            f = codecs.getreader("hex_codec")(f)
            f = io.BytesIO(f.read())
    else:
        try:
            f = io.BytesIO(binascii.unhexlify(args.hex_input))
        except Exception:
            parser.error("can't parse %s as hex\n" % args.hex_input)
    try:
        tx = Tx.parse(f)
        try:
            tx_db = parse_minimal_tx_db_for_tx(f, tx)
            return tx, tx_db
        except Exception:
            parser.error("can't parse extended info... is this an airgapped transaction?")
    except Exception:
        parser.error("can't parse input")

EPILOG = 'Files are binary by default unless they end with the suffix ".hex".'


def main():
    parser = argparse.ArgumentParser(description="Sign a Bitcoin transaction.", epilog=EPILOG)

    parser.add_argument('-f', "--private-key-file", nargs="+",
                        help='file containing WIF or BIP0032 private keys',
                        metavar="path-to-file-with-private-keys", type=argparse.FileType('r'))
    parser.add_argument('-p', "--private-key", help='WIF or BIP0032 private key',
                        metavar="private-key", type=str, nargs="+")
    parser.add_argument("-H", "--hex-input", help='a hex dump of the unsigned transaction')
    parser.add_argument("-i", "--input-file", help='path to the unsigned transaction',
                        type=argparse.FileType('rb'), required=True)
    parser.add_argument('-o', "--output-file", help='output file containing (more) signed transaction',
                        metavar="path-to-output-file", type=argparse.FileType('wb'))

    args = parser.parse_args()

    unsigned_tx, tx_db = get_unsigned_tx(parser)
    actual_tx_fee = check_fee(unsigned_tx, tx_db)
    if actual_tx_fee < 0:
        sys.exit(1)
    print("transaction fee: %s BTC" % satoshi_to_btc(actual_tx_fee))

    secret_exponents = secret_exponents_iterator(args.private_key_file, args.private_key)

    class Lookup(object):
        def __init__(self, secret_exponents):
            self.secret_exponents = secret_exponents
            self.d = {}

        def get(self, v):
            while True:
                if v in self.d:
                    return self.d[v]
                for s in self.secret_exponents:
                    self.d.update(build_hash160_lookup_db([s]))
                    break
                else:
                    break
            return None

    lookup = Lookup(secret_exponents)
    unsigned_before = unsigned_tx.bad_signature_count(tx_db)
    new_tx = unsigned_tx.sign(lookup, tx_db)
    unsigned_after = unsigned_tx.bad_signature_count(tx_db)

    print("%d newly signed TxOut object(s) (%d before and %d after)" %
            (unsigned_before-unsigned_after, unsigned_before, unsigned_after))
    if unsigned_after == len(new_tx.txs_in):
        print("signing complete")

    tx_bytes = stream_to_bytes(new_tx.stream)
    f = args.output_file
    if f:
        if f.name.endswith("hex"):
            f = codecs.getwriter("hex_codec")(f)
        f.write(tx_bytes)
        f.close()
    else:
        tx_hex = binascii.hexlify(tx_bytes).decode("utf8")
        if unsigned_after == len(new_tx.txs_in):
            print("copy the following hex to http://blockchain.info/pushtx"
                  " to put the transaction on the network:\n")
        print(tx_hex)

if __name__ == '__main__':
    main()
