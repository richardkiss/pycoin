#!/usr/bin/env python

# Sample usage
# ./sign_tx.py -p KxwGdpvzjzD5r6Qwg5Ev7gAv2Wn53tmSFfingBThhJEThQFcWPdj

import argparse
import binascii
import io
import itertools
import sys

from pycoin import encoding
from pycoin.convention import tx_fee, satoshi_to_btc
from pycoin.serialize import stream_to_bytes
from pycoin.tx import UnsignedTx, SecretExponentSolver
from pycoin.wallet import Wallet


def roundrobin(*iterables):
    "roundrobin('ABC', 'D', 'EF') --> A D E B F C"
    # Recipe credited to George Sakkis
    pending = len(iterables)
    nexts = itertools.cycle(iter(it).__next__ for it in iterables)
    while pending:
        try:
            for next in nexts:
                yield next()
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


def check_fee(unsigned_tx):
    actual_tx_fee = unsigned_tx.fee()
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
    if args.input_file:
        return UnsignedTx.parse(args.input_file)
    try:
        s = io.BytesIO(binascii.unhexlify(args.hex_input))
        return UnsignedTx.parse(s)
    except Exception:
        parser.error("can't parse %s as hex\n" % args.hex_input)

EPILOG = ""


def main():
    parser = argparse.ArgumentParser(description="Sign a Bitcoin transaction.", epilog=EPILOG)

    parser.add_argument('-f', "--private-key-file", nargs="+",
                        help='file containing WIF or BIP0032 private keys',
                        metavar="path-to-file-with-private-keys", type=argparse.FileType('r'))
    parser.add_argument('-p', "--private-key", help='WIF or BIP0032 private key',
                        metavar="private-key", type=str, nargs="+")
    parser.add_argument("-i", "--input-file", help='a binary containing the unsigned transaction', type=argparse.FileType('rb'))
    parser.add_argument('-o', "--output-file", help='output file containing (more) signed transaction', metavar="path-to-output-file", type=argparse.FileType('wb'))
    parser.add_argument("-H", "--hex-input", help='a hex dump of the unsigned transaction')

    args = parser.parse_args()

    unsigned_tx = get_unsigned_tx(parser)
    actual_tx_fee = check_fee(unsigned_tx)
    if actual_tx_fee < 0:
        sys.exit(1)
    print("transaction fee: %s BTC" % satoshi_to_btc(actual_tx_fee))

    secret_exponents = secret_exponents_iterator(args.private_key_file, args.private_key)
    solver = SecretExponentSolver(secret_exponents)
    unsigned_before = unsigned_tx.unsigned_count()
    new_tx = unsigned_tx.sign(solver)
    unsigned_after = unsigned_tx.unsigned_count()

    print("%d newly signed TxOut object(s) (%d before and %d after)" % (unsigned_after-unsigned_before, unsigned_before, unsigned_after))
    if unsigned_after == len(new_tx.txs_in):
        print("signing complete")

    tx_bytes = stream_to_bytes(new_tx.stream)
    tx_hex = binascii.hexlify(tx_bytes).decode("utf8")
    print("copy the following hex to http://blockchain.info/pushtx"
          " to put the transaction on the network:\n")
    print(tx_hex)
    if args.output_file:
        args.output_file.write(tx_bytes)
        args.output_file.close()

if __name__ == '__main__':
    main()
