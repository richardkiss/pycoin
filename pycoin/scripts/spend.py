#!/usr/bin/env python

import argparse
import binascii
import io
import json
import sys
import urllib.request

from pycoin import encoding
from pycoin.tx import Tx, UnsignedTx, TxOut, SecretExponentSolver

def hash_index_tx_out_list_for_address(bitcoin_address):
    r = json.loads(urllib.request.urlopen("http://blockchain.info/unspent?active=%s" % bitcoin_address).read().decode("utf8"))
    coins_sources = []
    for unspent_output in r["unspent_outputs"]:
        tx_out = TxOut(unspent_output["value"], binascii.unhexlify(unspent_output["script"]))
        coins_source = (binascii.unhexlify(unspent_output["tx_hash"]), unspent_output["tx_output_n"], tx_out)
        coins_sources.append(coins_source)
    return coins_sources

def main():
    parser = argparse.ArgumentParser(description="Create a Bitcoin transaction.")

    parser.add_argument('-s', "--source-address", help='source Bitcoin address', nargs="+", metavar='source_address')
    parser.add_argument('-d', "--destination-address", help='destination Bitcoin address/amount', metavar='dest_address/amount', nargs="+")
    parser.add_argument('-f', "--secret-exponents", help='WIF items for source Bitcoin addresses', type=argparse.FileType('r'))
    args = parser.parse_args()

    coins_from = []
    for bca in args.source_address:
        coins_from.extend(hash_index_tx_out_list_for_address(bca))

    secret_exponents = []
    for l in args.secret_exponents:
        secret_exponents.append(encoding.wif_to_secret_exponent(l[:-1]))

    coins_to = []
    for daa in args.destination_address:
        address, amount = daa.split("/")
        amount = int(amount)
        coins_to.append((amount, address))

    unsigned_tx = UnsignedTx.standard_tx(coins_from, coins_to)
    solver = SecretExponentSolver(secret_exponents)
    new_tx = unsigned_tx.sign(solver)
    s = io.BytesIO()
    new_tx.stream(s)
    print(binascii.hexlify(s.getvalue()))
    print(repr(new_tx))

if __name__ == '__main__':
    main()
