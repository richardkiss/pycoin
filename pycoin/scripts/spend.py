#!/usr/bin/env python

import argparse
import binascii
import io
import json
import sys
import urllib.request

from pycoin import encoding
from pycoin.tx import Tx
from pycoin.tx.TxOut import TxOut

def source_tx_for_address(bitcoin_address):
    r = json.loads(urllib.request.urlopen("http://blockchain.info/unspent?active=%s" % bitcoin_address).read().decode("utf8"))
    tx_db = {}
    for unspent_output in r["unspent_outputs"]:
        tx_db[(binascii.unhexlify(unspent_output["tx_hash"]), unspent_output["tx_output_n"])] = binascii.unhexlify(unspent_output["script"])
    return tx_db

def main():
    parser = argparse.ArgumentParser(description="Create a Bitcoin transaction.")

    parser.add_argument('-s', "--source-address", help='source Bitcoin address', nargs="+", metavar='source_address')
    parser.add_argument('-d', "--destination-address", help='destination Bitcoin address/amount', metavar='dest_address/amount', nargs="+")
    parser.add_argument('-f', "--secret-exponents", help='WIF items for source Bitcoin addresses', type=argparse.FileType('r'))
    args = parser.parse_args()

    tx_db = {}

    previous_hash_index__tuple_list = []
    for bca in args.source_address:
        tx_db.update(source_tx_for_address(bca))
    for k, v in tx_db.items():
        previous_hash_index__tuple_list.append(k)

    secret_exponents = []
    for l in args.secret_exponents:
        secret_exponents.append(encoding.wif_to_secret_exponent(l[:-1]))

    coin_value__bitcoin_address__tuple_list = []
    for daa in args.destination_address:
        address, amount = daa.split("/")
        amount = int(amount)
        coin_value__bitcoin_address__tuple_list.append((amount, address))

    new_tx = Tx.standard_tx(previous_hash_index__tuple_list, coin_value__bitcoin_address__tuple_list, tx_db, secret_exponents)
    s = io.BytesIO()
    new_tx.stream(s)
    print(binascii.hexlify(s.getvalue()))
    print(repr(new_tx))

if __name__ == '__main__':
    main()
