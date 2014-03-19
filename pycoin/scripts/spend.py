#!/usr/bin/env python

import argparse
import binascii
import decimal
import io
import sys

from pycoin import encoding
from pycoin.convention import tx_fee, btc_to_satoshi, satoshi_to_btc
from pycoin.services import blockchain_info
from pycoin.tx import Tx, UnsignedTx, TxOut, SecretExponentSolver

def main():
    parser = argparse.ArgumentParser(description="Create a Bitcoin transaction.")

    parser.add_argument('-s', "--source-address", help='source Bitcoin address', required=True, nargs="+", metavar='source_address')
    parser.add_argument('-d', "--destination-address", help='destination Bitcoin address/amount', required=True, metavar='dest_address/amount_in_btc', nargs="+")
    parser.add_argument('-f', "--wif-file", help='WIF items for source Bitcoin addresses', required=True, metavar="path-to-WIF-values", type=argparse.FileType('r'))
    args = parser.parse_args()

    total_value = 0
    coins_from = []
    for bca in args.source_address:
        coins_sources = blockchain_info.coin_sources_for_address(bca)
        coins_from.extend(coins_sources)
        total_value += sum(cs[-1].coin_value for cs in coins_sources)

    secret_exponents = []
    for l in args.wif_file:
        secret_exponents.append(encoding.wif_to_secret_exponent(l[:-1]))

    coins_to = []
    total_spent = 0
    for daa in args.destination_address:
        address, amount = daa.split("/")
        amount = btc_to_satoshi(amount)
        total_spent += amount
        coins_to.append((amount, address))

    actual_tx_fee = total_value - total_spent
    if actual_tx_fee < 0:
        print("not enough source coins (%s BTC) for destination (%s BTC). Short %s BTC" % (satoshi_to_btc(total_value), satoshi_to_btc(total_spent), satoshi_to_btc(-actual_tx_fee)))
        sys.exit(1)

    print("transaction fee: %s BTC" % satoshi_to_btc(actual_tx_fee))
    unsigned_tx = UnsignedTx.standard_tx(coins_from, coins_to)
    solver = SecretExponentSolver(secret_exponents)
    new_tx = unsigned_tx.sign(solver)
    s = io.BytesIO()
    new_tx.stream(s)
    tx_bytes = s.getvalue()
    tx_hex = binascii.hexlify(tx_bytes).decode("utf8")
    recommended_tx_fee = tx_fee.recommended_fee_for_tx(new_tx)
    if actual_tx_fee > recommended_tx_fee:
        print("warning: transaction fee of exceeds expected value of %s BTC" % satoshi_to_btc(recommended_tx_fee))
    elif actual_tx_fee < recommended_tx_fee:
        print("warning: transaction fee lower than (casually calculated) expected value of %s BTC, transaction might not propogate" % satoshi_to_btc(recommended_tx_fee))
    print("copy the following hex to http://blockchain.info/pushtx to put the transaction on the network:\n")
    print(tx_hex)

if __name__ == '__main__':
    main()
