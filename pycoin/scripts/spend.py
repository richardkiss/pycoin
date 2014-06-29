#!/usr/bin/env python

# Sample usage (with fake coinbase transaction):
# ./spend.py `./spend.py -c KxwGdpvzjzD5r6Qwg5Ev7gAv2Wn53tmSFfingBThhJEThQFcWPdj/20` 19TKi9Mv8AVLguAVYyCTY5twy5PKoEqrRf/19.9999 -p KxwGdpvzjzD5r6Qwg5Ev7gAv2Wn53tmSFfingBThhJEThQFcWPdj

import argparse
import decimal
import io
import itertools
import sys

from pycoin import ecdsa
from pycoin import encoding
from pycoin.convention import tx_fee, btc_to_satoshi, satoshi_to_btc
from pycoin.serialize import b2h, h2b
from pycoin.services import blockchain_info
from pycoin.tx import Tx, UnsignedTx, TxOut, SecretExponentSolver
from pycoin.wallet import Wallet

def roundrobin(*iterables):
    "roundrobin('ABC', 'D', 'EF') --> A D E B F C"
    # Recipe credited to George Sakkis
    pending = len(iterables)
    nexts = itertools.cycle(iter(it).next for it in iterables)
    while pending:
        try:
            for next in nexts:
                yield next()
        except StopIteration:
            pending -= 1
            nexts = itertools.cycle(itertools.islice(nexts, pending))

def secret_exponents_iterator(wif_file, private_keys):
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
    if wif_file:
        for l in wif_file:
            iterables.append(private_key_iterator(l[:-1]))
    if private_keys:
        for pk in private_keys:
            iterables.append(private_key_iterator(pk))
    for v in roundrobin(*iterables):
        yield v

def calculate_fees(unsigned_tx):
    total_value = sum(unsigned_tx_out.coin_value for unsigned_tx_out in unsigned_tx.unsigned_txs_out)
    total_spent = sum(tx_out.coin_value for tx_out in unsigned_tx.new_txs_out)
    return total_value, total_spent

def check_fees(unsigned_tx):
    total_value, total_spent = calculate_fees(unsigned_tx)
    actual_tx_fee = total_value - total_spent
    recommended_tx_fee = tx_fee.recommended_fee_for_tx(unsigned_tx)
    if actual_tx_fee > recommended_tx_fee:
        print("warning: transaction fee of exceeds expected value of %s BTC" % satoshi_to_btc(recommended_tx_fee))
    elif actual_tx_fee < 0:
        print("not enough source coins (%s BTC) for destination (%s BTC). Short %s BTC" % (satoshi_to_btc(total_value), satoshi_to_btc(total_spent), satoshi_to_btc(-actual_tx_fee)))
    elif actual_tx_fee < recommended_tx_fee:
        print("warning: transaction fee lower than (casually calculated) expected value of %s BTC, transaction might not propogate" % satoshi_to_btc(recommended_tx_fee))
    return actual_tx_fee

def get_unsigned_tx(parser):
    args = parser.parse_args()
    # if there is only one item passed, it's assumed to be hex
    if len(args.txinfo) == 1:
        try:
            s = io.BytesIO(h2b(args.txinfo[0]))
            return UnsignedTx.parse(s)
        except Exception:
            parser.error("can't parse %s as hex\n" % args.txinfo[0])

    coins_from = []
    coins_to = []
    for txinfo in args.txinfo:
        if '/' in txinfo:
            parts = txinfo.split("/")
            if len(parts) == 2:
                # we assume it's an output
                address, amount = parts
                amount = btc_to_satoshi(amount)
                coins_to.append((amount, address))
            else:
                try:
                    # we assume it's an input of the form
                    #  tx_hash_hex/tx_output_index_decimal/tx_out_val/tx_out_script_hex
                    tx_hash_hex, tx_output_index_decimal, tx_out_val, tx_out_script_hex = parts
                    tx_hash = h2b(tx_hash_hex)
                    tx_output_index = int(tx_output_index_decimal)
                    tx_out_val = btc_to_satoshi(decimal.Decimal(tx_out_val))
                    tx_out_script = h2b(tx_out_script_hex)
                    tx_out = TxOut(tx_out_val, tx_out_script)
                    coins_source = (tx_hash, tx_output_index, tx_out)
                    coins_from.append(coins_source)
                except Exception:
                    parser.error("can't parse %s\n" % txinfo)
        else:
            print("looking up funds for %s from blockchain.info" % txinfo)
            coins_sources = blockchain_info.unspent_tx_outs_info_for_address(txinfo)
            coins_from.extend(coins_sources)

    unsigned_tx = UnsignedTx.standard_tx(coins_from, coins_to)
    return unsigned_tx

def create_coinbase_tx(parser):
    args = parser.parse_args()
    try:
        if len(args.txinfo) != 1:
            parser.error("coinbase transactions need exactly one output parameter (wif/BTC count)")
        wif, btc_amount = args.txinfo[0].split("/")
        satoshi_amount = btc_to_satoshi(btc_amount)
        secret_exponent, compressed = encoding.wif_to_tuple_of_secret_exponent_compressed(wif)
        public_pair = ecdsa.public_pair_for_secret_exponent(ecdsa.secp256k1.generator_secp256k1, secret_exponent)
        public_key_sec = encoding.public_pair_to_sec(public_pair, compressed=compressed)
        coinbase_tx = Tx.coinbase_tx(public_key_sec, satoshi_amount)
        return coinbase_tx
    except Exception:
        parser.error("coinbase transactions need exactly one output parameter (wif/BTC count)")

EPILOG = "If you generate an unsigned transaction, the output is a hex dump that can be used by this script on an air-gapped machine."

def main():
    parser = argparse.ArgumentParser(description="Create a Bitcoin transaction.", epilog=EPILOG)

    parser.add_argument('-g', "--generate-unsigned", help='generate unsigned transaction', action='store_true')
    parser.add_argument('-f', "--private-key-file", help='file containing WIF or BIP0032 private keys', metavar="path-to-file-with-private-keys", type=argparse.FileType('r'))
    parser.add_argument('-p', "--private-key", help='WIF or BIP0032 private key', metavar="private-key", type=str, nargs="+")
    parser.add_argument('-c', "--coinbase", help='Create a (bogus) coinbase transaction. For testing purposes. You must include exactly one WIF in this case.', action='store_true')
    parser.add_argument("txinfo", help='either a hex dump of the unsigned transaction, or a list of bitcoin addresses with optional "/value" if they are destination addresses', nargs="+")

    args = parser.parse_args()
    if args.coinbase:
        new_tx = create_coinbase_tx(parser)
        tx_hash_hex = b2h(new_tx.hash())
        tx_output_index = 0
        tx_out_val = str(satoshi_to_btc(new_tx.txs_out[tx_output_index].coin_value))
        tx_out_script_hex = b2h(new_tx.txs_out[tx_output_index].script)
        # product output in the form:
        #  tx_hash_hex/tx_output_index_decimal/tx_out_val/tx_out_script_hex
        # which can be used as a fake input to a later transaction
        print("/".join([tx_hash_hex, str(tx_output_index), tx_out_val, tx_out_script_hex]))
        return

    unsigned_tx = get_unsigned_tx(parser)
    actual_tx_fee = check_fees(unsigned_tx)
    if actual_tx_fee < 0:
        sys.exit(1)
    print("transaction fee: %s BTC" % satoshi_to_btc(actual_tx_fee))

    if args.generate_unsigned:
        s = io.BytesIO()
        unsigned_tx.stream(s)
        tx_bytes = s.getvalue()
        tx_hex = b2h(tx_bytes)
        print(tx_hex)
        sys.exit(0)

    secret_exponents = secret_exponents_iterator(args.private_key_file, args.private_key)
    solver = SecretExponentSolver(secret_exponents)
    new_tx = unsigned_tx.sign(solver)
    s = io.BytesIO()
    new_tx.stream(s)
    tx_bytes = s.getvalue()
    tx_hex = b2h(tx_bytes)
    print("copy the following hex to http://blockchain.info/pushtx to put the transaction on the network:\n")
    print(tx_hex)

if __name__ == '__main__':
    main()
