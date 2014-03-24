#!/usr/bin/env python

# Sample usage (with fake coinbase transaction):
# ./spend.py `./spend.py -c KxwGdpvzjzD5r6Qwg5Ev7gAv2Wn53tmSFfingBThhJEThQFcWPdj/20` 19TKi9Mv8AVLguAVYyCTY5twy5PKoEqrRf/19.9999 -p KxwGdpvzjzD5r6Qwg5Ev7gAv2Wn53tmSFfingBThhJEThQFcWPdj

import argparse
import binascii
import decimal
import io
import itertools
import json
import subprocess
import sys

from pycoin import ecdsa
from pycoin import encoding
from pycoin.convention import tx_fee, btc_to_satoshi, satoshi_to_btc
from pycoin.services import blockchain_info
from pycoin.tx import Tx, TxOut
from pycoin.wallet import Wallet, PublicPrivateMismatchError

def b2h(b):
    return binascii.hexlify(b).decode("utf8")

def get_entropy():
    def gpg_entropy():
        try:
            output = subprocess.Popen(["gpg", "--gen-random", "2", "64"], stdout=subprocess.PIPE).communicate()[0]
            return output
        except OSError:
            sys.stderr.write("warning: can't open gpg, can't use as entropy source\n")
        return b''

    def dev_random_entropy():
        return open("/dev/random", "rb").read(64)

    entropy = bytearray()
    entropy.extend(gpg_entropy())
    entropy.extend(dev_random_entropy())
    return entropy

def parse_as_wallet_key(s, is_test):
    try:
        if s.startswith("P:"):
            return Wallet.from_master_secret(s[2:], is_test=is_test)
        if s == 'create':
            entropy = get_entropy()
            return Wallet.from_master_secret(bytes(entropy))
        w = Wallet.from_wallet_key(s)
        return w
    except encoding.EncodingError:
        pass

def parse_as_wif(s, is_test):
    try:
        return encoding.wif_to_tuple_of_secret_exponent_compressed(s, is_test=is_test)
    except encoding.EncodingError:
        pass

def parse_as_number(s):
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return int(s, 16)
    except ValueError:
        pass

def parse_as_secret_exponent(s):
    return parse_as_number(s)

def parse_as_private_key(s):
    v = parse_as_number(s)
    if v and v < ecdsa.secp256k1._r:
        return v
    try:
        v = encoding.wif_to_secret_exponent(s)
        return v
    except encoding.EncodingError:
        pass

def parse_as_public_pair(s):
    try:
        if s[:2] in (["02", "03", "04"]):
            return encoding.sec_to_public_pair(encoding.h2b(s))
        if s.startswith("sec:"):
            return encoding.sec_to_public_pair(encoding.h2b(s[3:]))
    except (encoding.EncodingError, binascii.Error):
        pass
    for c in ",/":
        if c in s:
            s0, s1 = s.split(c, 1)
            v0 = parse_as_number(s0)
            if v0:
                if s1 in ("even", "odd"):
                    return ecdsa.public_pair_for_x(ecdsa.generator_secp256k1, v0, is_even=(s1=='even'))
                v1 = parse_as_number(s1)
                if v1:
                    if not ecdsa.is_public_pair_valid(ecdsa.generator_secp256k1, (v0, v1)):
                        sys.stderr.write("invalid (x, y) pair\n")
                        sys.exit(1)
                    return (v0, v1)

def parse_as_hash160(s):
    try:
        v = encoding.bitcoin_address_to_hash160_sec_with_network(s)
        if v:
            return v[0]
    except EncodingError:
        pass
    if s.startswith("h:"):
        s = s[2:]
    try:
        v = encoding.h2b(s)
        if len(v) == 20:
            return v
    except (TypeError, binascii.Error):
        pass

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
            s = io.BytesIO(binascii.unhexlify(args.txinfo[0].decode("utf8")))
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
                    tx_hash = binascii.unhexlify(tx_hash_hex)
                    tx_output_index = int(tx_output_index_decimal)
                    tx_out_val = btc_to_satoshi(decimal.Decimal(tx_out_val))
                    tx_out_script = binascii.unhexlify(tx_out_script_hex)
                    tx_out = TxOut(tx_out_val, tx_out_script)
                    coins_source = (tx_hash, tx_output_index, tx_out)
                    coins_from.append(coins_source)
                except Exception:
                    parser.error("can't parse %s\n" % txinfo)
        else:
            print("looking up funds for %s from blockchain.info" % txinfo)
            coins_sources = blockchain_info.unspent_for_address(txinfo)
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
        tx_hash_hex = binascii.hexlify(new_tx.hash())
        tx_output_index = 0
        tx_out_val = str(satoshi_to_btc(new_tx.txs_out[tx_output_index].coin_value))
        tx_out_script_hex = binascii.hexlify(new_tx.txs_out[tx_output_index].script)
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
        tx_hex = binascii.hexlify(tx_bytes).decode("utf8")
        print(tx_hex)
        sys.exit(0)

    secret_exponents = secret_exponents_iterator(args.private_key_file, args.private_key)
    solver = SecretExponentSolver(secret_exponents)
    new_tx = unsigned_tx.sign(solver)
    s = io.BytesIO()
    new_tx.stream(s)
    tx_bytes = s.getvalue()
    tx_hex = binascii.hexlify(tx_bytes).decode("utf8")
    print("copy the following hex to http://blockchain.info/pushtx to put the transaction on the network:\n")
    print(tx_hex)

def main():
    parser = argparse.ArgumentParser(description='Bitcoin utility bd ("Bitcoin dump") to dump information about Bitcoin data structures.')
    parser.add_argument('-w', "--wallet", help='show just Bitcoin wallet key', action='store_true')
    parser.add_argument('-W', "--wif", help='show just Bitcoin WIF', action='store_true')
    parser.add_argument('-a', "--address", help='show just Bitcoin address', action='store_true')
    parser.add_argument('-n', "--uncompressed", help='show output in uncompressed form', action='store_true')
    parser.add_argument('-P', "--public", help='only show public version of wallet keys', action='store_true')

    parser.add_argument('-j', "--json", help='output as JSON', action='store_true')

    parser.add_argument('-s', "--subkey", help='subkey path (example: 0p/2/15)')
    parser.add_argument('-t', "--test-network", help='use test network', action="store_true")

    parser.add_argument('item', help='a wallet key; a WIF; a bitcoin address; the literal string "create" to create a new wallet key using strong entropy sources; P:wallet passphrase (not recommended); p:value where value=a secret exponent; x,y where x,y form a public pair (y is a number or one of the strings "even" or "odd"); sec:SEC (as hex); h:value where value is a hash160 as hex', nargs="+")

    args = parser.parse_args()

    json_output = []
    for item in args.item:
        output_dict = {}
        output_order = []
        input_is_compressed = None

        def add_output(json_key, value=None, human_readable_key=None):
            if human_readable_key is None:
                human_readable_key = json_key.replace("_", " ")
            if value:
                output_dict[json_key.strip().lower()] = value
            output_order.append((json_key.lower(), human_readable_key))

        wallet = parse_as_wallet_key(item, args.test_network)
        if wallet and args.public:
            wallet = wallet.public_copy()
        secret_exponent = None
        public_pair = None
        hash160 = None
        hash160_unc = None

        if wallet:
            if args.subkey:
                wallet = wallet.subkey_for_path(args.subkey)
                add_output("subkey_path", args.subkey)
            add_output("wallet_key", wallet.wallet_key(as_private=wallet.is_private))
            if wallet.child_number >= 0x80000000:
                wc = wallet.child_number - 0x80000000
                child_index = "%dp (%d)" % (wc, wallet.child_number)
            else:
                child_index = "%d" % wallet.child_number
            if wallet.is_test:
                add_output("test_network")
            else:
                add_output("main_network")
            if wallet.is_private:
                secret_exponent = wallet.secret_exponent
                add_output("private_key")
                add_output("public_version", wallet.public_copy().wallet_key())
            else:
                add_output("public_key_only")
                public_pair = wallet.public_pair
            add_output("tree_depth", "%d" % wallet.depth)
            add_output("fingerprint", b2h(wallet.fingerprint()))
            add_output("parent_fingerprint", b2h(wallet.parent_fingerprint), "parent f'print")
            add_output("child_index", child_index)
            add_output("chain_code", b2h(wallet.chain_code))
        else:
            wif_parsed = parse_as_wif(item, is_test=args.test_network)
            if wif_parsed:
                secret_exponent, input_is_compressed = wif_parsed

        if not secret_exponent:
            secret_exponent = parse_as_secret_exponent(item)

        if secret_exponent:
            add_output("secret_exponent", '%d' % secret_exponent)
            add_output("secret_exponent_hex", '%x' % secret_exponent, " hex")
            add_output("wif", encoding.secret_exponent_to_wif(secret_exponent, compressed=True, is_test=args.test_network))
            add_output("wif_uncompressed", encoding.secret_exponent_to_wif(secret_exponent, compressed=False, is_test=args.test_network), " uncompressed")
            public_pair = ecdsa.public_pair_for_secret_exponent(ecdsa.secp256k1.generator_secp256k1, secret_exponent)

        if not public_pair:
            public_pair = parse_as_public_pair(item)

        if public_pair:
            bitcoin_address_uncompressed = encoding.public_pair_to_bitcoin_address(public_pair, compressed=False)
            bitcoin_address_compressed = encoding.public_pair_to_bitcoin_address(public_pair, compressed=True)

            add_output("public_pair_x", '%d' % public_pair[0])
            add_output("public_pair_y", '%d' % public_pair[1])
            add_output("public_pair_x_hex", '%x' % public_pair[0], " x as hex")
            add_output("public_pair_y_hex", '%x' % public_pair[1], " y as hex")
            add_output("y_parity", "odd" if (public_pair[1] & 1) else "even")

            add_output("key_pair_as_sec", b2h(encoding.public_pair_to_sec(public_pair, compressed=True)))
            add_output("key_pair_as_sec_uncompressed", b2h(encoding.public_pair_to_sec(public_pair, compressed=False)), " uncompressed")

            hash160 = encoding.public_pair_to_hash160_sec(public_pair, compressed=True)
            hash160_unc = encoding.public_pair_to_hash160_sec(public_pair, compressed=False)

        if not hash160:
            hash160 = parse_as_hash160(item)

        if not hash160:
            sys.stderr.write("can't decode input %s\n" % item)
            sys.exit(1)

        add_output("hash160", b2h(hash160))
        if hash160_unc:
            add_output("hash160_uncompressed", b2h(hash160_unc), " uncompressed")

        add_output("Bitcoin_address", encoding.hash160_sec_to_bitcoin_address(hash160, is_test=args.test_network))
        if hash160_unc:
            add_output("Bitcoin_address_uncompressed", encoding.hash160_sec_to_bitcoin_address(hash160_unc, is_test=args.test_network), " uncompressed")

        if args.wallet or args.wif or args.address:
            if args.wallet:
                key = "wallet_key"
            else:
                key = "wif" if args.wif else "bitcoin_address"
            key_unc = "%s_uncompressed" % key
            if args.uncompressed and key_unc in output_dict:
                key = key_unc
            if key in output_dict:
                print(output_dict[key])
            else:
                parser.error("can't generate %s" % key)
        if args.json:
            add_output("input", item)
            json_output.append(output_dict)
        else:
            dump_output(output_dict, output_order)

    if args.json:
        print(json.dumps(json_output, indent=3))

def dump_output(output_dict, output_order):
    print('')
    max_length = max(len(v[1]) for v in output_order)
    for key, hr_key in output_order:
        space_padding = ' ' * (1 + max_length - len(hr_key))
        val = output_dict.get(key)
        if val is None:
            print(hr_key)
        else:
            if len(val) > 80:
                val = "%s\\\n%s%s" % (val[:66], ' ' * (5 + max_length), val[66:])
            print("%s%s: %s" % (hr_key, space_padding, val))

if __name__ == '__main__':
    main()

