#!/usr/bin/env python

from __future__ import print_function

import argparse
import calendar
import codecs
import datetime
import io
import os.path
import re
import subprocess
import sys

from pycoin import encoding
from pycoin.convention import tx_fee, satoshi_to_mbtc
from pycoin.key import Key
from pycoin.networks import address_prefix_for_netcode
from pycoin.serialize import b2h_rev, h2b_rev, stream_to_bytes
from pycoin.services import spendables_for_address, get_tx_db
from pycoin.services.providers import message_about_tx_cache_env, \
    message_about_get_tx_env, message_about_spendables_for_address_env
from pycoin.tx import Spendable, Tx, TxOut
from pycoin.tx.Tx import BadSpendableError
from pycoin.tx.tx_utils import distribute_from_split_pool, sign_tx
from pycoin.tx.TxOut import standard_tx_out_script


DEFAULT_VERSION = 1
DEFAULT_LOCK_TIME = 0
LOCKTIME_THRESHOLD = 500000000


def validate_bitcoind(tx, tx_db, bitcoind_url):
    try:
        from pycoin.services.bitcoind import bitcoind_agrees_on_transaction_validity
        if bitcoind_agrees_on_transaction_validity(bitcoind_url, tx):
            print("interop test passed for %s" % tx.id(), file=sys.stderr)
        else:
            print("tx ==> %s FAILED interop test" % tx.id(), file=sys.stderr)
    except ImportError:
        print("warning: can't talk to bitcoind due to missing library")


def dump_tx(tx, netcode='BTC'):
    address_prefix = address_prefix_for_netcode(netcode)
    tx_bin = stream_to_bytes(tx.stream)
    print("Version: %2d  tx hash %s  %d bytes   " % (tx.version, tx.id(), len(tx_bin)))
    print("TxIn count: %d; TxOut count: %d" % (len(tx.txs_in), len(tx.txs_out)))
    if tx.lock_time == 0:
        meaning = "valid anytime"
    elif tx.lock_time < LOCKTIME_THRESHOLD:
        meaning = "valid after block index %d" % tx.lock_time
    else:
        when = datetime.datetime.utcfromtimestamp(tx.lock_time)
        meaning = "valid on or after %s utc" % when.isoformat()
    print("Lock time: %d (%s)" % (tx.lock_time, meaning))
    print("Input%s:" % ('s' if len(tx.txs_in) != 1 else ''))
    missing_unspents = tx.missing_unspents()
    for idx, tx_in in enumerate(tx.txs_in):
        if tx.is_coinbase():
            print("%3d: COINBASE  %12.5f mBTC" % (idx, satoshi_to_mbtc(tx.total_in())))
        else:
            suffix = ""
            if tx.missing_unspent(idx):
                address = tx_in.bitcoin_address(address_prefix=address_prefix)
            else:
                tx_out = tx.unspents[idx]
                sig_result = " sig ok" if tx.is_signature_ok(idx) else " BAD SIG"
                suffix = " %12.5f mBTC %s" % (satoshi_to_mbtc(tx_out.coin_value), sig_result)
                address = tx_out.bitcoin_address(netcode=netcode)
            print("%3d: %34s from %s:%d%s" % (idx, address, b2h_rev(tx_in.previous_hash),
                  tx_in.previous_index, suffix))
    print("Output%s:" % ('s' if len(tx.txs_out) != 1 else ''))
    for idx, tx_out in enumerate(tx.txs_out):
        amount_mbtc = satoshi_to_mbtc(tx_out.coin_value)
        address = tx_out.bitcoin_address(netcode=netcode) or "(unknown)"
        print("%3d: %34s receives %12.5f mBTC" % (idx, address, amount_mbtc))
    if not missing_unspents:
        print("Total input  %12.5f mBTC" % satoshi_to_mbtc(tx.total_in()))
    print(    "Total output %12.5f mBTC" % satoshi_to_mbtc(tx.total_out()))
    if not missing_unspents:
        print("Total fees   %12.5f mBTC" % satoshi_to_mbtc(tx.fee()))


def check_fees(tx):
    total_in, total_out = tx.total_in(), tx.total_out()
    actual_tx_fee = total_in - total_out
    recommended_tx_fee = tx_fee.recommended_fee_for_tx(tx)
    print("warning: transaction fees recommendations casually calculated and estimates may be incorrect",
          file=sys.stderr)
    if actual_tx_fee > recommended_tx_fee:
        print("warning: transaction fee of %s exceeds expected value of %s mBTC" %
              (satoshi_to_mbtc(actual_tx_fee), satoshi_to_mbtc(recommended_tx_fee)),
              file=sys.stderr)
    elif actual_tx_fee < 0:
        print("not enough source coins (%s mBTC) for destination (%s mBTC)."
              " Short %s mBTC" %
              (satoshi_to_mbtc(total_in),
               satoshi_to_mbtc(total_out), satoshi_to_mbtc(-actual_tx_fee)),
              file=sys.stderr)
    elif actual_tx_fee < recommended_tx_fee:
        print("warning: transaction fee lower than (casually calculated)"
              " expected value of %s mBTC, transaction might not propogate" %
              satoshi_to_mbtc(recommended_tx_fee), file=sys.stderr)
    return actual_tx_fee


EARLIEST_DATE = datetime.datetime(year=2009, month=1, day=1)


def parse_locktime(s):
    s = re.sub(r"[ ,:\-]+", r"-", s)
    for fmt1 in ["%Y-%m-%dT", "%Y-%m-%d", "%b-%d-%Y", "%b-%d-%y", "%B-%d-%Y", "%B-%d-%y"]:
        for fmt2 in ["T%H-%M-%S", "T%H-%M", "-%H-%M-%S", "-%H-%M", ""]:
            fmt = fmt1 + fmt2
            try:
                when = datetime.datetime.strptime(s, fmt)
                if when < EARLIEST_DATE:
                    raise ValueError("invalid date: must be after %s" % EARLIEST_DATE)
                return calendar.timegm(when.timetuple())
            except ValueError:
                pass
    return int(s)


def parse_fee(fee):
    if fee in ["standard"]:
        return fee
    return int(fee)


EPILOG = 'Files are binary by default unless they end with the suffix ".hex".'


def main():
    parser = argparse.ArgumentParser(
        description="Manipulate bitcoin (or alt coin) transactions.",
        epilog=EPILOG)

    parser.add_argument('-t', "--transaction-version", type=int,
                        help='Transaction version, either 1 (default) or 3 (not yet supported).')

    parser.add_argument('-l', "--lock-time", type=parse_locktime, help='Lock time; either a block'
                        'index, or a date/time (example: "2014-01-01T15:00:00"')

    parser.add_argument('-n', "--network", default="BTC",
                        help='Define network code (M=Bitcoin mainnet, T=Bitcoin testnet).')

    parser.add_argument('-a', "--augment", action='store_true',
                        help='augment tx by adding any missing spendable metadata by fetching'
                             ' inputs from cache and/or web services')

    parser.add_argument("-i", "--fetch-spendables", metavar="address", action="append",
                        help='Add all unspent spendables for the given bitcoin address. This information'
                        ' is fetched from web services.')

    parser.add_argument('-f', "--private-key-file", metavar="path-to-private-keys", action="append",
                        help='file containing WIF or BIP0032 private keys. If file name ends with .gpg, '
                        '"gpg -d" will be invoked automatically. File is read one line at a time, and if '
                        'the file contains only one WIF per line, it will also be scanned for a bitcoin '
                        'address, and any addresses found will be assumed to be public keys for the given'
                        ' private key.',
                        type=argparse.FileType('r'))

    parser.add_argument('-g', "--gpg-argument", help='argument to pass to gpg (besides -d).', default='')

    parser.add_argument("--remove-tx-in", metavar="tx_in_index_to_delete", action="append", type=int,
                        help='remove a tx_in')

    parser.add_argument("--remove-tx-out", metavar="tx_out_index_to_delete", action="append", type=int,
                        help='remove a tx_out')

    parser.add_argument('-F', "--fee", help='fee, in satoshis, to pay on transaction, or '
                        '"standard" to auto-calculate. This is only useful if the "split pool" '
                        'is used; otherwise, the fee is automatically set to the unclaimed funds.',
                        default="standard", metavar="transaction-fee", type=parse_fee)

    parser.add_argument('-C', "--cache", help='force the resultant transaction into the transaction cache.'
                        ' Mostly for testing.', action='store_true'),

    parser.add_argument('-u', "--show-unspents", action='store_true',
                        help='show TxOut items for this transaction in Spendable form.')

    parser.add_argument('-b', "--bitcoind-url",
                        help='URL to bitcoind instance to validate against (http://user:pass@host:port).')

    parser.add_argument('-o', "--output-file", metavar="path-to-output-file", type=argparse.FileType('wb'),
                        help='file to write transaction to. This supresses most other output.')

    parser.add_argument("argument", nargs="+", help='generic argument: can be a hex transaction id '
                        '(exactly 64 characters) to be fetched from cache or a web service;'
                        ' a transaction as a hex string; a path name to a transaction to be loaded;'
                        ' a spendable 4-tuple of the form tx_id/tx_out_idx/script_hex/satoshi_count '
                        'to be added to TxIn list; an address/satoshi_count to be added to the TxOut '
                        'list; an address to be added to the TxOut list and placed in the "split'
                        ' pool".')

    args = parser.parse_args()

    # defaults

    txs = []
    spendables = []
    payables = []

    key_iters = []

    TX_ID_RE = re.compile(r"^[0-9a-fA-F]{64}$")

    # there are a few warnings we might optionally print out, but only if
    # they are relevant. We don't want to print them out multiple times, so we
    # collect them here and print them at the end if they ever kick in.

    warning_tx_cache = None
    warning_get_tx = None
    warning_spendables = None

    if args.private_key_file:
        wif_re = re.compile(r"[1-9a-km-zA-LMNP-Z]{51,111}")
        # address_re = re.compile(r"[1-9a-kmnp-zA-KMNP-Z]{27-31}")
        for f in args.private_key_file:
            if f.name.endswith(".gpg"):
                gpg_args = ["gpg", "-d"]
                if args.gpg_argument:
                    gpg_args.extend(args.gpg_argument.split())
                gpg_args.append(f.name)
                popen = subprocess.Popen(gpg_args, stdout=subprocess.PIPE)
                f = popen.stdout
            for line in f.readlines():
                # decode
                if isinstance(line, bytes):
                    line = line.decode("utf8")
                # look for WIFs
                possible_keys = wif_re.findall(line)

                def make_key(x):
                    try:
                        return Key.from_text(x)
                    except Exception:
                        return None

                keys = [make_key(x) for x in possible_keys]
                for key in keys:
                    if key:
                        key_iters.append((k.wif() for k in key.subkeys("")))

                # if len(keys) == 1 and key.hierarchical_wallet() is None:
                #    # we have exactly 1 WIF. Let's look for an address
                #   potential_addresses = address_re.findall(line)

    # we create the tx_db lazily
    tx_db = None

    for arg in args.argument:

        # hex transaction id
        if TX_ID_RE.match(arg):
            if tx_db is None:
                warning_tx_cache = message_about_tx_cache_env()
                warning_get_tx = message_about_get_tx_env()
                tx_db = get_tx_db()
            tx = tx_db.get(h2b_rev(arg))
            if not tx:
                for m in [warning_tx_cache, warning_get_tx, warning_spendables]:
                    if m:
                        print("warning: %s" % m, file=sys.stderr)
                parser.error("can't find Tx with id %s" % arg)
            txs.append(tx)
            continue

        # hex transaction data
        try:
            tx = Tx.tx_from_hex(arg)
            txs.append(tx)
            continue
        except Exception:
            pass

        try:
            key = Key.from_text(arg)
            # TODO: check network
            if key.wif() is None:
                payables.append((key.address(), 0))
                continue
            # TODO: support paths to subkeys
            key_iters.append((k.wif() for k in key.subkeys("")))
            continue
        except Exception:
            pass

        if os.path.exists(arg):
            try:
                with open(arg, "rb") as f:
                    if f.name.endswith("hex"):
                        f = io.BytesIO(codecs.getreader("hex_codec")(f).read())
                    tx = Tx.parse(f)
                    txs.append(tx)
                    try:
                        tx.parse_unspents(f)
                    except Exception as ex:
                        pass
                    continue
            except Exception:
                pass

        parts = arg.split("/")
        if len(parts) == 4:
            # spendable
            try:
                spendables.append(Spendable.from_text(arg))
                continue
            except Exception:
                pass

        # TODO: fix allowable_prefixes
        allowable_prefixes = b'\0'
        if len(parts) == 2 and encoding.is_valid_bitcoin_address(
                parts[0], allowable_prefixes=allowable_prefixes):
            try:
                payables.append(parts)
                continue
            except ValueError:
                pass

        parser.error("can't parse %s" % arg)

    if args.fetch_spendables:
        warning_spendables = message_about_spendables_for_address_env()
        for address in args.fetch_spendables:
            spendables.extend(spendables_for_address(address))

    for tx in txs:
        if tx.missing_unspents() and args.augment:
            if tx_db is None:
                warning_tx_cache = message_about_tx_cache_env()
                warning_get_tx = message_about_get_tx_env()
                tx_db = get_tx_db()
            tx.unspents_from_db(tx_db, ignore_missing=True)

    txs_in = []
    txs_out = []
    unspents = []
    # we use a clever trick here to keep each tx_in corresponding with its tx_out
    for tx in txs:
        smaller = min(len(tx.txs_in), len(tx.txs_out))
        txs_in.extend(tx.txs_in[:smaller])
        txs_out.extend(tx.txs_out[:smaller])
        unspents.extend(tx.unspents[:smaller])
    for tx in txs:
        smaller = min(len(tx.txs_in), len(tx.txs_out))
        txs_in.extend(tx.txs_in[smaller:])
        txs_out.extend(tx.txs_out[smaller:])
        unspents.extend(tx.unspents[smaller:])
    for spendable in spendables:
        txs_in.append(spendable.tx_in())
        unspents.append(spendable)
    for address, coin_value in payables:
        script = standard_tx_out_script(address)
        txs_out.append(TxOut(coin_value, script))

    lock_time = args.lock_time
    version = args.transaction_version

    # if no lock_time is explicitly set, inherit from the first tx or use default
    if lock_time is None:
        if txs:
            lock_time = txs[0].lock_time
        else:
            lock_time = DEFAULT_LOCK_TIME

    # if no version is explicitly set, inherit from the first tx or use default
    if version is None:
        if txs:
            version = txs[0].version
        else:
            version = DEFAULT_VERSION

    if args.remove_tx_in:
        s = set(args.remove_tx_in)
        txs_in = [tx_in for idx, tx_in in enumerate(txs_in) if idx not in s]

    if args.remove_tx_out:
        s = set(args.remove_tx_out)
        txs_out = [tx_out for idx, tx_out in enumerate(txs_out) if idx not in s]

    tx = Tx(txs_in=txs_in, txs_out=txs_out, lock_time=lock_time, version=version, unspents=unspents)

    fee = args.fee
    try:
        distribute_from_split_pool(tx, fee)
    except ValueError as ex:
        print("warning: %s" % ex.args[0], file=sys.stderr)

    unsigned_before = tx.bad_signature_count()
    if unsigned_before > 0 and key_iters:
        def wif_iter(iters):
            while len(iters) > 0:
                for idx, iter in enumerate(iters):
                    try:
                        wif = next(iter)
                        yield wif
                    except StopIteration:
                        iters = iters[:idx] + iters[idx+1:]
                        break

        print("signing...", file=sys.stderr)
        sign_tx(tx, wif_iter(key_iters))

    unsigned_after = tx.bad_signature_count()
    if unsigned_after > 0 and key_iters:
        print("warning: %d TxIn items still unsigned" % unsigned_after, file=sys.stderr)

    if len(tx.txs_in) == 0:
        print("warning: transaction has no inputs", file=sys.stderr)

    if len(tx.txs_out) == 0:
        print("warning: transaction has no outputs", file=sys.stderr)

    include_unspents = (unsigned_after > 0)
    tx_as_hex = tx.as_hex(include_unspents=include_unspents)

    if args.output_file:
        f = args.output_file
        if f.name.endswith(".hex"):
            f.write(tx_as_hex.encode("utf8"))
        else:
            tx.stream(f)
            if include_unspents:
                tx.stream_unspents(f)
        f.close()
    elif args.show_unspents:
        for spendable in tx.tx_outs_as_spendable():
            print(spendable.as_text())
    else:
        if not tx.missing_unspents():
            check_fees(tx)
        dump_tx(tx, args.network)
        if include_unspents:
            print("including unspents in hex dump since transaction not fully signed")
        print(tx_as_hex)

    if args.cache:
        if tx_db is None:
            warning_tx_cache = message_about_tx_cache_env()
            warning_get_tx = message_about_get_tx_env()
            tx_db = get_tx_db()
        tx_db.put(tx)

    if args.bitcoind_url:
        if tx_db is None:
            warning_tx_cache = message_about_tx_cache_env()
            warning_get_tx = message_about_get_tx_env()
            tx_db = get_tx_db()
        validate_bitcoind(tx, tx_db, args.bitcoind_url)

    if tx.missing_unspents():
        print("\n** can't validate transaction as source transactions missing", file=sys.stderr)
    else:
        try:
            if tx_db is None:
                warning_tx_cache = message_about_tx_cache_env()
                warning_get_tx = message_about_get_tx_env()
                tx_db = get_tx_db()
            tx.validate_unspents(tx_db)
            print('all incoming transaction values validated')
        except BadSpendableError as ex:
            print("\n**** ERROR: FEES INCORRECTLY STATED: %s" % ex.args[0], file=sys.stderr)
        except Exception as ex:
            print("\n*** can't validate source transactions as untampered: %s" %
                  ex.args[0], file=sys.stderr)

    # print warnings
    for m in [warning_tx_cache, warning_get_tx, warning_spendables]:
        if m:
            print("warning: %s" % m, file=sys.stderr)

if __name__ == '__main__':
    main()
