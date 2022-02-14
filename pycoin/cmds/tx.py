#!/usr/bin/env python

from __future__ import print_function

import argparse
import calendar
import codecs
import datetime
import io
import os.path
import re
import sqlite3
import subprocess
import sys

from .dump import dump_tx

from pycoin.coins.exceptions import BadSpendableError
from pycoin.convention import tx_fee, satoshi_to_mbtc
from pycoin.encoding.hexbytes import b2h, h2b, h2b_rev
from pycoin.key.subpaths import subpaths_for_path_range
from pycoin.networks.registry import network_codes, network_for_netcode
from pycoin.networks.default import get_current_netcode
from pycoin.services import spendables_for_address, get_tx_db
from pycoin.services.providers import message_about_tx_cache_env, \
    message_about_tx_for_tx_hash_env, message_about_spendables_for_address_env


DEFAULT_VERSION = 1
DEFAULT_LOCK_TIME = 0


def range_int(min, max, name):

    def cast(v):
        v = int(v)
        if not (min <= v <= max):
            raise ValueError()
        return v

    cast.__name__ = name
    return cast


def validate_bitcoind(tx, tx_db, bitcoind_url):
    try:
        from pycoin.services.bitcoind import bitcoind_agrees_on_transaction_validity
        if bitcoind_agrees_on_transaction_validity(bitcoind_url, tx):
            print("interop test passed for %s" % tx.id(), file=sys.stderr)
        else:
            print("tx ==> %s FAILED interop test" % tx.id(), file=sys.stderr)
    except ImportError:
        print("warning: can't talk to bitcoind due to missing library")


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


parse_locktime.__name__ = 'locktime'


def parse_fee(fee):
    if fee in ["standard"]:
        return fee
    return int(fee)


def parse_script_index_hex(input):
    index_s, opcodes = input.split("/", 1)
    index = int(index_s)
    return (index, h2b(opcodes))


def create_parser():
    codes = network_codes()
    EPILOG = ('Files are binary by default unless they end with the suffix ".hex". ' +
              'Known networks codes:\n  ' +
              ', '.join(['%s (%s)' % (i, network_for_netcode(i).full_name()) for i in codes]))

    parser = argparse.ArgumentParser(
        description="Manipulate bitcoin (or alt coin) transactions.",
        epilog=EPILOG)

    parser.add_argument('-t', "--transaction-version", type=range_int(0, 255, "version"),
                        help='Transaction version, either 1 (default) or 3 (not yet supported).')

    parser.add_argument('-l', "--lock-time", type=parse_locktime, help='Lock time; either a block'
                        'index, or a date/time (example: "2014-01-01T15:00:00"')

    parser.add_argument('-n', "--network", default=get_current_netcode(), choices=codes,
                        help=('Default network code (environment variable PYCOIN_DEFAULT_NETCODE '
                              'or "BTC"=Bitcoin mainnet if unset'))

    parser.add_argument('-a', "--augment", action='store_true',
                        help='augment tx by adding any missing spendable metadata by fetching'
                             ' inputs from cache and/or web services')

    parser.add_argument('-s', "--verbose-signature", action='store_true',
                        help='Display technical signature details.')

    parser.add_argument("-i", "--fetch-spendables", metavar="address", action="append",
                        help='Add all unspent spendables for the given bitcoin address. This information'
                        ' is fetched from web services. With no outputs, incoming spendables will be printed.')

    parser.add_argument("-I", "--dump-inputs", action='store_true', help='Dump inputs to this transaction.')

    parser.add_argument(
        "-k", "--keychain", default=":memory:",
        help="path to keychain file for hierarchical key hints (SQLite3 file created with keychain tool)")

    parser.add_argument(
        "-K", "--key-paths", default="",
        help="Key path hints to search hiearachical private keys (example: 0/0H/0-20)")

    parser.add_argument('-f', "--private-key-file", metavar="path-to-private-keys", action="append", default=[],
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

    parser.add_argument("--replace-input-script", metavar="tx_in_script_slash_hex", action="append", default=[],
                        type=parse_script_index_hex, help='replace an input script: arg looks like "1/796a"')

    parser.add_argument('-F', "--fee", help='fee, in satoshis, to pay on transaction, or '
                        '"standard" to auto-calculate. This is only useful if the "split pool" '
                        'is used; otherwise, the fee is automatically set to the unclaimed funds.',
                        default="standard", metavar="transaction-fee", type=parse_fee)

    parser.add_argument('-C', "--cache", help='force the resultant transaction into the transaction cache.'
                        ' Mostly for testing.', action='store_true'),

    parser.add_argument("--db", help='force the transaction expressed by the given hex '
                        'into a RAM-based transaction cache. Mostly for testing.', action="append"),

    parser.add_argument('-u', "--show-unspents", action='store_true',
                        help='show TxOut items for this transaction in Spendable form.')

    parser.add_argument('-b', "--bitcoind-url",
                        help='URL to bitcoind instance to validate against (http://user:pass@host:port).')

    parser.add_argument('-o', "--output-file", metavar="path-to-output-file", type=argparse.FileType('wb'),
                        help='file to write transaction to. This supresses most other output.')

    parser.add_argument('-d', "--disassemble", action='store_true',
                        help='Disassemble scripts.')

    parser.add_argument("--pdb", action="store_true", help='Enter PDB debugger on each script instruction.')

    parser.add_argument("--trace", action='store_true', help='Trace scripts.')

    parser.add_argument('-p', "--pay-to-script", metavar="pay-to-script", action="append",
                        help='a hex version of a script required for a pay-to-script'
                        'input (a bitcoin address that starts with 3)')

    parser.add_argument("--signature", metavar="known-good-signature", action="append",
                        help='a hex version of a signature that will be used if useful')

    parser.add_argument("--sec", metavar="known-sec", action="append",
                        help='a hex version of an SEC that will be used if useful')

    parser.add_argument('-P', "--pay-to-script-file", metavar="pay-to-script-file", nargs=1,
                        type=argparse.FileType('r'), help='a file containing hex scripts '
                        '(one per line) corresponding to pay-to-script inputs')

    parser.add_argument("--dump-signatures", action="store_true",
                        help="print signatures (for use with --signature)")

    parser.add_argument("--dump-secs", action="store_true",
                        help="print secs (for use with --sec)")

    parser.add_argument("--coinbase", type=str, help="add an input as a coinbase from the given address")

    parser.add_argument("argument", nargs="*", help='generic argument: can be a hex transaction id '
                        '(exactly 64 characters) to be fetched from cache or a web service;'
                        ' a transaction as a hex string; a path name to a transaction to be loaded;'
                        ' a spendable 4-tuple of the form tx_id/tx_out_idx/script_hex/satoshi_count '
                        'to be added to TxIn list; an address/satoshi_count to be added to the TxOut '
                        'list; an address or script to be added to the TxOut list and placed in the '
                        '"split pool".')

    return parser


def replace_with_gpg_pipe(args, f):
    gpg_args = ["gpg", "-d"]
    if args.gpg_argument:
        gpg_args.extend(args.gpg_argument.split())
    gpg_args.append(f.name)
    popen = subprocess.Popen(gpg_args, stdout=subprocess.PIPE)
    return popen.stdout


def parse_private_key_file(args, keychain, network):
    wif_re = re.compile(r"[1-9a-km-zA-LMNP-Z]{51,111}")
    # address_re = re.compile(r"[1-9a-kmnp-zA-KMNP-Z]{27-31}")
    for f in args.private_key_file:
        if f.name.endswith(".gpg"):
            f = replace_with_gpg_pipe(args, f)
        for line in f.readlines():
            # decode
            if isinstance(line, bytes):
                line = line.decode("utf8")
            # look for WIFs
            possible_keys = wif_re.findall(line)

            def make_key(x):
                try:
                    return network.parse.secret(x)
                except Exception:
                    return None

            keys = [make_key(x) for x in possible_keys]
            for key in keys:
                if key:
                    keychain.add_secrets([key])
                    keychain.add_key_paths(key, subpaths_for_path_range(args.key_paths))


TX_ID_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def parse_tx(tx_class, arg, parser, tx_db, network):
    # hex transaction id
    tx = None

    if TX_ID_RE.match(arg):
        if tx_db is None:
            tx_db = create_tx_db(network)
        tx = tx_db.get(h2b_rev(arg))
        if not tx:
            parser.error("can't find Tx with id %s" % arg)
        return tx, tx_db

    # hex transaction data
    try:
        return tx_class.from_hex(arg), tx_db
    except Exception:
        pass

    if os.path.exists(arg):
        try:
            with open(arg, "rb") as f:
                if f.name.endswith("hex"):
                    f = io.BytesIO(codecs.getreader("hex_codec")(f).read())
                tx = tx_class.parse(f)
                tx.parse_unspents(f)
        except Exception:
            pass

    return tx, tx_db


def parse_scripts(args, keychain):
    warnings = []

    for p2s in args.pay_to_script or []:
        try:
            keychain.add_p2s_script(h2b(p2s))
        except Exception:
            warnings.append("warning: error parsing pay-to-script value %s" % p2s)

    hex_re = re.compile(r"[0-9a-fA-F]+")
    for f in args.pay_to_script_file or []:
        count = 0
        for l in f:
            try:
                m = hex_re.search(l)
                if m:
                    p2s = m.group(0)
                    keychain.add_p2s_script(h2b(p2s))
                    count += 1
            except Exception:
                warnings.append("warning: error parsing pay-to-script file %s" % f.name)
        if count == 0:
            warnings.append("warning: no scripts found in %s" % f.name)
    keychain.commit()
    return warnings


def create_tx_db(network):
    tx_db = get_tx_db(network.symbol)
    tx_db.warning_tx_cache = message_about_tx_cache_env()
    tx_db.warning_tx_for_tx_hash = message_about_tx_for_tx_hash_env(network.symbol)
    return tx_db


def parse_parts(tx_class, arg, spendables, payables, network):
    parts = arg.split("/")
    if 4 <= len(parts) <= 7:
        # spendable
        try:
            spendables.append(tx_class.Spendable.from_text(arg))
            return True
        except Exception:
            pass

    if len(parts) == 2:
        script = script_for_address_or_opcodes(network, parts[0])
        if script is not None:
            payables.append((script, parts[1]))
            return True


def key_found(arg, keychain, key_paths, network):
    try:
        secret = network.parse.secret(arg)
        if secret:
            # TODO: check network
            keychain.add_secrets([secret])
            keychain.add_key_paths(secret, subpaths_for_path_range(key_paths))
            return True
    except Exception:
        pass

    return False


def script_for_address_or_opcodes(network, text):
    try:
        script = network.contract.for_address(text)
        if script:
            return script
    except Exception:
        pass
    try:
        return network.script.compile(text)
    except Exception:
        pass


def build_coinbase_tx(network, address_or_opcodes):
    puzzle_script = script_for_address_or_opcodes(network, address_or_opcodes)
    txs_in = [network.tx.TxIn.coinbase_tx_in(b'fake-pycoin-coinbase')]
    txs_out = [network.tx.TxOut(int(50*1e8), puzzle_script)]
    tx = network.tx(1, txs_in, txs_out)
    return tx


def parse_context(args, parser):
    network = network_for_netcode(args.network)
    tx_class = network.tx

    # defaults

    spendables = []
    payables = []

    # we create the tx_db lazily
    tx_db = None

    if args.db:

        try:
            txs = [tx_class.from_hex(tx_hex) for tx_hex in args.db or []]
        except Exception:
            parser.error("can't parse ")

        the_ram_tx_db = dict((tx.hash(), tx) for tx in txs)
        if tx_db is None:
            tx_db = create_tx_db(network)
        tx_db.lookup_methods.append(the_ram_tx_db.get)

    txs = []

    if args.coinbase:
        coinbase_tx = build_coinbase_tx(network, args.coinbase)
        txs.append(coinbase_tx)

    keychain = network.keychain(sqlite3.connect(args.keychain))

    # there are a few warnings we might optionally print out, but only if
    # they are relevant. We don't want to print them out multiple times, so we
    # collect them here and print them at the end if they ever kick in.

    warning_spendables = None

    for arg in args.argument:
        tx, tx_db = parse_tx(tx_class, arg, parser, tx_db, network)
        if tx:
            txs.append(tx)
            continue

        if key_found(arg, keychain, args.key_paths, network):
            continue

        if parse_parts(tx_class, arg, spendables, payables, network):
            continue

        payable = script_for_address_or_opcodes(network, arg)
        if payable is not None:
            payables.append((payable, 0))
            continue

        parser.error("can't parse %s" % arg)

    parse_private_key_file(args, keychain, network)

    if args.fetch_spendables:
        warning_spendables = message_about_spendables_for_address_env(args.network)
        for address in args.fetch_spendables:
            spendables.extend(spendables_for_address(address, args.network))

    return (network, txs, spendables, payables, keychain, tx_db, warning_spendables)


def merge_txs(network, txs, spendables, payables):

    tx_class = network.tx
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
    for script, coin_value in payables:
        txs_out.append(tx_class.TxOut(coin_value, script))

    return txs_in, txs_out, unspents


def calculate_lock_time_and_version(args, txs):

    # if no lock_time is explicitly set, inherit from the first tx or use default
    lock_time = args.lock_time
    if lock_time is None:
        if txs:
            lock_time = txs[0].lock_time
        else:
            lock_time = DEFAULT_LOCK_TIME

    # if no version is explicitly set, inherit from the first tx or use default
    version = args.transaction_version
    if version is None:
        if txs:
            version = txs[0].version
        else:
            version = DEFAULT_VERSION
    return lock_time, version


def remove_indices(items, indices):
    if indices:
        s = set(indices)
        items = [i for idx, i in enumerate(items) if idx not in s]
    return items


def replace_input_scripts(txs_in, replacements):
    for index, blob in replacements:
        txs_in[index].script = blob


def wif_iter(iters):
    while len(iters) > 0:
        for idx, iter in enumerate(iters):
            try:
                wif = next(iter)
                yield wif
            except StopIteration:
                iters = iters[:idx] + iters[idx+1:]
                break


def generate_tx(network, txs, spendables, payables, args):
    txs_in, txs_out, unspents = merge_txs(network, txs, spendables, payables)
    lock_time, version = calculate_lock_time_and_version(args, txs)
    if len(unspents) == len(txs_in):
        unspents = remove_indices(unspents, args.remove_tx_in)
    replace_input_scripts(txs_in, args.replace_input_script)
    txs_in = remove_indices(txs_in, args.remove_tx_in)
    txs_out = remove_indices(txs_out, args.remove_tx_out)
    tx = network.tx(txs_in=txs_in, txs_out=txs_out, lock_time=lock_time, version=version, unspents=unspents)
    fee = args.fee
    try:
        if len(payables) > 0:
            network.tx_utils.distribute_from_split_pool(tx, fee)
    except ValueError as ex:
        print("warning: %s" % ex.args[0], file=sys.stderr)
    return tx


def print_output(tx, include_unspents, output_file, show_unspents,
                 network, verbose_signature, disassembly_level, trace, pdb):
    if len(tx.txs_in) == 0:
        print("warning: transaction has no inputs", file=sys.stderr)

    if len(tx.txs_out) == 0:
        print("warning: transaction has no outputs", file=sys.stderr)

    tx_as_hex = tx.as_hex(include_unspents=include_unspents)

    if output_file:
        f = output_file
        if f.name.endswith(".hex"):
            f.write(tx_as_hex.encode("utf8"))
        else:
            tx.stream(f, include_unspents=include_unspents)
        f.close()
    elif show_unspents:
        for spendable in tx.tx_outs_as_spendable():
            print(spendable.as_text())
    elif len(tx.txs_out) == 0:
        for spendable in tx.unspents:
            print(spendable.as_text())
    else:
        if not tx.missing_unspents():
            check_fees(tx)
        output = []
        dump_tx(output, tx, network, verbose_signature, disassembly_level, trace, pdb)
        for line in output:
            print(line)
        if include_unspents:
            print("including unspents in hex dump since transaction not fully signed")
        print(tx_as_hex)


def do_signing(tx, keychain, p2sh_lookup, sec_hints, signature_hints, network):
    unsigned_before = tx.bad_solution_count()
    unsigned_after = unsigned_before
    if unsigned_before > 0 and (keychain.has_secrets() or sec_hints or signature_hints):
        print("signing...", file=sys.stderr)
        solver = tx.Solver(tx)
        solver.sign(keychain, p2sh_lookup=p2sh_lookup, sec_hints=sec_hints, signature_hints=signature_hints)

        unsigned_after = tx.bad_solution_count()
        if unsigned_after > 0:
            print("warning: %d TxIn items still unsigned" % unsigned_after, file=sys.stderr)
    return unsigned_after == 0


def cache_result(tx, tx_db, cache, network):
    if cache:
        if tx_db is None:
            tx_db = create_tx_db(network)
        tx_db.put(tx)
    return tx_db


def validate_tx(tx, tx_db, network):
    if not tx.txs_out:
        return
    if tx.missing_unspents():
        print("\n** can't validate transaction as source transactions missing", file=sys.stderr)
    else:
        try:
            if tx_db is None:
                tx_db = create_tx_db(network)
            tx.validate_unspents(tx_db)
            print('all incoming transaction values validated')
        except BadSpendableError as ex:
            print("\n**** ERROR: FEES INCORRECTLY STATED: %s" % ex.args[0], file=sys.stderr)
        except Exception as ex:
            print("\n*** can't validate source transactions as untampered: %s" %
                  ex.args[0], file=sys.stderr)


def validate_against_bitcoind(tx, tx_db, network, bitcoind_url):
    if bitcoind_url:
        if tx_db is None:
            tx_db = create_tx_db(network)
        validate_bitcoind(tx, tx_db, bitcoind_url)
    return tx_db


def dump_signatures_hex(tx, network):
    sigs = []
    for _, tx_in in enumerate(tx.txs_in):
        sigs.extend(network.who_signed.extract_signatures(tx, _))
    if len(sigs):
        print("SIGNATURES")
    for sig in sigs:
        print(b2h(sig[0]))


def dump_secs_hex(tx, network):
    sec_key_list = []
    for _, tx_in in enumerate(tx.txs_in):
        sec_key_list.extend(network.who_signed.extract_secs(tx, _))
    if len(sec_key_list):
        print("SECS")
    for sec in sec_key_list:
        print(b2h(sec))


def dump_inputs(tx, network):
    for _, tx_out in enumerate(tx.unspents):
        if tx_out:
            print("%d: %s %s" % (_, tx_out.coin_value, network.script.disassemble(tx_out.script)))
        else:
            print("%d: (missing spendable)" % _)


def tx(args, parser):
    (network, txs, spendables, payables, keychain, tx_db, warning_spendables) = parse_context(args, parser)

    for tx in txs:
        if tx.missing_unspents() and (args.augment or tx_db):
            if tx_db is None:
                tx_db = create_tx_db(network)
            tx.unspents_from_db(tx_db, ignore_missing=True)

    # build p2sh_lookup
    warnings = parse_scripts(args, keychain)
    for w in warnings:
        print(w)

    tx = generate_tx(network, txs, spendables, payables, args)

    signature_hints = [h2b(sig) for sig in (args.signature or [])]
    sec_hints = network.tx.solve.build_sec_lookup([h2b(sec) for sec in (args.sec or [])])

    is_fully_signed = do_signing(tx, keychain, keychain, sec_hints, signature_hints, network)

    include_unspents = not is_fully_signed

    if args.dump_signatures or args.dump_secs:
        if args.dump_signatures:
            dump_signatures_hex(tx, network)

        if args.dump_secs:
            dump_secs_hex(tx, network)

        return

    print_output(tx, include_unspents, args.output_file, args.show_unspents, network,
                 args.verbose_signature, args.disassemble, args.trace, args.pdb)

    tx_db = cache_result(tx, tx_db, args.cache, network)

    tx_db = validate_against_bitcoind(tx, tx_db, network, args.bitcoind_url)

    if args.dump_inputs:
        dump_inputs(tx, network)

    if not args.show_unspents:
        tx_db = validate_tx(tx, tx_db, network)

    # print warnings
    if tx_db:
        for m in [tx_db.warning_tx_cache, tx_db.warning_tx_for_tx_hash]:
            if m:
                print("warning: %s" % m, file=sys.stderr)
    if warning_spendables:
        print("warning: %s" % warning_spendables, file=sys.stderr)


def main():
    parser = create_parser()
    args = parser.parse_args()
    tx(args, parser)


if __name__ == '__main__':
    main()
