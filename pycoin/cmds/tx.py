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

from pycoin.convention import tx_fee, satoshi_to_mbtc
from pycoin.encoding import hash160
from pycoin.key import Key
from pycoin.key.validate import is_address_valid
from pycoin.networks import address_prefix_for_netcode, full_network_name_for_netcode, network_codes
from pycoin.networks.default import get_current_netcode
from pycoin.serialize import b2h_rev, h2b, h2b_rev, stream_to_bytes
from pycoin.services import spendables_for_address, get_tx_db
from pycoin.services.providers import message_about_tx_cache_env, \
    message_about_tx_for_tx_hash_env, message_about_spendables_for_address_env
from pycoin.tx.exceptions import BadSpendableError
from pycoin.tx.script.tools import opcode_list, disassemble_for_opcode_data
from pycoin.tx.script.check_signature import parse_signature_blob
from pycoin.tx.script.der import UnexpectedDER
from pycoin.tx.script.disassemble import disassemble_scripts, sighash_type_to_string
from pycoin.tx.tx_utils import distribute_from_split_pool, sign_tx
from pycoin.tx.Tx import Spendable, Tx, TxOut
from pycoin.ui import standard_tx_out_script

DEFAULT_VERSION = 1
DEFAULT_LOCK_TIME = 0
LOCKTIME_THRESHOLD = 500000000


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


def dump_header(tx):
    tx_bin = stream_to_bytes(tx.stream)
    print("Version: %2d  tx hash %s  %d bytes" % (tx.version, tx.id(), len(tx_bin)))
    if tx.has_witness_data():
        print("      segwit tx hash %s" % tx.w_id())
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


def make_trace_script(do_trace, use_pdb):
    if not (do_trace or use_pdb):
        return None

    def trace_script(pc, opcode, data, stack, altstack, if_condition_stack, is_signature):
        from pycoin.serialize import b2h
        print("stack: [%s]" % ' '.join(b2h(s) for s in stack))
        if len(altstack) > 0:
            print("altstack: %s" % altstack)
        print("condition stack: %s" % if_condition_stack)
        print("%3d : %02x  %s" % (pc, opcode, disassemble_for_opcode_data(opcode, data)))
        if use_pdb:
            import pdb
            pdb.set_trace()
    return trace_script


def dump_inputs(tx, netcode, verbose_signature, address_prefix, traceback_f, disassembly_level):

    def signature_for_hash_type_f(hash_type, script):
        return tx.signature_hash(script, idx, hash_type)

    for idx, tx_in in enumerate(tx.txs_in):
        if tx.is_coinbase():
            print("%4d: COINBASE  %12.5f mBTC" % (idx, satoshi_to_mbtc(tx.total_in())))
            continue
        suffix = ""
        if tx.missing_unspent(idx):
            tx_out = None
            address = tx_in.bitcoin_address(address_prefix=address_prefix)
        else:
            tx_out = tx.unspents[idx]
            sig_result = " sig ok" if tx.is_signature_ok(idx, traceback_f=traceback_f) else " BAD SIG"
            suffix = " %12.5f mBTC %s" % (satoshi_to_mbtc(tx_out.coin_value), sig_result)
            address = tx_out.bitcoin_address(netcode=netcode)
        t = "%4d: %34s from %s:%-4d%s" % (idx, address, b2h_rev(tx_in.previous_hash),
                                          tx_in.previous_index, suffix)
        print(t.rstrip())
        if disassembly_level > 0:
            dump_disassembly(tx_in, tx_out, tx.lock_time, signature_for_hash_type_f)

        if verbose_signature:
            dump_signatures(tx, tx_in, tx_out, idx, netcode, address_prefix, traceback_f, disassembly_level)


def dump_disassembly(tx_in, tx_out, lock_time, signature_for_hash_type_f):
    out_script = b''
    if tx_out:
        out_script = tx_out.script
    for (pre_annotations, pc, opcode, instruction, post_annotations) in \
            disassemble_scripts(
                tx_in.script, out_script, lock_time, signature_for_hash_type_f):
        for l in pre_annotations:
            print("           %s" % l)
        if 1:
            print("    %4x: %02x  %s" % (pc, opcode, instruction))
        for l in post_annotations:
            print("           %s" % l)


def dump_signatures(tx, tx_in, tx_out, idx, netcode, address_prefix, traceback_f, disassembly_level):
    signatures = []
    for opcode in opcode_list(tx_in.script):
        if not opcode.startswith("OP_"):
            try:
                signatures.append(parse_signature_blob(h2b(opcode[1:-1])))
            except UnexpectedDER:
                pass
    if signatures:
        sig_types_identical = (
            tuple(zip(*signatures))[1].count(signatures[0][1]) == len(signatures))
        i = 1 if len(signatures) > 1 else ''
        for sig_pair, sig_type in signatures:
            print("      r{0}: {1:#x}\n      s{0}: {2:#x}".format(i, *sig_pair))
            if not sig_types_identical and tx_out:
                print("      z{}: {:#x} {}".format(i, tx.signature_hash(tx_out.script, idx, sig_type),
                                                   sighash_type_to_string(sig_type)))
            if i:
                i += 1
        if sig_types_identical and tx_out:
            print("      z:{} {:#x} {}".format(' ' if i else '', tx.signature_hash(
                tx_out.script, idx, sig_type), sighash_type_to_string(sig_type)))


def dump_footer(tx, missing_unspents):
    if not missing_unspents:
        print("Total input  %12.5f mBTC" % satoshi_to_mbtc(tx.total_in()))
    if 1:
        print("Total output %12.5f mBTC" % satoshi_to_mbtc(tx.total_out()))
    if not missing_unspents:
        print("Total fees   %12.5f mBTC" % satoshi_to_mbtc(tx.fee()))


def dump_tx(tx, netcode, verbose_signature, disassembly_level, do_trace, use_pdb):
    address_prefix = address_prefix_for_netcode(netcode)
    missing_unspents = tx.missing_unspents()
    traceback_f = make_trace_script(do_trace, use_pdb)

    dump_header(tx)

    dump_inputs(tx, netcode, verbose_signature, address_prefix, traceback_f, disassembly_level)

    def signature_for_hash_type_f(hash_type, script):
        return tx.signature_hash(script, idx, hash_type)

    print("Output%s:" % ('s' if len(tx.txs_out) != 1 else ''))
    for idx, tx_out in enumerate(tx.txs_out):
        amount_mbtc = satoshi_to_mbtc(tx_out.coin_value)
        address = tx_out.bitcoin_address(netcode=netcode) or "(unknown)"
        print("%4d: %34s receives %12.5f mBTC" % (idx, address, amount_mbtc))
        if disassembly_level > 0:
            for (pre_annotations, pc, opcode, instruction, post_annotations) in \
                    disassemble_scripts(b'', tx_out.script, tx.lock_time, signature_for_hash_type_f):
                for l in pre_annotations:
                    print("           %s" % l)
                if 1:
                    print("    %4x: %02x  %s" % (pc, opcode, instruction))
                for l in post_annotations:
                    print("           %s" % l)

    dump_footer(tx, missing_unspents)


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


def create_parser():
    codes = network_codes()
    EPILOG = ('Files are binary by default unless they end with the suffix ".hex". ' +
            'Known networks codes:\n  ' +
            ', '.join(['%s (%s)' % (i, full_network_name_for_netcode(i)) for i in codes]))

    parser = argparse.ArgumentParser(
        description="Manipulate bitcoin (or alt coin) transactions.",
        epilog=EPILOG)

    parser.add_argument('-t', "--transaction-version", type=range_int(0, 255, "version"),
                        help='Transaction version, either 1 (default) or 3 (not yet supported).')

    parser.add_argument('-l', "--lock-time", type=parse_locktime, help='Lock time; either a block'
                        'index, or a date/time (example: "2014-01-01T15:00:00"')

    parser.add_argument('-n', "--network", default=get_current_netcode(), choices=codes,
                        help='Define network code (BTC=Bitcoin mainnet, XTN=Bitcoin testnet).')

    parser.add_argument('-a', "--augment", action='store_true',
                        help='augment tx by adding any missing spendable metadata by fetching'
                             ' inputs from cache and/or web services')

    parser.add_argument('-s', "--verbose-signature", action='store_true',
                        help='Display technical signature details.')

    parser.add_argument("-i", "--fetch-spendables", metavar="address", action="append",
                        help='Add all unspent spendables for the given bitcoin address. This information'
                        ' is fetched from web services. With no outputs, incoming spendables will be printed.')

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

    parser.add_argument('-F', "--fee", help='fee, in satoshis, to pay on transaction, or '
                        '"standard" to auto-calculate. This is only useful if the "split pool" '
                        'is used; otherwise, the fee is automatically set to the unclaimed funds.',
                        default="standard", metavar="transaction-fee", type=parse_fee)

    parser.add_argument('-C', "--cache", help='force the resultant transaction into the transaction cache.'
                        ' Mostly for testing.', action='store_true'),

    parser.add_argument("--db", type=Tx.from_hex, help='force the transaction expressed by the given hex '
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

    parser.add_argument('-P', "--pay-to-script-file", metavar="pay-to-script-file", nargs=1,
                        type=argparse.FileType('r'), help='a file containing hex scripts '
                        '(one per line) corresponding to pay-to-script inputs')

    parser.add_argument("argument", nargs="*", help='generic argument: can be a hex transaction id '
                        '(exactly 64 characters) to be fetched from cache or a web service;'
                        ' a transaction as a hex string; a path name to a transaction to be loaded;'
                        ' a spendable 4-tuple of the form tx_id/tx_out_idx/script_hex/satoshi_count '
                        'to be added to TxIn list; an address/satoshi_count to be added to the TxOut '
                        'list; an address to be added to the TxOut list and placed in the "split'
                        ' pool".')

    return parser


def replace_with_gpg_pipe(args, f):
    gpg_args = ["gpg", "-d"]
    if args.gpg_argument:
        gpg_args.extend(args.gpg_argument.split())
    gpg_args.append(f.name)
    popen = subprocess.Popen(gpg_args, stdout=subprocess.PIPE)
    return popen.stdout


def parse_private_key_file(args, key_list):
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
                    return Key.from_text(x)
                except Exception:
                    return None

            keys = [make_key(x) for x in possible_keys]
            for key in keys:
                if key:
                    key_list.append((k.wif() for k in key.subkeys("")))

            # if len(keys) == 1 and key.hierarchical_wallet() is None:
            #    # we have exactly 1 WIF. Let's look for an address
            #   potential_addresses = address_re.findall(line)


TX_ID_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def parse_tx(arg, parser, tx_db, network):
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
        return Tx.from_hex(arg), tx_db
    except Exception:
        pass

    if os.path.exists(arg):
        try:
            with open(arg, "rb") as f:
                if f.name.endswith("hex"):
                    f = io.BytesIO(codecs.getreader("hex_codec")(f).read())
                tx = Tx.parse(f)
                tx.parse_unspents(f)
        except Exception:
            pass

    return tx, tx_db


def parse_scripts(args):
    scripts = []
    warnings = []

    for p2s in args.pay_to_script or []:
        try:
            scripts.append(h2b(p2s))
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
                    scripts.append(h2b(p2s))
                    count += 1
            except Exception:
                warnings.append("warning: error parsing pay-to-script file %s" % f.name)
        if count == 0:
            warnings.append("warning: no scripts found in %s" % f.name)
    return scripts, warnings


def build_p2sh_lookup(args):
    scripts, warnings = parse_scripts(args)
    for w in warnings:
        print(w)

    p2sh_lookup = {}
    for script in scripts:
        p2sh_lookup[hash160(script)] = script
    return p2sh_lookup


def create_tx_db(network):
    tx_db = get_tx_db(network)
    tx_db.warning_tx_cache = message_about_tx_cache_env()
    tx_db.warning_tx_for_tx_hash = message_about_tx_for_tx_hash_env(network)
    return tx_db


def parse_parts(arg, spendables, payables, network):
    parts = arg.split("/")
    if 4 <= len(parts) <= 7:
        # spendable
        try:
            spendables.append(Spendable.from_text(arg))
            return True
        except Exception:
            pass

    if len(parts) == 2 and is_address_valid(parts[0], allowable_netcodes=[network]):
        try:
            payables.append(parts)
            return True
        except ValueError:
            pass


def key_found(arg, payables, key_iters):
    try:
        key = Key.from_text(arg)
        # TODO: check network
        if key.wif() is None:
            payables.append((key.address(), 0))
            return True
        key_iters.append(iter([key.wif()]))
        return True
    except Exception:
        pass

    return False


def parse_context(args, parser):
    # we create the tx_db lazily
    tx_db = None

    if args.db:
        the_ram_tx_db = dict((tx.hash(), tx) for tx in args.db)
        if tx_db is None:
            tx_db = create_tx_db(args.network)
        tx_db.lookup_methods.append(the_ram_tx_db.get)

    # defaults

    txs = []
    spendables = []
    payables = []

    key_iters = []

    # there are a few warnings we might optionally print out, but only if
    # they are relevant. We don't want to print them out multiple times, so we
    # collect them here and print them at the end if they ever kick in.

    warning_spendables = None

    for arg in args.argument:

        if is_address_valid(arg, allowable_netcodes=[args.network], allowable_types=[
                "address", "pay_to_script", "segwit"]):
            payables.append((arg, 0))
            continue

        if key_found(arg, payables, key_iters):
            continue

        tx, tx_db = parse_tx(arg, parser, tx_db, args.network)
        if tx:
            txs.append(tx)
            continue

        if parse_parts(arg, spendables, payables, args.network):
            continue

        parser.error("can't parse %s" % arg)

    parse_private_key_file(args, key_iters)

    if args.fetch_spendables:
        warning_spendables = message_about_spendables_for_address_env(args.network)
        for address in args.fetch_spendables:
            spendables.extend(spendables_for_address(address, args.network))

    return (txs, spendables, payables, key_iters, tx_db, warning_spendables)


def merge_txs(txs, spendables, payables):

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


def wif_iter(iters):
    while len(iters) > 0:
        for idx, iter in enumerate(iters):
            try:
                wif = next(iter)
                yield wif
            except StopIteration:
                iters = iters[:idx] + iters[idx+1:]
                break


def generate_tx(txs, spendables, payables, args):
    txs_in, txs_out, unspents = merge_txs(txs, spendables, payables)
    lock_time, version = calculate_lock_time_and_version(args, txs)
    if len(unspents) == len(txs_in):
        unspents = remove_indices(unspents, args.remove_tx_in)
    txs_in = remove_indices(txs_in, args.remove_tx_in)
    txs_out = remove_indices(txs_out, args.remove_tx_out)
    tx = Tx(txs_in=txs_in, txs_out=txs_out, lock_time=lock_time, version=version, unspents=unspents)
    fee = args.fee
    try:
        if len(payables) > 0:
            distribute_from_split_pool(tx, fee)
    except ValueError as ex:
        print("warning: %s" % ex.args[0], file=sys.stderr)
    return tx


def print_output(tx, include_unspents, output_file, show_unspents, network, verbose_signature, disassemble, trace, pdb):
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
        dump_tx(tx, network, verbose_signature, disassemble, trace, pdb)
        if include_unspents:
            print("including unspents in hex dump since transaction not fully signed")
        print(tx_as_hex)


def do_signing(tx, key_iters, p2sh_lookup, netcode):
    unsigned_before = tx.bad_signature_count()
    unsigned_after = unsigned_before
    if unsigned_before > 0 and key_iters:
        print("signing...", file=sys.stderr)
        sign_tx(tx, wif_iter(key_iters), p2sh_lookup=p2sh_lookup, netcode=netcode)

        unsigned_after = tx.bad_signature_count()
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


def tx(args, parser):

    (txs, spendables, payables, key_iters, tx_db, warning_spendables) = parse_context(args, parser)

    for tx in txs:
        if tx.missing_unspents() and (args.augment or tx_db):
            if tx_db is None:
                tx_db = create_tx_db(args.network)
            tx.unspents_from_db(tx_db, ignore_missing=True)

    # build p2sh_lookup
    p2sh_lookup = build_p2sh_lookup(args)

    tx = generate_tx(txs, spendables, payables, args)

    is_fully_signed = do_signing(tx, key_iters, p2sh_lookup, args.network)

    include_unspents = not is_fully_signed

    print_output(tx, include_unspents, args.output_file, args.show_unspents, args.network,
                 args.verbose_signature, args.disassemble, args.trace, args.pdb)

    tx_db = cache_result(tx, tx_db, args.cache, args.network)

    tx_db = validate_against_bitcoind(tx, tx_db, args.network, args.bitcoind_url)

    if not args.show_unspents:
        tx_db = validate_tx(tx, tx_db, args.network)

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
