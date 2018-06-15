from __future__ import print_function

import datetime

from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from pycoin.convention import satoshi_to_mbtc
from pycoin.serialize import b2h_rev, stream_to_bytes
from pycoin.satoshi.checksigops import parse_signature_blob


LOCKTIME_THRESHOLD = 500000000


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

    def trace_script(opcode, data, pc, vmc):
        from pycoin.serialize import b2h
        print("stack: [%s]" % ' '.join(b2h(s) for s in vmc.stack))
        if len(vmc.altstack) > 0:
            print("altstack: %s" % vmc.altstack)
        print("condition stack: %s" % vmc.conditional_stack)
        print("%3d : %02x  %s" % (vmc.pc, opcode, BitcoinScriptTools.disassemble_for_opcode_data(opcode, data)))
        if use_pdb:
            import pdb
            pdb.set_trace()
    return trace_script


def dump_inputs(tx, network, verbose_signature, traceback_f, disassembly_level):
    for idx, tx_in in enumerate(tx.txs_in):
        if tx.is_coinbase():
            print("%4d: COINBASE  %12.5f mBTC" % (idx, satoshi_to_mbtc(tx.total_in())))
            continue
        suffix = ""
        if tx.missing_unspent(idx):
            tx_out = None
            address = tx_in.address(ui_context=network.ui)
        else:
            tx_out = tx.unspents[idx]
            sig_result = " sig ok" if tx.is_signature_ok(idx, traceback_f=traceback_f) else " BAD SIG"
            suffix = " %12.5f mBTC %s" % (satoshi_to_mbtc(tx_out.coin_value), sig_result)
            address = network.ui.address_for_script(tx_out.puzzle_script())
        t = "%4d: %34s from %s:%-4d%s" % (idx, address, b2h_rev(tx_in.previous_hash),
                                          tx_in.previous_index, suffix)
        print(t.rstrip())
        if disassembly_level > 0:
            dump_disassembly(tx, idx, network.extras.annotate)

        if verbose_signature:
            dump_signatures(tx, tx_in, tx_out, idx, network, traceback_f)


def dump_disassembly(tx, tx_in_idx, annotate):
    for (pre_annotations, pc, opcode, instruction, post_annotations) in \
            annotate.annotate_scripts(tx, tx_in_idx):
        for l in pre_annotations:
            print("           %s" % l)
        if 1:
            print("    %4x: %02x  %s" % (pc, opcode, instruction))
        for l in post_annotations:
            print("           %s" % l)


def dump_signatures(tx, tx_in, tx_out, idx, network, traceback_f):
    sc = tx.SolutionChecker(tx)
    signatures = [parse_signature_blob(blob) for blob, sig_hash in network.extras.extract_signatures(tx, idx)]
    if signatures:
        sig_types_identical = (
            tuple(zip(*signatures))[1].count(signatures[0][1]) == len(signatures))
        i = 1 if len(signatures) > 1 else ''
        for sig_pair, sig_type in signatures:
            print("      r{0}: {1:#x}\n      s{0}: {2:#x}".format(i, *sig_pair))
            if not sig_types_identical and tx_out:
                print("      z{}: {:#x} {}".format(i, sc._signature_hash(tx_out.script, idx, sig_type),
                                                   network.extras.annotate.sighash_type_to_string(sig_type)))
            if i:
                i += 1
        if sig_types_identical and tx_out:
            print("      z:{} {:#x} {}".format(' ' if i else '', sc._signature_hash(
                tx_out.script, idx, sig_type), network.extras.annotate.sighash_type_to_string(sig_type)))


def dump_footer(tx, missing_unspents):
    if not missing_unspents:
        print("Total input  %12.5f mBTC" % satoshi_to_mbtc(tx.total_in()))
    if 1:
        print("Total output %12.5f mBTC" % satoshi_to_mbtc(tx.total_out()))
    if not missing_unspents:
        print("Total fees   %12.5f mBTC" % satoshi_to_mbtc(tx.fee()))


def dump_tx(tx, network, verbose_signature, disassembly_level, do_trace, use_pdb):
    missing_unspents = tx.missing_unspents()
    traceback_f = make_trace_script(do_trace, use_pdb)

    dump_header(tx)

    dump_inputs(tx, network, verbose_signature, traceback_f, disassembly_level)

    print("Output%s:" % ('s' if len(tx.txs_out) != 1 else ''))
    for idx, tx_out in enumerate(tx.tx_outs_as_spendable()):
        amount_mbtc = satoshi_to_mbtc(tx_out.coin_value)
        address = network.ui.address_for_script(tx_out.puzzle_script()) or "(unknown)"
        print("%4d: %34s receives %12.5f mBTC" % (idx, address, amount_mbtc))
        if disassembly_level > 0:
            for (pre_annotations, pc, opcode, instruction, post_annotations) in \
                    network.extras.annotate.annotate_spendable(tx.__class__, tx_out):
                for l in pre_annotations:
                    print("           %s" % l)
                if 1:
                    print("    %4x: %02x  %s" % (pc, opcode, instruction))
                for l in post_annotations:
                    print("           %s" % l)

    dump_footer(tx, missing_unspents)
