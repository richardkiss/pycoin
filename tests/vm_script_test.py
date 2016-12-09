#!/usr/bin/env python

import json
import unittest
import os
#import sys
#import tempfile

from pycoin.serialize import h2b

from pycoin.tx import TxIn, TxOut, Tx
from pycoin.tx.script import ScriptError
from pycoin.tx.script import flags
from pycoin.tx.script.tools import compile, disassemble
from pycoin.tx.script.vm import eval_script
from pycoin.tx.script.vm import verify_script


SCRIPT_TESTS_JSON = os.path.dirname(__file__) + '/data/script_tests.json'

class TestTx(unittest.TestCase):
    pass


def parse_flags(flag_string):
    v = 0
    if len(flag_string) > 0:
        for f in flag_string.split(","):
            v |= getattr(flags, "VERIFY_%s" % f)
    return v

def build_credit_tx(script_out_bin, coin_value=0):
    txs_in = [TxIn(b'\0'*32, 4294967295, b'\0\0', sequence=4294967295)]
    txs_out = [TxOut(coin_value, script_out_bin)]
    return Tx(1, txs_in, txs_out)

def build_spending_tx(script_in_bin, credit_tx):
    txs_in = [TxIn(credit_tx.hash(), 0, script_in_bin, sequence=4294967295)]
    txs_out = [TxOut(credit_tx.txs_out[0].coin_value, b'')]
    spend_tx = Tx(1, txs_in, txs_out, unspents=credit_tx.tx_outs_as_spendable())
    return spend_tx


def dump_failure_info(spend_tx, script_in, script_out, flags, flags_string, expected, comment):
    return
    print()
    print(flags_string)
    print("EXPECTED: %s" % expected)
    print(comment)
    print(disassemble(compile(script_in)))
    print(disassemble(compile(script_out)))
    from pycoin.serialize import b2h
    def tbf(*args):
        pc, opcode, data, stack, altstack, is_signature, is_condition = args
        from pycoin.tx.script.tools import disassemble_for_opcode_data
        opd = disassemble_for_opcode_data(opcode, data)
        if len(altstack) == 0:
            altstack = ''
        print("%s %s\n  %3x  %s" % (stack, altstack, pc, opd))
        import pdb
        pdb.set_trace()
    print("test failed: '%s' '%s' : %s  %s" % (script_in, script_out, comment, flags_string))
    try:
        r = spend_tx.is_signature_ok(tx_in_idx=0, traceback_f=tbf, flags=flags)
    except Exception as ex:
        print(ex)
    try:
        r = spend_tx.is_signature_ok(tx_in_idx=0, traceback_f=tbf, flags=flags)
    except Exception as ex:
        print(ex)
        import pdb; pdb.set_trace()


def make_script_test(script_in, script_out, flags_string, comment, expected, coin_value, script_witness):
    script_in_bin = compile(script_in)
    script_out_bin = compile(script_out)
    script_witness_bin = [h2b(w) for w in script_witness]
    flags = parse_flags(flags_string)
    def f(self):
        try:
            credit_tx = build_credit_tx(script_out_bin, coin_value)
            spend_tx = build_spending_tx(script_in_bin, credit_tx)
            spend_tx.txs_in[0].witness = script_witness_bin
            r = spend_tx.is_signature_ok(tx_in_idx=0, flags=flags)
        except ScriptError:
            r = False
        except:
            r = -1
        # for now, just deal with 0 versus nonzero
        expect_valid = (expected == 'OK')
        if r != expect_valid:
            dump_failure_info(spend_tx, script_in, script_out, flags, flags_string, expected, comment)
        self.assertEqual(r, expect_valid)
    return f

def items_from_json(path):
    with open(path, "r") as f:
        for i in json.load(f):
            if len(i) >= 4:
                yield i

def inject():
    for idx, args in enumerate(items_from_json(SCRIPT_TESTS_JSON)):
        script_witness, coin_value = [], 0
        if type(args[0]) is list:
            script_witness, coin_value = args[0][:-1], int(1e8 * args[0][-1] + 0.5)
            args = args[1:]
        (script_in, script_out, flags, expected) = args[:4]
        comments = '/'.join(args[4:])
        name_of_f = "test_scripts_%03d" % idx
        setattr(TestTx, name_of_f, make_script_test(script_in, script_out, flags, comments, expected, coin_value, script_witness))
        print("adding %s" % name_of_f)

inject()
