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
from pycoin.tx.script.tools import compile
from pycoin.tx.script.vm import eval_script
from pycoin.tx.script.vm import verify_script


SCRIPT_VALID_JSON = os.path.dirname(__file__) + '/data/script_valid.json'
SCRIPT_INVALID_JSON = os.path.dirname(__file__) + '/data/script_invalid.json'

class TestTx(unittest.TestCase):
    pass


def parse_flags(flag_string):
    v = 0
    if len(flag_string) > 0:
        for f in flag_string.split(","):
            v |= getattr(flags, "VERIFY_%s" % f)
    return v

def build_credit_tx(script_out_bin):
    txs_in = [TxIn(b'\0'*32, 4294967295, b'\0\0', sequence=4294967295)]
    txs_out = [TxOut(0, script_out_bin)]
    return Tx(1, txs_in, txs_out)

def build_spending_tx(script_in_bin, credit_tx):
    txs_in = [TxIn(credit_tx.hash(), 0, script_in_bin, sequence=4294967295)]
    txs_out = [TxOut(0, b'')]
    spend_tx = Tx(1, txs_in, txs_out, unspents=credit_tx.tx_outs_as_spendable())
    return spend_tx


def dump_failure_info(spend_tx, script_in, script_out, flags, comment):
    return
    print(script_in)
    print(script_out)
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
    try:
        r = spend_tx.is_signature_ok(tx_in_idx=0, traceback_f=tbf, flags=flags)
    except Exception as ex:
        print(ex)
    print("test failed: '%s' '%s' : %s  %s" % (script_in, script_out, comment, flags))
    try:
        r = spend_tx.is_signature_ok(tx_in_idx=0, traceback_f=tbf, flags=flags)
    except Exception as ex:
        print(ex)
        import pdb; pdb.set_trace()


def make_test(script_in, script_out, flags_string, comment, expect_valid=True):
    def f(self):
        script_in_bin = compile(script_in)
        script_out_bin = compile(script_out)
        flags = parse_flags(flags_string)
        try:
            credit_tx = build_credit_tx(script_out_bin)
            spend_tx = build_spending_tx(script_in_bin, credit_tx)
            r = spend_tx.is_signature_ok(tx_in_idx=0, flags=flags)
        except ScriptError:
            r = False
        except:
            r = -1
        if r != expect_valid:
            dump_failure_info(spend_tx, script_in, script_out, flags, comment)
        self.assertEqual(r, expect_valid)
    return f

def items_from_json(path):
    with open(path, "r") as f:
        for i in json.load(f):
            if len(i) in [3, 4]:
                if len(i) == 3:
                    i.append("no comment")
                yield i

def inject():
    for idx, (script_in, script_out, flags, comment) in enumerate(items_from_json(SCRIPT_VALID_JSON)):
        name_of_f = "test_valid_%03d" % idx
        setattr(TestTx, name_of_f, make_test(script_in, script_out, flags, comment))
        print("adding %s" % name_of_f)

    for idx, (script_in, script_out, flags, comment) in enumerate(items_from_json(SCRIPT_INVALID_JSON)):
        name_of_f = "test_invalid_%03d" % idx
        setattr(TestTx, name_of_f, make_test(script_in, script_out, flags, comment, expect_valid=False))
        print("adding %s" % name_of_f)

inject()
