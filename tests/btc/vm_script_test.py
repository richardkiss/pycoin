import json
import unittest
import os

from pycoin.encoding.hexbytes import h2b
from pycoin.symbols.btc import network


errno = network.validator.errno
flags = network.validator.flags
ScriptError = network.validator.ScriptError

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
    txs_in = [network.tx.TxIn(b'\0'*32, 4294967295, b'\0\0', sequence=4294967295)]
    txs_out = [network.tx.TxOut(coin_value, script_out_bin)]
    return network.tx(1, txs_in, txs_out)


def build_spending_tx(script_in_bin, credit_tx):
    txs_in = [network.tx.TxIn(credit_tx.hash(), 0, script_in_bin, sequence=4294967295)]
    txs_out = [network.tx.TxOut(credit_tx.txs_out[0].coin_value, b'')]
    spend_tx = network.tx(1, txs_in, txs_out, unspents=credit_tx.tx_outs_as_spendable())
    return spend_tx


def dump_failure_info(spend_tx, script_in, script_out, flags, flags_string, expected, actual, message, comment):
    # return
    print()
    print(flags_string)
    print("EXPECTED: %s" % expected)
    print("ACTUAL: %s" % actual)
    print("MESSAGE: %s" % message)
    print(comment)
    print(network.script.disassemble(network.script.compile(script_in)))
    print(network.script.disassemble(network.script.compile(script_out)))

    def tbf(*args):
        opcode, data, pc, vm = args
        stack = vm.stack
        altstack = vm.altstack
        opd = network.script.disassemble_for_opcode_data(opcode, data)
        if len(altstack) == 0:
            altstack = ''
        print("%s %s\n  %3x  %s" % (stack, altstack, pc, opd))
        import pdb
        pdb.set_trace()
    print("test failed: '%s' '%s' : %s  %s" % (script_in, script_out, comment, flags_string))
    try:
        import pdb
        pdb.set_trace()
        spend_tx.check_solution(tx_in_idx=0, traceback_f=tbf, flags=flags)
    except Exception as ex:
        print(ex)
    try:
        spend_tx.check_solution(tx_in_idx=0, traceback_f=tbf, flags=flags)
    except Exception as ex:
        print(ex)
        import pdb
        pdb.set_trace()


def make_script_test(script_in, script_out, flags_string, comment, expected, coin_value, script_witness):
    script_in_bin = network.script.compile(script_in)
    script_out_bin = network.script.compile(script_out)
    script_witness_bin = [h2b(w) for w in script_witness]
    flags = parse_flags(flags_string)

    def f(self):
        try:
            credit_tx = build_credit_tx(script_out_bin, coin_value)
            spend_tx = build_spending_tx(script_in_bin, credit_tx)
            spend_tx.txs_in[0].witness = script_witness_bin
            msg = ''
            spend_tx.check_solution(tx_in_idx=0, flags=flags)
            r = 0
        except ScriptError as se:
            r = se.error_code()
            msg = se.args[0]
        except Exception:
            r = -1
        # for now, just deal with 0 versus nonzero
        expect_error = getattr(errno, expected)
        if r != expect_error:
            dump_failure_info(spend_tx, script_in, script_out, flags, flags_string, expected, r, msg, comment)
        self.assertEqual(r, expect_error)
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
        setattr(TestTx, name_of_f,
                make_script_test(script_in, script_out, flags, comments, expected, coin_value, script_witness))
        print("adding %s" % name_of_f)


inject()
