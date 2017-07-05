# generic solver

import functools
import pdb

from ..script.checksigops import parse_signature_blob
from ...key import Key
from ...serialize import b2h

from pycoin import ecdsa
from pycoin import encoding
from pycoin.tx.script import der
from pycoin.intbytes import int2byte

from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools

from pycoin.tx.exceptions import SolvingError

DEFAULT_PLACEHOLDER_SIGNATURE = b''
DEFAULT_SIGNATURE_TYPE = 1


def _find_signatures(script_blobs, signature_for_hash_type_f, max_sigs, sec_keys):
    signatures = []
    secs_solved = set()
    seen = 0
    for data in script_blobs:
        if seen >= max_sigs:
            break
        try:
            sig_pair, signature_type = parse_signature_blob(data)
            seen += 1
            for idx, sec_key in enumerate(sec_keys):
                public_pair = encoding.sec_to_public_pair(sec_key)
                sign_value = signature_for_hash_type_f(signature_type)
                v = ecdsa.verify(ecdsa.generator_secp256k1, public_pair, sign_value, sig_pair)
                if v:
                    signatures.append((idx, data))
                    secs_solved.add(sec_key)
                    break
        except (ValueError, encoding.EncodingError, der.UnexpectedDER):
            # if public_pair is invalid, we just ignore it
            pass
    return signatures, secs_solved


@functools.total_ordering
class Atom(object):
    def __init__(self, name):
        self.name = name

    def dependencies(self):
        return frozenset([self])

    def __len__(self):
        # HACK to allow MAX_BLOB_LENGTH comparison to succeed
        return 0

    def __eq__(self, other):
        if isinstance(other, Atom):
            return self.name == other.name
        return False

    def __lt__(self, other):
        if isinstance(other, Atom):
            return self.name < other.name
        return False

    def __hash__(self):
        return self.name.__hash__()

    def __repr__(self):
        return "<%s>" % self.name


class Operator(Atom):
    def __init__(self, op_name, *args):
        self._op_name = op_name
        self._args = tuple(args)
        s = set()
        for a in self._args:
            if hasattr(a, "dependencies"):
                s.update(a.dependencies())
        self._dependencies = frozenset(s)

    def __hash__(self):
        return self._args.__hash__()

    def __eq__(self, other):
        if isinstance(other, Operator):
            return self._op_name, self._args == other._op_name, other._args
        return False

    def dependencies(self):
        return self._dependencies

    def __repr__(self):
        return "(%s %s)" % (self._op_name, ' '.join(repr(a) for a in self._args))


OP_HASH160 = BitcoinScriptTools.int_for_opcode("OP_HASH160")
OP_EQUAL = BitcoinScriptTools.int_for_opcode("OP_EQUAL")
OP_EQUALVERIFY = BitcoinScriptTools.int_for_opcode("OP_EQUALVERIFY")
OP_CHECKSIG = BitcoinScriptTools.int_for_opcode("OP_CHECKSIG")
OP_CHECKMULTISIG = BitcoinScriptTools.int_for_opcode("OP_CHECKMULTISIG")
OP_IF = BitcoinScriptTools.int_for_opcode("OP_IF")


def my_op_if(vm):
    pdb.set_trace()
    t = vm.stack.pop()
    t = Operator('IF', t)
    vm.stack.append(t)


def my_op_hash160(vm):
    t = vm.stack.pop()
    t = Operator('HASH160', t)
    vm.stack.append(t)


my_op_hash160.stack_size = 1


def my_op_equal(vm):
    t1 = vm.stack.pop()
    t2 = vm.stack.pop()
    c = Operator('EQUAL', t1, t2)
    vm.append(c)


my_op_equal.stack_size = 2


def make_traceback_f(solution_checker, tx_context, constraints, reset_stack_f):

    def my_op_equalverify(vm):
        t1 = vm.stack.pop()
        t2 = vm.stack.pop()
        c = Operator('IS_TRUE', Operator('EQUAL', t1, t2))
        constraints.append(c)
    my_op_equalverify.stack_size = 2

    def my_op_checksig(vm):

        def sighash_f(signature_type):
            return vm.signature_for_hash_type_f(signature_type, [], vm)

        t1 = vm.stack.pop()
        t2 = vm.stack.pop()
        t = Operator('SIGNATURES_CORRECT', [t1], [t2], sighash_f)
        constraints.append(Operator('IS_PUBKEY', t1))
        constraints.append(Operator('IS_SIGNATURE', t2))
        vm.stack.append(t)

    def my_op_checkmultisig(vm):

        def sighash_f(signature_type):
            return vm.signature_for_hash_type_f(signature_type, [], vm)

        key_count = vm.IntStreamer.int_from_script_bytes(vm.stack.pop(), require_minimal=False)
        public_pair_blobs = []
        for i in range(key_count):
            constraints.append(Operator('IS_PUBKEY', vm.stack[-1]))
            public_pair_blobs.append(vm.stack.pop())
        signature_count = vm.IntStreamer.int_from_script_bytes(vm.stack.pop(), require_minimal=False)
        sig_blobs = []
        for i in range(signature_count):
            constraints.append(Operator('IS_SIGNATURE', vm.stack[-1]))
            sig_blobs.append(vm.stack.pop())
        t1 = vm.stack.pop()
        constraints.append(Operator('IS_TRUE', Operator('EQUAL', t1, b'')))
        t = Operator('SIGNATURES_CORRECT', public_pair_blobs, sig_blobs, sighash_f)
        vm.stack.append(t)

    MY_OPCODES = {
        OP_HASH160: my_op_hash160,
        OP_EQUALVERIFY: my_op_equalverify,
        OP_EQUAL: my_op_equal,
        OP_CHECKSIG: my_op_checksig,
        OP_CHECKMULTISIG: my_op_checkmultisig,
    }

    def prelaunch(vmc):
        if not vmc.is_solution_script:
            # reset stack
            vmc.stack = reset_stack_f(vmc.stack)

    def traceback_f(opcode, data, pc, vm):
        f = MY_OPCODES.get(opcode)
        if f is None:
            return
        stack_size = getattr(f, "stack_size", 0)
        if stack_size and all(not isinstance(v, Atom) for v in vm.stack[-stack_size:]):
            return
        return f

    def postscript(vmc):
        if not vmc.is_solution_script:
            constraints.append(Operator('IS_TRUE', vmc.stack[-1]))
            vmc.stack = [vmc.VM_TRUE]

    traceback_f.prelaunch = prelaunch
    traceback_f.postscript = postscript
    return traceback_f


class CONSTANT(object):
    def __init__(self, name):
        self._name = name


class VAR(object):
    def __init__(self, name):
        self._name = name


class LIST(object):
    def __init__(self, name):
        self._name = name


def lookup_solved_value(solved_values, item):
    if isinstance(item, Atom):
        return solved_values[item]
    return item


def solution_constraint_lookup():
    l = []

    def factory(m):

        def f(solved_values, **kwargs):
            the_hash = m["the_hash"]
            db = kwargs.get("hash160_lookup", {})
            result = db.get(the_hash)
            if result is None:
                raise SolvingError("can't find secret exponent for %s" % b2h(the_hash))
            return {m["1"]: Key(result[0]).sec(use_uncompressed=not result[2])}

        return (f, [m["1"]], ())

    factory.pattern = ('IS_TRUE', ('EQUAL', CONSTANT("the_hash"), ('HASH160', VAR("1"))))
    l.append(factory)

    def factory(m):

        def f(solved_values, **kwargs):
            return {m["var"]: m["const"]}

        return (f, [m["var"]], ())

    factory.pattern = ('IS_TRUE', ('EQUAL', VAR("var"), CONSTANT('const')))
    l.append(factory)

    def factory(m):
        def f(solved_values, **kwargs):
            signature_type = kwargs.get("signature_type", DEFAULT_SIGNATURE_TYPE)
            signature_for_hash_type_f = m["signature_for_hash_type_f"]
            existing_signatures, secs_solved = _find_signatures(kwargs.get(
                "existing_script", b''), signature_for_hash_type_f, len(m["sig_list"]), m["sec_list"])

            sec_keys = m["sec_list"]
            signature_variables = m["sig_list"]

            signature_placeholder = kwargs.get("signature_placeholder", DEFAULT_PLACEHOLDER_SIGNATURE)

            db = kwargs.get("hash160_lookup", {})
            order = ecdsa.generator_secp256k1.order()
            for signature_order, sec_key in enumerate(sec_keys):
                sec_key = lookup_solved_value(solved_values, sec_key)
                if sec_key in secs_solved:
                    continue
                if len(existing_signatures) >= len(signature_variables):
                    break
                result = db.get(sec_key)
                if result is None:
                    continue
                secret_exponent = result[0]
                sig_hash = signature_for_hash_type_f(signature_type)
                r, s = ecdsa.sign(ecdsa.generator_secp256k1, secret_exponent, sig_hash)
                if s + s > order:
                    s = order - s
                binary_signature = der.sigencode_der(r, s) + int2byte(signature_type)
                existing_signatures.append((signature_order, binary_signature))

            # pad with placeholder signatures
            if signature_placeholder is not None:
                while len(existing_signatures) < len(signature_variables):
                    existing_signatures.append((-1, signature_placeholder))
            existing_signatures.sort()
            return dict(zip(signature_variables, (es[-1] for es in existing_signatures)))
        return (f, m["sig_list"], [a for a in m["sec_list"] if isinstance(a, Atom)])

    factory.pattern = ('IS_TRUE', (
        'SIGNATURES_CORRECT', LIST("sec_list"), LIST("sig_list"), CONSTANT("signature_for_hash_type_f")))
    l.append(factory)

    return l


SOLUTIONS_BY_CONSTRAINT = solution_constraint_lookup()


def solutions_for_constraint(c):
    # given a constraint c
    # return None or
    # a solution (solution_f, target atom, dependency atom list)
    # where solution_f take list of solved values

    for f_factory in SOLUTIONS_BY_CONSTRAINT:
        m = constraint_matches(c, f_factory.pattern)
        if m:
            return f_factory(m)


def constraint_matches(c, m):
    """
    Return False or dict with indices the substitution values
    """
    if c == m:
        return {}
    if isinstance(m, CONSTANT):
        if not isinstance(c, Atom):
            return {m._name: c}
    if isinstance(m, VAR):
        if isinstance(c, (bytes, Atom)):
            return {m._name: c}
    if isinstance(m, LIST):
        if isinstance(c, (tuple, list)):
            return {m._name: c}
    if isinstance(m, tuple):
        if isinstance(c, Operator):
            d = {}
            for c1, m1 in zip(c._args, m[1:]):
                r = constraint_matches(c1, m1)
                if r is False:
                    return r
                d.update(r)
            return d
    return False
