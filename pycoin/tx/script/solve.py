# generic solver

import pdb

from .. import Tx, TxIn, TxOut
from ...key import Key
from ...ui import standard_tx_out_script

from pycoin import ecdsa
from pycoin.tx.script import der
from pycoin.intbytes import bytes_from_int
from pycoin.tx.script.VM import VM

from pycoin.tx.pay_to import ScriptPayToPublicKey


class Atom(object):
    def __init__(self, name):
        self.name = name

    def dependencies(self):
        return frozenset([self.name])

    def __eq__(self, other):
        if isinstance(other, Atom):
            return self.name == other.name
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


def make_traceback_f(constraints):
    def traceback_f(*args):
        opcode, data, pc, vm = args
        if vm.pc == 0:
            # reset stack
            vm.stack = vm.Stack(reversed([Atom("x_%d" % i) for i in range(10)]))
        stack = vm.stack
        altstack = vm.altstack
        if len(altstack) == 0:
            altstack = ''
        # print("%s %s\n  %3x  %s" % (vm.stack, altstack, vm.pc, vm.disassemble_for_opcode_data(opcode, data)))
        if opcode == vm.OP_HASH160 and not isinstance(vm.stack[-1], bytes):
            def my_op_hash160(vm):
                t = vm.stack.pop()
                t = Operator('HASH160', t)
                vm.stack.append(t)
            return my_op_hash160
        if opcode == vm.OP_EQUALVERIFY and any(not isinstance(v, bytes) for v in vm.stack[-2:]):
            def my_op_equalverify(vm):
                t1 = vm.stack.pop()
                t2 = vm.stack.pop()
                c = Operator('EQUAL', t1, t2)
                constraints.append(c)
            return my_op_equalverify
        if opcode == vm.OP_CHECKSIG:
            def my_op_checksig(vm):
                t1 = vm.stack.pop()
                t2 = vm.stack.pop()
                t = Operator('CHECKSIG', t1, t2)
                constraints.append(Operator('IS_PUBKEY', t1))
                constraints.append(Operator('IS_SIGNATURE', t2))
                vm.stack.append(t)
                if pc >= len(vm.script):
                    constraints.append(Operator('IS_TRUE', vm.stack[-1]))
                    if len(vm.stack) > 1:
                        constraints.append(Operator('STACK_EMPTY_AFTER', vm.stack[-2]))
                    vm.stack = vm.Stack([vm.VM_TRUE])
            return my_op_checksig
    return traceback_f


def determine_constraints(tx, tx_in_idx):
    constraints = []
    tx.check_solution(tx_in_idx, traceback_f=make_traceback_f(constraints))
    return constraints


def solve(tx, tx_in_idx, **kwargs):
    constraints = determine_constraints(tx, tx_in_idx)
    for c in constraints:
        print(c, sorted(c.dependencies()))
    solutions = []
    for c in constraints:
        s = solution_for_constraint(c)
        # s = (solution_f, target atom, dependency atom list)
        if s is not None:
            solutions.append(s)
    max_stack_size = kwargs["max_stack_size"]  # BRAIN DAMAGE
    solved_values = dict((Atom("x_%d" % i), None) for i in range(max_stack_size))
    progress = True
    while progress and any(v is None for v in solved_values.values()):
        progress = False
        for solution, target, dependencies in solutions:
            if solved_values.get(target) is not None:
                continue
            if any(solved_values[d] is None for d in dependencies):
                continue
            solved_values[target] = solution(solved_values, **kwargs)
            progress = True

    solution_list = [solved_values.get(Atom("x_%d" % i)) for i in reversed(range(max_stack_size))]
    return VM.bin_script(solution_list)


class CONSTANT(object):
    def __init__(self, name):
        self._name = name


class VAR(object):
    def __init__(self, name):
        self._name = name


def solution_for_constraint(c):
    # given a constraint c
    # return None or
    # a solution (solution_f, target atom, dependency atom list)
    # where solution_f take list of solved values

    def lookup_solved_value(solved_values, item):
        if isinstance(item, Atom):
            return solved_values[item]
        return item

    def filtered_dependencies(*args):
        return [a for a in args if isinstance(a, Atom)]


    m = constraint_matches(c, ('EQUAL', CONSTANT("0"), ('HASH160', VAR("1"))))
    if m:
        the_hash = m["0"]

        def f(solved_values, **kwargs):
            return kwargs["pubkey_for_hash"](the_hash)

        return (f, m["1"], ())

    m = constraint_matches(c, (('IS_TRUE', ('CHECKSIG', VAR("0"), VAR("1")))))
    if m:

        def f(solved_values, **kwargs):
            pubkey = lookup_solved_value(solved_values, m["0"])
            pdb.set_trace()
            privkey = kwargs["privkey_for_pubkey"](pubkey)
            signature = kwargs["signature_for_secret_exponent"](privkey)
            return signature
        return (f, m["1"], filtered_dependencies(m["0"]))

    return None


def constraint_matches(c, m):
    """
    Return False or dict with indices the substitution values
    """
    d = {}
    if isinstance(m, tuple):
        if not isinstance(c, Operator):
            return False
        if c._op_name != m[0]:
            return False
        if len(c._args) != len(m[1:]):
            return False
        for c1, m1 in zip(c._args, m[1:]):
            if isinstance(m1, tuple) and isinstance(c1, Operator):
                d1 = constraint_matches(c1, m1)
                if d1 is False:
                    return False
                d.update(d1)
                continue
            if isinstance(m1, CONSTANT):
                if isinstance(c1, bytes):
                    d[m1._name] = c1
                    continue
            if isinstance(m1, VAR):
                if isinstance(c1, (bytes, Atom)):
                    d[m1._name] = c1
                    continue
            if c1 == m1:
                continue
            return False
        return d


def test_solve(tx, tx_in_idx, **kwargs):
    solution_script = solve(tx, 0, **kwargs)
    print(VM.disassemble(solution_script))

    tx.txs_in[tx_in_idx].script = solution_script
    tx.check_solution(0)


def make_test_tx(input_script):
    previous_hash = b'\1' * 32
    txs_in = [TxIn(previous_hash, 0)]
    txs_out = [TxOut(1000, standard_tx_out_script(Key(1).address()))]
    version, lock_time = 1, 0
    tx = Tx(version, txs_in, txs_out, lock_time)
    unspents = [TxOut(1000, input_script)]
    tx.set_unspents(unspents)
    return tx


def test_tx(incoming_script, max_stack_size):
    key = Key(1)
    tx = make_test_tx(incoming_script)
    tx_in_idx = 0

    def pubkey_for_hash(the_hash):
        if the_hash == key.hash160():
            return key.sec()

    def privkey_for_pubkey(pubkey):
        if pubkey == key.sec():
            return key.secret_exponent()

    def signature_for_secret_exponent(secret_exponent):
        signature_type = 1  # BRAIN DAMAGE

        def signature_for_hash_type_f(hash_type, script):
            return tx.signature_hash(script, tx_in_idx, hash_type)

        script_to_hash = incoming_script
        sign_value = signature_for_hash_type_f(signature_type, script_to_hash)
        order = ecdsa.generator_secp256k1.order()
        r, s = ecdsa.sign(ecdsa.generator_secp256k1, secret_exponent, sign_value)
        if s + s > order:
            s = order - s
        return der.sigencode_der(r, s) + bytes_from_int(signature_type)

    kwargs = dict(pubkey_for_hash=pubkey_for_hash,
                  privkey_for_pubkey=privkey_for_pubkey,
                  signature_for_secret_exponent=signature_for_secret_exponent,
                  max_stack_size=max_stack_size)

    test_solve(tx, tx_in_idx, **kwargs)


def test_p2pkh():
    key = Key(1)
    test_tx(standard_tx_out_script(key.address()), 2)


def test_p2pk():
    key = Key(1)
    test_tx(ScriptPayToPublicKey.from_key(key).script(), 1)


def main():
    test_p2pkh()
    test_p2pk()


if __name__ == '__main__':
    main()


"""
WE REQUIRE: b'u\x1ev\xe8\x19\x91\x96\xd4T\x94\x1cE\xd1\xb3\xa3#\xf1C;\xd6' == hash160(<X_0>)
WE REQUIRE: <X_0> to be a public key
WE REQUIRE: <X_1> to be a signature
WE REQUIRE: checksig(<X_0>, <X_1>) be true
hash160(x0) == K
for x0_candidates = public_keys()
for x0 in invhash160(k, x0_candidates):
   for x1 in invchecksig(x0, private_keys):

build a list of Constraints for each variable

x0 :
  is a public key
  has hash160 of K

x1 :
  is a signature with PK x0


public_key_candidates
x0 = hashes_to_k(K)
x1 = sign(x0, sig_type)

"""
