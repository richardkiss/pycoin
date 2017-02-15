# generic solver

# from .SolutionChecker import SolutionChecker
# from .VM import VM

from .. import Tx, TxIn, TxOut
from ...key import Key
from ...ui import standard_tx_out_script


class Atom(object):
    def __init__(self, name):
        self.name = name

    def dependencies(self):
        return frozenset([self.name])

    def __repr__(self):
        return "<%s>" % self.name


class Operator(Atom):
    def __init__(self, op_name, *args):
        self._op_name = op_name
        self._args = args

    def dependencies(self):
        s = set()
        for a in self._args:
            if hasattr(a, "dependencies"):
                s.update(a.dependencies())
        return frozenset(s)

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
        import pdb
        # pdb.set_trace()
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



def solve(tx, tx_in_idx, **kwargs):
    constraints = []
    tx.check_solution(tx_in_idx, traceback_f=make_traceback_f(constraints))
    for c in constraints:
        print(c, sorted(c.dependencies()))
    solutions = []
    for c in constraints:
        s = solution_for_constraint(c)
        # s = (solution_f, target atom, dependency atom list)
        if s is not None:
            solutions.append(s)
    max_stack_size = 2  # BRAIN DAMAGE
    solved_values = dict((Atom("x_%d" % i), None) for i in range(max_stack_size))
    progress = True
    while progress and any(v is None for v in solved_values.values()):
        progress = False
        for solution, target, dependencies in solutions:
            if any(solved_values[d] is None for d in dependencies):
                continue
            solved_values[target] = solution(solved_values, **kwargs)
            progress = True
    print(solved_values)


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
    m = constraint_matches(c, ('EQUAL', CONSTANT("0"), ('HASH160', VAR("1"))))
    if m:
        pass
    # (EQUAL K (HASH160 <x_0>))


def constraint_matches(c, m):
    if isinstance(m, tuple):
        if not isinstance(c, Operator):
            return False
        if c._op_name != m[0]:
            return False
        if len(c.args) != len(m[1:]):
            return False
        pass


def test():
    key = Key(1)
    previous_hash = b'\1' * 32
    txs_in = [TxIn(previous_hash, 0)]
    txs_out = [TxOut(1000, standard_tx_out_script(key.address()))]
    version, lock_time = 1, 0
    tx = Tx(version, txs_in, txs_out, lock_time)
    tx.set_unspents(txs_out)
    print(tx)
    solve(tx, 0)
    return tx


test()


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
