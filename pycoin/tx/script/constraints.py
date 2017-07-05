import functools
import pdb

from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools


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


def make_traceback_f(constraints, reset_stack_f):

    def my_op_equalverify(vm):
        my_op_equal(vm)
        constraints.append(Operator('IS_TRUE', vm.pop()))
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
        "OP_HASH160": my_op_hash160,
        "OP_EQUALVERIFY": my_op_equalverify,
        "OP_EQUAL": my_op_equal,
        "OP_CHECKSIG": my_op_checksig,
        "OP_CHECKMULTISIG": my_op_checkmultisig,
    }

    MY_OPCODES = {BitcoinScriptTools.int_for_opcode(k): v for k, v in MY_OPCODES.items()}

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
