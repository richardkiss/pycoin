# generic solver

import functools
import pdb

from ..Tx import Tx, TxIn, TxOut
from ..script.checksigops import parse_signature_blob
from ...key import Key
from ...ui import address_for_pay_to_script, standard_tx_out_script
from ...serialize import b2h

from pycoin import ecdsa
from pycoin import encoding
from pycoin.tx.pay_to import ScriptMultisig, ScriptPayToPublicKey, ScriptPayToScript, build_p2sh_lookup
from pycoin.tx.script import der, ScriptError
from pycoin.intbytes import int2byte

from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from pycoin.coins.bitcoin.SolutionChecker import BitcoinSolutionChecker, check_solution


DEFAULT_PLACEHOLDER_SIGNATURE = b''


def _create_script_signature(secret_exponent, sign_value, signature_type):
    order = ecdsa.generator_secp256k1.order()
    r, s = ecdsa.sign(ecdsa.generator_secp256k1, secret_exponent, sign_value)
    if s + s > order:
        s = order - s
    return der.sigencode_der(r, s) + int2byte(signature_type)


def _find_signatures(script, signature_for_hash_type_f, script_to_hash, max_sigs, sec_keys):
    signatures = []
    secs_solved = set()
    pc = 0
    seen = 0
    opcode, data, pc = VM.get_opcode(script, pc)
    # ignore the first opcode
    for opcode, data, pc, new_pc in BitcoinScriptTools.get_opcodes(script):
        if seen >= max_sigs:
            break
        try:
            sig_pair, signature_type = parse_signature_blob(data)
            seen += 1
            for idx, sec_key in enumerate(sec_keys):
                public_pair = encoding.sec_to_public_pair(sec_key)
                sign_value = signature_for_hash_type_f(signature_type, script_to_hash)
                v = ecdsa.verify(ecdsa.generator_secp256k1, public_pair, sign_value, sig_pair)
                if v:
                    signatures.append((idx, data))
                    secs_solved.add(sec_key)
                    break
        except (encoding.EncodingError, der.UnexpectedDER):
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


class DynamicStack(list):
    def __init__(self, l=[], reserve_count=0, fill_template="x_%d"):
        self.total_item_count = reserve_count
        self.fill_template = fill_template
        super(DynamicStack, self).__init__(l)

    def _fill(self):
        self.insert(0, Atom(self.fill_template % self.total_item_count))
        self.total_item_count += 1

    def pop(self, i=-1):
        while len(self) < abs(i):
            self._fill()
        return super(DynamicStack, self).pop(i)

    def __getitem__(self, *args, **kwargs):
        while True:
            try:
                return super(DynamicStack, self).__getitem__(*args, **kwargs)
            except IndexError:
                self._fill()


OP_HASH160 = BitcoinScriptTools.int_for_opcode("OP_HASH160")
OP_EQUAL = BitcoinScriptTools.int_for_opcode("OP_EQUAL")
OP_EQUALVERIFY = BitcoinScriptTools.int_for_opcode("OP_EQUALVERIFY")
OP_CHECKSIG = BitcoinScriptTools.int_for_opcode("OP_CHECKSIG")
OP_CHECKMULTISIG = BitcoinScriptTools.int_for_opcode("OP_CHECKMULTISIG")

def make_traceback_f(solution_checker, tx_context, constraints, **kwargs):

    def prelaunch(vmc):
        if not vmc.is_solution_script:
            # reset stack
            vmc.stack = DynamicStack(vmc.stack, kwargs.get("solution_reserve_count", 0))

    def traceback_f(opcode, data, pc, vm):
        stack = vm.stack
        altstack = vm.altstack
        if len(altstack) == 0:
            altstack = ''
        print("%s %s\n  %3x  %s" % (vm.stack, altstack, vm.pc, BitcoinScriptTools.disassemble_for_opcode_data(opcode, data)))
        if opcode == OP_HASH160 and not isinstance(vm.stack[-1], bytes):
            def my_op_hash160(vm):
                t = vm.stack.pop()
                t = Operator('HASH160', t)
                vm.stack.append(t)
            return my_op_hash160
        if opcode == OP_EQUALVERIFY and any(not isinstance(v, bytes) for v in vm.stack[-2:]):
            def my_op_equalverify(vm):
                t1 = vm.stack.pop()
                t2 = vm.stack.pop()
                c = Operator('IS_TRUE', Operator('EQUAL', t1, t2))
                constraints.append(c)
            return my_op_equalverify
        if opcode == OP_EQUAL and any(not isinstance(v, bytes) for v in vm.stack[-2:]):
            def my_op_equalverify(vm):
                t1 = vm.stack.pop()
                t2 = vm.stack.pop()
                c = Operator('EQUAL', t1, t2)
                vm.append(c)
            return my_op_equalverify
        if opcode == OP_CHECKSIG:
            def my_op_checksig(vm):

                def sighash_f(signature_type):
                    return vm.signature_for_hash_type_f(signature_type, [], vm)

                t1 = vm.stack.pop()
                t2 = vm.stack.pop()
                t = Operator('CHECKSIG', t1, t2, sighash_f)
                constraints.append(Operator('IS_PUBKEY', t1))
                constraints.append(Operator('IS_SIGNATURE', t2))
                vm.stack.append(t)
            return my_op_checksig
        if opcode == OP_CHECKMULTISIG:
            def my_op_checkmultisig(vm):

                def sighash_f(signature_type):
                    return vm.signature_for_hash_type_f(signature_type, [], vm)

                key_count = vm.IntStreamer.int_from_script_bytes(vm.stack.pop(), require_minimal=False)
                public_pair_blobs = []
                for i in range(key_count):
                    constraints.append(Operator('IS_PUBKEY', vm.stack[-1]))
                    public_pair_blobs.append(vm.stack.pop())
                signature_count = vm.IntStreamer.int_from_script_bytes(stack.pop(), require_minimal=False)
                sig_blobs = []
                for i in range(signature_count):
                    constraints.append(Operator('IS_SIGNATURE', vm.stack[-1]))
                    sig_blobs.append(stack.pop())
                t1 = vm.stack.pop()
                constraints.append(Operator('IS_TRUE', Operator('EQUAL', t1, b'')))
                t = Operator('CHECKMULTISIG', public_pair_blobs, sig_blobs, sighash_f)
                vm.stack.append(t)
            return my_op_checkmultisig

    def postscript(vmc):
        if not vmc.is_solution_script:
            constraints.append(Operator('IS_TRUE', vmc.stack[-1]))
            vmc.stack = [vmc.VM_TRUE]

    traceback_f.prelaunch = prelaunch
    traceback_f.postscript = postscript
    return traceback_f


def determine_constraints(tx, tx_in_idx, **kwargs):
    solution_checker = BitcoinSolutionChecker(tx)
    tx_context = solution_checker.tx_context_for_idx(tx_in_idx)
    tx_context.witness_solution_stack = DynamicStack([Atom("w_%d" % (1-_)) for _ in range(2)], fill_template="w_%d")
    script_hash = solution_checker.script_hash_from_script(tx_context.puzzle_script)
    if script_hash:
        underlying_script = kwargs.get("p2sh_lookup", {}).get(script_hash, None)
        if underlying_script is None:
            raise ValueError("p2sh_lookup not set or does not have script hash for %s" % b2h(script_hash))
        tx_context.solution_script = BitcoinScriptTools.compile_push_data_list([underlying_script])
        kwargs["solution_reserve_count"] = 1
    constraints = []
    try:
        solution_checker.check_solution(
            tx_context, traceback_f=make_traceback_f(solution_checker, tx_context, constraints, **kwargs))
    except ScriptError:
        pass
    if script_hash:
        constraints.append(Operator('IS_EQUAL', Atom("x_0"), underlying_script))
    return constraints


def solve_for_constraints(constraints, **kwargs):
    solutions = []
    for c in constraints:
        s = solutions_for_constraint(c, **kwargs)
        # s = (solution_f, target atom, dependency atom list)
        if s:
            solutions.append(s)
    deps = set()
    for c in constraints:
        deps.update(c.dependencies())
    solved_values = { d: None for d in deps }
    progress = True
    while progress and any(v is None for v in solved_values.values()):
        progress = False
        for solution, target, dependencies in solutions:
            if any(solved_values.get(t) is not None for t in target):
                continue
            if any(solved_values[d] is None for d in dependencies):
                continue
            s = solution(solved_values, **kwargs)
            solved_values.update(s)
            progress = progress or (len(s) > 0)

    x_keys = sorted((k for k in solved_values.keys() if k > Atom("x")), reverse=True)
    w_keys = sorted((k for k in solved_values.keys() if k < Atom("x")), reverse=True)
    solution_list = [solved_values.get(k) for k in x_keys]
    witness_list = [solved_values.get(k) for k in w_keys]
    return solution_list, witness_list


def solve(tx, tx_in_idx, **kwargs):
    constraints = determine_constraints(tx, tx_in_idx, **kwargs)
    for c in constraints:
        print(c, sorted(c.dependencies()))
    return solve_for_constraints(constraints, **kwargs)


class CONSTANT(object):
    def __init__(self, name):
        self._name = name


class VAR(object):
    def __init__(self, name):
        self._name = name


class LIST(object):
    def __init__(self, name):
        self._name = name


def solutions_for_constraint(c, **kwargs):
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

    m = constraint_matches(c, ('IS_TRUE', ('EQUAL', CONSTANT("0"), ('HASH160', VAR("1")))))
    if m:
        the_hash = m["0"]

        def f(solved_values, **kwargs):
            return {m["1"]: kwargs["pubkey_for_hash"](the_hash)}

        return (f, [m["1"]], ())

    m = constraint_matches(c, ('IS_TRUE', ('EQUAL', VAR("0"), CONSTANT('1'))))
    if m:
        def f(solved_values, **kwargs):
            return {m["0"]: m["1"]}

        return (f, [m["0"]], ())

    m = constraint_matches(c, (('IS_TRUE', ('CHECKSIG', VAR("0"), VAR("1"), CONSTANT("2")))))
    if m:

        def f(solved_values, **kwargs):
            pubkey = lookup_solved_value(solved_values, m["0"])
            privkey = kwargs["privkey_for_pubkey"](pubkey)
            signature_type = kwargs.get("signature_type")
            sig_hash = m["2"](signature_type)
            signature = _create_script_signature(privkey, sig_hash, signature_type)
            return {m["1"]: signature}
        return (f, [m["1"]], filtered_dependencies(m["0"]))

    m = constraint_matches(c, (('IS_TRUE', ('CHECKMULTISIG', LIST("0"), LIST("1"), CONSTANT("2")))))
    if m:

        def f(solved_values, **kwargs):
            signature_for_hash_type_f = kwargs.get("signature_for_hash_type_f")
            script_to_hash = kwargs.get("script_to_hash")

            secs_solved = set()
            signature_type = kwargs.get("signature_type")

            existing_signatures = []
            existing_script = kwargs.get("existing_script")
            if existing_script:
                existing_signatures, secs_solved = _find_signatures(
                    existing_script, signature_for_hash_type_f, script_to_hash)

            sec_keys = m["0"]
            signature_variables = m["1"]

            signature_placeholder = kwargs.get("signature_placeholder", DEFAULT_PLACEHOLDER_SIGNATURE)

            privkey_for_pubkey = kwargs["privkey_for_pubkey"]

            for signature_order, sec_key in enumerate(sec_keys):
                if sec_key in secs_solved:
                    continue
                if len(existing_signatures) >= len(signature_variables):
                    break
                secret_exponent = privkey_for_pubkey(sec_key)
                if not secret_exponent:
                    continue
                signature_type = kwargs.get("signature_type")
                sig_hash = m["2"](signature_type)
                binary_signature = _create_script_signature(secret_exponent, sig_hash, signature_type)
                existing_signatures.append((signature_order, binary_signature))

            # pad with placeholder signatures
            if signature_placeholder is not None:
                while len(existing_signatures) < len(signature_variables):
                    existing_signatures.append((-1, signature_placeholder))
            existing_signatures.sort()
            return dict(zip(signature_variables, (es[-1] for es in existing_signatures)))
        return (f, m["1"], ())

    m = constraint_matches(c, (('IS_EQUAL', VAR("0"), CONSTANT("1"))))
    if m:

        def f(solved_values, **kwargs):
            return {m["0"]: m["1"]}
        return (f, [m["0"]], ())



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
                if not isinstance(c1, Atom):
                    d[m1._name] = c1
                    continue
            if isinstance(m1, VAR):
                if isinstance(c1, (bytes, Atom)):
                    d[m1._name] = c1
                    continue
            if isinstance(m1, LIST):
                if isinstance(c1, (tuple, list)):
                    d[m1._name] = c1
                    continue
            if c1 == m1:
                continue
            return False
        return d


def test_solve(tx, tx_in_idx, **kwargs):
    solution_list, witness_list = solve(tx, tx_in_idx, **kwargs)
    solution_script = BitcoinScriptTools.compile_push_data_list(solution_list)
    print(BitcoinScriptTools.disassemble(solution_script))
    print(witness_list)
    tx.txs_in[tx_in_idx].script = solution_script
    tx.txs_in[tx_in_idx].witness = witness_list
    check_solution(tx, tx_in_idx)


def make_test_tx(input_script):
    previous_hash = b'\1' * 32
    txs_in = [TxIn(previous_hash, 0)]
    txs_out = [TxOut(1000, standard_tx_out_script(Key(1).address()))]
    version, lock_time = 1, 0
    tx = Tx(version, txs_in, txs_out, lock_time)
    unspents = [TxOut(1000, input_script)]
    tx.set_unspents(unspents)
    return tx


def test_tx(incoming_script, **kwargs):
    keys = [Key(i) for i in range(1, 20)]
    tx = make_test_tx(incoming_script)
    tx_in_idx = 0

    def pubkey_for_hash(the_hash):
        for key in keys:
            if the_hash == key.hash160():
                return key.sec()

    def privkey_for_pubkey(pubkey):
        for key in keys:
            if pubkey == key.sec():
                return key.secret_exponent()

    kwargs.update(dict(pubkey_for_hash=pubkey_for_hash,
                       privkey_for_pubkey=privkey_for_pubkey,
                       signature_type=1))

    test_solve(tx, tx_in_idx, **kwargs)


def test_p2pkh():
    key = Key(1)
    test_tx(standard_tx_out_script(key.address()))


def test_p2pk():
    key = Key(1)
    test_tx(ScriptPayToPublicKey.from_key(key).script())


def test_nonstandard_p2pkh():
    key = Key(1)
    test_tx(BitcoinScriptTools.compile("OP_SWAP") + standard_tx_out_script(key.address()))


def test_p2multisig():
    keys = [Key(i) for i in (1, 2, 3)]
    secs = [k.sec() for k in keys]
    test_tx(ScriptMultisig(2, secs).script())


def test_p2sh():
    keys = [Key(i) for i in (1, 2, 3)]
    secs = [k.sec() for k in keys]
    script = ScriptMultisig(1, secs).script()
    test_tx(script, p2sh_lookup=build_p2sh_lookup([script]))

    script = BitcoinScriptTools.compile("OP_SWAP") + standard_tx_out_script(keys[0].address())
    test_tx(script, p2sh_lookup=build_p2sh_lookup([script]))

    script = ScriptPayToPublicKey.from_key(keys[2]).script()
    test_tx(script, p2sh_lookup=build_p2sh_lookup([script]))


def test_p2pkh_wit():
    key = Key(1)
    script = BitcoinScriptTools.compile("OP_0 [%s]" % b2h(key.hash160()))
    test_tx(script)


def main():
    if 1:
        test_p2pkh()
        test_p2pk()
        test_nonstandard_p2pkh()
        test_p2multisig()
    test_p2sh()


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
