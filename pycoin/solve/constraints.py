from __future__ import annotations

import functools
import pdb
from typing import Any, Callable


@functools.total_ordering
class Atom(object):
    def __init__(self, name: str) -> None:
        self.name = name

    def dependencies(self) -> frozenset[Atom]:
        return frozenset([self])

    def __len__(self) -> int:
        # HACK to allow MAX_BLOB_LENGTH comparison to succeed
        return 0

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Atom):
            return self.name == other.name
        return False

    def __lt__(self, other: object) -> bool:
        if isinstance(other, Atom):
            return self.name < other.name
        return False

    def __hash__(self) -> int:
        return self.name.__hash__()

    def __repr__(self) -> str:
        return "<%s>" % self.name


class Operator(Atom):
    def __init__(self, op_name: str, *args: Any) -> None:
        self._op_name = op_name
        self._args = tuple(args)
        s: set[Atom] = set()
        for a in self._args:
            if hasattr(a, "dependencies"):
                s.update(a.dependencies())
        self._dependencies = frozenset(s)

    def __hash__(self) -> int:
        return self._args.__hash__()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Operator):
            return self._op_name, self._args == other._op_name, other._args  # type: ignore[return-value]
        return False

    def dependencies(self) -> frozenset[Atom]:
        return self._dependencies

    def __repr__(self) -> str:
        return "(%s %s)" % (self._op_name, " ".join(repr(a) for a in self._args))


def make_op_if(constraints: list[Any]) -> Callable[[Any], None]:

    def my_op_if(vm: Any) -> None:
        pdb.set_trace()
        t = vm.stack.pop()
        t = Operator("IF", t)
        vm.stack.append(t)

    return my_op_if


def make_op_hash160(constraints: list[Any]) -> Callable[[Any], None]:

    def my_op_hash160(vm: Any) -> None:
        t = vm.stack.pop()
        t = Operator("HASH160", t)
        vm.stack.append(t)

    setattr(my_op_hash160, "stack_size", 1)
    return my_op_hash160


def make_op_equal(constraints: list[Any]) -> Callable[[Any], None]:
    def my_op_equal(vm: Any) -> None:
        t1 = vm.stack.pop()
        t2 = vm.stack.pop()
        c = Operator("EQUAL", t1, t2)
        vm.append(c)

    setattr(my_op_equal, "stack_size", 2)
    return my_op_equal


def make_op_equalverify(constraints: list[Any]) -> Callable[[Any], None]:
    def my_op_equalverify(vm: Any) -> None:
        t1 = vm.stack.pop()
        t2 = vm.stack.pop()
        c = Operator("EQUAL", t1, t2)
        constraints.append(c)

    setattr(my_op_equalverify, "stack_size", 2)
    return my_op_equalverify


def make_op_checksig(constraints: list[Any]) -> Callable[[Any], None]:
    def my_op_checksig(vm: Any) -> None:

        def sighash_f(signature_type: Any) -> Any:
            return vm.signature_for_hash_type_f(signature_type, [], vm)

        t1 = vm.stack.pop()
        t2 = vm.stack.pop()
        t = Operator("SIGNATURES_CORRECT", [t1], [t2], sighash_f)
        constraints.append(Operator("IS_PUBKEY", t1))
        constraints.append(Operator("IS_SIGNATURE", t2))
        vm.stack.append(t)

    return my_op_checksig


def make_op_checkmultisig(constraints: list[Any]) -> Callable[[Any], None]:
    def my_op_checkmultisig(vm: Any) -> None:

        def sighash_f(signature_type: Any) -> Any:
            return vm.signature_for_hash_type_f(signature_type, [], vm)

        key_count = vm.IntStreamer.int_from_script_bytes(
            vm.stack.pop(), require_minimal=False
        )
        public_pair_blobs = []
        for i in range(key_count):
            constraints.append(Operator("IS_PUBKEY", vm.stack[-1]))
            public_pair_blobs.append(vm.stack.pop())
        signature_count = vm.IntStreamer.int_from_script_bytes(
            vm.stack.pop(), require_minimal=False
        )
        sig_blobs = []
        for i in range(signature_count):
            constraints.append(Operator("IS_SIGNATURE", vm.stack[-1]))
            sig_blobs.append(vm.stack.pop())
        t1 = vm.stack.pop()
        constraints.append(Operator("EQUAL", t1, b""))
        t = Operator("SIGNATURES_CORRECT", public_pair_blobs, sig_blobs, sighash_f)
        vm.stack.append(t)

    return my_op_checkmultisig


def make_traceback_f(
    constraints: list[Any],
    int_for_opcode_f: Callable[[str], int | None],
    reset_stack_f: Callable[[list[Any]], list[Any]],
) -> Any:

    TWEAKED_OPCODES = (
        ("OP_HASH160", make_op_hash160),
        ("OP_EQUALVERIFY", make_op_equalverify),
        ("OP_EQUAL", make_op_equal),
        ("OP_CHECKSIG", make_op_checksig),
        ("OP_CHECKMULTISIG", make_op_checkmultisig),
    )

    MY_OPCODES = {int_for_opcode_f(k): v(constraints) for k, v in TWEAKED_OPCODES}

    def prelaunch(vmc: Any) -> None:
        if not vmc.is_solution_script:
            # reset stack
            vmc.stack = reset_stack_f(vmc.stack)

    def traceback_f(opcode: int, data: bytes | None, pc: int, vm: Any) -> Any:
        f = MY_OPCODES.get(opcode)
        if f is None:
            return
        stack_size = getattr(f, "stack_size", 0)
        if stack_size and all(not isinstance(v, Atom) for v in vm.stack[-stack_size:]):
            return
        return f

    def postscript(vmc: Any) -> None:
        if not vmc.is_solution_script:
            if isinstance(vmc.stack[-1], Atom):
                constraints.append(vmc.stack[-1])
            vmc.stack = [vmc.VM_TRUE]

    setattr(traceback_f, "prelaunch", prelaunch)
    setattr(traceback_f, "postscript", postscript)
    return traceback_f
