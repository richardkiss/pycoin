from . import errno

from .flags import (
    SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_TYPE_FLAG,
    VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    VERIFY_CHECKLOCKTIMEVERIFY,
    VERIFY_MINIMALIF, VERIFY_CHECKSEQUENCEVERIFY,
)

from pycoin.coins.SolutionChecker import ScriptError


def make_bad_opcode(opcode, even_outside_conditional=False, err=errno.BAD_OPCODE):
    def bad_opcode(vm):
        raise ScriptError("invalid opcode %s at %d" % (opcode, vm.pc-1), err)
    bad_opcode.outside_conditional = even_outside_conditional
    return bad_opcode


def do_OP_CODESEPARATOR(vm):
    vm.begin_code_hash = vm.pc


def do_OP_TOALTSTACK(vm):
    vm.altstack.append(vm.pop())


def do_OP_RESERVED(vm):
    if vm.conditional_stack.all_if_true():
        raise ScriptError("OP_RESERVED encountered", errno.BAD_OPCODE)
    vm.op_count -= 1


do_OP_RESERVED.outside_conditional = True


def do_OP_FROMALTSTACK(vm):
    if len(vm.altstack) < 1:
        raise ScriptError("alt stack empty", errno.INVALID_ALTSTACK_OPERATION)
    vm.append(vm.altstack.pop())


def discourage_nops(vm):
    if (vm.flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS):
        raise ScriptError("discouraging nops", errno.DISCOURAGE_UPGRADABLE_NOPS)


def make_if(reverse_bool=False):
    def f(vm):
        stack = vm.stack
        conditional_stack = vm.conditional_stack
        the_bool = False
        if conditional_stack.all_if_true():
            if len(stack) < 1:
                raise ScriptError("IF with no condition", errno.UNBALANCED_CONDITIONAL)
            item = vm.pop()
            if vm.flags & VERIFY_MINIMALIF:
                if item not in (vm.VM_FALSE, vm.VM_TRUE):
                    raise ScriptError("non-minimal IF", errno.MINIMALIF)
            the_bool = vm.bool_from_script_bytes(item)
        vm.conditional_stack.OP_IF(the_bool, reverse_bool=reverse_bool)
    f.outside_conditional = True
    return f


def do_OP_ELSE(vm):
    vm.conditional_stack.OP_ELSE()


do_OP_ELSE.outside_conditional = True


def do_OP_ENDIF(vm):
    vm.conditional_stack.OP_ENDIF()


do_OP_ENDIF.outside_conditional = True


def do_OP_CHECKLOCKTIMEVERIFY(vm):
    if not (vm.flags & VERIFY_CHECKLOCKTIMEVERIFY):
        if (vm.flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS):
            raise ScriptError("discouraging nops", errno.DISCOURAGE_UPGRADABLE_NOPS)
        return
    if vm.tx_context.sequence == 0xffffffff:
        raise ScriptError("nSequence equal to 0xffffffff")
    if len(vm.stack) < 1:
        raise ScriptError("empty stack on CHECKLOCKTIMEVERIFY")
    if len(vm.stack[-1]) > 5:
        raise ScriptError("script number overflow")
    max_lock_time = vm.pop_int()
    vm.push_int(max_lock_time)
    if max_lock_time < 0:
        raise ScriptError("top stack item negative on CHECKLOCKTIMEVERIFY")
    era_max = (max_lock_time >= 500000000)
    era_lock_time = (vm.tx_context.lock_time >= 500000000)
    if era_max != era_lock_time:
        raise ScriptError("eras differ in CHECKLOCKTIMEVERIFY")
    if max_lock_time > vm.tx_context.lock_time:
        raise ScriptError("nLockTime too soon")


def _check_sequence_verify(sequence, tx_context_sequence):
    # this mask is applied to extract lock-time from the sequence field
    SEQUENCE_LOCKTIME_MASK = 0xffff

    mask = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK
    sequence_masked = sequence & mask
    tx_sequence_masked = tx_context_sequence & mask
    if not (((tx_sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG) and
             (sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG)) or
            ((tx_sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG) and
             (sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG))):
        raise ScriptError("sequence numbers not comparable")
    if sequence_masked > tx_sequence_masked:
        raise ScriptError("sequence number too small")


def do_OP_CHECKSEQUENCEVERIFY(vm):
    if not (vm.flags & VERIFY_CHECKSEQUENCEVERIFY):
        if (vm.flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS):
            raise ScriptError("discouraging nops", errno.DISCOURAGE_UPGRADABLE_NOPS)
        return
    if len(vm.stack) < 1:
        raise ScriptError("empty stack on CHECKSEQUENCEVERIFY", errno.INVALID_STACK_OPERATION)
    if len(vm.stack[-1]) > 5:
        raise ScriptError("script number overflow", errno.INVALID_STACK_OPERATION+1)
    sequence = vm.pop_int()
    vm.push_int(sequence)
    if sequence < 0:
        raise ScriptError(
            "top stack item negative on CHECKSEQUENCEVERIFY", errno.NEGATIVE_LOCKTIME)
    if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
        return
    # do the actual check
    if vm.tx_context.version < 2:
        raise ScriptError("CHECKSEQUENCEVERIFY: bad tx version", errno.UNSATISFIED_LOCKTIME)
    if vm.tx_context.sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
        raise ScriptError("CHECKSEQUENCEVERIFY: locktime disabled")

    _check_sequence_verify(sequence, vm.tx_context.sequence)


def extra_opcodes():
    d = {}
    BAD_OPCODES = "OP_VERIF OP_VERNOTIF ".split()
    for opcode in BAD_OPCODES:
        d[opcode] = make_bad_opcode(opcode, even_outside_conditional=True)

    DISABLED_OPCODES = (
        "OP_CAT OP_SUBSTR OP_LEFT OP_RIGHT OP_INVERT OP_AND OP_OR OP_XOR OP_2MUL OP_2DIV OP_MUL "
        "OP_DIV OP_MOD OP_LSHIFT OP_RSHIFT".split())
    for opcode in DISABLED_OPCODES:
        d[opcode] = make_bad_opcode(
            opcode, even_outside_conditional=True, err=errno.DISABLED_OPCODE)

    BAD_OPCODES_OUTSIDE_IF = "OP_NULLDATA OP_PUBKEYHASH OP_PUBKEY OP_INVALIDOPCODE".split()
    for opcode in BAD_OPCODES_OUTSIDE_IF:
        d[opcode] = make_bad_opcode(opcode, even_outside_conditional=False)

    NOP_SET = (
        "OP_NOP1 OP_NOP3 OP_NOP4 OP_NOP5 OP_NOP6 OP_NOP7 OP_NOP8 OP_NOP9 OP_NOP10".split())
    for opcode in NOP_SET:
        d[opcode] = discourage_nops

    d["OP_IF"] = make_if()
    d["OP_NOTIF"] = make_if(reverse_bool=True)

    for i in (1, 2, 4):
        d["OP_PUSHDATA%d" % i] = lambda s: 0

    for v in range(0, 128):
        d["OP_%d" % v] = lambda s: 0
    return d


"""
The MIT License (MIT)

Copyright (c) 2013-2017 by Richard Kiss

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
