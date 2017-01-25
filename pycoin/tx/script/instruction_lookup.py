# -*- coding: utf-8 -*-
"""
Parse, stream, create, sign and verify Bitcoin transactions as Tx structures.


The MIT License (MIT)

Copyright (c) 2013 by Richard Kiss

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

from . import intops, stackops, checksigops, miscops
from . import ScriptError
from . import errno


def make_bad_instruction(v):
    def f(vm_state):
        raise ScriptError("invalid instruction x%02x at %d" % (v, vm_state.pc), errno.BAD_OPCODE)
    return f


def collect_opcodes(module):
    d = {}
    for k in dir(module):
        if k.startswith("do_OP"):
            d[k[3:]] = getattr(module, k)
    return d


def make_instruction_lookup(opcode_pairs):
    # start with all opcodes invalid
    instruction_lookup = [make_bad_instruction(i) for i in range(256)]
    for i in range(0, 76):
        instruction_lookup[i] = lambda s: 0
    opcode_lookups = {}
    opcode_lookups.update(stackops.all_opcodes())
    opcode_lookups.update(checksigops.collect_opcodes())
    opcode_lookups.update(collect_opcodes(intops))
    opcode_lookups.update(miscops.collect_opcodes())
    for opcode_name, opcode_value in opcode_pairs:
        if opcode_name in opcode_lookups:
            instruction_lookup[opcode_value] = opcode_lookups[opcode_name]
    return instruction_lookup
