# -*- coding: utf-8 -*-
"""
Some tools for traversing Bitcoin VM scripts.


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

import binascii
import io
import logging

from .opcodes import OPCODE_TO_INT, INT_TO_OPCODE

bytes_from_int = chr if bytes == str else lambda x: bytes([x])

def get_opcode(script, pc):
    """Step through the script, returning a tuple with the next opcode, the next
    piece of data (if the opcode represents data), and the new PC."""
    opcode = ord(script[pc:pc+1])
    pc += 1
    data = b''
    if opcode <= OPCODE_TO_INT["OP_PUSHDATA4"]:
        if opcode < OPCODE_TO_INT["OP_PUSHDATA1"]:
            size = opcode
        elif opcode == OPCODE_TO_INT["OP_PUSHDATA1"]:
            size = as_bignum(script[pc])
            pc += 1
        elif opcode == OPCODE_TO_INT["OP_PUSHDATA2"]:
            size = as_bignum(script[pc:pc+2])
            pc += 2
        elif opcode == OPCODE_TO_INT["OP_PUSHDATA4"]:
            size = as_bignum(script[pc:pc+4])
            pc += 4
        data = script[pc:pc+size]
        pc += size
    return opcode, data, pc

def compile(s):
    """Compile the given script. Returns a bytes object with the compiled script."""
    f = io.BytesIO()
    for t in s.split():
        if t in OPCODE_TO_INT:
            f.write(bytes_from_int(OPCODE_TO_INT[t]))
        else:
            t = binascii.unhexlify(t.encode("utf8"))
            # BRAIN DAMAGE: if len(t) is too much, we need a different opcode
            f.write(bytes_from_int(len(t)))
            f.write(t)
    return f.getvalue()

def disassemble(script):
    """Disassemble the given script. Returns a string."""
    opcodes = []
    pc = 0
    while pc < len(script):
        opcode, data, pc = get_opcode(script, pc)
        if len(data) > 0:
            opcodes.append(binascii.hexlify(data).decode("utf8"))
            continue
        if not opcode in INT_TO_OPCODE:
            logging.info("missing opcode %r", opcode)
            continue
        opcodes.append(INT_TO_OPCODE[opcode])
    return ' '.join(opcodes)

def delete_subscript(script, subscript):
    """Returns a script with the given subscript removed. The subscript
    must appear in the main script aligned to opcode boundaries for it
    to be removed."""
    new_script = bytearray()
    pc = 0
    size = len(subscript)
    while pc < len(script):
        if script[pc:pc+size] == subscript:
            pc += size
            continue
        opcode, data, pc = get_opcode(script, pc)
        new_script.append(opcode)
        new_script += data
    return bytes(new_script)
