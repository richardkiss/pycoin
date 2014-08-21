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
bytes_to_ints = (lambda x: (ord(c) for c in x)) if bytes == str else lambda x: x

if hasattr(int, "to_bytes"):
    int_to_bytes = lambda v: v.to_bytes((v.bit_length()+7)//8, byteorder="big")
else:
    def int_to_bytes(v):
        l = bytearray()
        while v > 0:
            v, mod = divmod(v, 256)
            l.append(mod)
        l.reverse()
        return bytes(l)

if hasattr(int, "from_bytes"):
    bytes_to_int = lambda v: int.from_bytes(v, byteorder="big")
else:
    def bytes_to_int(s):
        v = 0
        b = 0
        for c in bytes_to_ints(s):
            v += (c << b)
            b += 8
        return v

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
            size = bytes_to_int(script[pc:pc+1])
            pc += 1
        elif opcode == OPCODE_TO_INT["OP_PUSHDATA2"]:
            size = bytes_to_int(script[pc:pc+2])
            pc += 2
        elif opcode == OPCODE_TO_INT["OP_PUSHDATA4"]:
            size = bytes_to_int(script[pc:pc+4])
            pc += 4
        data = script[pc:pc+size]
        pc += size
    return opcode, data, pc

def write_push_data(data_list, f):
    # return bytes that causes the given data to be pushed onto the stack
    for t in data_list:
        if len(t) == 1:
            v = bytes_to_ints(t)[0]
            if v <= 16:
                f.write(bytes_from_int(OPCODE_TO_INT["OP_%d" % v]))
                continue
        if len(t) <= 255:
            if len(t) > 75:
                f.write(bytes_from_int(OPCODE_TO_INT["OP_PUSHDATA1"]))
            f.write(int_to_bytes(len(t)))
            f.write(t)
        elif len(t) <= 65535:
            f.write(bytes_from_int(OPCODE_TO_INT["OP_PUSHDATA2"]))
            f.write(int_to_bytes(len(t)))
            f.write(t)
        # BRAIN DAMAGE: if len(t) is too much, we need a different opcode
        # This will never be used in practice as it makes the scripts too long.

def bin_script(data_list):
    f = io.BytesIO()
    write_push_data(data_list, f)
    return f.getvalue()

def compile(s):
    """Compile the given script. Returns a bytes object with the compiled script."""
    f = io.BytesIO()
    for t in s.split():
        if t in OPCODE_TO_INT:
            f.write(bytes_from_int(OPCODE_TO_INT[t]))
        elif ("OP_%s" % t) in OPCODE_TO_INT:
            f.write(bytes_from_int(OPCODE_TO_INT["OP_%s" % t]))
        else:
            if (t[0], t[-1]) == ('[', ']'):
                t = t[1:-1]
            if len(t) == 1:
                t = "0" + t
            t = binascii.unhexlify(t.encode("utf8"))
            write_push_data([t], f)
    return f.getvalue()

def opcode_list(script):
    """Disassemble the given script. Returns a list of opcodes."""
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
    return opcodes

def disassemble(script):
    """Disassemble the given script. Returns a string."""
    return ' '.join(opcode_list(script))

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
