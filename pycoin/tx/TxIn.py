# -*- coding: utf-8 -*-
"""
Deal with the part of a Tx that specifies where the Bitcoin comes from.


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

from ..serialize import b2h, b2h_rev
from ..serialize.bitcoin_streamer import parse_struct, stream_struct

from .script.tools import disassemble

class TxIn(object):
    """
    The part of a Tx that specifies where the Bitcoin comes from.
    """
    def __init__(self, previous_hash, previous_index, script=b'', sequence=4294967295):
        self.previous_hash = previous_hash
        self.previous_index = previous_index
        self.script = script
        self.sequence = sequence

    def stream(self, f):
        stream_struct("#LSL", f, self.previous_hash, self.previous_index, self.script, self.sequence)

    @classmethod
    def parse(self, f):
        return self(*parse_struct("#LSL", f))

    def __str__(self):
        return 'TxIn<%s[%d] "%s">' % (b2h_rev(self.previous_hash), self.previous_index, disassemble(self.script))

class TxInGeneration(TxIn):
    def __str__(self):
        return 'TxIn<COINBASE: %s>' % b2h(self.script)
