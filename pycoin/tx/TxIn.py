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

from .. import encoding

from ..serialize import b2h, b2h_rev, h2b
from ..serialize.bitcoin_streamer import parse_struct, stream_struct

from .script.tools import disassemble, opcode_list
from .script.vm import verify_script

ZERO = b'\0' * 32


class TxIn(object):
    """
    The part of a Tx that specifies where the Bitcoin comes from.
    """
    def __init__(self, previous_hash, previous_index, script=b'', sequence=4294967295):
        self.previous_hash = previous_hash
        self.previous_index = previous_index
        self.script = script
        self.sequence = sequence

    @classmethod
    def coinbase_tx_in(self, script):
        tx = TxIn(previous_hash=ZERO, previous_index=4294967295, script=script)
        return tx

    def stream(self, f, blank_solutions=False):
        script = b'' if blank_solutions else self.script
        stream_struct("#LSL", f, self.previous_hash, self.previous_index, script, self.sequence)

    @classmethod
    def parse(self, f):
        return self(*parse_struct("#LSL", f))

    def is_coinbase(self):
        return self.previous_hash == ZERO

    def bitcoin_address(self, address_prefix=b'\0'):
        if self.is_coinbase():
            return "(coinbase)"
        # attempt to return the source address, or None on failure
        opcodes = opcode_list(self.script)
        if len(opcodes) == 2 and opcodes[0].startswith("30"):
            # the second opcode is probably the public key as sec
            sec = h2b(opcodes[1])
            bitcoin_address = encoding.hash160_sec_to_bitcoin_address(
                encoding.hash160(sec), address_prefix=address_prefix)
            return bitcoin_address
        return "(unknown)"

    def verify(self, tx_out_script, signature_for_hash_type_f, expected_hash_type=None):
        """
        Return True or False depending upon whether this TxIn verifies.

        tx_out_script: the script of the TxOut that corresponds to this input
        signature_hash: the hash of the partial transaction
        """
        return verify_script(self.script, tx_out_script, signature_for_hash_type_f, expected_hash_type=expected_hash_type)

    def __str__(self):
        if self.is_coinbase():
            return 'TxIn<COINBASE: %s>' % b2h(self.script)
        return 'TxIn<%s[%d] "%s">' % (
            b2h_rev(self.previous_hash), self.previous_index, disassemble(self.script))
