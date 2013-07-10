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

import io

from ..encoding import double_sha256, from_bytes_32
from ..serialize import b2h, b2h_rev
from ..serialize.bitcoin_streamer import parse_struct, stream_struct

from .TxIn import TxIn, TxInGeneration
from .TxOut import TxOut

from .script import opcodes
from .script import tools
from .script.vm import verify_script

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

class ValidationFailureError(Exception): pass

class Tx(object):
    @classmethod
    def coinbase_tx(class_, public_key_sec, coin_value, coinbase_bytes=b'', version=1, lock_time=0):
        """Create a special "first in block" transaction that includes the bonus for mining and transaction fees."""
        tx_in = TxInGeneration(previous_hash=(b'\0' * 32), previous_index=(1<<32)-1, script=coinbase_bytes)
        COINBASE_SCRIPT_OUT = "%s OP_CHECKSIG"
        script_text = COINBASE_SCRIPT_OUT % b2h(public_key_sec)
        script_bin = tools.compile(script_text)
        tx_out = TxOut(coin_value, script_bin)
        return class_(version, [tx_in], [tx_out], lock_time)

    @classmethod
    def parse(self, f, is_first_in_block=False):
        """Parse a Bitcoin transaction Tx from the file-like object f."""
        version, count = parse_struct("LI", f)
        txs_in = []
        if is_first_in_block:
            txs_in.append(TxInGeneration.parse(f))
            count = count - 1
        for i in range(count):
            txs_in.append(TxIn.parse(f))
        count, = parse_struct("I", f)
        txs_out = []
        for i in range(count):
            txs_out.append(TxOut.parse(f))
        lock_time, = parse_struct("L", f)
        return self(version, txs_in, txs_out, lock_time)

    def __init__(self, version, txs_in, txs_out, lock_time=0):
        self.version = version
        self.txs_in = txs_in
        self.txs_out = txs_out
        self.lock_time = lock_time

    def stream(self, f):
        """Stream a Bitcoin transaction Tx to the file-like object f."""
        stream_struct("LI", f, self.version, len(self.txs_in))
        for t in self.txs_in:
            t.stream(f)
        stream_struct("I", f, len(self.txs_out))
        for t in self.txs_out:
            t.stream(f)
        stream_struct("L", f, self.lock_time)

    def hash(self, hash_type=None):
        """Return the hash for this Tx object."""
        s = io.BytesIO()
        self.stream(s)
        if hash_type:
            stream_struct("L", s, hash_type)
        return double_sha256(s.getvalue())

    def id(self):
        """Return the human-readable hash for this Tx object."""
        return b2h_rev(self.hash())

    def signature_hash(self, tx_out_script, unsigned_txs_out_idx, hash_type):
        """Return the canonical hash for a transaction. We need to
        remove references to the signature, since it's a signature
        of the hash before the signature is applied.

        tx_out_script: the script the coins for unsigned_txs_out_idx are coming from
        unsigned_txs_out_idx: where to put the tx_out_script
        hash_type: always seems to be SIGHASH_ALL
        """

        # In case concatenating two scripts ends up with two codeseparators,
        # or an extra one at the end, this prevents all those possible incompatibilities.
        tx_out_script = tools.delete_subscript(tx_out_script, [opcodes.OP_CODESEPARATOR])

        # blank out other inputs' signatures
        def tx_in_for_idx(idx, tx_in):
            if idx == unsigned_txs_out_idx:
                return TxIn(tx_in.previous_hash, tx_in.previous_index, tx_out_script, tx_in.sequence)
            return TxIn(tx_in.previous_hash, tx_in.previous_index, b'', tx_in.sequence)

        txs_in = [tx_in_for_idx(i, tx_in) for i, tx_in in enumerate(self.txs_in)]
        txs_out = self.txs_out

        # Blank out some of the outputs
        if (hash_type & 0x1f) == SIGHASH_NONE:
            # Wildcard payee
            txs_out = []

            # Let the others update at will
            for i in range(len(txs_in)):
                if i != unsigned_txs_out_idx:
                    txs_in[i].sequence = 0

        elif (hash_type & 0x1f) == SIGHASH_SINGLE:
            # Only lockin the txout payee at same index as txin
            # BRAIN DAMAGE: this probably doesn't work right
            txs_out = [TxOut(-1, b'')] * unsigned_txs_out_idx
            txs_out.append(self.txs_out[unsigned_txs_out_idx])

            # Let the others update at will
            for i in range(len(tx_tmp.txs_in)):
                if i != unsigned_txs_out_idx:
                    txs_in[i].sequence = 0

        # Blank out other inputs completely, not recommended for open transactions
        if hash_type & SIGHASH_ANYONECANPAY:
            txs_in = [txs_in[unsigned_txs_out_idx]]

        tmp_tx = Tx(self.version, txs_in, txs_out, self.lock_time)
        return from_bytes_32(tmp_tx.hash(hash_type=hash_type))

    def validate(self, tx_out_for_hash_index_f):
        """Raise a ValidationFailureError if the transaction does not validate.

        tx_out_for_hash_index_f must be a function that takes two parameters:
            previous_hash and previous_index; and returns the
            corresponding TxOut.
        """
        for idx, tx_in in enumerate(self.txs_in):
            possible_solution = tx_in.script
            tx_out_script_to_check = tx_out_for_hash_index_f(tx_in.previous_hash, tx_in.previous_index).script
            signature_hash = self.signature_hash(tx_out_script_to_check, idx, hash_type=SIGHASH_ALL)
            if not verify_script(possible_solution, tx_out_script_to_check, signature_hash, hash_type=0):
                previous_hash = tx_in.previous_hash
                previous_index = tx_in.previous_index
                raise ValidationFailureError("Tx %s TxIn index %d script did not verify" % (b2h_rev(previous_hash), previous_index))

    def __str__(self):
        return "Tx [%s]" % self.id()

    def __repr__(self):
        return "Tx [%s] (v:%d) [%s] [%s]" % (self.id(), self.version, ", ".join(str(t) for t in self.txs_in), ", ".join(str(t) for t in self.txs_out))
