# -*- coding: utf-8 -*-
"""
A template for unsigned transactions.

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

from ..encoding import bitcoin_address_to_hash160_sec
from ..serialize import b2h, b2h_rev
from ..serialize.bitcoin_streamer import parse_struct, stream_struct

from .Tx import Tx, SIGHASH_ALL, ValidationFailureError
from .TxIn import TxIn
from .TxOut import TxOut

from .script import tools
from .script.vm import verify_script
from .script.solvers import SolvingError

class UnsignedTx(Tx):
    @classmethod
    def parse(class_, f, is_first_in_block=False):
        """Parse a Bitcoin transaction Tx from the file-like object f."""
        version, count = parse_struct("LI", f)
        txs_in = []
        for i in range(count):
            txs_in.append(TxIn.parse(f))
        count, = parse_struct("I", f)
        txs_out = []
        for i in range(count):
            txs_out.append(TxOut.parse(f))
        lock_time, = parse_struct("L", f)
        count, = parse_struct("I", f)
        txs_out_for_txs_in = []
        for i in range(count):
            txs_out_for_txs_in.append(TxOut.parse(f))
        return class_(txs_out_for_txs_in, version, txs_in, txs_out, lock_time)

    def __init__(self, txs_out_for_txs_in, version, txs_in, txs_out, lock_time=0):
        """
        """
        super(UnsignedTx, self).__init__(version, txs_in, txs_out, lock_time)
        self.txs_out_for_txs_in = txs_out_for_txs_in

    def stream(self, f):
        """Stream an UnsignedTx to the file-like object f."""
        super(UnsignedTx, self).stream(f)
        stream_struct("I", f, len(self.txs_out_for_txs_in))
        for t in self.txs_out_for_txs_in:
            t.stream(f)

    @classmethod
    def standard_tx(class_, previous_hash_index_txout_tuple_list, coin_value__bitcoin_address__tuple_list, version=1, lock_time=0, is_test=False):
        """Create a standard transaction.
        previous_hash_index_txout_tuple_list: a list of tuples of the form
            (previous hash, previous index, tx_out) corresponding to the
            source coins. You obviously must have private keys for these incoming
            transactions if you want to sign it.
        coin_value__bitcoin_address__tuple_list: a list of pairs of the
            form (satoshi_count, bitcoin_address) corresponding to the payees.
            The satoshi_count is an integer indicating number of Satoshis (there
            are 1e8 Satoshis in a Bitcoin) and bitcoin_address is a standard
            Bitcoin address like 1FKYxGDywd7giFbnmKdvYmVgBHB9B2HXMw.
        Returns an UnsignedTx object. You must call "sign" before you drop it
        on the network."""

        txs_in = []
        txs_out_for_txs_in = []
        for h, idx, tx_out in previous_hash_index_txout_tuple_list:
            txs_in.append(TxIn(h, idx))
            txs_out_for_txs_in.append(tx_out)

        txs_out = []
        STANDARD_SCRIPT_OUT = "OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG"
        for coin_value, bitcoin_address in coin_value__bitcoin_address__tuple_list:
            hash160 = bitcoin_address_to_hash160_sec(bitcoin_address, is_test)
            script_text = STANDARD_SCRIPT_OUT % b2h(hash160)
            script_bin = tools.compile(script_text)
            txs_out.append(TxOut(coin_value, script_bin))

        return class_(txs_out_for_txs_in, version, txs_in, txs_out, lock_time)

    def unsigned_count(self):
        unsigned_count = 0
        for idx, tx_in in enumerate(self.txs_in):
            tx_out_script = self.txs_out_for_txs_in[idx].script
            signature_hash = self.signature_hash(tx_out_script, idx, hash_type=SIGHASH_ALL)
            if tx_in.verify(tx_out_script, signature_hash, hash_type=0):
                unsigned_count += 1
        return unsigned_count

    def sign(self, solver, hash_type=SIGHASH_ALL):
        """Sign a standard transaction.
        solver:
            A function solver(tx_out_script, signature_hash, signature_type)
            that accepts the tx_out_script, the signature hash, and a signature
            type, and returns a script that "solves" the tx_out_script.
            Normally you would use an instance of a SecretExponentSolver object
            (which has a __call__ method declared)."""

        for idx, tx_in in enumerate(self.txs_in):
            tx_out = self.txs_out_for_txs_in[idx]
            try:
                self.sign_tx_in(solver, idx, tx_out.script)
            except SolvingError:
                pass

        return self

    def total_in(self):
        return sum(tx_out.coin_value for tx_out in self.txs_out_for_txs_in)

    def fee(self):
        return self.total_in() - self.total_out()
