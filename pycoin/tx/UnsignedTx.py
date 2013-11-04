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

from .Tx import Tx, SIGHASH_ALL
from .TxIn import TxIn
from .TxOut import TxOut

from .script import tools
from .script.vm import verify_script

class UnsignedTxOut(object):
    def __init__(self, previous_hash, previous_index, coin_value, script, sequence=4294967295):
        self.previous_hash = previous_hash
        self.previous_index = previous_index
        self.coin_value = coin_value
        self.script = script
        self.sequence = sequence

class UnsignedTx(object):
    def __init__(self, version, unsigned_txs_out, new_txs_out, lock_time=0):
        self.version = version
        self.unsigned_txs_out = unsigned_txs_out
        self.new_txs_out = new_txs_out
        self.lock_time = lock_time

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

        new_txs_out = []
        STANDARD_SCRIPT_OUT = "OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG"
        for coin_value, bitcoin_address in coin_value__bitcoin_address__tuple_list:
            hash160 = bitcoin_address_to_hash160_sec(bitcoin_address, is_test)
            script_text = STANDARD_SCRIPT_OUT % b2h(hash160)
            script_bin = tools.compile(script_text)
            new_txs_out.append(TxOut(coin_value, script_bin))

        unsigned_txs_out = [UnsignedTxOut(h, idx, tx_out.coin_value, tx_out.script) for h, idx, tx_out in previous_hash_index_txout_tuple_list]

        return class_(version, unsigned_txs_out, new_txs_out, lock_time)

    def sign(self, solver, hash_type=SIGHASH_ALL):
        """Sign a standard transaction.
        solver:
            A function solver(tx_out_script, signature_hash, signature_type)
            that accepts the tx_out_script, the signature hash, and a signature
            type, and returns a script that "solves" the tx_out_script.
            Normally you would use an instance of a SecretExponentSolver object
            (which has a __call__ method declared)."""

        blank_txs_in = [TxIn(unsigned_tx_out.previous_hash, unsigned_tx_out.previous_index) for unsigned_tx_out_idx, unsigned_tx_out in enumerate(self.unsigned_txs_out)]
        tx = Tx(self.version, blank_txs_in, self.new_txs_out, self.lock_time)

        new_txs_in = []
        for unsigned_tx_out_idx, unsigned_tx_out in enumerate(self.unsigned_txs_out):
            # Leave out the signature from the hash, since a signature can't sign itself.
            # The checksig op will also drop the signatures from its hash.
            signature_hash = tx.signature_hash(unsigned_tx_out.script, unsigned_tx_out_idx, hash_type=hash_type)
            new_script = solver(unsigned_tx_out.script, signature_hash, hash_type)
            new_txs_in.append(TxIn(unsigned_tx_out.previous_hash, unsigned_tx_out.previous_index, new_script))
            if not verify_script(new_script, unsigned_tx_out.script, signature_hash, hash_type=0):
                raise ValidationFailureError("just signed script Tx %s TxIn index %d did not verify" % (b2h_rev(tx_in.previous_hash), unsigned_tx_out_idx))

        # we have our solutions! Fill them in
        tx.txs_in = new_txs_in
        return tx
