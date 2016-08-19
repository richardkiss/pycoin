# -*- coding: utf-8 -*-
"""
Parse, stream, create, sign and verify Bitcoin transactions as Tx structures.


The MIT License (MIT)

Copyright (c) 2013-2016 by Richard Kiss

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

from ..encoding import double_sha256
from ..serialize import b2h, b2h_rev, h2b
from ..serialize.bitcoin_streamer import stream_struct

from .exceptions import ValidationFailureError
from .BaseTxIn import BaseTxIn
from .BaseTxOut import BaseTxOut
from .BaseSpendable import BaseSpendable


class BaseTx(object):
    TxIn = BaseTxIn
    TxOut = BaseTxOut
    Spendable = BaseSpendable

    MAX_MONEY = int(21000000 * 1e8)
    MAX_TX_SIZE = 1000000

    def __init__(self, version, txs_in, txs_out, lock_time=0, unspents=[]):
        self.version = version
        self.txs_in = txs_in
        self.txs_out = txs_out
        self.lock_time = lock_time
        self.unspents = unspents
        for tx_in in self.txs_in:
            assert type(tx_in) == self.TxIn
        for tx_out in self.txs_out:
            assert type(tx_out) == self.TxOut

    @classmethod
    def parse(cls, f):
        """Parse a transaction from the file-like object f."""
        raise NotImplemented

    @classmethod
    def from_bin(cls, blob):
        """Return the Tx for the given binary blob."""
        f = io.BytesIO(blob)
        tx = cls.parse(f)
        try:
            tx.parse_unspents(f)
        except Exception:
            # parsing unspents failed
            tx.unspents = []
        return tx

    @classmethod
    def from_hex(cls, hex_string):
        """Return the Tx for the given hex string."""
        return cls.from_bin(h2b(hex_string))

    def stream(self, f, blank_solutions=False, include_unspents=False):
        """Stream a transaction to the file-like object f."""
        raise NotImplemented

    def as_bin(self, include_unspents=False):
        """Return the transaction as binary."""
        f = io.BytesIO()
        self.stream(f, include_unspents=include_unspents)
        return f.getvalue()

    def as_hex(self, include_unspents=False):
        """Return the transaction as hex."""
        return b2h(self.as_bin(include_unspents=include_unspents))

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

    def blanked_hash(self):
        """
        Return the hash for this Tx object with solution scripts blanked.
        Useful for determining if two Txs might be equivalent modulo
        malleability. (That is, even if tx1 is morphed into tx2 using the malleability
        weakness, they will still have the same blanked hash.)
        """
        s = io.BytesIO()
        self.stream(s, blank_solutions=True)
        return double_sha256(s.getvalue())

    def solve(self, tx_in_idx, tx_out_script, **kwargs):
        """
        Sign a standard transaction.
        tx_in_idx:
            the index of the tx_in we are currently signing
        tx_out:
            the tx_out referenced by the given tx_in
        """
        raise NotImplemented

    def sign_tx_in(self, tx_in_idx, tx_out_script, **kwargs):
        self.txs_in[tx_in_idx].script = self.solve(tx_in_idx, tx_out_script, **kwargs)

    def verify_tx_in(self, tx_in_idx, tx_out_script, expected_hash_type=None):
        tx_in = self.txs_in[tx_in_idx]

        def signature_for_hash_type_f(hash_type, script):
            return self.signature_hash(script, tx_in_idx, hash_type)

        if not tx_in.verify(tx_out_script, signature_for_hash_type_f, expected_hash_type):
            raise ValidationFailureError(
                "just signed script Tx %s TxIn index %d did not verify" % (
                    b2h_rev(tx_in.previous_hash), tx_in_idx))

    def total_out(self):
        return sum(tx_out.coin_value for tx_out in self.txs_out)

    def tx_outs_as_spendable(self, block_index_available=0):
        h = self.hash()
        return [
            self.Spendable(tx_out.coin_value, tx_out.script, h, tx_out_index, block_index_available)
            for tx_out_index, tx_out in enumerate(self.txs_out)]

    def is_coinbase(self):
        return len(self.txs_in) == 1 and self.txs_in[0].is_coinbase()

    def __str__(self):
        return "Tx [%s]" % self.id()

    def __repr__(self):
        return "Tx [%s] (v:%d) [%s] [%s]" % (
            self.id(), self.version, ", ".join(str(t) for t in self.txs_in),
            ", ".join(str(t) for t in self.txs_out))

    def _check_tx_inout_count(self):
        if not self.txs_in:
            raise ValidationFailureError("txs_in = []")
        if not self.txs_out:
            raise ValidationFailureError("txs_out = []")

    def _check_size_limit(self):
        size = len(self.as_bin())
        if size > self.MAX_TX_SIZE:
            raise ValidationFailureError("size > MAX_TX_SIZE")

    def _check_txs_out(self):
        # Check for negative or overflow output values
        nValueOut = 0
        for tx_out in self.txs_out:
            if tx_out.coin_value < 0 or tx_out.coin_value > self.MAX_MONEY:
                raise ValidationFailureError("tx_out value negative or out of range")
            nValueOut += tx_out.coin_value
            if nValueOut > self.MAX_MONEY:
                raise ValidationFailureError("tx_out total out of range")

    def _check_txs_in(self):
        # Check for duplicate inputs
        if [x for x in self.txs_in if self.txs_in.count(x) > 1]:
            raise ValidationFailureError("duplicate inputs")
        if (self.is_coinbase()):
            if not (2 <= len(self.txs_in[0].script) <= 100):
                raise ValidationFailureError("bad coinbase script size")
        else:
            refs = set()
            for tx_in in self.txs_in:
                if tx_in.previous_hash == b'0' * 32:
                    raise ValidationFailureError("prevout is null")
                pair = (tx_in.previous_hash, tx_in.previous_index)
                if pair in refs:
                    raise ValidationFailureError("spendable reused")
                refs.add(pair)

    def check(self):
        """
        Basic checks that don't depend on any context.
        Adapted from Bicoin Code: main.cpp
        """
        self._check_tx_inout_count()
        # Size limits
        self._check_size_limit()
        self._check_txs_out()
        self._check_txs_in()

    """
    The functions below here deal with an optional additional parameter: "unspents".
    This parameter is a list of tx_out objects that are referenced by the
    list of self.tx_in objects.
    """

    def unspents_from_db(self, tx_db, ignore_missing=False):
        unspents = []
        for tx_in in self.txs_in:
            tx = tx_db.get(tx_in.previous_hash)
            if tx and tx.hash() == tx_in.previous_hash:
                spendable = self.Spendable.from_tx_out(
                    tx.txs_out[tx_in.previous_index], tx_in.previous_hash, tx_in.previous_index)
                unspents.append(spendable)
            elif ignore_missing:
                unspents.append(None)
            else:
                raise KeyError(
                    "can't find tx_out for %s:%d" % (b2h_rev(tx_in.previous_hash), tx_in.previous_index))
        if ignore_missing:
            # we may have some None values, so we can't use the set_unspents method which
            # requires all values
            self.unspents = unspents
        else:
            self.set_unspents(unspents)

    def set_unspents(self, unspents):
        for unspent in unspents:
            assert isinstance(unspent, self.TxOut)
        if len(unspents) != len(self.txs_in):
            raise ValueError("wrong number of unspents")
        self.unspents = unspents

    def missing_unspent(self, idx):
        if self.is_coinbase():
            return True
        if len(self.unspents) <= idx:
            return True
        return self.unspents[idx] is None

    def missing_unspents(self):
        if self.is_coinbase():
            return False
        return (len(self.unspents) != len(self.txs_in) or
                any(self.missing_unspent(idx) for idx, tx_in in enumerate(self.txs_in)))

    def check_unspents(self):
        if self.missing_unspents():
            raise ValueError("wrong number of unspents. Call unspents_from_db or set_unspents.")

    def unspent_for_tx_in_idx(self, tx_in_idx):
        if len(self.unspents) <= tx_in_idx:
            raise ValueError("missing unspent of TxIn %d" % tx_in_idx)
        unspent = self.unspents[tx_in_idx]
        if unspent is None:
            raise ValueError("missing unspent of TxIn %d" % tx_in_idx)
        return unspent

    def txs_in_as_spendable(self):
        return [
            self.Spendable.from_tx_out(tx_out, tx_in.previous_hash, tx_in.previous_index)
            for tx_in, tx_out in zip(self.txs_in, self.unspents)]

    def stream_unspents(self, f):
        self.check_unspents()
        for tx_out in self.unspents:
            tx_out.stream(f)

    def parse_unspents(self, f):
        unspents = []
        for i in enumerate(self.txs_in):
            tx_out = self.TxOut.parse(f)
            if tx_out.coin_value == 0:
                tx_out = None
            unspents.append(tx_out)
        self.set_unspents(unspents)

    def is_signature_ok(self, tx_in_idx, **kwargs):
        raise NotImplemented

    def check_solution(self, tx_in_idx):
        """
        Check the solution script for the TxIn corresponding to tx_in_idx.
        """
        raise NotImplemented

    def sign(self, **kwargs):
        """
        Sign a standard transaction.
        """
        raise NotImplemented

    def bad_solution_count(self, flags=None):
        count = 0
        for idx, tx_in in enumerate(self.txs_in):
            if not self.is_signature_ok(idx, flags=flags):
                count += 1
        return count

    def total_in(self):
        self.check_unspents()
        return sum(tx_out.coin_value for tx_out in self.unspents)

    def fee(self):
        return self.total_in() - self.total_out()
