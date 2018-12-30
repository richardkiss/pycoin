import io
import warnings

from ..Tx import Tx as BaseTx

from .ScriptTools import BitcoinScriptTools
from .Solver import BitcoinSolver as Solver
from .SolutionChecker import BitcoinSolutionChecker as SolutionChecker

from pycoin.convention import SATOSHI_PER_COIN
from pycoin.encoding.hash import double_sha256
from pycoin.encoding.hexbytes import b2h, b2h_rev, h2b_rev
from pycoin.satoshi.satoshi_struct import parse_struct, stream_struct
from pycoin.satoshi.satoshi_int import parse_satoshi_int
from pycoin.satoshi.satoshi_string import parse_satoshi_string, stream_satoshi_string

from ..exceptions import BadSpendableError, ValidationFailureError
from .TxIn import TxIn
from .TxOut import TxOut
from .Spendable import Spendable


MAX_MONEY = 21000000 * SATOSHI_PER_COIN
MAX_BLOCK_SIZE = 1000000

ZERO32 = b'\0' * 32


class Tx(BaseTx):
    TxIn = TxIn
    TxOut = TxOut
    Spendable = Spendable
    Solver = Solver
    SolutionChecker = SolutionChecker

    MAX_MONEY = MAX_MONEY
    MAX_TX_SIZE = MAX_BLOCK_SIZE

    ALLOW_SEGWIT = True

    @classmethod
    def coinbase_tx(cls, public_key_sec, coin_value, coinbase_bytes=b'', version=1, lock_time=0):
        """Create the special "first in block" transaction that includes the mining fees."""
        tx_in = cls.TxIn.coinbase_tx_in(script=coinbase_bytes)
        COINBASE_SCRIPT_OUT = "%s OP_CHECKSIG"
        script_text = COINBASE_SCRIPT_OUT % b2h(public_key_sec)
        script_bin = BitcoinScriptTools.compile(script_text)
        tx_out = cls.TxOut(coin_value, script_bin)
        return cls(version, [tx_in], [tx_out], lock_time)

    @classmethod
    def parse(class_, f, allow_segwit=None):
        """Parse a Bitcoin transaction Tx.

        :param f: a file-like object that contains a binary streamed transaction
        :param allow_segwit: (optional) set to True to allow parsing of segwit transactions.
            The default value is defined by the class variable ALLOW_SEGWIT
        """
        if allow_segwit is None:
            allow_segwit = class_.ALLOW_SEGWIT
        txs_in = []
        txs_out = []
        version, = parse_struct("L", f)
        v1 = ord(f.read(1))
        is_segwit = allow_segwit and (v1 == 0)
        v2 = None
        if is_segwit:
            flag = f.read(1)
            if flag == b'\0':
                raise ValueError("bad flag in segwit")
            if flag == b'\1':
                v1 = None
            else:
                is_segwit = False
                v2 = ord(flag)
        count = parse_satoshi_int(f, v=v1)
        txs_in = []
        for i in range(count):
            txs_in.append(class_.TxIn.parse(f))
        count = parse_satoshi_int(f, v=v2)
        txs_out = []
        for i in range(count):
            txs_out.append(class_.TxOut.parse(f))

        if is_segwit:
            for tx_in in txs_in:
                stack = []
                count = parse_satoshi_int(f)
                for i in range(count):
                    stack.append(parse_satoshi_string(f))
                tx_in.witness = stack
        lock_time, = parse_struct("L", f)
        return class_(version, txs_in, txs_out, lock_time)

    @classmethod
    def tx_from_hex(cls, hex_string):
        warnings.simplefilter('always', DeprecationWarning)
        warnings.warn("Call to deprecated function tx_from_hex, use from_hex instead",
                      category=DeprecationWarning, stacklevel=2)
        warnings.simplefilter('default', DeprecationWarning)
        return cls.from_hex(hex_string)

    def __init__(self, version, txs_in, txs_out, lock_time=0, unspents=None):
        """Tx constructor.

        :param version: version number of the Tx, usually 1
        :param txs_in: a list of :class:`Tx.TxIn <TxIn>` instances, which
            act as inputs to the transaction
        :param txs_out: a list of :class:`Tx.TxOut <TxOut>` instances, which
            act as outputs to the transaction
        :param lock_time: (optional) the lock time for the transaction, usually 0
        :param unspents: (optional) a list of :class:`Tx.Spendable <Spendable>` instances,
            which correspond to the entries referred to by txs_in
        :return: :class:`Tx`
        """
        self.version = version
        self.txs_in = txs_in
        self.txs_out = txs_out
        self.lock_time = lock_time
        self.unspents = unspents or []
        for tx_in in self.txs_in:
            assert type(tx_in) == self.TxIn
        for tx_out in self.txs_out:
            assert type(tx_out) == self.TxOut

    def stream(self, f, blank_solutions=False, include_unspents=False, include_witness_data=True):
        """Stream a Bitcoin transaction Tx to the file-like object f.

        :param f: writable file-like object to stream binary data of transaction
        :param blank_solutions: (optional) clear out the solutions scripts, effectively "unsigning" the
            transaction before writing it. Defaults to False
        :param include_unspents: (optional) stread out the Spendable objects after streaming the transaction.
            This is a pycoin-specific extension. Defaults to False.
        :param include_witness_data: (optional) stream segwit transactions including the witness data if the
            transaction has any witness data. Defaults to True.
        """
        include_witnesses = include_witness_data and self.has_witness_data()
        stream_struct("L", f, self.version)
        if include_witnesses:
            f.write(b'\0\1')
        stream_struct("I", f, len(self.txs_in))
        for t in self.txs_in:
            t.stream(f, blank_solutions=blank_solutions)
        stream_struct("I", f, len(self.txs_out))
        for t in self.txs_out:
            t.stream(f)
        if include_witnesses:
            for tx_in in self.txs_in:
                witness = tx_in.witness
                stream_struct("I", f, len(witness))
                for w in witness:
                    stream_satoshi_string(f, w)
        stream_struct("L", f, self.lock_time)
        if include_unspents and not self.missing_unspents():
            self.stream_unspents(f)

    def set_witness(self, tx_idx_in, witness):
        """Set the witness data for a given :class:`TxIn`.

        :param tx_idx_in: an integer index corresponding to the txs_in puzzle script entry that this is a witness to
        :param witness: a list of binary blobs that witness the solution to the given puzzle script
        """
        self.txs_in[tx_idx_in].witness = tuple(witness)

    def has_witness_data(self):
        """Return a boolean indicating if the transaction has any segwit data."""
        return any(len(tx_in.witness) > 0 for tx_in in self.txs_in)

    def hash(self, hash_type=None):
        """Return the binary hash for this :class:`Tx` object.

        :param hash_type: (optional) if set, generates a hash specific to a particular type of signature.

        :return: 32 byte long binary blob corresponding to the hash
        """
        s = io.BytesIO()
        self.stream(s, include_witness_data=False)
        if hash_type is not None:
            stream_struct("L", s, hash_type)
        return double_sha256(s.getvalue())

    def w_hash(self):
        """Return the segwit-specific binary hash for this :class:`Tx` object.

        :return: 32 byte long binary blob corresponding to the hash
        """
        return double_sha256(self.as_bin())

    def w_id(self):
        """Return the segwit-specific binary hash for this :class:`Tx` object as a hex string.
        Note that this is a ``reversed`` version of :func:`Tx.w_hash <w_hash>`.

        :return: 64 character long hex string corresponding to the hash
        """
        return b2h_rev(self.w_hash())

    def blanked_hash(self):
        """
        Return the hash for this Tx object with solution scripts blanked.
        This hash is useful for determining if two Txs might be equivalent modulo
        malleability. (That is, even if tx1 is morphed into tx2 using the malleability
        weakness, they will still have the same blanked hash.)

        :return: 32 byte long binary blob corresponding to the blanked hash
        """
        s = io.BytesIO()
        self.stream(s, blank_solutions=True)
        return double_sha256(s.getvalue())

    def total_out(self):
        return sum(tx_out.coin_value for tx_out in self.txs_out)

    def tx_outs_as_spendable(self, block_index_available=0):
        h = self.hash()
        return [
            self.Spendable.from_tx_out(tx_out, h, tx_out_index, block_index_available)
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
        if not self.txs_out:
            raise ValidationFailureError("txs_out = []")
        if not self.is_coinbase() and not self.txs_in:
            raise ValidationFailureError("txs_in = []")

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
                if tx_in.previous_hash == ZERO32:
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
        self._check_txs_out()
        self._check_txs_in()
        # Size limits
        self._check_size_limit()

    def bad_solution_count(self, *args, **kwargs):
        if self.is_coinbase():
            return 0
        return super(Tx, self).bad_solution_count(*args, **kwargs)

    """
    The functions below here deal with an optional additional parameter: "unspents".
    This parameter is a list of tx_out objects that are referenced by the
    list of self.tx_in objects.
    """

    def unspents_from_db(self, tx_db, ignore_missing=False):
        unspents = []
        for tx_in in self.txs_in:
            if tx_in.is_coinbase():
                unspents.append(None)
                continue
            tx = tx_db.get(tx_in.previous_hash)
            if tx and tx.hash() == tx_in.previous_hash:
                unspents.append(tx.txs_out[tx_in.previous_index])
            elif ignore_missing:
                unspents.append(None)
            else:
                raise KeyError(
                    "can't find tx_out for %s:%d" % (b2h_rev(tx_in.previous_hash), tx_in.previous_index))
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

    def stream_unspents(self, f):
        self.check_unspents()
        for tx_out in self.unspents:
            if tx_out is None:
                tx_out = self.TxOut(0, b'')
            tx_out.stream(f)

    def parse_unspents(self, f):
        unspents = []
        for i in enumerate(self.txs_in):
            tx_out = self.TxOut.parse(f)
            if tx_out.coin_value == 0:
                tx_out = None
            unspents.append(tx_out)
        self.set_unspents(unspents)

    def total_in(self):
        if self.is_coinbase():
            return self.txs_out[0].coin_value
        self.check_unspents()
        return sum(tx_out.coin_value for tx_out in self.unspents)

    def fee(self):
        return self.total_in() - self.total_out()

    def validate_unspents(self, tx_db):
        """
        Spendable objects returned from blockchain.info or
        similar services contain coin_value information that must be trusted
        on faith. Mistaken coin_value data can result in coins being wasted
        to fees.

        This function solves this problem by iterating over the incoming
        transactions, fetching them from the tx_db in full, and verifying
        that the coin_values are as expected.

        Returns the fee for this transaction. If any of the spendables set by
        tx.set_unspents do not match the authenticated transactions, a
        ValidationFailureError is raised.
        """
        tx_hashes = set((tx_in.previous_hash for tx_in in self.txs_in))

        # build a local copy of the DB
        tx_lookup = {}
        for h in tx_hashes:
            if h == ZERO32:
                continue
            the_tx = tx_db.get(h)
            if the_tx is None:
                raise KeyError("hash id %s not in tx_db" % b2h_rev(h))
            if the_tx.hash() != h:
                raise KeyError("attempt to load Tx %s yielded a Tx with id %s" % (h2b_rev(h), the_tx.id()))
            tx_lookup[h] = the_tx

        for idx, tx_in in enumerate(self.txs_in):
            if tx_in.previous_hash == ZERO32:
                continue
            txs_out = tx_lookup[tx_in.previous_hash].txs_out
            if tx_in.previous_index > len(txs_out):
                raise BadSpendableError("tx_out index %d is too big for Tx %s" %
                                        (tx_in.previous_index, b2h_rev(tx_in.previous_hash)))
            tx_out1 = txs_out[tx_in.previous_index]
            tx_out2 = self.unspents[idx]
            if tx_out1.coin_value != tx_out2.coin_value:
                raise BadSpendableError(
                    "unspents[%d] coin value mismatch (%d vs %d)" % (
                        idx, tx_out1.coin_value, tx_out2.coin_value))
            if tx_out1.script != tx_out2.script:
                raise BadSpendableError("unspents[%d] script mismatch!" % idx)

        return self.fee()


"""
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
