import io

from .SolutionChecker import SolutionChecker, ScriptError
from .TxIn import TxIn
from .TxOut import TxOut

from pycoin.encoding.hexbytes import b2h, b2h_rev, h2b


class Tx(object):
    TxIn = TxIn
    TxOut = TxOut
    Spendable = None
    Solver = None
    SolutionChecker = SolutionChecker

    @classmethod
    def parse(class_, f):
        """Parse a transaction Tx from the file-like object f."""
        raise NotImplemented()

    @classmethod
    def from_bin(class_, blob):
        """Return the Tx for the given binary blob.

        :param blob: a binary blob containing a transaction streamed in standard
            form. The blob may also include the unspents (a nonstandard extension,
            optionally written by :func:`Tx.stream <stream>`), and they will also be parsed.
        :return: :class:`Tx`

        If parsing fails, an exception is raised.
        """
        f = io.BytesIO(blob)
        tx = class_.parse(f)
        try:
            tx.parse_unspents(f)
        except Exception:
            # parsing unspents failed
            tx.unspents = []
        return tx

    @classmethod
    def from_hex(class_, hex_string):
        """Return the Tx for the given hex string.

        :param hex_string: a hex string containing a transaction streamed in standard
            form. The blob may also include the unspents (a nonstandard extension,
            optionally written by :func:`Tx.stream <stream>`), and they will also be parsed.
        :return: :class:`Tx`

        If parsing fails, an exception is raised.
        """
        return class_.from_bin(h2b(hex_string))

    def __init__(self, *args, **kwargs):
        raise NotImplemented()

    def stream(self, f, *args, **kwargs):
        """Stream a transaction Tx to the file-like object f."""
        raise NotImplemented()

    def as_bin(self, *args, **kwargs):
        """Returns a binary blob containing the streamed transaction.

        For information about the parameters, see :func:`Tx.stream <stream>`

        :return: binary blob that would parse to the given transaction
        """
        f = io.BytesIO()
        self.stream(f, *args, **kwargs)
        return f.getvalue()

    def as_hex(self, *args, **kwargs):
        """Returns a text string containing the streamed transaction encoded as hex.

        For information about the parameters, see :func:`Tx.stream <stream>`

        :return: hex string that would parse to the given transaction
        """
        return b2h(self.as_bin(*args, **kwargs))

    def hash(self, hash_type=None):
        """Return the hash for this Tx object."""
        raise NotImplemented()

    def id(self):
        """Return the human-readable hash for this Tx object."""
        return b2h_rev(self.hash())

    def total_out(self):
        return sum(tx_out.coin_value for tx_out in self.txs_out)

    def tx_outs_as_spendable(self, block_index_available=0):
        h = self.hash()
        return [
            self.Spendable.from_tx_out(tx_out, h, tx_out_index, block_index_available)
            for tx_out_index, tx_out in enumerate(self.txs_out)]

    def __str__(self):
        raise NotImplemented()

    def __repr__(self):
        raise NotImplemented()

    def check(self):
        """
        Basic checks that don't depend on network or block context.
        """
        raise NotImplemented()

    """
    The functions below here deal with an optional additional parameter: "unspents".
    This parameter is a list of tx_out objects that are referenced by the
    list of self.tx_in objects.
    """

    def set_unspents(self, unspents):
        """
        Set the unspent inputs for a transaction.

        :param unspents: a list of :class:`TxOut` (or the subclass :class:`Spendable`) objects
            corresponding to the :class:`TxIn` objects for this transaction (same number of
            items in each list)
        """
        if len(unspents) != len(self.txs_in):
            raise ValueError("wrong number of unspents")
        self.unspents = unspents

    def sign(self, *args, **kwargs):
        """
        Sign all transaction inputs. The parameters vary depending upon the way the coins being
        spent are encumbered.
        """
        self.Solver(self).sign(*args, **kwargs)
        return self

    def check_solution(self, tx_in_idx, *args, **kwargs):
        sc = self.SolutionChecker(self)
        tx_context = sc.tx_context_for_idx(tx_in_idx)
        sc.check_solution(tx_context, *args, **kwargs)

    def is_solution_ok(self, tx_in_idx, *args, **kwargs):
        if len(self.unspents) <= tx_in_idx or self.unspents[tx_in_idx] is None:
            return False
        try:
            self.check_solution(tx_in_idx, *args, **kwargs)
            return True
        except ScriptError:
            return False

    def bad_solution_count(self, *args, **kwargs):
        "Return a count of how many :class:`TxIn` objects are not correctly solved."
        return sum(0 if self.is_solution_ok(idx, *args, **kwargs) else 1 for idx in range(len(self.txs_in)))


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
