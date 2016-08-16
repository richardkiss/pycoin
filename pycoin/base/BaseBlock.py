# -*- coding: utf-8 -*-
"""
Parse and stream Bitcoin blocks as either Block or BlockHeader structures.


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

import struct

import io

from pycoin.encoding import double_sha256
from pycoin.serialize.bitcoin_streamer import parse_struct, stream_struct
from pycoin.serialize import b2h, b2h_rev

from .merkle import merkle
from .BaseTx import BaseTx


class BadMerkleRootError(Exception):
    pass


def difficulty_max_mask_for_bits(bits):
    prefix = bits >> 24
    mask = (bits & 0x7ffff) << (8 * (prefix - 3))
    return mask


class BaseBlockHeader(object):
    """
    A BlockHeader is a block with the transaction data removed. With a
    complete Merkle tree database, it can be reconstructed from the
    merkle_root.
    Use these attribute names: nonce, txs, __hash, previous_block_hash
    """

    Tx = BaseTx

    @classmethod
    def parse(cls, f):
        """Parse the BlockHeader from the file-like object in the standard way
        that blocks are sent in the network (well, except we ignore the
        transaction information)."""
        raise NotImplemented()

    def __init__(self):
        raise NotImplemented()

    def set_nonce(self, nonce):
        self.nonce = nonce
        if hasattr(self, "__hash"):
            del self.__hash

    def _calculate_hash(self):
        raise NotImplemented()

    def hash(self):
        """Calculate the hash for the block header. Note that this has the bytes
        in the opposite order from how the header is usually displayed (so the
        long string of 00 bytes is at the end, not the beginning)."""
        if not hasattr(self, "__hash"):
            self.__hash = self._calculate_hash()
        return self.__hash

    def stream_header(self, f):
        """Stream the block header in the standard way to the file-like object f."""
        raise NotImplemented()

    def stream(self, f):
        """Stream the block header in the standard way to the file-like object f.
        The Block subclass also includes the transactions."""
        return self.stream_header(f)

    def as_bin(self):
        """Return the transaction as binary."""
        f = io.BytesIO()
        self.stream(f)
        return f.getvalue()

    def as_hex(self):
        """Return the transaction as hex."""
        return b2h(self.as_bin())

    def id(self):
        """Returns the hash of the block displayed with the bytes in the order
        they are usually displayed in."""
        return b2h_rev(self.hash())

    def previous_block_id(self):
        """Returns the hash of the previous block, with the bytes in the order
        they are usually displayed in."""
        return b2h_rev(self.previous_block_hash)

    def __str__(self):
        return "%s [%s] (previous %s)" % (self.__class__.__name__, self.id(), self.previous_block_id())

    def __repr__(self):
        return self.__str__()


class BaseBlock(BaseBlockHeader):
    """A Block is an element of the Bitcoin chain. Generating a block
    yields a reward!"""

    @classmethod
    def parse(cls, f, include_offsets=None):
        """Parse the BlockHeader from the file-like object in the standard way
        that blocks are sent in the network (well, except we ignore the
        transaction information)."""
        raise NotImplemented()

    def stream(self, f):
        raise NotImplemented()

    def __init__(self):
        raise NotImplemented()

    def as_blockheader(self):
        raise NotImplemented()

    def check_merkle_hash(self):
        """Raise a BadMerkleRootError if the Merkle hash of the
        transactions does not match the Merkle hash included in the block."""
        calculated_hash = merkle([tx.hash() for tx in self.txs], double_sha256)
        if calculated_hash != self.merkle_root:
            raise BadMerkleRootError(
                "calculated %s but block contains %s" % (b2h(calculated_hash), b2h(self.merkle_root)))

    def __str__(self):
        return "%s [%s] (previous %s)" % (self.__class__.__name__, self.id(), self.previous_block_id())

    def __repr__(self):
        return "%s [%s] (previous %s) [tx count:%d] %s" % (
            self.__class__.__name__, self.id(), self.previous_block_id(), len(self.txs), self.txs)
