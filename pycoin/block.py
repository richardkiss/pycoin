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

from .encoding import double_sha256
from .merkle import merkle
from .serialize.bitcoin_streamer import parse_struct, stream_struct
from .serialize import b2h, b2h_rev

from .tx import Tx


class BadMerkleRootError(Exception):
    pass


def difficulty_max_mask_for_bits(bits):
    prefix = bits >> 24
    mask = (bits & 0x7ffff) << (8 * (prefix - 3))
    return mask


class BlockHeader(object):
    """A BlockHeader is a block with the transaction data removed. With a
    complete Merkle tree database, it can be reconstructed from the
    merkle_root."""

    @classmethod
    def parse(self, f):
        """Parse the BlockHeader from the file-like object in the standard way
        that blocks are sent in the network (well, except we ignore the
        transaction information)."""
        (version, previous_block_hash, merkle_root,
            timestamp, difficulty, nonce) = struct.unpack("<L32s32sLLL", f.read(4+32+32+4*3))
        return self(version, previous_block_hash, merkle_root, timestamp, difficulty, nonce)

    def __init__(self, version, previous_block_hash, merkle_root, timestamp, difficulty, nonce):
        self.version = version
        self.previous_block_hash = previous_block_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.nonce = nonce

    def hash(self):
        """Calculate the hash for the block header. Note that this has the bytes
        in the opposite order from how the header is usually displayed (so the
        long string of 00 bytes is at the end, not the beginning)."""
        if not hasattr(self, "__hash"):
            s = io.BytesIO()
            self.stream_header(s)
            self.__hash = double_sha256(s.getvalue())
        return self.__hash

    def stream_header(self, f):
        """Stream the block header in the standard way to the file-like object f."""
        stream_struct("L##LLL", f, self.version, self.previous_block_hash,
                      self.merkle_root, self.timestamp, self.difficulty, self.nonce)

    def stream(self, f):
        """Stream the block header in the standard way to the file-like object f.
        The Block subclass also includes the transactions."""
        self.stream_header(f)

    def id(self):
        """Returns the hash of the block displayed with the bytes in the order
        they are usually displayed in."""
        return b2h_rev(self.hash())

    def previous_block_id(self):
        """Returns the hash of the previous block, with the bytes in the order
        they are usually displayed in."""
        return b2h_rev(self.previous_block_hash)

    def __str__(self):
        return "BlockHeader [%s] (previous %s)" % (self.id(), self.previous_block_id())

    def __repr__(self):
        return "BlockHeader [%s] (previous %s)" % (self.id(), self.previous_block_id())


class Block(BlockHeader):
    """A Block is an element of the Bitcoin chain. Generating a block
    yields a reward!"""

    @classmethod
    def parse(self, f):
        """Parse the Block from the file-like object in the standard way
        that blocks are sent in the network."""
        (version, previous_block_hash, merkle_root, timestamp,
            difficulty, nonce, count) = parse_struct("L##LLLI", f)
        txs = []
        for i in range(count):
            txs.append(Tx.parse(f))
        return self(version, previous_block_hash, merkle_root, timestamp, difficulty, nonce, txs)

    def __init__(self, version, previous_block_hash, merkle_root, timestamp, difficulty, nonce, txs):
        self.version = version
        self.previous_block_hash = previous_block_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.nonce = nonce
        self.txs = txs

    def as_blockheader(self):
        return BlockHeader(self.version, self.previous_block_hash, self.merkle_root,
                           self.timestamp, self.difficulty, self.nonce)

    def stream(self, f):
        """Stream the block in the standard way to the file-like object f."""
        stream_struct("L##LLLI", f, self.version, self.previous_block_hash,
                      self.merkle_root, self.timestamp, self.difficulty, self.nonce, len(self.txs))
        for t in self.txs:
            t.stream(f)

    def check_merkle_hash(self):
        """Raise a BadMerkleRootError if the Merkle hash of the
        transactions does not match the Merkle hash included in the block."""
        calculated_hash = merkle([tx.hash() for tx in self.txs], double_sha256)
        if calculated_hash != self.merkle_root:
            raise BadMerkleRootError(
                "calculated %s but block contains %s" % (b2h(calculated_hash), b2h(self.merkle_root)))

    def __str__(self):
        return "Block [%s] (previous %s) [tx count: %d]" % (
            self.id(), self.previous_block_id(), len(self.txs))

    def __repr__(self):
        return "Block [%s] (previous %s) [tx count: %d] %s" % (
            self.id(), self.previous_block_id(), len(self.txs), self.txs)
