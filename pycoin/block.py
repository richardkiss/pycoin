
import decimal
import logging
import struct

import io

from .serialize.bitcoin_streamer import parse_struct, stream_struct
from .serialize import b2h, b2h_rev
from .encoding import double_sha256
from .merkle import merkle

from .tx.Tx import Tx

class BadMerkleRootError(Exception): pass

class BlockHeader(object):
    def __init__(self, version, previous_block_hash, merkle_root, timestamp, difficulty, nonce):
        self.version = version
        self.previous_block_hash = previous_block_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.nonce = nonce

    def hash(self):
        if not hasattr(self, "__hash"):
            s = io.BytesIO()
            stream_struct("L##LLL", s, self.version, self.previous_block_hash, self.merkle_root, self.timestamp, self.difficulty, self.nonce)
            self.__hash = double_sha256(s.getvalue())
        return self.__hash

    def stream_header(self, f):
        stream_struct("L##LLL", f, self.version, self.previous_block_hash, self.merkle_root, self.timestamp, self.difficulty, self.nonce)

    def stream(self, f):
        self.stream_header(f)

    @classmethod
    def parse(self, f):
        version, previous_block_hash, merkle_root, timestamp, difficulty, nonce = struct.unpack("<L32s32sLLL", f.read(4+32+32+4*3))
        return self(version, previous_block_hash, merkle_root, timestamp, difficulty, nonce)

    def id(self):
        return b2h_rev(self.hash())

    def __str__(self):
        return "BlockHeader [%s] (previous %s)" % (b2h_rev(self.hash()), b2h_rev(self.previous_block_hash))

    def __repr__(self):
        return "BlockHeader [%s] (previous %s)" % (b2h_rev(self.hash()), b2h_rev(self.previous_block_hash))

class Block(BlockHeader):
    def __init__(self, version, previous_block_hash, merkle_root, timestamp, difficulty, nonce, txs):
        self.version = version
        self.previous_block_hash = previous_block_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.nonce = nonce
        self.txs = txs

    def stream(self, f):
        stream_struct("L##LLLI", f, self.version, self.previous_block_hash, self.merkle_root, self.timestamp, self.difficulty, self.nonce, len(self.txs))
        for t in self.txs:
            t.stream(f)

    @classmethod
    def parse(self, f):
        version, previous_block_hash, merkle_root, timestamp, difficulty, nonce, count = parse_struct("L##LLLI", f)
        txs = []
        for i in range(count):
            txs.append(Tx.parse(f, is_first_in_block=(i==0)))
        return self(version, previous_block_hash, merkle_root, timestamp, difficulty, nonce, txs)

    def check_merkle_hash(self):
        calculated_hash = merkle([tx.hash() for tx in self.txs], double_sha256)
        if calculated_hash != self.merkle_root:
            raise BadMerkleRootError("calculated %s but block contains %s" % (b2h(calculated_hash), b2h(self.merkle_root)))

    def __str__(self):
        return "Block [%s] (previous %s) [tx count: %d]" % (self.id(), b2h_rev(self.previous_block_hash), len(self.txs))

    def __repr__(self):
        return "Block [%s] (previous %s) [tx count: %d] %s" % (self.id(), b2h_rev(self.previous_block_hash), len(self.txs), self.txs)
