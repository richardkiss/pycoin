from __future__ import annotations

import io
from typing import Any, IO

from .encoding.hash import double_sha256
from .encoding.hexbytes import b2h, b2h_rev
from .merkle import merkle
from .satoshi.satoshi_struct import parse_struct, stream_struct


class BadMerkleRootError(Exception):
    pass


def difficulty_max_mask_for_bits(bits: int) -> int:
    prefix = bits >> 24
    mask = (bits & 0x7FFFF) << (8 * (prefix - 3))
    return mask


class Block(object):
    """A Block is an element of the Bitcoin chain."""

    Tx: Any = None

    @classmethod
    def make_subclass(class_: type[Block], symbol: str, tx: Any) -> type[Block]:
        return type(
            "%s_%s" % (symbol, class_.__name__),
            (class_,),
            dict(Tx=tx),
        )

    @classmethod
    def parse(
        class_: type[Block],
        f: IO[bytes],
        include_transactions: bool = True,
        include_offsets: Any = None,
        check_merkle_hash: bool = True,
    ) -> Block:
        """
        Parse the Block from the file-like object
        """
        block = class_.parse_as_header(f)
        if include_transactions:
            count = parse_struct("I", f)[0]
            txs = block._parse_transactions(f, count, include_offsets=include_offsets)
            block.set_txs(txs, check_merkle_hash=check_merkle_hash)
        return block

    @classmethod
    def parse_as_header(class_: type[Block], f: IO[bytes]) -> Block:
        """
        Parse the Block header from the file-like object
        """
        (version, previous_block_hash, merkle_root, timestamp, difficulty, nonce) = (
            parse_struct("L##LLL", f)
        )
        return class_(
            version, previous_block_hash, merkle_root, timestamp, difficulty, nonce
        )

    @classmethod
    def from_bin(class_: type[Block], bytes: bytes) -> Block:
        f = io.BytesIO(bytes)
        return class_.parse(f)

    def __init__(
        self,
        version: int,
        previous_block_hash: bytes,
        merkle_root: bytes,
        timestamp: int,
        difficulty: int,
        nonce: int,
    ) -> None:
        self.version = version
        self.previous_block_hash = previous_block_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.nonce = nonce
        self.txs: list[Any] = []

    def set_nonce(self, nonce: int) -> None:
        self.nonce = nonce
        if hasattr(self, "__hash"):
            del self.__hash  # type: ignore[misc]

    def _calculate_hash(self) -> bytes:
        s = io.BytesIO()
        self.stream_header(s)
        return double_sha256(s.getvalue())

    def hash(self) -> bytes:
        """Calculate the hash for the block header. Note that this has the bytes
        in the opposite order from how the header is usually displayed (so the
        long string of 00 bytes is at the end, not the beginning)."""
        if not hasattr(self, "__hash"):
            self.__hash = self._calculate_hash()  # type: ignore[misc]
        return self.__hash  # type: ignore[misc,return-value]

    @classmethod
    def _parse_transactions(
        class_: type[Block],
        f: IO[bytes],
        count: int,
        include_offsets: Any = None,
    ) -> list[Any]:
        txs = []
        for i in range(count):
            if include_offsets:
                offset_in_block = f.tell()
            tx = class_.Tx.parse(f)
            txs.append(tx)
            if include_offsets:
                tx.offset_in_block = offset_in_block
        return txs

    def set_txs(self, txs: list[Any], check_merkle_hash: bool = True) -> None:
        self.txs = txs
        if not txs:
            return
        for tx in txs:
            tx.block = self
        if check_merkle_hash:
            self.check_merkle_hash()

    def as_blockheader(self) -> Block:
        return Block(
            self.version,
            self.previous_block_hash,
            self.merkle_root,
            self.timestamp,
            self.difficulty,
            self.nonce,
        )

    def stream_header(self, f: IO[bytes]) -> None:
        """Stream the block header in the standard way to the file-like object f."""
        stream_struct(
            "L##LLL",
            f,
            self.version,
            self.previous_block_hash,
            self.merkle_root,
            self.timestamp,
            self.difficulty,
            self.nonce,
        )

    def _stream_transactions(self, f: IO[bytes]) -> None:
        if self.txs:
            stream_struct("I", f, len(self.txs))
            for tx in self.txs:
                tx.stream(f)

    def stream(self, f: IO[bytes]) -> None:
        """Stream the block header in the standard way to the file-like object f.
        The Block subclass also includes the transactions."""
        self.stream_header(f)
        self._stream_transactions(f)

    def as_bin(self) -> bytes:
        """Return the block (or header) as binary."""
        f = io.BytesIO()
        self.stream(f)
        return f.getvalue()

    def as_hex(self) -> str:
        """Return the block (or header) as hex."""
        return b2h(self.as_bin())

    def id(self) -> str:
        """Returns the hash of the block displayed with the bytes in the order
        they are usually displayed in."""
        return b2h_rev(self.hash())

    def previous_block_id(self) -> str:
        """Returns the hash of the previous block, with the bytes in the order
        they are usually displayed in."""
        return b2h_rev(self.previous_block_hash)

    def check_merkle_hash(self) -> None:
        """Raise a BadMerkleRootError if the Merkle hash of the
        transactions does not match the Merkle hash included in the block."""
        calculated_hash = merkle([tx.hash() for tx in self.txs], double_sha256)
        if calculated_hash != self.merkle_root:
            raise BadMerkleRootError(
                "calculated %s but block contains %s"
                % (b2h(calculated_hash), b2h(self.merkle_root))
            )

    def __str__(self) -> str:
        c = "%s%s" % (self.__class__.__name__, "" if self.txs else "Header")
        return "%s [%s] (previous %s)" % (c, self.id(), self.previous_block_id())

    def __repr__(self) -> str:
        return self.__str__()
