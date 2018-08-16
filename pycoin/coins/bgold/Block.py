
import io

from pycoin.encoding.hash import double_sha256
from pycoin.satoshi.satoshi_struct import parse_struct, stream_struct

from pycoin.block import Block as BaseBlock

from .Tx import Tx


# Allow NON_FORKID in legacy tests and blocks under BTG hard fork height
ALLOW_NON_FORKID = (1 << 17)

# BRAIN DAMAGE: TODO: implement this in vm


class Block(BaseBlock):
    """A Block is an element of the Bitcoin chain."""

    Tx = Tx

    FORK_BLOCK = 491407

    @classmethod
    def parse_as_header(class_, f):
        """
        Parse the Block header from the file-like object
        """
        version, previous_block_hash, merkle_root, height = parse_struct("L##L", f)
        # https://github.com/BTCGPU/BTCGPU/wiki/Technical-Spec
        f.read(28)  # reserved area
        (timestamp, difficulty, nonce, solution) = parse_struct("LL#S", f)
        return class_(version, previous_block_hash, merkle_root, timestamp,
                      difficulty, nonce, height, solution)

    def __init__(self, version, previous_block_hash, merkle_root, timestamp,
                 difficulty, nonce, height, solution):
        self.version = version
        self.previous_block_hash = previous_block_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.nonce = nonce
        self.height = height
        self.solution = solution
        self.txs = []

    def _calculate_hash(self):
        s = io.BytesIO()
        if self.height < self.FORK_BLOCK:
            self.stream_header_legacy(s)
        else:
            self.stream_header(s)
        return double_sha256(s.getvalue())

    def as_blockheader(self):
        return Block(self.version, self.previous_block_hash, self.merkle_root,
                     self.timestamp, self.difficulty, self.nonce,
                     self.height, self.solution)

    def stream_header_legacy(self, f):
        """Stream the block header in the standard way to the file-like object f."""
        stream_struct("L##LL", f, self.version, self.previous_block_hash,
                      self.merkle_root, self.timestamp, self.difficulty)
        f.write(self.nonce[:4])

    def stream_header(self, f):
        """Stream the block header in the standard way to the file-like object f."""
        stream_struct("L##L", f, self.version, self.previous_block_hash,
                      self.merkle_root, self.height)
        f.write(b'\0' * 28)
        stream_struct("LL#S", f, self.timestamp, self.difficulty, self.nonce, self.solution)
