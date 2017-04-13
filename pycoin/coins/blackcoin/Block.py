
import io

from pycoin.block import Block as BaseBlock
from pycoin.serialize import b2h_rev
from pycoin.serialize.bitcoin_streamer import parse_struct, stream_struct

from .Tx import Tx

try:
    import ltc_scrypt
except ImportError:
    print("can't import ltc_scrypt, required for litecoin. Quick solution: pip install ltc_scrypt")
    import sys
    sys.exit(-1)


class SCryptMixin(object):
    """
    Switch to scrypt-based block hash (instead of SHA256).
    Typically for Litecoin and similar altcoins.
    """
    def hash(self):
        """Calculate the scrypt-hash for the block header. Note that this has the bytes
        in the opposite order from how the header is usually displayed."""
        if not hasattr(self, "__hash"):
            s = io.BytesIO()
            self.stream_header(s)
            content = s.getvalue()

            import ltc_scrypt
            self.__hash = ltc_scrypt.getPoWHash(content)

        return self.__hash


class Block(SCryptMixin, BaseBlock):
    """
    A Proof-of-Stake Block (at least for BlackCoin):
       - has an extra signature over the block, appended after
         the array of transactions. Seems to have been introduced in PPC first?
       - has nTime value inserted after version number of txn, before vin array
     """
    Tx = Tx

    def pow_hash(self):
        s = io.BytesIO()
        self.stream_header(s)
        return ltc_scrypt.getPoWHash(s.getvalue())

    def pow_id(self):
        return b2h_rev(self.pow_hash())

    @classmethod
    def parse(class_, f, include_transactions=True, include_offsets=None):
        """Parse the Block from the file-like object in the standard way
        that blocks are sent in the network."""
        (version, previous_block_hash, merkle_root, timestamp,
            difficulty, nonce) = parse_struct("L##LLL", f)
        block = class_(version, previous_block_hash, merkle_root, timestamp, difficulty, nonce)
        if include_transactions:
            count = parse_struct("I", f)[0]
            txs = block._parse_transactions(f, count, include_offsets=include_offsets)
            block.set_txs(txs)
            block.set_signature(parse_struct("S", f)[0])
        return block

    def __init__(self, version, previous_block_hash, merkle_root, timestamp, difficulty, nonce):
        self.version = version
        self.previous_block_hash = previous_block_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.nonce = nonce
        self.signature = b''
        self.txs = []

    def set_signature(self, signature):
        self.signature = signature

    def zstream_header(self, f):
        """Stream the block header in the standard way to the file-like object f."""
        foo
        stream_struct("L##LLL", f, self.version, self.previous_block_hash, self.merkle_root,
                      self.timestamp, self.difficulty, self.nonce)

    def stream(self, f):
        super(Block, self).stream(f)
        stream_struct("S", f, self.signature)
