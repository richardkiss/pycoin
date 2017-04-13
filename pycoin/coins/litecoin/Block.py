
import io

from pycoin.block import Block as BaseBlock
from pycoin.serialize import b2h_rev

from .Tx import Tx

try:
    import ltc_scrypt
except ImportError:
    print("can't import ltc_scrypt, required for litecoin. Quick solution: pip install ltc_scrypt")
    import sys
    sys.exit(-1)


class Block(BaseBlock):
    Tx = Tx

    def pow_hash(self):
        s = io.BytesIO()
        self.stream_header(s)
        return ltc_scrypt.getPoWHash(s.getvalue())

    def pow_id(self):
        return b2h_rev(self.pow_hash())
