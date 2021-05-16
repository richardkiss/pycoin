import struct

from ..encoding.bytes32 import from_bytes_32
from ..encoding.hash import hash160
from ..encoding.hexbytes import h2b
from ..encoding.sec import sec_to_public_pair
from .BIP32Node import BIP32Node

class PublicPrivateMismatchError(Exception):
    pass


class BIP84Node(BIP32Node):
    """
    This is a deterministic wallet that complies with BIP0084 ("zpub" on mainnet)
    [https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki]
    """

    def address(self, is_compressed=True):
        pk_hash = self.hash160(is_compressed=is_compressed)
        return self._network.address.for_p2pkh_wit(pk_hash)

    def hwif(self, as_private=False):
        """Yield a 111-byte string corresponding to this node."""
        return self._network.bip84_as_string(
            self.serialize(as_private=as_private), as_private=as_private
        )

    as_text = hwif

    def ku_output_for_address(self):
        yield ("address", self.address(), None)


"""
The MIT License (MIT)

Copyright (c) 2021 by Richard Kiss

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
