import struct

from ..encoding.bytes32 import from_bytes_32
from ..encoding.sec import sec_to_public_pair
from .BIP32Node import BIP32Node


class PublicPrivateMismatchError(Exception):
    pass


class BIP49Node(BIP32Node):
    """
    This is a deterministic wallet that complies with BIP0049 ("ypub" on mainnet)
    [https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki]
    """

    def address(self, is_compressed=None):
        pk_hash = self.hash160(is_compressed=is_compressed)
        push_20 = bytes.fromhex("0014")
        script_sig = push_20 + pk_hash
        address_bytes = self.hash160_bytes(script_sig)
        # use `for_p2sh_wit` ?
        return self._network.address.for_p2sh(address_bytes)

    def hwif(self, as_private=False):
        """Yield a 111-byte string corresponding to this node."""
        breakpoint()
        return self._network.bip49_as_string(
            self.serialize(as_private=as_private), as_private=as_private
        )

    as_text = hwif


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
