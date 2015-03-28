# -*- coding: utf-8 -*-
"""
A BIP0032-style hierarchical wallet.

Implement a BIP0032-style hierarchical wallet which can create public
or private wallet keys. Each key can create many child nodes. Each node
has a wallet key and a corresponding private & public key, which can
be used to generate Bitcoin addresses or WIF private keys.

At any stage, the private information can be stripped away, after which
descendants can only produce public keys.

Private keys can also generate "hardened" children, which cannot be
generated by the corresponding public keys. This is useful for generating
"change" addresses, for example, which there is no need to share with people
you give public keys to.


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

import hashlib
import hmac
import itertools
import struct

from ..encoding import a2b_hashed_base58, b2a_hashed_base58, from_bytes_32, to_bytes_32
from ..encoding import sec_to_public_pair, public_pair_to_hash160_sec, EncodingError
from ..networks import prv32_prefix_for_netcode, pub32_prefix_for_netcode
from .validate import netcode_and_type_for_data
from .Key import Key
from .bip32 import subkey_public_pair_chain_code_pair, subkey_secret_exponent_chain_code_pair


class PublicPrivateMismatchError(Exception):
    pass


class BIP32Node(Key):
    """
    This is a deterministic wallet that complies with BIP0032
    https://en.bitcoin.it/wiki/BIP_0032
    """
    @classmethod
    def from_master_secret(class_, master_secret, netcode='BTC'):
        """Generate a Wallet from a master password."""
        I64 = hmac.HMAC(key=b"Bitcoin seed", msg=master_secret, digestmod=hashlib.sha512).digest()
        return class_(netcode=netcode, chain_code=I64[32:], secret_exponent=from_bytes_32(I64[:32]))

    @classmethod
    def from_hwif(class_, b58_str, allow_subkey_suffix=True):
        """Generate a Wallet from a base58 string in a standard way."""
        # TODO: support subkey suffixes

        data = a2b_hashed_base58(b58_str)
        netcode, key_type = netcode_and_type_for_data(data)

        if key_type not in ("pub32", "prv32"):
            raise EncodingError("bad wallet key header")

        is_private = (key_type == 'prv32')
        parent_fingerprint, child_index = struct.unpack(">4sL", data[5:13])

        d = dict(netcode=netcode, chain_code=data[13:45], depth=ord(data[4:5]),
                 parent_fingerprint=parent_fingerprint, child_index=child_index)

        if is_private:
            if data[45:46] != b'\0':
                raise EncodingError("private key encoded wrong")
            d["secret_exponent"] = from_bytes_32(data[46:])
        else:
            d["public_pair"] = sec_to_public_pair(data[45:])

        return class_(**d)

    from_wallet_key = from_hwif

    def __init__(self, netcode, chain_code, depth=0, parent_fingerprint=b'\0\0\0\0',
                 child_index=0, secret_exponent=None, public_pair=None):
        """Don't use this. Use a classmethod to generate from a string instead."""

        if [secret_exponent, public_pair].count(None) != 1:
            raise ValueError("must include exactly one of public_pair and secret_exponent")

        super(BIP32Node, self).__init__(
            secret_exponent=secret_exponent, public_pair=public_pair, prefer_uncompressed=False,
            is_compressed=True, is_pay_to_script=False, netcode=netcode)

        if secret_exponent:
            self._secret_exponent_bytes = to_bytes_32(secret_exponent)

        if not isinstance(chain_code, bytes):
            raise ValueError("chain code must be bytes")
        if len(chain_code) != 32:
            raise ValueError("chain code wrong length")
        self._netcode = netcode
        self._chain_code = chain_code
        self._depth = depth
        if len(parent_fingerprint) != 4:
            raise EncodingError("parent_fingerprint wrong length")
        self._parent_fingerprint = parent_fingerprint
        self._child_index = child_index
        self._prefer_uncompressed = False
        self._subkey_cache = dict()

    def chain_code(self):
        return self._chain_code

    def tree_depth(self):
        return self._depth

    def parent_fingerprint(self):
        return self._parent_fingerprint

    def child_index(self):
        return self._child_index

    def serialize(self, as_private=None):
        """Yield a 78-byte binary blob corresponding to this node."""
        if as_private is None:
            as_private = self.secret_exponent() is not None
        if self.secret_exponent() is None and as_private:
            raise PublicPrivateMismatchError("public key has no private parts")

        ba = bytearray()
        if as_private:
            ba.extend(prv32_prefix_for_netcode(self._netcode))
        else:
            ba.extend(pub32_prefix_for_netcode(self._netcode))
        ba.extend([self._depth])
        ba.extend(self._parent_fingerprint + struct.pack(">L", self._child_index) + self._chain_code)
        if as_private:
            ba += b'\0' + self._secret_exponent_bytes
        else:
            ba += self.sec(use_uncompressed=False)
        return bytes(ba)

    def fingerprint(self):
        return public_pair_to_hash160_sec(self.public_pair(), compressed=True)[:4]

    def hwif(self, as_private=False):
        """Yield a 111-byte string corresponding to this node."""
        return b2a_hashed_base58(self.serialize(as_private=as_private))

    as_text = hwif
    wallet_key = hwif

    def public_copy(self):
        """Yield the corresponding public node for this node."""
        return self.__class__(netcode=self._netcode, chain_code=self._chain_code,
                              depth=self._depth, parent_fingerprint=self._parent_fingerprint,
                              child_index=self._child_index, public_pair=self.public_pair())

    def _subkey(self, i, is_hardened, as_private):
        """Yield a child node for this node.

        i: the index for this node.
        is_hardened: use "hardened key derivation". That is, the public version
            of this node cannot calculate this child.
        as_private: set to True to get a private subkey.

        Note that setting i<0 uses private key derivation, no matter the
        value for is_hardened."""
        if i >= 0x80000000:
            raise ValueError("subkey index 0x%x too large" % i)
        if i <= -0x80000000:
            raise ValueError("subkey index 0x%x too small" % i)

        if i < 0:
            i = -i
            is_hardened = True

        if is_hardened:
            i |= 0x80000000

        d = dict(netcode=self._netcode, depth=self._depth+1,
                 parent_fingerprint=self.fingerprint(), child_index=i)

        if self.secret_exponent() is None:
            if is_hardened:
                raise PublicPrivateMismatchError("can't derive a private key from a public key")
            d["public_pair"], chain_code = subkey_public_pair_chain_code_pair(
                self.public_pair(), self._chain_code, i)
        else:
            d["secret_exponent"], chain_code = subkey_secret_exponent_chain_code_pair(
                self.secret_exponent(), self._chain_code, i, is_hardened, self.public_pair())
        d["chain_code"] = chain_code
        key = self.__class__(**d)
        if not as_private:
            key = key.public_copy()
        return key

    def __repr__(self):
        r = self.as_text(as_private=False)
        if self.secret_exponent():
            return "private_for <%s>" % r
        return "<%s>" % r

    def subkey(self, i=0, is_hardened=False, as_private=None):
        if as_private is None:
            as_private = self.secret_exponent() is not None
        is_hardened = not not is_hardened
        as_private = not not as_private
        lookup = (i, is_hardened, as_private)
        if lookup not in self._subkey_cache:
            self._subkey_cache[lookup] = self._subkey(i, is_hardened, as_private)
        return self._subkey_cache[lookup]

    def subkey_for_path(self, path):
        """
        path: a path of subkeys denoted by numbers and slashes. Use
            H or i<0 for private key derivation. End with .pub to force
            the key public.

        Examples:
            1H/-5/2/1 would call subkey(i=1, is_hardened=True).subkey(i=-5).
                subkey(i=2).subkey(i=1) and then yield the private key
            0/0/458.pub would call subkey(i=0).subkey(i=0).subkey(i=458) and
                then yield the public key

        You should choose one of the p or the negative number convention for private key
        derivation and stick with it.
        """
        force_public = (path[-4:] == '.pub')
        if force_public:
            path = path[:-4]
        key = self
        if path:
            invocations = path.split("/")
            for v in invocations:
                is_hardened = v[-1] in ("'pH")
                if is_hardened:
                    v = v[:-1]
                v = int(v)
                key = key.subkey(i=v, is_hardened=is_hardened, as_private=key.secret_exponent() is not None)
        if force_public and key.secret_exponent() is not None:
            key = key.public_copy()
        return key

    def subkeys(self, path):
        """
        A generalized form that can return multiple subkeys.
        """
        if path == '':
            yield self
            return

        def range_iterator(the_range):
            for r in the_range.split(","):
                is_hardened = r[-1] in "'pH"
                if is_hardened:
                    r = r[:-1]
                hardened_char = "H" if is_hardened else ''
                if '-' in r:
                    low, high = [int(x) for x in r.split("-", 1)]
                    for t in range(low, high+1):
                        yield "%d%s" % (t, hardened_char)
                else:
                    yield "%s%s" % (r, hardened_char)

        def subkey_iterator(subkey_paths):
            # examples:
            #   0/1H/0-4 => ['0/1H/0', '0/1H/1', '0/1H/2', '0/1H/3', '0/1H/4']
            #   0/2,5,9-11 => ['0/2', '0/5', '0/9', '0/10', '0/11']
            #   3H/2/5/15-20p => ['3H/2/5/15p', '3H/2/5/16p', '3H/2/5/17p', '3H/2/5/18p',
            #          '3H/2/5/19p', '3H/2/5/20p']
            #   5-6/7-8p,15/1-2 => ['5/7H/1', '5/7H/2', '5/8H/1', '5/8H/2',
            #         '5/15/1', '5/15/2', '6/7H/1', '6/7H/2', '6/8H/1', '6/8H/2', '6/15/1', '6/15/2']

            components = subkey_paths.split("/")
            iterators = [range_iterator(c) for c in components]
            for v in itertools.product(*iterators):
                yield '/'.join(v)

        for subkey in subkey_iterator(path):
            yield self.subkey_for_path(subkey)

    def children(self, max_level=50, start_index=0, include_hardened=True):
        for i in range(start_index, max_level+start_index+1):
            yield self.subkey(i)
            if include_hardened:
                yield self.subkey(i, is_hardened=True)
