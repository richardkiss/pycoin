"""- methods that need to be accessible under network:
  - key_from_text
    - info_from_text (bech32_prefix, bip32_prefix, address_prefix, wif_prefix)
      - key_type, key_class, **kwargs
    - key_from_info
    - returns key with network included in it
    - maybe we don't need to parse address (since that's actually only really parsed by script_from_address)
"""

import binascii
import struct

from pycoin import encoding
from pycoin.contrib.segwit_addr import bech32_decode
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.serialize import b2h, h2b


class KeyParser(object):
    def __init__(self, wif_prefix, address_prefix, bip32_prv_prefix, bip32_pub_prefix, bech32_prefix,
                 key_class, bip32node_class=None, electrum_class=None):
        self._wif_prefix = wif_prefix
        self._address_prefix = address_prefix
        self._bip32_prv_prefix = bip32_prv_prefix
        self._bip32_pub_prefix = bip32_pub_prefix
        self._bech32_prefix = bech32_prefix
        self._key_class = key_class
        self._bip32node_class = bip32node_class
        self._electrum_class = electrum_class

    def key_from_text(self, text):
        key_info = self.key_info_from_text(text)
        if key_info:
            return key_from_key_info(key_info)

    def key_info_from_text(self, text):
        try:
            data = encoding.a2b_hashed_base58(text)
            return self.key_info_from_b58(data)
        except encoding.EncodingError:
            pass

        try:
            hrp, data = bech32_decode(text)
            if hrp and data:
                return self.key_info_from_bech32(hrp, data)
        except (TypeError, KeyError):
            pass

        try:
            prefix, rest = text.split(":", 1)
            data = h2b(rest)
            return self.key_info_from_prefixed_hex(prefix, data)
        except (binascii.Error, TypeError, ValueError):
            pass

        return self.key_info_from_plaintext(text)

    def key_info_from_b58(self, data):

        bip32_prv = data.startswith(self._bip32_prv_prefix)
        bip32_pub = data.startswith(self._bip32_pub_prefix)
        if bip32_prv or bip32_pub:
            parent_fingerprint, child_index = struct.unpack(">4sL", data[5:13])

            d = dict(generator=secp256k1_generator, chain_code=data[13:45],
                     depth=ord(data[4:5]), parent_fingerprint=parent_fingerprint,
                     child_index=child_index)
            if bip32_prv:
                if data[45:46] != b'\0':
                    return None
                d["secret_exponent"] = encoding.from_bytes_32(data[46:])
            else:
                d["public_pair"] = encoding.sec_to_public_pair(data[45:], secp256k1_generator)
            return dict(key_class=self._bip32node_class, key_type="bip32", is_private=bip32_prv, kwargs=d)

        if data.startswith(self._wif_prefix):
            data = data[1:]
            is_compressed = (len(data) > 32)
            if is_compressed:
                data = data[:-1]
            se = encoding.from_bytes_32(data)
            kwargs = dict(secret_exponent=se, generator=secp256k1_generator,
                          prefer_uncompressed=not is_compressed)
            return dict(key_class=self._key_class, key_type="wif", kwargs=kwargs)

        if data.startswith(self._address_prefix):
            kwargs = dict(hash160=data[1:])
            return dict(key_class=self._key_class, key_type="address", kwargs=kwargs)

        return None

    def key_info_from_bech32(self, prefix, blob):
        return None

    def key_info_from_prefixed_hex(self, prefix, data):
        if prefix == 'E' and self._electrum_class:
            if len(data) == 16:
                kwargs = dict(initial_key=b2h(data), generator=secp256k1_generator)
                return dict(key_class=self._electrum_class, key_type="elc_seed", kwargs=kwargs)

            if len(data) == 32:
                kwargs = dict(master_private_key=encoding.from_bytes_32(data), generator=secp256k1_generator)
                return dict(key_class=self._electrum_class, key_type="elc_prv", kwargs=kwargs)

            if len(data) == 64:
                kwargs = dict(master_public_key=data, generator=secp256k1_generator)
                return dict(key_class=self._electrum_class, key_type="elc_pub", kwargs=kwargs)

        return None

    def key_info_from_plaintext(self, text):
        return None


def key_from_key_info(key_info):
    return key_info["key_class"](**key_info["kwargs"])

