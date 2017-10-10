"""- methods that need to be accessible under network:
  - key_from_text
    - info_from_text (bech32_prefix, bip32_prefix, address_prefix, wif_prefix)
      - key_type, key_class, **kwargs
    - key_from_info
    - returns key with network included in it
    - maybe we don't need to parse address (since that's actually only really parsed by script_from_address)
"""


from .ScriptTools import BitcoinScriptTools
from pycoin import encoding
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.key.electrum import ElectrumWallet
from pycoin.key.BIP32Node import BIP32Node
from pycoin.key.Key import Key
from pycoin.serialize import b2h


class KeyParser(object):
    def __init__(self, netcode, wif_prefix, address_prefix, bip32_prv_prefix, bip32_pub_prefix, bech32_prefix):
        self._netcode = netcode
        self._wif_prefix = wif_prefix
        self._address_prefix = address_prefix
        self._bip32_prv_prefix = bip32_prv_prefix
        self._bip32_pub_prefix = bip32_pub_prefix
        self._bech32_prefix = bech32_prefix

    def key_from_text(self, text):
        key_info = self.key_info_from_text(text)
        return self.key_from_key_info(key_info)

    def key_info_from_text(self, text):
        try:
            data = encoding.a2b_hashed_base58(text)
            return self.key_info_from_b58(data)
        except encoding.EncodingError:
            pass

        try:
            hrp, data = bech32_decode(text)
            return self.key_info_from_bech32(hrp, data)
        except (TypeError, KeyError):
            pass

        try:
            prefix, rest = text.split(":", 1)
            data = h2b(rest)
            return self.key_info_from_prefixed_hex(prefix, data)
        except (binascii.Error, TypeError):
            pass

        return self.key_info_from_plaintext(text)

    def key_info_from_b58(self, data):

        bip32_prv = data.startswith(self._bip32_prv_prefix)
        bip32_pub = data.startswith(self._bip32_pub_prefix)
        if bip32_prv or bip32_pub:
            is_private = (key_type == 'prv32')
            parent_fingerprint, child_index = struct.unpack(">4sL", data[5:13])

            d = dict(generator=generator, netcode=netcode, chain_code=data[13:45], depth=ord(data[4:5]),
                     parent_fingerprint=parent_fingerprint, child_index=child_index)
            if bip32_prv:
                if data[45:46] != b'\0':
                    return None
                d["secret_exponent"] = from_bytes_32(data[46:])
            else:
                d["public_pair"] = sec_to_public_pair(data[45:], generator)
            return dict(key_class=BIP32Node, key_type="bip32", kwargs=d)

        if data.startswith(self._wif_prefix):
            is_compressed = (len(data) > 32)
            if is_compressed:
                data = data[:-1]
            se = encoding.from_bytes_32(data)
            kwargs = dict(secret_exponent=se, generator=secp256k1_generator,
                          prefer_uncompressed=not is_compressed, netcode=self._netcode)
            return dict(key_class=Key, key_type="wif", kwargs=kwargs)

        if data.startswith(self._address_prefix):
            kwargs = dict(hash160=data, netcode=self._netcode)
            return dict(key_class=Key, key_type="address", kwargs=kwargs)

        return None

    def key_info_from_bech32(self, prefix, blob):
        return None

    def key_info_from_prefixed_hex(self, prefix, blob):
        if prefix == 'E':
            if len(blob) == 16:
                kwargs = dict(initial_key=b2h(data), generator=secp256k1_generator)
                return dict(key_class=ElectrumWallet, key_type="elc_seed", kwargs=kwargs)

            if len(blob) == 32:
                kwargs = dict(master_private_key=encoding.from_bytes_32(data), generator=secp256k1_generator)
                return dict(key_class=ElectrumWallet, key_type="elc_prv", kwargs=kwargs)

            if len(blob) == 64:
                kwargs = dict(master_public_key=data, generator=secp256k1_generator)
                return dict(key_class=ElectrumWallet, key_type="elc_pub", kwargs=kwargs)

        return None

    def key_info_from_plaintext(self, text):
        return None

    def key_from_key_info(self, key_info):
        return key_info["key_class"](**key_info["kwargs"])
