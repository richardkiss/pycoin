from pycoin.encoding.b58 import b2a_hashed_base58
from pycoin.encoding.hexbytes import b2h


class UI(object):
    def __init__(self, generator, bip32_prv_prefix=None, bip32_pub_prefix=None,
                 wif_prefix=None, sec_prefix=None, address_prefix=None, pay_to_script_prefix=None, bech32_hrp=None):
        self._bip32_prv_prefix = bip32_prv_prefix
        self._bip32_pub_prefix = bip32_pub_prefix
        self._wif_prefix = wif_prefix
        self._sec_prefix = sec_prefix
        self._address_prefix = address_prefix
        self._pay_to_script_prefix = pay_to_script_prefix
        self._bech32_hrp = bech32_hrp

    def bip32_as_string(self, blob, as_private):
        prefix = self._bip32_prv_prefix if as_private else self._bip32_pub_prefix
        return b2a_hashed_base58(prefix + blob)

    def wif_for_blob(self, blob):
        return b2a_hashed_base58(self._wif_prefix + blob)

    def sec_text_for_blob(self, blob):
        return self._sec_prefix + b2h(blob)
