from pycoin.ui.uiclass import UI
from pycoin.encoding.b58 import b2a_base58

from .hash import groestlHash


def b2a_hashed_base58_grs(data):
    return b2a_base58(data + groestlHash(data)[:4])


class GroestlcoinUI(UI):
    """Groestlcoin UI subclass."""
    def bip32_as_string(self, blob, as_private):
        prefix = self._bip32_prv_prefix if as_private else self._bip32_pub_prefix
        return b2a_hashed_base58_grs(prefix + blob)

    def wif_for_blob(self, blob):
        return b2a_hashed_base58_grs(self._wif_prefix + blob)

    def address_for_p2pkh(self, h160):
        if self._address_prefix:
            return b2a_hashed_base58_grs(self._address_prefix + h160)
        return "???"

    def address_for_p2sh(self, h160):
        if self._pay_to_script_prefix:
            return b2a_hashed_base58_grs(self._pay_to_script_prefix + h160)
        return "???"
