from pycoin.encoding.bytes32 import from_bytes_32
from pycoin.networks.ParseAPI import BitcoinishPayable, ParseAPI
from pycoin.ui.parseable_str import parseable_str, parse_b58

from .hash import groestlHash


def b58_groestl(s):
    data = parse_b58(s)
    if data:
        data, the_hash = data[:-4], data[-4:]
        if groestlHash(data)[:4] == the_hash:
            return data


def parse_b58_groestl(s):
    s = parseable_str(s)
    return s.cache("b58_groestl", b58_groestl)


class GRSParseAPI(ParseAPI):
    """Set GRS parse functions."""

    def bip32_prv(self, s):
        data = parse_b58_groestl(s)
        if data is None or not data.startswith(self._bip32_prv_prefix):
            return None
        return self._network.BIP32Node.deserialize(data)

    def bip32_pub(self, s):
        data = parse_b58_groestl(s)
        if data is None or not data.startswith(self._bip32_pub_prefix):
            return None
        return self._network.BIP32Node.deserialize(data)

    def p2pkh(self, s):
        data = parse_b58_groestl(s)
        if data is None or not data.startswith(self._address_prefix):
            return None
        size = len(self._address_prefix)
        script = self._network.contract.for_p2pkh(data[size:])
        script_info = self._network.contract.info_for_script(script)
        return BitcoinishPayable(script_info, self._network)

    def p2sh(self, s):
        data = parse_b58_groestl(s)
        if (None in (data, self._pay_to_script_prefix) or
                not data.startswith(self._pay_to_script_prefix)):
            return None
        size = len(self._pay_to_script_prefix)
        script = self._network.contract.for_p2sh(data[size:])
        script_info = self._network.contract.info_for_script(script)
        return BitcoinishPayable(script_info, self._network)

    def wif(self, s):
        data = parse_b58_groestl(s)
        if data is None or not data.startswith(self._wif_prefix):
            return None
        data = data[len(self._wif_prefix):]
        is_compressed = (len(data) > 32)
        if is_compressed:
            data = data[:-1]
        se = from_bytes_32(data)
        return self._network.Key(se, is_compressed=is_compressed)
