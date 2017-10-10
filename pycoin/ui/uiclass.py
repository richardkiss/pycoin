import collections
import hashlib

from pycoin import encoding
from pycoin.serialize import b2h
#from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools as ScriptTools  # BRAIN DAMAGEs
#from pycoin.coins.bitcoin.ScriptStreamer import BitcoinScriptStreamer as ScriptStreamer  # BRAIN DAMAGEs

from pycoin.contrib import segwit_addr
from pycoin.intbytes import iterbytes, byte2int
#from pycoin.networks import (
#    address_prefix_for_netcode, bech32_hrp_for_netcode, pay_to_script_prefix_for_netcode)
from pycoin.ui.validate import netcode_and_type_for_text


class UI(object):
    def __init__(self, puzzle_scripts, address_prefix, pay_to_script_prefix, bech32_hrp=None):
        self._puzzle_scripts = puzzle_scripts
        self._address_prefix = address_prefix
        self._pay_to_script_prefix = pay_to_script_prefix
        self._bech32_hrp = bech32_hrp
        #self._netcode = netcode

    def address_for_script(self, script):
        d = self._puzzle_scripts.info_from_script_p2pkh(script)
        if d:
            return encoding.hash160_sec_to_bitcoin_address(
                d["PUBKEYHASH_LIST"][0], address_prefix=self._address_prefix)

        d = self._puzzle_scripts.info_from_script_p2pkh_wit(script)
        if d:
            if self._bech32_hrp:
                return segwit_addr.encode(self._bech32_hrp, 0, iterbytes(d["PUBKEYHASH_LIST"][0]))

        d = self._puzzle_scripts.info_from_script_p2pk(script)
        if d:
            hash160 = encoding.hash160(d["PUBKEY_LIST"][0])
            return encoding.hash160_sec_to_bitcoin_address(hash160, address_prefix=self._address_prefix)

        d = self._puzzle_scripts.info_from_script_p2sh(script)
        if d:
            return encoding.hash160_sec_to_bitcoin_address(
                d["PUBKEYHASH_LIST"][0], address_prefix=self._pay_to_script_prefix)

        if (len(script), script[0:2]) in ((34, b'\00\x20'), (66, 'b\00\x40')):
            return segwit_addr.encode(self._bech32_hrp, self.version, self.hash256)

        d = self._puzzle_scripts.info_from_nulldata(script)
        if d:
            return "(nulldata %s)" % b2h(d["DATA"])

        return "???"

    def address_for_pay_to_script_hash(self, hash160):
        if self._pay_to_script_prefix:
            return encoding.hash160_sec_to_bitcoin_address(hash160, address_prefix=self._pay_to_script_prefix)
        return None

    def address_for_pay_to_script(self, script):
        return self.address_for_pay_to_script_hash(encoding.hash160(script))

    def address_for_p2skh_wit(self, hash160):
        if self._bech32_hrp:
            return segwit_addr.encode(self._bech32_hrp, 0, iterbytes(hash160))
        return None

    def address_for_p2sh_wit(self, hash256):
        if self._bech32_hrp:
            return segwit_addr.encode(self._bech32_hrp, 0, iterbytes(hash256))
        return None

    def address_for_pay_to_script_wit(self, script):
        return self.address_for_p2sh_wit(hashlib.sha256(script).digest())

    def script_for_address(self, address):
        # BRAIN DAMAGE
        netcode, key_type, data = netcode_and_type_for_text(address)
        if key_type == 'address':
            return self._puzzle_scripts.script_for_p2pkh(data)
        if key_type == 'pay_to_script':
            return self._puzzle_scripts.script_for_p2sh(data)
        if key_type == 'segwit':
            return data
        # BRAIN DAMAGE: TODO
        raise ValueError("bad text")

    def standard_tx_out_script(self, address):
        return self.script_for_address(address)
