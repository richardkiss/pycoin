import hashlib

from pycoin import encoding
from pycoin.serialize import b2h

from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools, IntStreamer
from pycoin.contrib import segwit_addr
from pycoin.intbytes import int2byte, iterbytes


class UI(object):
    def __init__(self, puzzle_scripts, address_prefix, pay_to_script_prefix, bech32_hrp=None):
        self._puzzle_scripts = puzzle_scripts
        self._address_prefix = address_prefix
        self._pay_to_script_prefix = pay_to_script_prefix
        self._bech32_hrp = bech32_hrp

    def address_for_script(self, script):
        d = self._puzzle_scripts.info_from_script_p2pkh(script)
        if d:
            return self.address_for_pay_to_pkh(d["PUBKEYHASH_LIST"][0])

        d = self._puzzle_scripts.info_from_script_p2pkh_wit(script)
        if d:
            if self._bech32_hrp:
                return self.address_for_p2skh_wit(iterbytes(d["PUBKEYHASH_LIST"][0]))

        d = self._puzzle_scripts.info_from_script_p2pk(script)
        if d:
            hash160 = encoding.hash160(d["PUBKEY_LIST"][0])
            # BRAIN DAMAGE: this isn't really a p2pkh
            return self.address_for_pay_to_pkh(hash160)

        d = self._puzzle_scripts.info_from_script_p2sh(script)
        if d:
            return self.address_for_pay_to_script_hash(d["PUBKEYHASH_LIST"][0])

        if (len(script), script[0:2]) in ((34, b'\00\x20'), (66, 'b\00\x40')):
            return segwit_addr.encode(self._bech32_hrp, self.version, self.hash256)

        d = self._puzzle_scripts.info_from_nulldata(script)
        if d:
            return "(nulldata %s)" % b2h(d["DATA"])

        return "???"

    def address_for_pay_to_pkh(self, hash160):
        if self._pay_to_script_prefix:
            return encoding.hash160_sec_to_bitcoin_address(hash160, address_prefix=self._address_prefix)
        return None

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
        try:
            hrp, data = segwit_addr.bech32_decode(address)
            if data:
                if hrp != self._bech32_hrp:
                    return None
                decoded = segwit_addr.convertbits(data[1:], 5, 8, False)
                decoded_data = b''.join(int2byte(d) for d in decoded)
                script = BitcoinScriptTools.compile_push_data_list([
                    IntStreamer.int_to_script_bytes(data[0]), decoded_data])
                return script
        except (TypeError, KeyError):
            pass

        data = encoding.a2b_hashed_base58(address)
        if data:
            if data.startswith(self._address_prefix):
                return self._puzzle_scripts.script_for_p2pkh(data[len(self._address_prefix):])
            if data.startswith(self._pay_to_script_prefix):
                return self._puzzle_scripts.script_for_p2sh(data[len(self._pay_to_script_prefix):])
        return None

    def standard_tx_out_script(self, address):
        return self.script_for_address(address)
