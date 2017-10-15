"""- methods that need to be accessible under network:
  - script_from_address
    - info_from_address (bech32_prefix, address_prefix, p2sh_prefix)
      - script_type, hash, hash_size (160 or 256), hash_type ("sha256" or "hash160"), script_f
    - script_from_info
  - address_from_script
    - info_from_script
        - script_type, hash, hash_size, hash_type, secs, multisig_m, script_f
    - address_from_info (bech32_prefix, address_prefix, p2sh_prefix)
"""


from .ScriptTools import BitcoinScriptTools
from pycoin import encoding
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.key.electrum import ElectrumWallet
from pycoin.key.BIP32Node import BIP32Node
from pycoin.key.Key import Key
from pycoin.serialize import b2h

from pycoin.vm.PayTo import PayTo


class ScriptParser(PayTo):
    def __init__(self, address_prefix, bech32_prefix):
        super(self, ScriptParser).__init__(BitcoinScriptTools)
        self._address_prefix = address_prefix
        self._bech32_prefix = bech32_prefix

    def script_for_address(self, address):
        script_info = self.script_info_for_text(address)
        return script_info["create_f"](**script_info["kwargs"])

    def script_info_for_text(self, text):
        try:
            data = encoding.a2b_hashed_base58(text)
            return self.script_info_from_b58(data)
        except encoding.EncodingError:
            pass

        try:
            hrp, data = bech32_decode(text)
            return self.script_info_from_bech32(hrp, data)
        except (TypeError, KeyError):
            pass

        try:
            prefix, rest = text.split(":", 1)
            data = h2b(rest)
            return self.script_info_from_prefixed_hex(prefix, data)
        except (binascii.Error, TypeError):
            pass

        return self.script_info_from_plaintext(text)

    def script_info_from_b58(self, data):
        if data.startswith(self._address_prefix):
            kwargs=dict(hash160=data)
            return dict(create_f=self.script_for_p2pkh, key_type="p2pkh", kwargs=kwargs)

    def script_info_from_bech32(self, data):
        if data.startswith(self._address_prefix):
            kwargs=dict(hash160=data)
            return dict(create_f=self.script_for_p2pkh_wit, key_type="p2pkh_wit", kwargs=kwargs)

    def script_info_from_prefixed_hex(self, prefix, data):
        return None

    def address_for_script(self, script):
        address_info = address_info_for_script(self)
        if address_info:
            return address_info["address"]

    def script_info_for_script(self, script):
        d = self._puzzle_scripts.info_from_script_p2pkh(script)
        if d:
            hash160 = d["PUBKEYHASH_LIST"][0]
            return dict(
                address=encoding.hash160_sec_to_bitcoin_address(
                    hash160, address_prefix=self._address_prefix),
                

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

"""
  - script_from_address
    - info_from_address (bech32_prefix, address_prefix, p2sh_prefix)
      - script_type, hash, hash_size (160 or 256), hash_type ("sha256" or "hash160"), script_f
    - script_from_info
  - address_from_script
    - info_from_script
        - script_type, hash, hash_size, hash_type, secs, multisig_m, script_f
    - address_from_info (bech32_prefix, address_prefix, p2sh_prefix)
"""