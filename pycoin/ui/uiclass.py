import binascii
import hashlib

from pycoin import encoding
from pycoin.serialize import b2h, h2b

from pycoin.contrib import segwit_addr
from pycoin.intbytes import int2byte, iterbytes
from pycoin.key.Key import Key
from pycoin.key.BIP32Node import BIP32Node
from pycoin.key.electrum import ElectrumWallet
from pycoin.ui.KeyParser import KeyParser
from pycoin.ui.Hash160Parser import Hash160Parser
from pycoin.ui.BIP32Parser import BIP32Parser
from pycoin.ui.ElectrumParser import ElectrumParser
from pycoin.ui.AddressParser import AddressParser

from .Parser import metadata_for_text, parse, parse_to_info



class UI(object):
    def __init__(self, puzzle_scripts, generator, bip32_prv_prefix, bip32_pub_prefix,
                 wif_prefix, sec_prefix, address_prefix, pay_to_script_prefix, bech32_hrp=None):
        self._puzzle_scripts = puzzle_scripts
        self._key_class = Key.make_subclass(default_ui_context=self)
        self._electrum_class = ElectrumWallet.make_subclass(default_ui_context=self)
        self._bip32node_class = BIP32Node.make_subclass(default_ui_context=self)
        self._parsers = [
            KeyParser(generator, wif_prefix, address_prefix, self._key_class),
            ElectrumParser(generator, self._electrum_class),
            BIP32Parser(generator, bip32_prv_prefix, bip32_pub_prefix, self._bip32node_class),
            Hash160Parser(address_prefix, self._key_class),
            AddressParser(puzzle_scripts, address_prefix, pay_to_script_prefix, bech32_hrp)
        ]
        self._bip32_prv_prefix = bip32_prv_prefix
        self._bip32_pub_prefix = bip32_pub_prefix
        self._wif_prefix = wif_prefix
        self._sec_prefix = sec_prefix
        self._address_prefix = address_prefix
        self._pay_to_script_prefix = pay_to_script_prefix
        self._bech32_hrp = bech32_hrp

    def bip32_private_prefix(self):
        return self._bip32_prv_prefix

    def bip32_public_prefix(self):
        return self._bip32_pub_prefix

    def wif_for_blob(self, blob):
        return encoding.b2a_hashed_base58(self._wif_prefix + blob)

    def sec_text_for_blob(self, blob):
        return self._sec_prefix + b2h(blob)

    def address_for_script(self, script):
        script_info = self._puzzle_scripts.info_for_script(script)
        return self.address_for_script_info(script_info)

    def address_for_script_info(self, script_info):
        type = script_info.get("type")

        if type == "p2pkh":
            return self.address_for_p2pkh(script_info["hash160"])

        if type == "p2pkh_wit":
            return self.address_for_p2pkh_wit(script_info["hash160"])

        if type == "p2sh_wit":
            return self.address_for_p2sh_wit(script_info["hash256"])

        if type == "p2pk":
            hash160 = encoding.hash160(script_info["sec"])
            # BRAIN DAMAGE: this isn't really a p2pkh
            return self.address_for_p2pkh(hash160)

        if type == "p2sh":
            return self.address_for_p2sh(script_info["hash160"])

        if type == "nulldata":
            return "(nulldata %s)" % b2h(script_info["data"])

        return "???"

    def address_for_p2pkh(self, hash160):
        if self._address_prefix:
            return encoding.hash160_sec_to_bitcoin_address(hash160, address_prefix=self._address_prefix)
        return "???"

    def address_for_p2sh(self, hash160):
        if self._pay_to_script_prefix:
            return encoding.hash160_sec_to_bitcoin_address(hash160, address_prefix=self._pay_to_script_prefix)
        return "???"

    def address_for_p2s(self, script):
        return self.address_for_p2sh(encoding.hash160(script))

    def address_for_p2pkh_wit(self, hash160):
        if self._bech32_hrp and len(hash160) == 20:
            return segwit_addr.encode(self._bech32_hrp, 0, iterbytes(hash160))
        return "???"

    def address_for_p2sh_wit(self, hash256):
        if self._bech32_hrp and len(hash256) == 32:
            return segwit_addr.encode(self._bech32_hrp, 0, iterbytes(hash256))
        return "???"

    def address_for_p2s_wit(self, script):
        return self.address_for_p2sh_wit(hashlib.sha256(script).digest())

    def script_for_address(self, address):
        return self.parse(address, types=["address"])

    ##############################################################################

    def parse_metadata_to_info(self, metadata, types):
        parsers = [p for p in self._parsers if p.TYPE in types]
        return parse_to_info(None, parsers, metadata=metadata)

    def parse(self, item, metadata=None, types=None):
        """
        type: one of "key", "address"
            eventually add "spendable", "payable", "address", "keychain_hint"
        """
        if types:
            parsers = [p for p in self._parsers if p.TYPE in types]
        else:
            parsers = self._parsers
        return parse(item, parsers, metadata=None)
