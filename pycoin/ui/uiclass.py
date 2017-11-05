import binascii
import hashlib

from pycoin import encoding
from pycoin.serialize import b2h, h2b

from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools, IntStreamer # BRAIN DAMAGE
from pycoin.contrib import segwit_addr
from pycoin.intbytes import int2byte, iterbytes
from pycoin.ui.KeyParser import KeyParser


class UI(object):
    def __init__(self, puzzle_scripts, generator, bip32_prv_prefix, bip32_pub_prefix,
                 wif_prefix, sec_prefix, address_prefix, pay_to_script_prefix, bech32_hrp=None):
        self._puzzle_scripts = puzzle_scripts
        self._bip32_prv_prefix = bip32_prv_prefix
        self._bip32_pub_prefix = bip32_pub_prefix
        self._wif_prefix = wif_prefix
        self._sec_prefix = sec_prefix
        self._address_prefix = address_prefix
        self._pay_to_script_prefix = pay_to_script_prefix
        self._bech32_hrp = bech32_hrp
        self._keyparser = KeyParser(self, generator)

    def bip32_private_prefix(self):
        return self._bip32_prv_prefix

    def bip32_public_prefix(self):
        return self._bip32_pub_prefix

    def wif_prefix(self):
        return self._wif_prefix

    def wif_for_blob(self, blob):
        return encoding.b2a_hashed_base58(self._wif_prefix + blob)

    def sec_text_for_blob(self, blob):
        return self._sec_prefix + b2h(blob)

    def address_for_hash160(self, hash160):
        return self.address_for_pay_to_pkh(hash160)

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
        if self._address_prefix:
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
        return self.parse(address, types=["address"])

    def standard_tx_out_script(self, address):
        return self.script_for_address(address)

    ##############################################################################

    def parse_address_as_base58(self, data):
        if data.startswith(self._address_prefix):
            hash160 = data[len(self._address_prefix):]
            if len(hash160) != 20:
                return
            info = dict(subtype="p2pkh", hash160=hash160)
            script = self._puzzle_scripts.script_for_p2pkh(hash160)
            return dict(type="address", info=info, script=script, create_f=lambda: script)

        if data.startswith(self._pay_to_script_prefix):
            hash160 = data[len(self._pay_to_script_prefix):]
            if len(hash160) != 20:
                return
            info = dict(subtype="p2sh", hash160=hash160)
            script = self._puzzle_scripts.script_for_p2sh(hash160)
            return dict(type="address", info=info, script=script, create_f=lambda: script)

    def parse_address_as_bech32(self, hrp, data):
        if hrp != self._bech32_hrp:
            return
        decoded = segwit_addr.convertbits(data[1:], 5, 8, False)
        decoded_data = b''.join(int2byte(d) for d in decoded)
        script = BitcoinScriptTools.compile_push_data_list([
            IntStreamer.int_to_script_bytes(data[0]), decoded_data])
        if len(decoded_data) == 20:
            info = dict(subtype="p2pkh_wit", hash160=decoded_data)
        elif len(decoded_data) == 32:
            info = dict(subtype="p2sh_wit", hash256=decoded_data)
        else:
            return
        return dict(type="address", info=info, script=script, create_f=lambda: script)

    def parse_key_generic(self, args, method):
        key_info = method(*args)
        if key_info:
            return dict(type="key", info=key_info, create_f=lambda: key_info["key_class"](**key_info["kwargs"]))

    def parse_key_as_base58(self, data):
        return self.parse_key_generic([data], self._keyparser.key_info_from_b58)

    def parse_key_as_bech32(self, hrp, data):
        return self.parse_key_generic([hrp, data], self._keyparser.key_info_from_bech32)

    def parse_key_as_prefixed_hex(self, prefix, data):
        return self.parse_key_generic([prefix, data], self._keyparser.key_info_from_prefixed_hex)

    def parse_item_to_metadata(self, text):
        d = {}
        try:
            data = encoding.a2b_hashed_base58(text)
            d["as_base58"] = (data,)
        except encoding.EncodingError:
            pass

        try:
            hrp, data = segwit_addr.bech32_decode(text)
            d["as_bech32"] = (hrp, data)
        except (TypeError, KeyError):
            pass

        try:
            prefix, rest = text.split(":", 1)
            data = h2b(rest)
            d["as_prefixed_hex"] = (prefix, data)
        except (binascii.Error, TypeError, ValueError):
            pass
        return d

    def parse_as_text(self, text):
        return None

    def parse_metadata_to_info(self, metadata, types):
        for f in ["base58", "bech32", "prefixed_hex", "text"]:
            k = "as_%s" % f
            d = metadata.get(k)
            if d is None:
                continue
            for t in types:
                r = getattr(self, "parse_%s_%s" % (t, k), lambda *args, **kwargs: None)(*d)
                if r:
                    return r

    def parse(self, item, metadata=None, types=["address", "key"]):
        """
        type: one of "key", "address"
            eventually add "spendable", "payable", "address", "keychain_hint"
        """
        if metadata is None:
            metadata = self.parse_item_to_metadata(item)
        info = self.parse_metadata_to_info(metadata, types=types)
        if info:
            return info["create_f"]()
