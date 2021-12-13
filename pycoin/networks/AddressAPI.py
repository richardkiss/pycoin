import hashlib

from pycoin.contrib import bech32m
from pycoin.encoding.b58 import b2a_hashed_base58
from pycoin.encoding.hash import hash160
from pycoin.encoding.hexbytes import b2h
from pycoin.intbytes import iterbytes


def make_address_api(
        contracts,
        bip32_prv_prefix=None, bip32_pub_prefix=None, bip49_prv_prefix=None,
        bip49_pub_prefix=None, bip84_prv_prefix=None, bip84_pub_prefix=None,
        wif_prefix=None, sec_prefix=None, address_prefix=None, pay_to_script_prefix=None,
        bech32_hrp=None):

    class AddressAPI(object):

        def for_script(self, script):
            info = contracts.info_for_script(script)
            return self.for_script_info(info)

        def b2a(self, blob):
            return b2a_hashed_base58(blob)

        # address_for_script and script_for_address stuff
        def for_script_info(self, script_info):
            type = script_info.get("type")

            if type == "p2pkh":
                return self.for_p2pkh(script_info["hash160"])

            if type == "p2pkh_wit":
                return self.for_p2pkh_wit(script_info["hash160"])

            if type == "p2sh_wit":
                return self.for_p2sh_wit(script_info["hash256"])

            if type == "p2pk":
                h160 = hash160(script_info["sec"])
                # BRAIN DAMAGE: this isn't really a p2pkh
                return self.for_p2pkh(h160)

            if type == "p2sh":
                return self.for_p2sh(script_info["hash160"])

            if type == "p2tr":
                return self.for_p2tr(script_info["synthetic_key"])

            if type == "nulldata":
                return "(nulldata %s)" % b2h(script_info["data"])

            return "???"

        if address_prefix:
            def for_p2pkh(self, h160):
                return self.b2a(address_prefix + h160)

        if pay_to_script_prefix:
            def for_p2sh(self, h160):
                return self.b2a(pay_to_script_prefix + h160)

        if bech32_hrp:
            def for_p2pkh_wit(self, h160):
                assert len(h160) == 20
                return bech32m.encode(bech32_hrp, 0, iterbytes(h160))

        if bech32_hrp:
            def for_p2sh_wit(self, hash256):
                assert len(hash256) == 32
                return bech32m.encode(bech32_hrp, 0, iterbytes(hash256))

        if bech32_hrp:
            def for_p2tr(self, synthetic_key):
                return bech32m.encode(bech32_hrp, 1, iterbytes(synthetic_key))

        # p2s and p2s_wit helpers

        if pay_to_script_prefix:
            def for_p2s(self, script):
                return self.for_p2sh(hash160(script))

        if bech32_hrp:
            def for_p2s_wit(self, script):
                return self.for_p2sh_wit(hashlib.sha256(
                    script).digest())

    return AddressAPI()
