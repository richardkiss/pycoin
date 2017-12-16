from pycoin.contrib import segwit_addr
from pycoin.intbytes import int2byte
from pycoin.ui.Parser import Parser, make_base58_prefixes


class AddressParser(Parser):
    TYPE = "address"

    def __init__(self, pay_to, address_prefix, pay_to_script_prefix, bech32_hrp):
        self._pay_to = pay_to
        prefixes = []
        if address_prefix:
            prefixes.append((address_prefix, self.info_for_p2pkh))
        if pay_to_script_prefix:
            prefixes.append((pay_to_script_prefix, self.info_for_p2sh))

        self._base58_prefixes = make_base58_prefixes(prefixes)
        if bech32_hrp:
            self._bech32_prefixes = {bech32_hrp: [self.info_for_p2wit]}

    def info_for_p2pkh(self, data):
        hash160 = data[1:]
        return dict(type="address", address_type="p2pkh", hash160=hash160,
                    create_f=lambda: self._pay_to.script_for_p2pkh(hash160))

    def info_for_p2sh(self, data):
        hash160 = data[1:]
        return dict(type="address", address_type="p2sh", hash160=hash160,
                    create_f=lambda: self._pay_to.script_for_p2sh(hash160))

    def info_for_p2wit(self, hrp, data):
        decoded = segwit_addr.convertbits(data[1:], 5, 8, False)
        decoded_data = b''.join(int2byte(d) for d in decoded)
        ldd = len(decoded_data)
        version_byte = int2byte(data[0])
        script = version_byte + int2byte(ldd) + decoded_data

        if version_byte == 0:
            if ldd == 20:
                return dict(type="address", address_type="p2pkh_wit", hash160=data,
                            create_f=lambda: self._pay_to.script_for_p2pkh_wit(data))

            if ldd == 32:
                return dict(type="address", address_type="p2sh_wit", hash256=data,
                            create_f=lambda: self._pay_to.script_for_p2sh_wit(data))

        return dict(type="address", address_type="wit_other", version_byte=version_byte,
                    create_f=lambda: script)
