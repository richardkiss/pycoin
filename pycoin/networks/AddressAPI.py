class AddressAPI(object):

    def __init__(self, canonical_scripts, ui):
        self._canonical_scripts = canonical_scripts
        self._ui = ui

    def address_for_script(self, script):
        info = self._canonical_scripts.info_for_script(script)
        return self._ui.address_for_script_info(info)

    def for_script_info(self, s):
        return self._ui.address_for_script_info(s)

    def for_script(self, s):
        return self.address_for_script(s)

    def for_p2s(self, s):
        return self._ui.address_for_p2s(s)

    def for_p2sh(self, s):
        return self._ui.address_for_p2sh(s)

    def for_p2pkh(self, s):
        return self._ui.address_for_p2pkh(s)

    def for_p2s_wit(self, s):
        if self._ui._bech32_hrp:
            return self._ui.address_for_p2s_wit(s)

    def for_p2sh_wit(self, s):
        if self._ui._bech32_hrp:
            return self._ui.address_for_p2sh_wit(s)

    def for_p2pkh_wit(self, s):
        if self._ui._bech32_hrp:
            return self._ui.address_for_p2pkh_wit(s)
