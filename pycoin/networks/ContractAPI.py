class ContractAPI(object):
    def __init__(self, network, contract, ui):
        self._network = network
        self._contract = contract
        self._ui = ui

    def for_address(self, address):
        info = self._network.parse.address(address)
        if info:
            return info.script()

    def for_multisig(self, m, sec_keys):
        return self._contract.script_for_multisig(m, sec_keys)

    def for_nulldata(self, s):
        return self._contract.script_for_nulldata(s)

    def for_nulldata_push(self, s):
        return self._contract.script_for_nulldata_push(s)

    def for_p2pk(self, s):
        return self._contract.script_for_p2pk(s)

    def for_p2pkh(self, s):
        return self._contract.script_for_p2pkh(s)

    def for_p2sh(self, s):
        return self._contract.script_for_p2sh(s)

    def for_p2s(self, s):
        return self._contract.script_for_p2s(s)

    def for_p2pkh_wit(self, s):
        if self._ui._bech32_hrp:
            return self._contract.script_for_p2pkh_wit(s)

    def for_p2s_wit(self, s):
        if self._ui._bech32_hrp:
            return self._contract.script_for_p2s_wit(s)

    def for_p2sh_wit(self, s):
        if self._ui._bech32_hrp:
            return self._contract.script_for_p2sh_wit(s)

    def for_info(self, s):
        return self._contract.script_for_info(s)
