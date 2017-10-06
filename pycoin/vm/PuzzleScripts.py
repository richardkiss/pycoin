from pycoin.serialize import b2h


class PuzzleScripts(object):
    def __init__(self, scriptTools):
        self._scriptTools = scriptTools

    def script_for_p2pk(self, public_key_as_sec):
        script_text = "%s OP_CHECKSIG" % b2h(public_key_as_sec)
        return self._scriptTools.compile(script_text)

    def script_for_p2pkh(self, hash160):
        script_source = "OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG" % b2h(hash160)
        return self._scriptTools.compile(script_source)

    def script_for_p2pkh_wit(self, hash160):
        script_text = "OP_0 %s" % b2h(hash160)
        return self._scriptTools.compile(script_text)

    def script_for_p2sh(self, underlying_script_hash160):
        script_text = "OP_HASH160 %s OP_EQUAL" % b2h(underlying_script_hash160)
        return self._scriptTools.compile(script_text)

    def script_for_p2s(self, underlying_script):
        return script_for_p2sh(encoding.hash160(underlying_script))

    def script_for_p2sh_wit(self, underlying_script):
        hash256 = hashlib.sha256(underlying_script).digest()
        script_text = "OP_0 %s" % b2h(hash256)
        return self._scriptTools.compile(script_text)

    def script_for_multisig(self, m, sec_keys):
        sec_keys_hex = " ".join(b2h(sk) for sk in sec_keys)
        script_source = "%d %s %d OP_CHECKMULTISIG" % (m, sec_keys_hex, len(sec_keys))
        return self._scriptTools.compile(script_source)

    def script_for_nulldata(self, bin_data):
        return self._scriptTools.compile("OP_RETURN") + bin_data

    def script_for_nulldata_push(self, bin_data):
        return self._scriptTools.compile("OP_RETURN [%s]" % b2h(bin_data))
