import collections
import hashlib

from pycoin import encoding
from pycoin.serialize import b2h


class PayTo(object):
    def __init__(self, scriptTools):
        self._scriptTools = scriptTools

    def types(self):
        return ["p2pk", "p2pkh", "p2pkh_wit", "p2sh", "p2s", "p2sh_wit", "multisig", "nulldata", "nulldata_push"]

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
        return self.script_for_p2sh(encoding.hash160(underlying_script))

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

    def match(self, template_disassembly, script):
        template = self._scriptTools.compile(template_disassembly)
        r = collections.defaultdict(list)
        pc1 = pc2 = 0
        while 1:
            if pc1 == len(script) and pc2 == len(template):
                return r
            if pc1 >= len(script) or pc2 >= len(template):
                break
            opcode1, data1, pc1 = self._scriptTools.scriptStreamer.get_opcode(script, pc1)
            opcode2, data2, pc2 = self._scriptTools.scriptStreamer.get_opcode(template, pc2)
            l1 = 0 if data1 is None else len(data1)
            if data2 == b'PUBKEY':
                if l1 < 33 or l1 > 120:
                    break
                r["PUBKEY_LIST"].append(data1)
            elif data2 == b'PUBKEYHASH':
                if l1 != 160/8:
                    break
                r["PUBKEYHASH_LIST"].append(data1)
            elif data2 == b'DATA':
                r["DATA_LIST"].append(data1)
            elif (opcode1, data1) != (opcode2, data2):
                break
        return None

    # TODO: info_for_script
    # type: "p2pk", "p2pkh", "p2pkh_wit", "p2sh", "p2s", "p2sh_wit", "multisig", "nulldata", "nulldata_push"
    # p2pk: PUBKEY
    # p2pkh: PUBKEYHASH
    # p2pkh_wit: PUBKEYHASH
    # p2sh: SCRIPTHASH160
    # p2s: SCRIPTHASH160 (never)
    # p2sh_wit: SCRIPTHASH256
    # multisig: PUBKEY_LIST, M
    # nulldata: DATA
    # nulldata_push: DATA, RAW_DATA

    def info_from_script_p2pkh(self, script):
        return self.match("OP_DUP OP_HASH160 'PUBKEYHASH' OP_EQUALVERIFY OP_CHECKSIG", script)

    def info_from_script_p2pkh_wit(self, script):
        return self.match("OP_0 'PUBKEYHASH'", script)

    def info_from_script_p2pk(self, script):
        return self.match("'PUBKEY' OP_CHECKSIG", script)

    def info_from_script_p2sh(self, script):
        return self.match("OP_HASH160 'PUBKEYHASH' OP_EQUAL", script)

    def info_from_nulldata(self, script):
        if self.match("OP_RETURN", script[:1]) is not None:
            return dict(DATA=script[1:])

    def info_from_multisig_script(self, script):
        scriptTools = self._scriptTools
        scriptStreamer = scriptTools.scriptStreamer
        OP_1 = scriptTools.int_for_opcode("OP_1")
        OP_16 = scriptTools.int_for_opcode("OP_16")
        pc = 0
        if len(script) == 0:
            return None
        opcode, data, pc = scriptStreamer.get_opcode(script, pc)

        if not OP_1 <= opcode < OP_16:
            return None
        m = opcode + (1 - OP_1)
        sec_keys = []
        while 1:
            if pc >= len(script):
                return None
            opcode, data, pc = scriptStreamer.get_opcode(script, pc)
            l = len(data) if data else 0
            if l < 33 or l > 120:
                break
            sec_keys.append(data)
        n = opcode + (1 - OP_1)
        if m > n or len(sec_keys) != n:
            return None

        opcode, data, pc = scriptStreamer.get_opcode(script, pc)
        OP_CHECKMULTISIG = scriptTools.int_for_opcode("OP_CHECKMULTISIG")
        if opcode != OP_CHECKMULTISIG:
            return None
        if pc != len(script):
            return None
        return dict(sec_keys=sec_keys, m=m)

    def nulldata_for_script(self, script):
        return script[1:]
