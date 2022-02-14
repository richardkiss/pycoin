import collections
import hashlib

from pycoin.encoding.hash import hash160
from pycoin.encoding.hexbytes import b2h

from .Contract import Contract


class ContractAPI(object):
    def __init__(self, network, script_tools):
        self._network = network
        self._script_tools = script_tools

    def for_address(self, address):
        info = self._network.parse.address(address)
        if info:
            return info.script()

    def for_p2pk(self, sec):
        return self.for_info(dict(type="p2pk", sec=sec))

    def for_p2pkh(self, hash160):
        return self.for_info(dict(type="p2pkh", hash160=hash160))

    def for_p2pkh_wit(self, hash160):
        return self.for_info(dict(type="p2pkh_wit", hash160=hash160))

    def for_p2sh(self, hash160):
        return self.for_info(dict(type="p2sh", hash160=hash160))

    def for_p2sh_wit(self, hash256):
        return self.for_info(dict(type="p2sh_wit", hash256=hash256))

    def for_multisig(self, m, sec_keys):
        return self.for_info(dict(type="multisig", m=m, sec_keys=sec_keys))

    def for_nulldata(self, data):
        return self.for_info(dict(type="nulldata", data=data))

    def for_nulldata_push(self, data):
        # BRAIN DAMAGE
        return self._script_tools.compile("OP_RETURN [%s]" % b2h(data))

    # BRAIN DAMAGE: the stuff above is redundant

    def for_p2s(self, underlying_script):
        return self.for_p2sh(hash160(underlying_script))

    def for_p2s_wit(self, underlying_script):
        return self.for_p2sh_wit(hashlib.sha256(underlying_script).digest())

    def for_p2tr(self, synthetic_key):
        return self.for_info(dict(type="p2tr", synthetic_key=synthetic_key))

    def match(self, template_disassembly, script):
        template = self._script_tools.compile(template_disassembly)
        r = collections.defaultdict(list)
        pc1 = pc2 = 0
        while 1:
            if pc1 == len(script) and pc2 == len(template):
                return r
            if pc1 >= len(script) or pc2 >= len(template):
                break
            opcode1, data1, pc1, is_ok2 = self._script_tools.scriptStreamer.get_opcode(script, pc1)
            opcode2, data2, pc2, is_ok2 = self._script_tools.scriptStreamer.get_opcode(template, pc2)
            l1 = 0 if data1 is None else len(data1)
            if data2 == b'PUBKEY':
                if l1 < 33 or l1 > 120:
                    break
                r["PUBKEY_LIST"].append(data1)
            elif data2 == b'PUBKEYHASH':
                if l1 != 160/8:
                    break
                r["PUBKEYHASH_LIST"].append(data1)
            elif data2 == b'SEGWIT':
                if l1 not in (256/8, 160/8):
                    break
                r["SEGWIT_LIST"].append(data1)
            elif data2 == b'DATA':
                r["DATA_LIST"].append(data1)
            elif data2 == b'SYNTHETIC_KEY':
                if l1 != 32:
                    break
                r["SYNTHETIC_KEY"].append(data1)
            elif (opcode1, data1) != (opcode2, data2):
                break
        return None

    _SCRIPT_LOOKUP = dict(
        p2pk=lambda info: "%s OP_CHECKSIG" % b2h(info.get("sec")),
        p2pkh=lambda info: "OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG" % b2h(info.get("hash160")),
        p2pkh_wit=lambda info: "OP_0 %s" % b2h(info.get("hash160")),
        p2sh=lambda info: "OP_HASH160 %s OP_EQUAL" % b2h(info.get("hash160")),
        p2sh_wit=lambda info: "OP_0 %s" % b2h(info.get("hash256")),
        p2tr=lambda info: "OP_1 %s" % b2h(info.get("synthetic_key")),
        multisig=lambda info: "%d %s %d OP_CHECKMULTISIG" % (
            info.get("m"), " ".join(b2h(sk) for sk in info.get("sec_keys")), len(info.get("sec_keys"))),
    )

    def for_info(self, info):
        type = info.get("type")
        if type == "nulldata":
            return self._script_tools.compile("OP_RETURN") + info.get("data")
        if type == "unknown":
            return info["script"]
        script_text = self._SCRIPT_LOOKUP[type](info)
        return self._script_tools.compile(script_text)

    def new(self, script_info):
        return Contract(script_info, self._network)

    # MISSING to consider
    # p2s: SCRIPTHASH160
    # nulldata_push: DATA, RAW_DATA

    def info_for_script(self, script):
        d = self.match("OP_DUP OP_HASH160 'PUBKEYHASH' OP_EQUALVERIFY OP_CHECKSIG", script)
        if d:
            return dict(type="p2pkh", hash160=d["PUBKEYHASH_LIST"][0])

        d = self.match("OP_0 'SEGWIT'", script)
        if d:
            data = d["SEGWIT_LIST"][0]
            if len(data) == 20:
                return dict(type="p2pkh_wit", hash160=data)
            if len(data) == 32:
                return dict(type="p2sh_wit", hash256=data)

        d = self.match("OP_HASH160 'PUBKEYHASH' OP_EQUAL", script)
        if d:
            return dict(type="p2sh", hash160=d["PUBKEYHASH_LIST"][0])

        d = self.match("'PUBKEY' OP_CHECKSIG", script)
        if d:
            return dict(type="p2pk", sec=d["PUBKEY_LIST"][0])

        d = self.match("OP_1 'SYNTHETIC_KEY'", script)
        if d:
            if len(d["SYNTHETIC_KEY"][0]) == 32:
                return dict(type="p2tr", synthetic_key=d["SYNTHETIC_KEY"][0])

        if self._script_tools.compile("OP_RETURN") == script[:1]:
            return dict(type="nulldata", data=script[1:])

        d = self._info_from_multisig_script(script)
        if d:
            return d

        return dict(type="unknown", script=script)

    def _info_from_multisig_script(self, script):
        script_tools = self._script_tools
        scriptStreamer = script_tools.scriptStreamer
        OP_1 = script_tools.int_for_opcode("OP_1")
        OP_16 = script_tools.int_for_opcode("OP_16")
        pc = 0
        if len(script) == 0:
            return None
        opcode, data, pc, is_ok = scriptStreamer.get_opcode(script, pc)

        if not OP_1 <= opcode < OP_16:
            return None
        m = opcode + (1 - OP_1)
        sec_keys = []
        while pc < len(script):
            opcode, data, pc, is_ok = scriptStreamer.get_opcode(script, pc)
            size = len(data) if data else 0
            if size < 33 or size > 120:
                break
            sec_keys.append(data)
        if pc >= len(script):
            return None
        n = opcode + (1 - OP_1)
        if m > n or len(sec_keys) != n:
            return None

        opcode, data, pc, is_ok = scriptStreamer.get_opcode(script, pc)
        OP_CHECKMULTISIG = script_tools.int_for_opcode("OP_CHECKMULTISIG")
        if opcode != OP_CHECKMULTISIG:
            return None
        if pc != len(script):
            return None
        return dict(type="multisig", sec_keys=sec_keys, m=m)
