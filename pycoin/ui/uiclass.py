import collections
import hashlib

from pycoin import encoding
from pycoin.serialize import b2h
#from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools as ScriptTools  # BRAIN DAMAGEs
#from pycoin.coins.bitcoin.ScriptStreamer import BitcoinScriptStreamer as ScriptStreamer  # BRAIN DAMAGEs

from pycoin.contrib import segwit_addr
from pycoin.intbytes import iterbytes, byte2int
from pycoin.networks import (
    address_prefix_for_netcode, bech32_hrp_for_netcode, pay_to_script_prefix_for_netcode)
from pycoin.ui.validate import netcode_and_type_for_text
from pycoin.vm.PuzzleScripts import PuzzleScripts


class UI(object):
    def __init__(self, scriptTools, netcode=None):
        puzzle_scripts = PuzzleScripts(scriptTools)
        self._scriptTools = scriptTools
        self._puzzle_scripts = puzzle_scripts
        self._scriptStreamer = scriptTools.scriptStreamer
        self._address_prefix = address_prefix_for_netcode(netcode)
        self._bech32_hrp = bech32_hrp_for_netcode(netcode)
        self._pay_to_script_prefix = pay_to_script_prefix_for_netcode(netcode)
        self._netcode = netcode

    def match(self, template_disassembly, script):
        template = self._scriptTools.compile(template_disassembly)
        r = collections.defaultdict(list)
        pc1 = pc2 = 0
        while 1:
            if pc1 == len(script) and pc2 == len(template):
                return r
            if pc1 >= len(script) or pc2 >= len(template):
                break
            opcode1, data1, pc1 = self._scriptStreamer.get_opcode(script, pc1)
            opcode2, data2, pc2 = self._scriptStreamer.get_opcode(template, pc2)
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

    def address_for_script(self, script):
        d = self.match("OP_DUP OP_HASH160 'PUBKEYHASH' OP_EQUALVERIFY OP_CHECKSIG", script)
        if d:
            return encoding.hash160_sec_to_bitcoin_address(
                d["PUBKEYHASH_LIST"][0], address_prefix=self._address_prefix)

        d = self.match("OP_0 'PUBKEYHASH'", script)
        if d:
            if self._bech32_hrp:
                return segwit_addr.encode(self._bech32_hrp, 0, iterbytes(d["PUBKEYHASH_LIST"][0]))

        d = self.match("'PUBKEY' OP_CHECKSIG", script)
        if d:
            hash160 = encoding.hash160(d["PUBKEY_LIST"][0])
            return encoding.hash160_sec_to_bitcoin_address(hash160, address_prefix=self._address_prefix)

        d = self.match("OP_HASH160 'PUBKEYHASH' OP_EQUAL", script)
        if d:
            return encoding.hash160_sec_to_bitcoin_address(
                d["PUBKEYHASH_LIST"][0], address_prefix=self._pay_to_script_prefix)

        if (len(script), script[0:2]) in ((34, b'\00\x20'), (66, 'b\00\x40')):
            return segwit_addr.encode(self._bech32_hrp, self.version, self.hash256)

        d = self.match("OP_RETURN", script[:1])
        if d is not None:
            return "(nulldata %s)" % b2h(self.nulldata_for_script(script))

        return "???"

    def info_from_multisig_script(self, script):
        OP_1 = self._scriptTools.int_for_opcode("OP_1")
        OP_16 = self._scriptTools.int_for_opcode("OP_16")
        pc = 0
        if len(script) == 0:
            return None
        opcode, data, pc = self._scriptStreamer.get_opcode(script, pc)

        if not OP_1 <= opcode < OP_16:
            return None
        m = opcode + (1 - OP_1)
        sec_keys = []
        while 1:
            if pc >= len(script):
                return None
            opcode, data, pc = self._scriptStreamer.get_opcode(script, pc)
            l = len(data) if data else 0
            if l < 33 or l > 120:
                break
            sec_keys.append(data)
        n = opcode + (1 - OP_1)
        if m > n or len(sec_keys) != n:
            return None

        opcode, data, pc = self._scriptStreamer.get_opcode(script, pc)
        OP_CHECKMULTISIG = self._scriptTools.int_for_opcode("OP_CHECKMULTISIG")
        if opcode != OP_CHECKMULTISIG:
            return None
        if pc != len(script):
            return None
        return dict(sec_keys=sec_keys, m=m)

    def nulldata_for_script(self, script):
        return script[1:]

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
        # BRAIN DAMAGE
        netcode, key_type, data = netcode_and_type_for_text(address, netcodes=[self._netcode])
        if key_type == 'address':
            return self._puzzle_scripts.script_for_p2pkh(data)
        if key_type == 'pay_to_script':
            return self._puzzle_scripts.script_for_p2sh(data)
        if key_type == 'segwit':
            return data
        # BRAIN DAMAGE: TODO
        raise ValueError("bad text")

    def standard_tx_out_script(self, address):
        return self.script_for_address(address)
