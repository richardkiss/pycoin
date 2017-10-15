import collections
import hashlib

from pycoin import encoding
from pycoin.serialize import b2h
from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools as ScriptTools  # BRAIN DAMAGEs
from pycoin.coins.bitcoin.ScriptStreamer import BitcoinScriptStreamer as ScriptStreamer  # BRAIN DAMAGEs

from pycoin.contrib import segwit_addr
from pycoin.intbytes import iterbytes, byte2int


def match(template_disassembly, script):
    template = ScriptTools.compile(template_disassembly)
    r = collections.defaultdict(list)
    pc1 = pc2 = 0
    while 1:
        if pc1 == len(script) and pc2 == len(template):
            return r
        if pc1 >= len(script) or pc2 >= len(template):
            break
        opcode1, data1, pc1 = ScriptStreamer.get_opcode(script, pc1)
        opcode2, data2, pc2 = ScriptStreamer.get_opcode(template, pc2)
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


def address_for_script(script, netcode='BTC'):
    d = match("OP_DUP OP_HASH160 'PUBKEYHASH' OP_EQUALVERIFY OP_CHECKSIG", script)
    if d:
        from pycoin.networks import address_prefix_for_netcode
        address_prefix = address_prefix_for_netcode(netcode)
        return encoding.hash160_sec_to_bitcoin_address(d["PUBKEYHASH_LIST"][0], address_prefix=address_prefix)

    d = match("OP_0 'PUBKEYHASH'", script)
    if d:
        from pycoin.networks import bech32_hrp_for_netcode
        from pycoin.intbytes import iterbytes
        bech32_hrp = bech32_hrp_for_netcode(netcode)
        if bech32_hrp:
            return segwit_addr.encode(bech32_hrp, 0, iterbytes(d["PUBKEYHASH_LIST"][0]))

    d = match("'PUBKEY' OP_CHECKSIG", script)
    if d:
        from pycoin.networks import address_prefix_for_netcode
        address_prefix = address_prefix_for_netcode(netcode)
        hash160 = encoding.hash160(d["PUBKEY_LIST"][0])
        return encoding.hash160_sec_to_bitcoin_address(hash160, address_prefix=address_prefix)

    d = match("OP_HASH160 'PUBKEYHASH' OP_EQUAL", script)
    if d:
        from pycoin.networks import pay_to_script_prefix_for_netcode
        address_prefix = pay_to_script_prefix_for_netcode(netcode)
        return encoding.hash160_sec_to_bitcoin_address(d["PUBKEYHASH_LIST"][0], address_prefix=address_prefix)

    if (len(script), script[0:2]) in ((34, b'\00\x20'), (66, 'b\00\x40')):
        from pycoin.networks import bech32_hrp_for_netcode
        bech32_hrp = bech32_hrp_for_netcode(netcode)
        return segwit_addr.encode(bech32_hrp, self.version, self.hash256)

    d = match("OP_RETURN", script[:1])
    if d is not None:
        return "(nulldata %s)" % b2h(nulldata_for_script(script))

    return "???"


def info_from_multisig_script(script):
    OP_1 = byte2int(ScriptTools.compile("OP_1"))
    OP_16 = byte2int(ScriptTools.compile("OP_16"))
    pc = 0
    if len(script) == 0:
        return None
    opcode, data, pc = ScriptStreamer.get_opcode(script, pc)

    if not OP_1 <= opcode < OP_16:
        return None
    m = opcode + (1 - OP_1)
    sec_keys = []
    while 1:
        if pc >= len(script):
            return None
        opcode, data, pc = ScriptStreamer.get_opcode(script, pc)
        l = len(data) if data else 0
        if l < 33 or l > 120:
            break
        sec_keys.append(data)
    n = opcode + (1 - OP_1)
    if m > n or len(sec_keys) != n:
        return None

    opcode, data, pc = ScriptStreamer.get_opcode(script, pc)
    if opcode != ScriptTools.int_for_opcode("OP_CHECKMULTISIG"):
        return None
    if pc != len(script):
        return None
    return dict(sec_keys=sec_keys, m=m)


def script_for_address(address, netcodes=["BTC"]):
    # BRAIN DAMAGE
    from pycoin.ui.validate import netcode_and_type_for_text
    netcode, key_type, data = netcode_and_type_for_text(address, netcodes)
    if key_type == 'address':
        return script_for_p2pkh(data)
    if key_type == 'pay_to_script':
        return script_for_p2sh(data)
    if key_type == 'segwit':
        return data
    # BRAIN DAMAGE: TODO
    raise ValueError("bad text")


def script_for_p2pk(public_key_as_sec):
    script_text = "%s OP_CHECKSIG" % b2h(public_key_as_sec)
    return ScriptTools.compile(script_text)


def script_for_p2pkh(hash160):
    script_source = "OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG" % b2h(hash160)
    return ScriptTools.compile(script_source)


def script_for_p2pkh_wit(hash160):
    script_text = "OP_0 %s" % b2h(hash160)
    return ScriptTools.compile(script_text)


def script_for_p2sh(underlying_script_hash160):
    script_text = "OP_HASH160 %s OP_EQUAL" % b2h(underlying_script_hash160)
    return ScriptTools.compile(script_text)


def script_for_p2s(underlying_script):
    return script_for_p2sh(encoding.hash160(underlying_script))


def script_for_p2sh_wit(underlying_script):
    hash256 = hashlib.sha256(underlying_script).digest()
    script_text = "OP_0 %s" % b2h(hash256)
    return ScriptTools.compile(script_text)


def script_for_multisig(m, sec_keys):
    script_source = "%d %s %d OP_CHECKMULTISIG" % (m, " ".join(b2h(sk) for sk in sec_keys), len(sec_keys))
    return ScriptTools.compile(script_source)


def script_for_nulldata(bin_data):
    return ScriptTools.compile("OP_RETURN") + bin_data


def script_for_nulldata_push(bin_data):
    return script_for_nulldata(ScriptStreamer.compile_push_data(bin_data))


def nulldata_for_script(script):
    return script[1:]


def standard_tx_out_script(address, netcode='BTC'):
    return script_for_address(address, netcodes=[netcode])


def address_for_p2skh_wit(hash160, netcode):
    from pycoin.networks import bech32_hrp_for_netcode
    bech32_hrp = bech32_hrp_for_netcode(netcode)
    if bech32_hrp:
        return segwit_addr.encode(bech32_hrp, 0, iterbytes(hash160))
    return None


def address_for_pay_to_script(script, netcode):
    from pycoin.networks import pay_to_script_prefix_for_netcode
    address_prefix = pay_to_script_prefix_for_netcode(netcode)
    if address_prefix:
        return encoding.hash160_sec_to_bitcoin_address(encoding.hash160(script), address_prefix=address_prefix)
    return None


def address_for_pay_to_script_wit(script, netcode):
    from pycoin.networks import bech32_hrp_for_netcode
    bech32_hrp = bech32_hrp_for_netcode(netcode)
    if bech32_hrp:
        return segwit_addr.encode(bech32_hrp, 0, iterbytes(hashlib.sha256(script).digest()))
    return None
