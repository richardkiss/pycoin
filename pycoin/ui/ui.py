import hashlib

from pycoin import encoding
from pycoin.serialize import b2h
from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools as ScriptTools  # BRAIN DAMAGEs

from pycoin.contrib import segwit_addr
from pycoin.intbytes import iterbytes
from pycoin.ui.validate import netcode_and_type_for_text
from pycoin.networks import (
    bech32_hrp_for_netcode, pay_to_script_prefix_for_netcode
)
from pycoin.networks.default import get_current_netcode

#from pycoin.tx.pay_to import (
#    ScriptPayToAddress, ScriptPayToScript,
#    ScriptPayToAddressWit, ScriptPayToScriptWit, script_obj_from_script
#)


def address_for_script(script):
    # BRAIN DAMAGE
    return "TO BE IMPLEMENTED"


def script_obj_from_address(address, netcodes=None):
    netcode, key_type, data = netcode_and_type_for_text(address, netcodes)
    if key_type == 'pay_to_script':
        return ScriptPayToScript(hash160=data)
    if key_type == 'address':
        return ScriptPayToAddress(hash160=data)
    if key_type == 'address_wit':
        return ScriptPayToAddressWit(version=data[:1], hash160=data[2:])
    if key_type == 'pay_to_script_wit':
        return ScriptPayToScriptWit(version=data[:1], hash256=data[2:])
    if key_type == 'segwit':
        return script_obj_from_script(data)
    raise ValueError("bad text")


def script_for_address(address, netcodes=["BTC"]):
    # BRAIN DAMAGE
    netcode, key_type, data = netcode_and_type_for_text(address, netcodes)
    if key_type == 'address':
        return script_for_p2phk(data)
    if key_type == 'pay_to_script':
        return script_for_p2sh(data)
    if key_type == 'segwit':
        return data
    # BRAIN DAMAGE: TODO
    import pdb
    pdb.set_trace()
    raise ValueError("bad text")


def script_for_p2pk(public_key_as_sec):
    script_text = "%s OP_CHECKSIG" % b2h(public_key_as_sec)
    return ScriptTools.compile(script_text)


def script_for_p2phk(hash160):
    script_source = "OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG" % b2h(hash160)
    return ScriptTools.compile(script_source)


def script_for_p2phk_wit(hash160):
    script_text = "OP_0 %s" % b2h(hash160)
    return ScriptTools.compile(script_text)


def script_for_p2sh(underlying_script):
    script_text = "OP_HASH160 %s OP_EQUAL" % b2h(underlying_script)
    return ScriptTools.compile(script_text)


def script_for_p2sh_wit(underlying_script):
    hash256 = hashlib.sha256(underlying_script).digest()
    script_text = "OP_0 %s" % b2h(hash256)
    return ScriptTools.compile(script_text)


def script_for_multisig(m, sec_keys):
    script_source = "%d %s %d OP_CHECKMULTISIG" % (m, " ".join(b2h(sk) for sk in sec_keys), len(sec_keys))
    return ScriptTools.compile(script_source)


def script_for_nulldata(bin_data):
    return ScriptTools.compile("OP_RETURN") + bin_data


def nulldata_for_script(script):
    return script[1:]


def standard_tx_out_script(address, netcodes=None):
    # BRAIN DAMAGE: this is lame
    data = encoding.a2b_hashed_base58(address)
    prefix, hash160 = data[:1], data[1:]
    # BRAIN DAMAGE: need to check prefix against netcodes
    return script_for_p2phk(hash160)


def match(cls, script):
    template = cls.TEMPLATE
    r = collections.defaultdict(list)
    pc1 = pc2 = 0
    while 1:
        if pc1 == len(script) and pc2 == len(template):
            return r
        if pc1 >= len(script) or pc2 >= len(template):
            break
        opcode1, data1, pc1 = VM.ScriptStreamer.get_opcode(script, pc1)
        opcode2, data2, pc2 = VM.ScriptStreamer.get_opcode(template, pc2)
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
    raise ValueError("script doesn't match")


def address_for_p2skh_wit(hash160, netcode):
    bech32_hrp = bech32_hrp_for_netcode(netcode)
    address = segwit_addr.encode(bech32_hrp, 0, iterbytes(hash160))
    return address


def address_for_pay_to_script(script, netcode=None):
    if netcode is None:
        netcode = get_current_netcode()
    address_prefix = pay_to_script_prefix_for_netcode(netcode)
    if address_prefix:
        return encoding.hash160_sec_to_bitcoin_address(encoding.hash160(script), address_prefix=address_prefix)
    return None


def address_for_pay_to_script_wit(script, netcode=None):
    if netcode is None:
        netcode = get_current_netcode()
    bech32_hrp = bech32_hrp_for_netcode(netcode)
    address = segwit_addr.encode(bech32_hrp, 0, iterbytes(hashlib.sha256(script).digest()))
    return address
