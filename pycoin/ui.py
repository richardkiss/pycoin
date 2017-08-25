import hashlib

from pycoin import encoding

from pycoin.contrib import segwit_addr
from pycoin.intbytes import iterbytes
from pycoin.key.validate import netcode_and_type_for_text
from pycoin.networks import (
    bech32_hrp_for_netcode, pay_to_script_prefix_for_netcode
)
from pycoin.networks.default import get_current_netcode

from pycoin.tx.pay_to import (
    ScriptPayToAddress, ScriptPayToScript,
    ScriptPayToAddressWit, ScriptPayToScriptWit, script_obj_from_script
)


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


def standard_tx_out_script(address, netcodes=None):
    script_obj = script_obj_from_address(address, netcodes)
    return script_obj.script()


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
