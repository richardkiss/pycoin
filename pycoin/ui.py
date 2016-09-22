
from pycoin import encoding

from pycoin.key.validate import netcode_and_type_for_text
from pycoin.networks.registry import network_codes
from pycoin.networks import pay_to_script_prefix_for_netcode
from pycoin.networks.default import get_current_netcode
from pycoin.tx.pay_to import ScriptPayToAddress, ScriptPayToScript


def script_obj_from_address(address, netcodes=None):
    netcode, key_type, data = netcode_and_type_for_text(address)
    if key_type == 'pay_to_script':
        return ScriptPayToScript(hash160=data)
    if key_type == 'address':
        return ScriptPayToAddress(hash160=data)
    raise ValueError("bad text")


def standard_tx_out_script(address, netcodes=None):
    script_obj = script_obj_from_address(address, netcodes)
    return script_obj.script()


def address_for_pay_to_script(script, netcode="BTC"):
    if netcode is None:
        netcode = get_current_netcode()
    address_prefix = pay_to_script_prefix_for_netcode(netcode)
    return encoding.hash160_sec_to_bitcoin_address(encoding.hash160(script), address_prefix=address_prefix)
