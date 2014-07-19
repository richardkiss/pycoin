
from ... import ecdsa
from ... import encoding

from ...networks import DEFAULT_NETCODES, pay_to_script_prefix_for_netcode
from ...key.validate import netcode_and_type_for_data

from .ScriptPayToAddress import ScriptPayToAddress
from .ScriptPayToPublicKey import ScriptPayToPublicKey
from .ScriptPayToScript import ScriptPayToScript
from .ScriptMultisig import ScriptMultisig
from .ScriptUnknown import ScriptUnknown

SUBCLASSES = [ScriptPayToAddress, ScriptPayToPublicKey, ScriptPayToScript, ScriptMultisig, ScriptUnknown]


class SolvingError(Exception):
    pass


def script_obj_from_address(text, netcodes=DEFAULT_NETCODES):
    data = encoding.a2b_hashed_base58(text)
    netcode, key_type = netcode_and_type_for_data(data, netcodes=netcodes)
    if key_type == 'pay_to_script':
        return ScriptPayToScript(hash160=data[1:])
    if key_type == 'address':
        return ScriptPayToAddress(hash160=data[1:])
    raise ValueError("bad text")


def script_obj_from_script(script):
    for sc in SUBCLASSES:
        try:
            st = sc.from_script(script)
            return st
        except ValueError:
            pass
    return None


def address_for_pay_to_script(script, netcode="BTC"):
    address_prefix = pay_to_script_prefix_for_netcode(netcode)
    return encoding.hash160_sec_to_bitcoin_address(encoding.hash160(script), address_prefix=address_prefix)


def build_hash160_lookup(secret_exponents):
    d = {}
    for secret_exponent in secret_exponents:
        public_pair = ecdsa.public_pair_for_secret_exponent(ecdsa.generator_secp256k1, secret_exponent)
        for compressed in (True, False):
            hash160 = encoding.public_pair_to_hash160_sec(public_pair, compressed=compressed)
            d[hash160] = (secret_exponent, public_pair, compressed)
    return d


def build_p2sh_lookup(scripts):
    return dict((encoding.hash160(s), s) for s in scripts)
