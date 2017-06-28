import hashlib

from ... import ecdsa
from ... import encoding

from .ScriptPayToAddress import ScriptPayToAddress
from .ScriptPayToAddressWit import ScriptPayToAddressWit
from .ScriptPayToPublicKey import ScriptPayToPublicKey
from .ScriptPayToScript import ScriptPayToScript
from .ScriptPayToScriptWit import ScriptPayToScriptWit
from .ScriptMultisig import ScriptMultisig
from .ScriptUnknown import ScriptUnknown
from .ScriptNulldata import ScriptNulldata


SUBCLASSES = [
    ScriptPayToAddress, ScriptPayToAddressWit, ScriptPayToPublicKey,
    ScriptPayToScript, ScriptPayToScriptWit,
    ScriptMultisig, ScriptNulldata, ScriptUnknown
]


def script_obj_from_script(script):
    for sc in SUBCLASSES:
        try:
            st = sc.from_script(script)
            return st
        except ValueError:
            pass
    return None


def build_hash160_lookup(secret_exponents):
    from ...key import Key
    d = {}
    for secret_exponent in secret_exponents:
        key = Key(secret_exponent)
        for compressed in (True, False):
            t = (secret_exponent, key.public_pair(), compressed)
            d[key.hash160(use_uncompressed=not compressed)] = t
            d[key.sec(use_uncompressed=not compressed)] = t
            d[key.public_pair()] = t
    return d


def build_p2sh_lookup(scripts):
    d1 = dict((encoding.hash160(s), s) for s in scripts)
    d1.update((hashlib.sha256(s).digest(), s) for s in scripts)
    return d1
