from ..script import tools

from ... import encoding
from ...networks import address_prefix_for_netcode
from ...serialize import b2h

from .ScriptType import ScriptType


class ScriptPayToPublicKey(ScriptType):
    """
    This is generally used in coinbase transactions only.
    """
    TEMPLATE = tools.compile("OP_PUBKEY OP_CHECKSIG")

    def __init__(self, sec):
        self.sec = sec
        self._address = None
        self._script = None

    @classmethod
    def from_key(cls, key, use_uncompressed=False):
        return cls.from_sec(key.sec(use_uncompressed=use_uncompressed))

    @classmethod
    def from_sec(cls, sec):
        return cls(sec)

    @classmethod
    def from_script(cls, script):
        r = cls.match(script)
        if r:
            sec = r["PUBKEY_LIST"][0]
            s = cls(sec)
            return s
        raise ValueError("bad script")

    def script(self):
        if self._script is None:
            # create the script
            STANDARD_SCRIPT_OUT = "%s OP_CHECKSIG"
            script_text = STANDARD_SCRIPT_OUT % b2h(self.sec)
            self._script = tools.compile(script_text)
        return self._script

    def solve(self, **kwargs):
        """
        The kwargs required depend upon the script type.
        hash160_lookup:
            dict-like structure that returns a secret exponent for a hash160
        sign_value:
            the integer value to sign (derived from the transaction hash)
        signature_type:
            usually SIGHASH_ALL (1)
        """
        # we need a hash160 => secret_exponent lookup
        db = kwargs.get("hash160_lookup")
        if db is None:
            raise SolvingError("missing hash160_lookup parameter")
        self.address()
        result = db.get(encoding.hash160(self.sec))
        if result is None:
            raise SolvingError("can't find secret exponent for %s" % self.address())

        sign_value = kwargs.get("sign_value")
        signature_type = kwargs.get("signature_type")

        secret_exponent, public_pair, compressed = result

        solution = tools.bin_script([self._create_script_signature(
            secret_exponent, sign_value, signature_type)])
        return solution

    def info(self, netcode="BTC"):
        address_prefix = address_prefix_for_netcode(netcode)
        hash160 = encoding.hash160(self.sec)
        address = encoding.hash160_sec_to_bitcoin_address(hash160, address_prefix=address_prefix)
        return dict(type="pay to public key", address=address, hash160=hash160,
                    script=self._script, address_prefix=address_prefix, summary=address)

    def __repr__(self):
        return "<Script: pay to %s (sec)>" % self.address()
