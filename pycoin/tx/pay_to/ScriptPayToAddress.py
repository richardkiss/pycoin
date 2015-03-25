from ..script import tools

from ... import encoding

from ...networks import address_prefix_for_netcode
from ...serialize import b2h

from .ScriptType import ScriptType


class ScriptPayToAddress(ScriptType):
    TEMPLATE = tools.compile("OP_DUP OP_HASH160 OP_PUBKEYHASH OP_EQUALVERIFY OP_CHECKSIG")

    def __init__(self, hash160):
        self.hash160 = hash160
        self._address = None
        self._script = None

    @classmethod
    def from_script(cls, script):
        r = cls.match(script)
        if r:
            hash160 = r["PUBKEYHASH_LIST"][0]
            s = cls(hash160)
            return s
        raise ValueError("bad script")

    def script(self):
        if self._script is None:
            # create the script
            STANDARD_SCRIPT_OUT = "OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG"
            script_text = STANDARD_SCRIPT_OUT % b2h(self.hash160)
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
        result = db.get(self.hash160)
        if result is None:
            raise SolvingError("can't find secret exponent for %s" % self.address())
        # we got it
        sign_value = kwargs.get("sign_value")
        signature_type = kwargs.get("signature_type")

        secret_exponent, public_pair, compressed = result

        binary_signature = self._create_script_signature(secret_exponent, sign_value, signature_type)
        binary_public_pair_sec = encoding.public_pair_to_sec(public_pair, compressed=compressed)

        solution = tools.bin_script([binary_signature, binary_public_pair_sec])
        return solution

    def info(self, netcode='BTC'):
        address_prefix = address_prefix_for_netcode(netcode)
        address = encoding.hash160_sec_to_bitcoin_address(self.hash160, address_prefix=address_prefix)
        return dict(type="pay to address", address=address, hash160=self.hash160,
                    script=self._script, address_prefix=address_prefix, summary=address)

    def __repr__(self):
        return "<Script: pay to %s>" % self.address()
