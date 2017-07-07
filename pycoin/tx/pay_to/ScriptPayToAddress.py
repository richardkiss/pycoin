from ..script import tools

from ... import encoding

from ...serialize import b2h

from ..exceptions import SolvingError

from .ScriptType import ScriptType


class ScriptPayToAddress(ScriptType):
    TEMPLATE = tools.compile("OP_DUP OP_HASH160 'PUBKEYHASH' OP_EQUALVERIFY OP_CHECKSIG")

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
        signature_for_hash_type_f:
            function returning sign value for a given signature type
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
        signature_for_hash_type_f = kwargs.get("signature_for_hash_type_f")
        signature_type = kwargs.get("signature_type")
        script_to_hash = kwargs.get("script_to_hash")

        secret_exponent, public_pair, compressed = result

        binary_signature = self._create_script_signature(
            secret_exponent, signature_for_hash_type_f, signature_type, script_to_hash)
        binary_public_pair_sec = encoding.public_pair_to_sec(public_pair, compressed=compressed)

        solution = tools.bin_script([binary_signature, binary_public_pair_sec])
        return solution

    def info(self, netcode=None):
        def address_f(netcode=netcode):
            from pycoin.networks import address_prefix_for_netcode
            from pycoin.networks.default import get_current_netcode
            if netcode is None:
                netcode = get_current_netcode()
            address_prefix = address_prefix_for_netcode(netcode)
            address = encoding.hash160_sec_to_bitcoin_address(self.hash160, address_prefix=address_prefix)
            return address
        return dict(type="pay to address", address="DEPRECATED call address_f instead",
                    address_f=address_f, hash160=self.hash160, script=self._script)

    def __repr__(self):
        return "<Script: pay to %s>" % self.address()
