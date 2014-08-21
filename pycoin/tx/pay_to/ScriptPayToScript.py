from ..script import tools

from ... import encoding

from ...networks import pay_to_script_prefix_for_netcode
from ...serialize import b2h

from .ScriptType import ScriptType


class ScriptPayToScript(ScriptType):
    TEMPLATE = tools.compile("OP_HASH160 OP_PUBKEYHASH OP_EQUAL")

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

    def solve(self, **kwargs):
        """
        p2sh_lookup:
            dict-like structure that returns the underlying script for the given hash160
        """
        from . import script_obj_from_script
        p2sh_lookup = kwargs.get("p2sh_lookup")
        if p2sh_lookup is None:
            raise ValueError("p2sh_lookup not set")
        underlying_script = p2sh_lookup.get(self.hash160)
        if underlying_script is None:
            raise ValueError("underlying script cannot be determined for %s" % b2h(self.hash160))
        script_obj = script_obj_from_script(underlying_script)
        underlying_solution = script_obj.solve(**kwargs)
        solution = underlying_solution + tools.bin_script([underlying_script])
        return solution

    def script(self):
        if self._script is None:
            # create the script
            STANDARD_SCRIPT_OUT = "OP_HASH160 %s OP_EQUAL"
            script_text = STANDARD_SCRIPT_OUT % b2h(self.hash160)
            self._script = tools.compile(script_text)
        return self._script

    def info(self, netcode="BTC"):
        address_prefix = pay_to_script_prefix_for_netcode(netcode)
        address = encoding.hash160_sec_to_bitcoin_address(self.hash160, address_prefix=address_prefix)
        return dict(type="pay to script", address=address, hash160=self.hash160,
                    script=self._script, address_prefix=address_prefix, summary=address)

    def __repr__(self):
        return "<Script: pay to %s>" % self.address()
