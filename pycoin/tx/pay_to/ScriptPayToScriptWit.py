from pycoin.intbytes import byte2int

from ..script import tools

from ...serialize import b2h

from .ScriptType import ScriptType

from pycoin.contrib import segwit_addr


class ScriptPayToScriptWit(ScriptType):
    def __init__(self, version, hash256):
        assert len(version) == 1
        assert isinstance(version, bytes)
        assert len(hash256) == 32
        assert isinstance(hash256, bytes)
        version_int = byte2int(version)
        assert 0 <= version_int <= 16
        self.version = version_int
        self.hash256 = hash256
        self._address = None
        self._script = None

    @classmethod
    def from_script(cls, script):
        if len(script) != 34 or script[0:2] != b'\00\x20':
            raise ValueError("bad script")
        return cls(script[:1], script[2:])

    def solve(self, **kwargs):
        """
        p2sh_lookup:
            dict-like structure that returns the underlying script for the given hash256
        """
        from . import script_obj_from_script
        p2sh_lookup = kwargs.get("p2sh_lookup")
        if p2sh_lookup is None:
            raise ValueError("p2sh_lookup (with hash256) not set")
        underlying_script = p2sh_lookup.get(self.hash256)
        if underlying_script is None:
            raise ValueError("underlying script cannot be determined for %s" % b2h(self.hash256))
        script_obj = script_obj_from_script(underlying_script)

        kwargs["signature_for_hash_type_f"] = kwargs["signature_for_hash_type_f"].witness
        kwargs["script_to_hash"] = underlying_script
        kwargs["existing_script"] = tools.bin_script(kwargs["existing_witness"])
        underlying_solution = script_obj.solve(**kwargs)
        # we need to unwrap the solution
        solution = []
        pc = 0
        while pc < len(underlying_solution):
            opcode, data, pc = tools.get_opcode(underlying_solution, pc)
            solution.append(data)
        solution.append(underlying_script)
        return (b"", solution)

    def script(self):
        if self._script is None:
            # create the script
            STANDARD_SCRIPT_OUT = "OP_0 %s"
            script_text = STANDARD_SCRIPT_OUT % b2h(self.hash256)
            self._script = tools.compile(script_text)
        return self._script

    def info(self, netcode=None):
        def address_f(netcode=netcode):
            from pycoin.networks import bech32_hrp_for_netcode
            from pycoin.networks.default import get_current_netcode
            if netcode is None:
                netcode = get_current_netcode()

            bech32_hrp = bech32_hrp_for_netcode(netcode)
            address = segwit_addr.encode(bech32_hrp, self.version, self.hash256)
            return address
        return dict(type="pay to witness script hash", address="DEPRECATED call address_f instead",
                    address_f=address_f, hash256=self.hash256, script=self._script)

    def __repr__(self):
        return "<Script: pay to %s (segwit)>" % self.address()
