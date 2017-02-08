from pycoin.intbytes import byte_to_int

from ..script import tools

from ...serialize import b2h

from .ScriptType import ScriptType


class ScriptPayToScriptWit(ScriptType):
    def __init__(self, version, hash256):
        assert len(version) == 1
        assert isinstance(version, bytes)
        assert len(hash256) == 32
        assert isinstance(hash256, bytes)
        version_int = byte_to_int(version[0])
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
        print(script_obj)

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

    def address(self, netcode=None):
        return "0x%s" % b2h(self.script())

    def info(self):
        return dict(type="pay to script (segwit)", address_f=self.address,
                    hash160=self.hash160, script=self._script)

    def __repr__(self):
        return "<Script: pay to %s (segwit)>" % self.address()
