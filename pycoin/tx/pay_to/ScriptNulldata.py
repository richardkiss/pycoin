from ..script.VM import VM

from ...intbytes import byte_to_int
from ...serialize import b2h

from .ScriptType import ScriptType


class ScriptNulldata(ScriptType):
    SCRIPT = VM.compile("OP_RETURN")

    def __init__(self, nulldata):
        self.nulldata = nulldata
        self._script = self.SCRIPT + self.nulldata

    @classmethod
    def from_script(cls, script):
        if byte_to_int(script[0]) == VM.OP_RETURN:
            return cls(script[1:])
        raise ValueError("bad script")

    def script(self):
        return self._script

    def info(self):
        def address_f(netcode=None):
            return "(nulldata %s)" % b2h(self.nulldata)
        return dict(type="nulldata", address_f=address_f, script=self._script, summary=self.nulldata)

    def __repr__(self):
        return "<Script: nulldata %s>" % self.nulldata
