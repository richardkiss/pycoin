from ..script import tools

from ...serialize import b2h

from .ScriptType import ScriptType


class ScriptNulldata(ScriptType):
    TEMPLATE = tools.compile("OP_RETURN 'DATA'")

    def __init__(self, nulldata):
        self.nulldata = nulldata
        self._script = None

    @classmethod
    def from_script(cls, script):
        r = cls.match(script)
        if r:
            nulldata = r["DATA_LIST"][0]
            s = cls(nulldata)
            return s
        raise ValueError("bad script")

    def script(self):
        if self._script is None:
            # create the script
            STANDARD_SCRIPT_OUT = "OP_RETURN [%s]"
            script_text = STANDARD_SCRIPT_OUT % b2h(self.nulldata)
            self._script = tools.compile(script_text)
        return self._script

    def info(self):
        def address_f(netcode=None):
            return "(nulldata %s)" % b2h(self.nulldata)
        return dict(type="nulldata", address_f=address_f, script=self._script, summary=self.nulldata)

    def __repr__(self):
        return "<Script: nulldata %s>" % self.nulldata
