from .ScriptType import ScriptType


class ScriptUnknown(ScriptType):
    def __init__(self, script):
        self._script = script

    @classmethod
    def from_script(cls, script):
        return cls(script)

    def script(self):
        return self._script

    def solve(self, **kwargs):
        raise SolvingError("unknown script type")

    def info(self, netcode='BTC'):
        address = "(unknown)"
        return dict(type="unknown script", address=address, script=self._script, summary=address)

    def __repr__(self):
        return "<Script: unknown of size %d>" % len(self._script)
