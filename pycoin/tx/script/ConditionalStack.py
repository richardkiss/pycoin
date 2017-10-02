
from pycoin.satoshi import errno
from . import ScriptError


class ConditionalStack(object):
    def __init__(self):
        self.true_count = 0
        self.false_count = 0

    def all_if_true(self):
        return self.false_count == 0

    def OP_IF(self, the_bool, reverse_bool=False):
        if self.false_count > 0:
            self.false_count += 1
            return
        if reverse_bool:
            the_bool = not the_bool
        if the_bool:
            self.true_count += 1
        else:
            self.false_count = 1

    def OP_ELSE(self):
        if self.false_count > 1:
            return
        if self.false_count == 1:
            self.false_count = 0
            self.true_count += 1
        else:
            if self.true_count == 0:
                raise ScriptError("OP_ELSE without OP_IF", errno.UNBALANCED_CONDITIONAL)
            self.true_count -= 1
            self.false_count += 1

    def OP_ENDIF(self):
        if self.false_count > 0:
            self.false_count -= 1
        else:
            if self.true_count == 0:
                raise ScriptError("OP_ENDIF without OP_IF", errno.UNBALANCED_CONDITIONAL)
            self.true_count -= 1

    def check_final_state(self):
        if self.false_count > 0 or self.true_count > 0:
            raise ScriptError("missing ENDIF", errno.UNBALANCED_CONDITIONAL)

    def __repr__(self):
        if self.true_count or self.false_count:
            return "[IfStack true:%d/false:%d]" % (self.true_count, self.false_count)
        return "[]"
