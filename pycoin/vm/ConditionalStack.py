from __future__ import annotations

from typing import Any, Callable


class ConditionalStack(object):
    def __init__(self, error_f: Callable[[str], Any]) -> None:
        self.true_count = 0
        self.false_count = 0
        self.error_f = error_f

    def all_if_true(self) -> bool:
        return self.false_count == 0

    def OP_IF(self, the_bool: bool, reverse_bool: bool = False) -> None:
        if self.false_count > 0:
            self.false_count += 1
            return
        if reverse_bool:
            the_bool = not the_bool
        if the_bool:
            self.true_count += 1
        else:
            self.false_count = 1

    def OP_ELSE(self) -> None:
        if self.false_count > 1:
            return
        if self.false_count == 1:
            self.false_count = 0
            self.true_count += 1
        else:
            if self.true_count == 0:
                self.error_f("OP_ELSE without OP_IF")
                return
            self.true_count -= 1
            self.false_count += 1

    def OP_ENDIF(self) -> None:
        if self.false_count > 0:
            self.false_count -= 1
        else:
            if self.true_count == 0:
                self.error_f("OP_ENDIF without OP_IF")
                return
            self.true_count -= 1

    def check_final_state(self) -> None:
        if self.false_count > 0 or self.true_count > 0:
            self.error_f("missing ENDIF")

    def __repr__(self) -> str:
        if self.true_count or self.false_count:
            return "[IfStack true:%d/false:%d]" % (self.true_count, self.false_count)
        return "[]"
