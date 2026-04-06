from __future__ import annotations

from typing import Any


class ScriptError(Exception):
    def error_code(self) -> Any:
        if len(self.args) > 1:
            return self.args[1]
        return None


class SolutionChecker(object):
    ScriptError = ScriptError

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError()

    def check_solution(
        self, tx_context: Any, traceback_f: Any = None, *args: Any, **kwargs: Any
    ) -> None:
        """
        tx_context: information about the transaction that the VM may need
        traceback_f: a function invoked on occasion to check intermediate state
        """
        raise NotImplementedError()
