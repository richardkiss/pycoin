from __future__ import annotations

from typing import Any

from .constraints import Atom, Operator


class SolvingError(Exception):
    pass


class CONSTANT(object):
    def __init__(self, name: str) -> None:
        self._name = name

    def match(self, c: Any) -> dict[str, Any] | bool:
        if not isinstance(c, Atom):
            return {self._name: c}
        return False


class VAR(object):
    def __init__(self, name: str) -> None:
        self._name = name

    def match(self, c: Any) -> dict[str, Any] | bool:
        if isinstance(c, Atom) and not isinstance(c, Operator):
            return {self._name: c}
        return False


class LIST(object):
    def __init__(self, name: str) -> None:
        self._name = name

    def match(self, c: Any) -> dict[str, Any] | bool:
        if isinstance(c, (tuple, list)):
            return {self._name: c}
        return False


class ConstraintSolver(object):
    def __init__(self) -> None:
        self._solvers_for_patterns: dict[Any, Any] = {}

    def register_solver(self, pattern: Any, solver_f: Any) -> None:
        self._solvers_for_patterns[pattern] = solver_f

    def solutions_for_constraint(self, c: Any) -> Any:
        # given a constraint c
        # return None or
        # a solution (solution_f, target atom, dependency atom list)
        # where solution_f take list of solved values

        for pattern, f_factory in self._solvers_for_patterns.items():
            m = self.constraint_matches(c, pattern)
            if m:
                return f_factory(m)

    def constraint_matches(self, c: Any, m: Any) -> dict[str, Any] | bool:
        """
        Return dict noting the substitution values (or False for no match)
        """
        if isinstance(m, tuple):
            d: dict[str, Any] = {}
            if isinstance(c, Operator) and c._op_name == m[0]:
                for c1, m1 in zip(c._args, m[1:]):
                    r = self.constraint_matches(c1, m1)
                    if r is False:
                        return r
                    d.update(r)  # type: ignore[arg-type]
                return d
            return False
        return m.match(c)  # type: ignore[no-any-return]
