from .constraints import Atom, Operator


class SolvingError(Exception):
    pass


class CONSTANT(object):
    def __init__(self, name):
        self._name = name

    def match(self, c):
        if not isinstance(c, Atom):
            return {self._name: c}
        return False


class VAR(object):
    def __init__(self, name):
        self._name = name

    def match(self, c):
        if isinstance(c, Atom) and not isinstance(c, Operator):
            return {self._name: c}
        return False


class LIST(object):
    def __init__(self, name):
        self._name = name

    def match(self, c):
        if isinstance(c, (tuple, list)):
            return {self._name: c}
        return False


class ConstraintSolver(object):
    def __init__(self):
        self._solvers_for_patterns = {}

    def register_solver(self, pattern, solver_f):
        self._solvers_for_patterns[pattern] = solver_f

    def solutions_for_constraint(self, c):
        # given a constraint c
        # return None or
        # a solution (solution_f, target atom, dependency atom list)
        # where solution_f take list of solved values

        for pattern, f_factory in self._solvers_for_patterns.items():
            m = self.constraint_matches(c, pattern)
            if m:
                return f_factory(m)

    def constraint_matches(self, c, m):
        """
        Return dict noting the substitution values (or False for no match)
        """
        if isinstance(m, tuple):
            d = {}
            if isinstance(c, Operator) and c._op_name == m[0]:
                for c1, m1 in zip(c._args, m[1:]):
                    r = self.constraint_matches(c1, m1)
                    if r is False:
                        return r
                    d.update(r)
                return d
            return False
        return m.match(c)
