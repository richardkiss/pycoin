from __future__ import annotations

from typing import Any

from ..SolutionChecker import ScriptError

from pycoin.encoding.hexbytes import b2h, h2b
from pycoin.satoshi.flags import SIGHASH_ALL
from pycoin.solve.constraints import Atom, Operator, make_traceback_f
from pycoin.solve.ConstraintSolver import SolvingError, ConstraintSolver
from pycoin.solve.some_solvers import register_all


def generate_default_placeholder_signature(generator: Any) -> bytes:
    return h2b(
        "3045022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414002207"
        "fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a001"
    )


class DynamicStack(list):  # type: ignore[type-arg]
    def __init__(
        self,
        initial_stack: list[Any] = [],
        reserve_count: int = 0,
        fill_template: str = "x_%d",
    ) -> None:
        self.total_item_count = reserve_count
        self.fill_template = fill_template
        super(DynamicStack, self).__init__(initial_stack)

    def _fill(self) -> None:
        self.insert(0, Atom(self.fill_template % self.total_item_count))
        self.total_item_count += 1

    def pop(self, i: int = -1) -> Any:  # type: ignore[override]
        while len(self) < abs(i):
            self._fill()
        return super(DynamicStack, self).pop(i)

    def __getitem__(self, *args: Any, **kwargs: Any) -> Any:
        while True:
            try:
                return super(DynamicStack, self).__getitem__(*args, **kwargs)
            except IndexError:
                self._fill()


class Solver(object):
    SolutionChecker: Any = None
    ScriptTools: Any = None

    def __init__(self, tx: Any) -> None:
        self.tx = tx
        self.solution_checker = self.SolutionChecker(tx)
        # self.sighash_cache = {}

    def determine_constraints(
        self, tx_in_idx: int, p2sh_lookup: dict[bytes, bytes] = {}
    ) -> list[Any]:
        tx_context = self.solution_checker.tx_context_for_idx(tx_in_idx)
        tx_context.witness_solution_stack = DynamicStack(
            [Atom("w_%d" % (1 - _)) for _ in range(2)], fill_template="w_%d"
        )
        script_hash = self.solution_checker.script_hash_from_script(
            tx_context.puzzle_script
        )
        witness_version = self.solution_checker._witness_program_version(
            tx_context.puzzle_script
        )
        tx_context.solution_script = b""
        solution_reserve_count = 0
        fill_template = "x_%d"
        underlying_script: bytes | None = None
        underlying_script_wit: bytes | None = None
        witness_program: bytes = b""
        if script_hash:
            underlying_script = p2sh_lookup.get(script_hash, None)
            if underlying_script is None:
                raise ValueError(
                    "p2sh_lookup not set or does not have script hash for %s"
                    % b2h(script_hash)
                )
            tx_context.solution_script = self.ScriptTools.compile_push_data_list(
                [underlying_script]
            )
            solution_reserve_count = 1
            witness_version = self.solution_checker._witness_program_version(
                underlying_script
            )
        if witness_version == 0:
            base_script: bytes = underlying_script if script_hash else tx_context.puzzle_script  # type: ignore[assignment]
            witness_program = base_script[2:]
            if len(witness_program) == 32:
                underlying_script_wit = p2sh_lookup.get(witness_program, None)
                if underlying_script_wit is None:
                    raise ValueError(
                        "p2sh_lookup not set or does not have script hash for %s"
                        % b2h(witness_program)
                    )
                fill_template = "w_%d"
                solution_reserve_count = 1
                tx_context.witness_solution_stack = [underlying_script_wit]
        constraints: list[Any] = []

        def reset_stack_f(stack: list[Any]) -> DynamicStack:
            return DynamicStack(stack, solution_reserve_count, fill_template)

        try:
            traceback_f = make_traceback_f(
                constraints, self.ScriptTools.int_for_opcode, reset_stack_f
            )
            self.solution_checker.check_solution(tx_context, traceback_f=traceback_f)
        except ScriptError:
            pass
        if script_hash:
            constraints.append(Operator("EQUAL", Atom("x_0"), underlying_script))
        if witness_version == 0:
            if len(witness_program) == 32:
                constraints.append(
                    Operator("EQUAL", Atom("w_0"), underlying_script_wit)
                )
        return constraints

    def solve_for_constraints(
        self, constraints: list[Any], **kwargs: Any
    ) -> tuple[list[Any], list[Any]]:
        solutions: list[Any] = []
        for c in constraints:
            s = self.solutions_for_constraint(c)
            # s = (solution_f, target atom, dependency atom list)
            if s:
                solutions.append(s)
        deps: set[Any] = set()
        for c in constraints:
            deps.update(c.dependencies())
        solved_values: dict[Any, Any] = {d: None for d in deps}
        progress = True
        while progress and None in solved_values.values():
            progress = False
            for solution, target, dependencies in solutions:
                if any(solved_values.get(t) is not None for t in target):
                    continue
                if any(solved_values[d] is None for d in dependencies):
                    continue
                s = solution(solved_values, **kwargs)
                solved_values.update(s)
                progress = progress or (len(s) > 0)

        x_keys = sorted(
            (k for k in solved_values.keys() if k.name.startswith("x")), reverse=True
        )
        w_keys = sorted(
            (k for k in solved_values.keys() if k.name.startswith("w")), reverse=True
        )
        solution_list = [solved_values.get(k) for k in x_keys]
        witness_list = [solved_values.get(k) for k in w_keys]
        return solution_list, witness_list

    def solve(
        self, hash160_lookup: Any, tx_in_idx: int, hash_type: int | None = None, **kwargs: Any
    ) -> Any:
        """
        Sign a standard transaction.
        hash160_lookup:
            An object with a get method that accepts a hash160 and returns the
            corresponding (secret exponent, public_pair, is_compressed) tuple or
            None if it's unknown (in which case the script will obviously not be signed).
            A standard dictionary will do nicely here.
        tx_in_idx:
            the index of the tx_in we are currently signing
        """
        if hash_type is None:
            hash_type = SIGHASH_ALL
        kwargs["hash160_lookup"] = hash160_lookup
        if "signature_placeholder" not in kwargs:
            kwargs["signature_placeholder"] = generate_default_placeholder_signature(
                kwargs.get("generator")
            )
        if self.tx.txs_in[tx_in_idx].witness:
            kwargs["existing_script"] = self.tx.txs_in[tx_in_idx].witness
        else:
            kwargs["existing_script"] = [
                data
                for opcode, data, pc, new_pc in self.ScriptTools.get_opcodes(
                    self.tx.txs_in[tx_in_idx].script
                )
                if data is not None
            ]
        kwargs["signature_type"] = hash_type
        kwargs["generator_for_signature_type_f"] = (
            self.solution_checker.VM.generator_for_signature_type
        )
        constraints = self.determine_constraints(
            tx_in_idx, p2sh_lookup=kwargs.get("p2sh_lookup") or {}
        )
        solution_list, witness_list = self.solve_for_constraints(constraints, **kwargs)
        solution_script = self.ScriptTools.compile_push_data_list(solution_list)
        if witness_list:
            return solution_script, witness_list
        return solution_script

    def sign(
        self,
        hash160_lookup: Any,
        tx_in_idx_set: Any = None,
        hash_type: int | None = None,
        **kwargs: Any,
    ) -> Solver:
        """
        Sign a standard transaction.
        hash160_lookup:
            A dictionary (or another object with .get) where keys are hash160 and
            values are tuples (secret exponent, public_pair, is_compressed) or None
            (in which case the script will obviously not be signed).
        """
        checker = self.SolutionChecker(self.tx)
        if tx_in_idx_set is None:
            tx_in_idx_set = range(len(self.tx.txs_in))
        self.tx.check_unspents()
        for tx_in_idx in sorted(tx_in_idx_set):
            tx_context = checker.tx_context_for_idx(tx_in_idx)
            try:
                checker.check_solution(tx_context, flags=None)
                continue
            except ScriptError:
                pass
            try:
                r = self.solve(hash160_lookup, tx_in_idx, hash_type=hash_type, **kwargs)
                if isinstance(r, bytes):
                    self.tx.txs_in[tx_in_idx].script = r
                else:
                    self.tx.txs_in[tx_in_idx].script = r[0]
                    self.tx.set_witness(tx_in_idx, r[1])
            except (SolvingError, ValueError):
                pass
        return self

    def solutions_for_constraint(self, c: Any) -> Any:
        raise NotImplementedError


BitcoinConstraintSolver = ConstraintSolver()
register_all(BitcoinConstraintSolver)

from .ScriptTools import BitcoinScriptTools  # noqa: E402
from .SolutionChecker import BitcoinSolutionChecker  # noqa: E402


class BitcoinSolver(Solver):
    SolutionChecker = BitcoinSolutionChecker
    ScriptTools = BitcoinScriptTools

    def solutions_for_constraint(self, c: Any) -> Any:
        return BitcoinConstraintSolver.solutions_for_constraint(c)
