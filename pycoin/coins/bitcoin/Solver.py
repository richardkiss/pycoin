from ...serialize import b2h

from ...tx.exceptions import SolvingError
from ...tx.script import ScriptError

from .SolutionChecker import BitcoinSolutionChecker, is_signature_ok
from .ScriptTools import BitcoinScriptTools
from .VM import BitcoinVM

from ...tx.script.flags import SIGHASH_ALL

from pycoin.tx.pay_to.ScriptType import DEFAULT_PLACEHOLDER_SIGNATURE
from pycoin.tx.script.solve import solve


class Solver(object):
    SolutionChecker = BitcoinSolutionChecker
    VM = BitcoinVM
    ScriptTools = BitcoinScriptTools

    def __init__(self, tx):
        self.tx = tx
        self.solution_checker = self.SolutionChecker(tx)
        # self.sighash_cache = {}

    def solve_new(self, hash160_lookup, tx_in_idx, hash_type=None, **kwargs):
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
        if "signature_placeholder" not in kwargs:
            kwargs["signature_placeholder"] = DEFAULT_PLACEHOLDER_SIGNATURE
        if self.tx.txs_in[tx_in_idx].witness:
            kwargs["existing_script"] = self.tx.txs_in[tx_in_idx].witness
        else:
            kwargs["existing_script"] = [
                data for opcode, data, pc, new_pc in BitcoinScriptTools.get_opcodes(
                    self.tx.txs_in[tx_in_idx].script) if data is not None]
        solution_list, witness_list = solve(self.tx, tx_in_idx, hash160_lookup=hash160_lookup, signature_type=hash_type, **kwargs)
        solution_script = BitcoinScriptTools.compile_push_data_list(solution_list)
        if witness_list:
            return solution_script, witness_list
        return solution_script

    def solve_old(self, hash160_lookup, tx_in_idx, hash_type=None, **kwargs):
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
        from ...tx.pay_to import script_obj_from_script, ScriptPayToScript

        tx_out_script = self.tx.unspents[tx_in_idx].script
        if hash_type is None:
            hash_type = SIGHASH_ALL
        tx_in = self.tx.txs_in[tx_in_idx]

        is_p2h = self.solution_checker.is_pay_to_script_hash(tx_out_script)
        if is_p2h:
            hash160 = ScriptPayToScript.from_script(tx_out_script).hash160
            p2sh_lookup = kwargs.get("p2sh_lookup")
            if p2sh_lookup is None:
                raise ValueError("p2sh_lookup not set")
            if hash160 not in p2sh_lookup:
                raise ValueError("hash160=%s not found in p2sh_lookup" %
                                 b2h(hash160))

            script_to_hash = p2sh_lookup[hash160]
        else:
            script_to_hash = tx_out_script

        # Leave out the signature from the hash, since a signature can't sign itself.
        # The checksig op will also drop the signatures from its hash.
        def signature_for_hash_type_f(hash_type, script):
            return self.solution_checker.signature_hash(script, tx_in_idx, hash_type)

        def witness_signature_for_hash_type(hash_type, script):
            return self.solution_checker.signature_for_hash_type_segwit(script, tx_in_idx, hash_type)
        witness_signature_for_hash_type.skip_delete = True

        signature_for_hash_type_f.witness = witness_signature_for_hash_type

        the_script = script_obj_from_script(tx_out_script)
        solution = the_script.solve(
            hash160_lookup=hash160_lookup, signature_type=hash_type,
            existing_script=self.tx.txs_in[tx_in_idx].script, existing_witness=tx_in.witness,
            script_to_hash=script_to_hash, signature_for_hash_type_f=signature_for_hash_type_f, **kwargs)
        return solution

    def solve(self, *args, **kwargs):
        s1 = self.solve_old(*args, **kwargs)
        s2 = self.solve_new(*args, **kwargs)
        #assert s1 == s2
        return s2

    def sign(self, hash160_lookup, tx_in_idx_set=None, hash_type=None, **kwargs):
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
        if hash_type is None:
            hash_type = SIGHASH_ALL
        self.tx.check_unspents()
        for idx in sorted(tx_in_idx_set):
            if is_signature_ok(self.tx, idx):
                continue
            tx_context = checker.tx_context_for_idx(idx)
            try:
                checker.check_solution(tx_context, flags=None)
                continue
            except ScriptError:
                try:
                    self.sign_tx_in(
                        hash160_lookup, idx, self.tx.unspents[idx].script, hash_type=hash_type, **kwargs)
                except SolvingError:
                    pass

        return self

    def sign_tx_in(self, hash160_lookup, tx_in_idx, tx_out_script, hash_type=None, **kwargs):
        if hash_type is None:
            hash_type = self.SIGHASH_ALL
        r = self.solve(hash160_lookup, tx_in_idx, hash_type=hash_type, **kwargs)
        if isinstance(r, bytes):
            self.tx.txs_in[tx_in_idx].script = r
        else:
            self.tx.txs_in[tx_in_idx].script = r[0]
            self.tx.set_witness(tx_in_idx, r[1])


class BitcoinSolver(Solver):
    SolutionChecker = BitcoinSolutionChecker
    VM = BitcoinVM
    ScriptTools = BitcoinScriptTools


def sign(tx, hash160_lookup, solver=BitcoinSolver, **kwargs):
    solver = solver(tx)
    solver.sign(hash160_lookup, **kwargs)
    return tx
