import hashlib
import unittest

from pycoin.encoding.hexbytes import b2h
from pycoin.symbols.btc import network


# BRAIN DAMAGE
Tx = network.tx
TxIn = Tx.TxIn
TxOut = Tx.TxOut
Solver = Tx.Solver

ScriptError = network.validator.ScriptError

class SolverTest(unittest.TestCase):

    def do_test_solve(self, tx, tx_in_idx, **kwargs):
        solver = Solver(tx)
        constraints = solver.determine_constraints(tx_in_idx, p2sh_lookup=kwargs.get("p2sh_lookup"))
        solution_list, witness_list = solver.solve_for_constraints(constraints, **kwargs)
        solution_script = network.script.compile_push_data_list(solution_list)
        tx.txs_in[tx_in_idx].script = solution_script
        tx.txs_in[tx_in_idx].witness = witness_list
        if not kwargs.get("nocheck"):
            tx.check_solution(tx_in_idx)
        return solution_script, witness_list

    def make_test_tx(self, input_script):
        previous_hash = b'\1' * 32
        txs_in = [TxIn(previous_hash, 0)]
        txs_out = [TxOut(1000, network.contract.for_address(network.keys.private(1).address()))]
        version, lock_time = 1, 0
        tx = Tx(version, txs_in, txs_out, lock_time)
        unspents = [TxOut(1000, input_script)]
        tx.set_unspents(unspents)
        return tx

    def do_test_tx(self, incoming_script, **kwargs):
        keys = [network.keys.private(i) for i in range(1, 20)]
        tx = self.make_test_tx(incoming_script)
        tx_in_idx = 0
        kwargs["hash160_lookup"] = network.tx.solve.build_hash160_lookup((k.secret_exponent() for k in keys))
        kwargs["generator_for_signature_type_f"] = Solver.SolutionChecker.VM.generator_for_signature_type
        self.do_test_solve(tx, tx_in_idx, **kwargs)

    def test_p2pkh(self):
        key = network.keys.private(1)
        self.do_test_tx(network.contract.for_address(key.address()))

    def test_p2pk(self):
        key = network.keys.private(1)
        self.do_test_tx(network.contract.for_p2pk(key.sec(is_compressed=False)))
        self.do_test_tx(network.contract.for_p2pk(key.sec(is_compressed=True)))

    def test_nonstandard_p2pkh(self):
        key = network.keys.private(1)
        self.do_test_tx(network.script.compile("OP_SWAP") + network.contract.for_address(key.address()))

    def test_p2multisig(self):
        keys = [network.keys.private(i) for i in (1, 2, 3)]
        secs = [k.sec() for k in keys]
        self.do_test_tx(network.contract.for_multisig(2, secs))

    def test_p2sh(self):
        keys = [network.keys.private(i) for i in (1, 2, 3)]
        secs = [k.sec() for k in keys]
        underlying_script = network.contract.for_multisig(1, secs)
        script = network.contract.for_address(network.address.for_p2s(underlying_script))
        self.do_test_tx(script, p2sh_lookup=network.tx.solve.build_p2sh_lookup([underlying_script]))

        underlying_script = network.script.compile("OP_SWAP") + network.contract.for_address(keys[0].address())
        script = network.contract.for_address(network.address.for_p2s(underlying_script))
        self.do_test_tx(script, p2sh_lookup=network.tx.solve.build_p2sh_lookup([underlying_script]))

        underlying_script = network.contract.for_p2pk(keys[2].sec())
        script = network.contract.for_address(network.address.for_p2s(underlying_script))
        self.do_test_tx(script, p2sh_lookup=network.tx.solve.build_p2sh_lookup([underlying_script]))

    def test_p2pkh_wit(self):
        key = network.keys.private(1)
        script = network.script.compile("OP_0 [%s]" % b2h(key.hash160()))
        self.do_test_tx(script)

    def test_p2sh_wit(self):
        keys = [network.keys.private(i) for i in (1, 2, 3)]
        secs = [k.sec() for k in keys]
        underlying_script = network.contract.for_multisig(2, secs)
        script = network.script.compile("OP_0 [%s]" % b2h(hashlib.sha256(underlying_script).digest()))
        self.do_test_tx(script, p2sh_lookup=network.tx.solve.build_p2sh_lookup([underlying_script]))

    def test_p2multisig_wit(self):
        keys = [network.keys.private(i) for i in (1, 2, 3)]
        secs = [k.sec() for k in keys]
        underlying_script = network.contract.for_multisig(2, secs)
        p2sh_script = network.script.compile("OP_0 [%s]" % b2h(hashlib.sha256(underlying_script).digest()))
        script = network.contract.for_address(network.address.for_p2s(p2sh_script))
        self.do_test_tx(script, p2sh_lookup=network.tx.solve.build_p2sh_lookup([underlying_script, p2sh_script]))

    def test_if(self):
        script = network.script.compile("IF 1 ELSE 0 ENDIF")
        # self.do_test_tx(script)

    def test_p2multisig_incremental(self):
        keys = [network.keys.private(i) for i in (1, 2, 3)]
        secs = [k.sec() for k in keys]
        tx = self.make_test_tx(network.contract.for_multisig(3, secs))
        tx_in_idx = 0
        for k in keys:
            try:
                tx.check_solution(tx_in_idx)
                assert 0
            except ScriptError:
                pass
            kwargs = {"hash160_lookup": network.tx.solve.build_hash160_lookup([k.secret_exponent()])}
            kwargs["existing_script"] = [
                data for opcode, data, pc, new_pc in network.script.get_opcodes(
                    tx.txs_in[tx_in_idx].script) if data is not None]
            kwargs["nocheck"] = True
            kwargs["generator_for_signature_type_f"] = Solver.SolutionChecker.VM.generator_for_signature_type
            solution_list, witness_list = self.do_test_solve(tx, tx_in_idx, **kwargs)
        tx.check_solution(tx_in_idx)


if __name__ == "__main__":
    unittest.main()
