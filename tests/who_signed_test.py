import unittest

from pycoin.symbols.btc import network


# BRAIN DAMAGE
who_signed_tx = network.who_signed.who_signed_tx
Tx = network.tx
SIGHASH_ALL = network.validator.flags.SIGHASH_ALL


class WhoSignedTest(unittest.TestCase):

    def multisig_M_of_N(self, M, N, unsigned_id, signed_id):
        keys = [network.keys.private(secret_exponent=i) for i in range(1, N+2)]
        tx_in = Tx.TxIn.coinbase_tx_in(script=b'')
        script = network.contract.for_multisig(m=M, sec_keys=[key.sec() for key in keys[:N]])
        tx_out = Tx.TxOut(1000000, script)
        tx1 = Tx(version=1, txs_in=[tx_in], txs_out=[tx_out])
        tx2 = network.tx_utils.create_tx(tx1.tx_outs_as_spendable(), [keys[-1].address()])
        self.assertEqual(tx2.id(), unsigned_id)
        self.assertEqual(tx2.bad_solution_count(), 1)
        hash160_lookup = network.tx.solve.build_hash160_lookup((key.secret_exponent() for key in keys[:M]))
        tx2.sign(hash160_lookup=hash160_lookup)
        self.assertEqual(tx2.id(), signed_id)
        self.assertEqual(tx2.bad_solution_count(), 0)
        self.assertEqual(sorted(who_signed_tx(tx2, 0)),
                         sorted(((key.address(), SIGHASH_ALL) for key in keys[:M])))

    def test_create_multisig_1_of_2(self):
        unsigned_id = "dd40f601e801ad87701b04851a4a6852d6b625e481d0fc9c3302faf613a4fc88"
        signed_id = "fb9ccc00d0e30ab2648768104fd777df8f856830233232c5e43f43584aec23d9"
        self.multisig_M_of_N(1, 2, unsigned_id, signed_id)

    def test_create_multisig_2_of_3(self):
        unsigned_id = "6bc5614a41c7c4aa828f5a4314fff23e5e49b1137e5d31e9716eb58f6fb198ff"
        signed_id = "c521962fe9d0e5efb7d0966759c57e7ee2595ce8e05cb342b19265a8722420dd"
        self.multisig_M_of_N(2, 3, unsigned_id, signed_id)

    def test_multisig_one_at_a_time(self):
        M = 3
        N = 3
        keys = [network.keys.private(secret_exponent=i) for i in range(1, N+2)]
        tx_in = Tx.TxIn.coinbase_tx_in(script=b'')
        script = network.contract.for_multisig(m=M, sec_keys=[key.sec() for key in keys[:N]])
        tx_out = Tx.TxOut(1000000, script)
        tx1 = Tx(version=1, txs_in=[tx_in], txs_out=[tx_out])
        tx2 = network.tx_utils.create_tx(tx1.tx_outs_as_spendable(), [keys[-1].address()])
        ids = ["403e5bfc59e097bb197bf77a692d158dd3a4f7affb4a1fa41072dafe7bec7058",
               "5931d9995e83721243dca24772d7012afcd4378996a8b953c458175f15a544db",
               "9bb4421088190bbbb5b42a9eaa9baed7ec7574a407c25f71992ba56ca43d9c44",
               "03a1dc2a63f93a5cf5a7cb668658eb3fc2eda88c06dc287b85ba3e6aff751771"]
        for i in range(1, N+1):
            self.assertEqual(tx2.bad_solution_count(), 1)
            self.assertEqual(tx2.id(), ids[i-1])
            hash160_lookup = network.tx.solve.build_hash160_lookup([keys[i-1].secret_exponent()])
            tx2.sign(hash160_lookup=hash160_lookup)
            self.assertEqual(tx2.id(), ids[i])
            t1 = sorted(who_signed_tx(tx2, 0))
            t2 = sorted(((key.address(), SIGHASH_ALL) for key in keys[:i]))
            self.assertEqual(t1, t2)
        self.assertEqual(tx2.bad_solution_count(), 0)

    def test_sign_pay_to_script_multisig(self):
        M, N = 3, 3
        keys = [network.keys.private(secret_exponent=i) for i in range(1, N+2)]
        tx_in = Tx.TxIn.coinbase_tx_in(script=b'')
        underlying_script = network.contract.for_multisig(m=M, sec_keys=[key.sec() for key in keys[:N]])
        address = network.address.for_p2s(underlying_script)
        self.assertEqual(address, "39qEwuwyb2cAX38MFtrNzvq3KV9hSNov3q")
        script = network.contract.for_address(address)
        tx_out = Tx.TxOut(1000000, script)
        tx1 = Tx(version=1, txs_in=[tx_in], txs_out=[tx_out])
        tx2 = network.tx_utils.create_tx(tx1.tx_outs_as_spendable(), [address])
        hash160_lookup = network.tx.solve.build_hash160_lookup((key.secret_exponent() for key in keys[:N]))
        p2sh_lookup = network.tx.solve.build_p2sh_lookup([underlying_script])
        tx2.sign(hash160_lookup=hash160_lookup, p2sh_lookup=p2sh_lookup)
        self.assertEqual(tx2.bad_solution_count(), 0)
        self.assertEqual(sorted(who_signed_tx(tx2, 0)),
                         sorted(((key.address(), SIGHASH_ALL) for key in keys[:M])))


if __name__ == "__main__":
    unittest.main()
