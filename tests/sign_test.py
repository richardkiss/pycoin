import unittest

from pycoin.cmds.tx import DEFAULT_VERSION
from pycoin.encoding.hexbytes import h2b
from pycoin.symbols.btc import network


Spendable = network.tx.Spendable
Tx = network.tx
TxIn = network.tx.TxIn
TxOut = network.tx.TxOut


class SignTest(unittest.TestCase):

    def test_sign_p2sh(self):
        tx_out_script = h2b("76a91491b24bf9f5288532960ac687abb035127b1d28a588ac")
        script = network.contract.for_address("1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")
        self.assertEqual(tx_out_script, script)
        tx_out = TxOut(100, tx_out_script)
        tx = Tx(1, [TxIn(b'\1' * 32, 1)], [TxOut(100, tx_out_script)])
        tx.set_unspents([tx_out])
        hl = network.tx.solve.build_hash160_lookup([1])
        self.assertEqual(tx.bad_solution_count(), 1)
        tx.sign(hash160_lookup=hl)
        self.assertEqual(tx.bad_solution_count(), 0)

    def multisig_M_of_N(self, M, N, unsigned_id, signed_id):
        keys = [network.keys.private(secret_exponent=i) for i in range(1, N+2)]
        tx_in = TxIn.coinbase_tx_in(script=b'')
        script = network.contract.for_multisig(m=M, sec_keys=[key.sec() for key in keys[:N]])
        tx_out = TxOut(1000000, script)
        tx1 = Tx(version=1, txs_in=[tx_in], txs_out=[tx_out])
        tx2 = network.tx_utils.create_tx(tx1.tx_outs_as_spendable(), [keys[-1].address()])
        self.assertEqual(tx2.id(), unsigned_id)
        self.assertEqual(tx2.bad_solution_count(), 1)
        hash160_lookup = network.tx.solve.build_hash160_lookup((key.secret_exponent() for key in keys[:M]))
        tx2.sign(hash160_lookup=hash160_lookup)
        self.assertEqual(tx2.id(), signed_id)
        self.assertEqual(tx2.bad_solution_count(), 0)

    def test_sign_multisig_1_of_2(self):
        unsigned_id = "dd40f601e801ad87701b04851a4a6852d6b625e481d0fc9c3302faf613a4fc88"
        signed_id = "fb9ccc00d0e30ab2648768104fd777df8f856830233232c5e43f43584aec23d9"
        self.multisig_M_of_N(1, 2, unsigned_id, signed_id)

    def test_sign_multisig_2_of_3(self):
        unsigned_id = "6bc5614a41c7c4aa828f5a4314fff23e5e49b1137e5d31e9716eb58f6fb198ff"
        signed_id = "c521962fe9d0e5efb7d0966759c57e7ee2595ce8e05cb342b19265a8722420dd"
        self.multisig_M_of_N(2, 3, unsigned_id, signed_id)

    def test_multisig_one_at_a_time(self):
        M = 3
        N = 3
        keys = [network.keys.private(secret_exponent=i) for i in range(1, N+2)]
        tx_in = TxIn.coinbase_tx_in(script=b'')
        script = network.contract.for_multisig(m=M, sec_keys=[key.sec() for key in keys[:N]])
        tx_out = TxOut(1000000, script)
        tx1 = Tx(version=1, txs_in=[tx_in], txs_out=[tx_out])
        tx2 = network.tx_utils.create_tx(tx1.tx_outs_as_spendable(), [keys[-1].address()])
        ids = ["403e5bfc59e097bb197bf77a692d158dd3a4f7affb4a1fa41072dafe7bec7058",
               "5931d9995e83721243dca24772d7012afcd4378996a8b953c458175f15a544db",
               "9bb4421088190bbbb5b42a9eaa9baed7ec7574a407c25f71992ba56ca43d9c44",
               "03a1dc2a63f93a5cf5a7cb668658eb3fc2eda88c06dc287b85ba3e6aff751771"]
        for i in range(1, N+1):
            self.assertEqual(tx2.bad_solution_count(), 1)
            self.assertEqual(tx2.id(), ids[i-1])
            hash160_lookup = network.tx.solve.build_hash160_lookup((key.secret_exponent() for key in keys[i-1:i]))
            tx2.sign(hash160_lookup=hash160_lookup)
            self.assertEqual(tx2.id(), ids[i])
        self.assertEqual(tx2.bad_solution_count(), 0)

    def test_p2sh_multisig_sequential_signing(self):
        raw_scripts = [h2b(
            "52210234abcffd2e80ad01c2ec0276ad02682808169c6fafdd25ebfb60703df272b461"
            "2102e5baaafff8094e4d77ce8b009d5ebc3de9110085ebd3d96e50cc7ce70faf175221"
            "0316ee25e80eb6e6fc734d9c86fa580cbb9c4bfd94a19f0373a22353ececd4db6853ae")]
        spendable = {'script_hex': 'a914c4ed4de526461e3efbb79c8b688a6f9282c0464687', 'does_seem_spent': 0,
                     'block_index_spent': 0, 'coin_value': 10000, 'block_index_available': 0, 'tx_out_index': 0,
                     'tx_hash_hex': '0ca152ba6b88db87a7ef1afd24554102aca1ab86cf2c10ccbc374472145dc943'}

        key_1 = network.parse.wif('Kz6pytJCigYHeMsGLmfHQPJhN5og2wpeSVrU43xWwgHLCAvpsprh')
        key_2 = network.parse.wif('Kz7NHgX7MBySA3RSKj9GexUSN6NepEDoPNugSPr5absRDoKgn2dT')
        for ordered_keys in [(key_1, key_2), (key_2, key_1)]:
            txs_in = [TxIn(previous_hash=h2b('43c95d14724437bccc102ccf86aba1ac02415524fd1aefa787db886bba52a10c'),
                           previous_index=0)]
            txs_out = [TxOut(10000, network.contract.for_address('3KeGeLFmsbmbVdeMLrWp7WYKcA3tdsB4AR'))]
            unspents = [Spendable.from_dict(spendable)]
            tx = Tx(version=DEFAULT_VERSION, txs_in=txs_in, txs_out=txs_out, unspents=unspents)
            for key in ordered_keys:
                self.assertEqual(tx.bad_solution_count(), 1)
                p2sh_lookup = network.tx.solve.build_p2sh_lookup(raw_scripts)
                tx.sign(network.tx.solve.build_hash160_lookup([key.secret_exponent()]), p2sh_lookup=p2sh_lookup)
            self.assertEqual(tx.bad_solution_count(), 0)

    def test_sign_pay_to_script_multisig(self):
        M, N = 3, 3
        keys = [network.keys.private(secret_exponent=i) for i in range(1, N+2)]
        tx_in = TxIn.coinbase_tx_in(script=b'')
        underlying_script = network.contract.for_multisig(m=M, sec_keys=[key.sec() for key in keys[:N]])
        address = network.address.for_p2s(underlying_script)
        self.assertEqual(address, "39qEwuwyb2cAX38MFtrNzvq3KV9hSNov3q")
        script = network.contract.for_address(address)
        tx_out = TxOut(1000000, script)
        tx1 = Tx(version=1, txs_in=[tx_in], txs_out=[tx_out])
        tx2 = network.tx_utils.create_tx(tx1.tx_outs_as_spendable(), [address])
        hash160_lookup = network.tx.solve.build_hash160_lookup((key.secret_exponent() for key in keys[:N]))
        p2sh_lookup = network.tx.solve.build_p2sh_lookup([underlying_script])
        tx2.sign(hash160_lookup=hash160_lookup, p2sh_lookup=p2sh_lookup)
        self.assertEqual(tx2.bad_solution_count(), 0)

    def test_sign_bitcoind_partially_signed_2_of_2(self):
        # Finish signing a 2 of 2 transaction, that already has one signature signed by bitcoind
        # This tx can be found on testnet3 blockchain
        # txid: 9618820d7037d2f32db798c92665231cd4599326f5bd99cb59d0b723be2a13a2
        raw_script = ("522103e33b41f5ed67a77d4c4c54b3e946bd30d15b8f66e42cb29fde059c168851165521"
                      "02b92cb20a9fb1eb9656a74eeb7387636cf64cdf502ff50511830328c1b479986452ae")
        p2sh_lookup = network.tx.solve.build_p2sh_lookup([h2b(raw_script)])
        partially_signed_raw_tx = (
            "010000000196238f11a5fd3ceef4efd5a186a7e6b9217d900418e72aca917cd6a6e634"
            "e74100000000910047304402201b41b471d9dd93cf97eed7cfc39a5767a546f6bfbf3e"
            "0c91ff9ad23ab9770f1f02205ce565666271d055be1f25a7e52e34cbf659f6c70770ff"
            "59bd783a6fcd1be3dd0147522103e33b41f5ed67a77d4c4c54b3e946bd30d15b8f66e4"
            "2cb29fde059c16885116552102b92cb20a9fb1eb9656a74eeb7387636cf64cdf502ff5"
            "0511830328c1b479986452aeffffffff01a0bb0d00000000001976a9143b3beefd6f78"
            "02fa8706983a76a51467bfa36f8b88ac00000000")
        tx = Tx.from_hex(partially_signed_raw_tx)
        tx_out = TxOut(1000000, h2b("a914a10dfa21ee8c33b028b92562f6fe04e60563d3c087"))
        tx.set_unspents([tx_out])
        key = network.parse.wif("L3LRiWuBJ6xcY4rnUsEiEX8mXRmKZG7uYyJ2sePDxSZ2haw1hPHW")
        hash160_lookup = network.tx.solve.build_hash160_lookup([key.secret_exponent()])
        self.assertEqual(tx.bad_solution_count(), 1)
        tx.sign(hash160_lookup=hash160_lookup, p2sh_lookup=p2sh_lookup)
        self.assertEqual(tx.bad_solution_count(), 0)
        self.assertEqual(tx.id(), "9618820d7037d2f32db798c92665231cd4599326f5bd99cb59d0b723be2a13a2")


if __name__ == "__main__":
    unittest.main()
