import io
import copy
import unittest
from pycoin.cmds.tx import DEFAULT_VERSION
from pycoin.key import Key
from pycoin.serialize import h2b
from pycoin.tx import tx_utils
from pycoin.tx.Spendable import Spendable
from pycoin.tx.Tx import Tx, TxIn, TxOut, SIGHASH_ALL
from pycoin.tx.tx_utils import LazySecretExponentDB
from pycoin.tx.pay_to import ScriptMultisig, ScriptPayToPublicKey, ScriptNulldata
from pycoin.tx.pay_to import build_hash160_lookup, build_p2sh_lookup, script_obj_from_script
from pycoin.tx.script import tools
from pycoin.ui import address_for_pay_to_script, standard_tx_out_script, script_obj_from_address


def const_f(v):
    def f(*args, **kwargs):
        return v
    return f


class ScriptTypesTest(unittest.TestCase):

    def test_script_type_pay_to_address(self):
        for se in range(1, 100):
            key = Key(secret_exponent=se)
            for b in [True, False]:
                addr = key.address(use_uncompressed=b)
                st = script_obj_from_address(addr)
                self.assertEqual(st.address(), addr)
                sc = st.script()
                st = script_obj_from_script(sc)
                self.assertEqual(st.address(), addr)

    def test_solve_pay_to_address(self):
        for se in range(1, 10):
            key = Key(secret_exponent=se)
            for b in [True, False]:
                addr = key.address(use_uncompressed=b)
                st = script_obj_from_address(addr)
                self.assertEqual(st.address(), addr)
                hl = build_hash160_lookup([se])
                sv = 100
                st.solve(hash160_lookup=hl, signature_for_hash_type_f=const_f(sv), signature_type=SIGHASH_ALL)
                sc = st.script()
                st = script_obj_from_script(sc)
                self.assertEqual(st.address(), addr)

    def test_script_type_pay_to_public_pair(self):
        for se in range(1, 100):
            key = Key(secret_exponent=se)
            for b in [True, False]:
                st = ScriptPayToPublicKey.from_key(key, use_uncompressed=b)
                addr = key.address(use_uncompressed=b)
                self.assertEqual(st.address(), addr)
                sc = st.script()
                st = script_obj_from_script(sc)
                self.assertEqual(st.address(), addr)

    def test_solve_pay_to_public_pair(self):
        for se in range(1, 10):
            key = Key(secret_exponent=se)
            for b in [True, False]:
                addr = key.address(use_uncompressed=b)
                st = ScriptPayToPublicKey.from_key(key, use_uncompressed=b)
                self.assertEqual(st.address(), addr)
                hl = build_hash160_lookup([se])
                sv = 100
                st.solve(hash160_lookup=hl, signature_for_hash_type_f=const_f(sv), signature_type=SIGHASH_ALL)
                sc = st.script()
                st = script_obj_from_script(sc)
                self.assertEqual(st.address(), addr)

    def test_sign(self):
        sv = 33143560198659167577410026742586567991638126035902913554051654024377193788946
        tx_out_script = b'v\xa9\x14\x91\xb2K\xf9\xf5(\x852\x96\n\xc6\x87\xab\xb05\x12{\x1d(\xa5\x88\xac'
        st = script_obj_from_script(tx_out_script)
        hl = build_hash160_lookup([1])
        solution = st.solve(hash160_lookup=hl, signature_for_hash_type_f=const_f(sv), signature_type=SIGHASH_ALL)
        self.assertEqual(
            solution, h2b(
                "47304402205e3df5b55be62140042c220b1fdf105cc85113af562a215c1fc5b5c522d1"
                "b3d3022038c9594b156faed7f37c30077affbf6acf42bf17b1e639a1fcc6c51a67aba2"
                "1601410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817"
                "98483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))

    def test_validate_multisig(self):
        # this is a transaction in the block chain
        # the unspents are included too, so it can be validated
        f = io.BytesIO(h2b(
            "01000000025718fb915fb8b3a802bb699ddf04dd91261ef6715f5f2820a2b1b9b7e38b"
            "4f27000000004a004830450221008c2107ed4e026ab4319a591e8d9ec37719cdea0539"
            "51c660566e3a3399428af502202ecd823d5f74a77cc2159d8af2d3ea5d36a702fef9a7"
            "edaaf562aef22ac35da401ffffffff038f52231b994efb980382e4d804efeadaee13cf"
            "e01abe0d969038ccb45ec17000000000490047304402200487cd787fde9b337ab87f9f"
            "e54b9fd46d5d1692aa58e97147a4fe757f6f944202203cbcfb9c0fc4e3c453938bbea9"
            "e5ae64030cf7a97fafaf460ea2cb54ed5651b501ffffffff0100093d00000000001976"
            "a9144dc39248253538b93d3a0eb122d16882b998145888ac0000000002000000000000"
            "004751210351efb6e91a31221652105d032a2508275f374cea63939ad72f1b1e02f477"
            "da782100f2b7816db49d55d24df7bdffdbc1e203b424e8cd39f5651ab938e5e4a19356"
            "9e52ae404b4c00000000004751210351efb6e91a31221652105d032a2508275f374cea"
            "63939ad72f1b1e02f477da7821004f0331742bbc917ba2056a3b8a857ea47ec088dd10"
            "475ea311302112c9d24a7152ae"))
        tx = Tx.parse(f)
        tx.parse_unspents(f)
        self.assertEqual(tx.id(), "70c4e749f2b8b907875d1483ae43e8a6790b0c8397bbb33682e3602617f9a77a")
        self.assertEqual(tx.bad_signature_count(), 0)

    def test_recognize_multisig(self):
        h = (
            "010000000139c92b102879eb95f14e7344e4dd7d481e1238b1bfb1fa0f735068d2927b"
            "231400000000910047304402208fc06d216ebb4b6a3a3e0f906e1512c372fa8a9c2a92"
            "505d04e9b451ea7acd0c0220764303bb7e514ddd77855949d941c934e9cbda8e3c3827"
            "bfdb5777477e73885b014730440220569ec6d2e81625dd18c73920e0079cdb4c1d67d3"
            "d7616759eb0c18cf566b3d3402201c60318f0a62e3ba85ca0f158d4dfe63c0779269eb"
            "6765b6fc939fc51e7a8ea901ffffffff0140787d01000000001976a914641ad5051edd"
            "97029a003fe9efb29359fcee409d88ac0000000040787d0100000000c952410496ec45"
            "f878b62c46c4be8e336dff7cc58df9b502178cc240eb3d31b1266f69f5767071aa3e01"
            "7d1b82a0bb28dab5e27d4d8e9725b3e68ed5f8a2d45c730621e34104cc71eb30d653c0"
            "c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b8"
            "7bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4410461cbdcc5409fb4b4d42b51"
            "d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8"
            "a540911abe3e7854a26f39f58b25c15342af53ae")
        f = io.BytesIO(h2b(h))
        tx = Tx.parse(f)
        tx.parse_unspents(f)
        self.assertEqual(tx.id(), "10c61e258e0a2b19b245a96a2d0a1538fe81cd4ecd547e0a3df7ed6fd3761ada")
        the_script = tx.unspents[0].script
        s = script_obj_from_script(tx.unspents[0].script)
        self.assertEqual(s.script(), the_script)

    def multisig_M_of_N(self, M, N, unsigned_id, signed_id):
        keys = [Key(secret_exponent=i) for i in range(1, N+2)]
        tx_in = TxIn.coinbase_tx_in(script=b'')
        script = ScriptMultisig(m=M, sec_keys=[key.sec() for key in keys[:N]]).script()
        tx_out = TxOut(1000000, script)
        tx1 = Tx(version=1, txs_in=[tx_in], txs_out=[tx_out])
        tx2 = tx_utils.create_tx(tx1.tx_outs_as_spendable(), [keys[-1].address()])
        self.assertEqual(tx2.id(), unsigned_id)
        self.assertEqual(tx2.bad_signature_count(), 1)
        hash160_lookup = build_hash160_lookup(key.secret_exponent() for key in keys)
        tx2.sign(hash160_lookup=hash160_lookup)
        self.assertEqual(tx2.id(), signed_id)
        self.assertEqual(tx2.bad_signature_count(), 0)

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
        keys = [Key(secret_exponent=i) for i in range(1, N+2)]
        tx_in = TxIn.coinbase_tx_in(script=b'')
        script = ScriptMultisig(m=M, sec_keys=[key.sec() for key in keys[:N]]).script()
        tx_out = TxOut(1000000, script)
        tx1 = Tx(version=1, txs_in=[tx_in], txs_out=[tx_out])
        tx2 = tx_utils.create_tx(tx1.tx_outs_as_spendable(), [keys[-1].address()])
        ids = ["403e5bfc59e097bb197bf77a692d158dd3a4f7affb4a1fa41072dafe7bec7058",
               "5931d9995e83721243dca24772d7012afcd4378996a8b953c458175f15a544db",
               "9bb4421088190bbbb5b42a9eaa9baed7ec7574a407c25f71992ba56ca43d9c44",
               "03a1dc2a63f93a5cf5a7cb668658eb3fc2eda88c06dc287b85ba3e6aff751771"]
        for i in range(1, N+1):
            self.assertEqual(tx2.bad_signature_count(), 1)
            self.assertEqual(tx2.id(), ids[i-1])
            hash160_lookup = build_hash160_lookup(key.secret_exponent() for key in keys[i-1:i])
            tx2.sign(hash160_lookup=hash160_lookup)
            self.assertEqual(tx2.id(), ids[i])
        self.assertEqual(tx2.bad_signature_count(), 0)

    def test_p2sh_multisig_sequential_signing(self):
        raw_scripts = [h2b(
            "52210234abcffd2e80ad01c2ec0276ad02682808169c6fafdd25ebfb60703df272b461"
            "2102e5baaafff8094e4d77ce8b009d5ebc3de9110085ebd3d96e50cc7ce70faf175221"
            "0316ee25e80eb6e6fc734d9c86fa580cbb9c4bfd94a19f0373a22353ececd4db6853ae")]
        txs_in = [TxIn(previous_hash=h2b('43c95d14724437bccc102ccf86aba1ac02415524fd1aefa787db886bba52a10c'),
                       previous_index=0)]
        txs_out = [TxOut(10000, standard_tx_out_script('3KeGeLFmsbmbVdeMLrWp7WYKcA3tdsB4AR'))]
        spendable = {'script_hex': 'a914c4ed4de526461e3efbb79c8b688a6f9282c0464687', 'does_seem_spent': 0,
                     'block_index_spent': 0, 'coin_value': 10000, 'block_index_available': 0, 'tx_out_index': 0,
                     'tx_hash_hex': '0ca152ba6b88db87a7ef1afd24554102aca1ab86cf2c10ccbc374472145dc943'}

        tx__prototype = Tx(version=DEFAULT_VERSION, txs_in=txs_in, txs_out=txs_out,
                           unspents=[Spendable.from_dict(spendable)])
        key_1 = 'Kz6pytJCigYHeMsGLmfHQPJhN5og2wpeSVrU43xWwgHLCAvpsprh'
        key_2 = 'Kz7NHgX7MBySA3RSKj9GexUSN6NepEDoPNugSPr5absRDoKgn2dT'
        for ordered_keys in [(key_1, key_2), (key_2, key_1)]:
            tx = copy.deepcopy(tx__prototype)
            for key in ordered_keys:
                self.assertEqual(tx.bad_signature_count(), 1)
                tx.sign(LazySecretExponentDB([key], {}), p2sh_lookup=build_p2sh_lookup(raw_scripts))
            self.assertEqual(tx.bad_signature_count(), 0)

    def test_sign_pay_to_script_multisig(self):
        M, N = 3, 3
        keys = [Key(secret_exponent=i) for i in range(1, N+2)]
        tx_in = TxIn.coinbase_tx_in(script=b'')
        underlying_script = ScriptMultisig(m=M, sec_keys=[key.sec() for key in keys[:N]]).script()
        address = address_for_pay_to_script(underlying_script)
        self.assertEqual(address, "39qEwuwyb2cAX38MFtrNzvq3KV9hSNov3q")
        script = standard_tx_out_script(address)
        tx_out = TxOut(1000000, script)
        tx1 = Tx(version=1, txs_in=[tx_in], txs_out=[tx_out])
        tx2 = tx_utils.create_tx(tx1.tx_outs_as_spendable(), [address])
        hash160_lookup = build_hash160_lookup(key.secret_exponent() for key in keys[:N])
        p2sh_lookup = build_p2sh_lookup([underlying_script])
        tx2.sign(hash160_lookup=hash160_lookup, p2sh_lookup=p2sh_lookup)
        self.assertEqual(tx2.bad_signature_count(), 0)

    def test_weird_tx(self):
        # this is from tx 12a8d1d62d12307eac6e62f2f14d7e826604e53c320a154593845aa7c8e59fbf
        st = script_obj_from_script(b'Q')
        self.assertNotEqual(st, None)

    def test_nulldata(self):
        OP_RETURN = tools.compile("OP_RETURN")
        # note that because chr() is used samples with length > 255 will not work
        for sample in [b'test', b'me', b'a', b'39qEwuwyb2cAX38MFtrNzvq3KV9hSNov3q', b'', b'0'*80]:
            sample_script = OP_RETURN + tools.bin_script([sample])
            nd = ScriptNulldata(sample)
            self.assertEqual(nd.nulldata, sample)
            self.assertEqual(nd.script(), sample_script)
            nd2 = ScriptNulldata.from_script(sample_script)
            self.assertEqual(nd.nulldata, nd2.nulldata)
            out = TxOut(1, nd.script())
            # ensure we can create a tx
            Tx(0, [], [out])
            # convert between asm and back to ensure no bugs with compilation
            self.assertEqual(nd.script(), tools.compile(tools.disassemble(nd.script())))

    def test_sign_bitcoind_partially_signed_2_of_2(self):
        # Finish signing a 2 of 2 transaction, that already has one signature signed by bitcoind
        # This tx can be found on testnet3 blockchain
        # txid: 9618820d7037d2f32db798c92665231cd4599326f5bd99cb59d0b723be2a13a2
        raw_script = ("522103e33b41f5ed67a77d4c4c54b3e946bd30d15b8f66e42cb29fde059c168851165521"
                      "02b92cb20a9fb1eb9656a74eeb7387636cf64cdf502ff50511830328c1b479986452ae")
        p2sh_lookup = build_p2sh_lookup([h2b(raw_script)])
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
        key = Key.from_text("cThRBRu2jAeshWL3sH3qbqdq9f4jDiDbd1SVz4qjTZD2xL1pdbsx")
        hash160_lookup = build_hash160_lookup([key.secret_exponent()])
        self.assertEqual(tx.bad_signature_count(), 1)
        tx.sign(hash160_lookup=hash160_lookup, p2sh_lookup=p2sh_lookup)
        self.assertEqual(tx.bad_signature_count(), 0)
        self.assertEqual(tx.id(), "9618820d7037d2f32db798c92665231cd4599326f5bd99cb59d0b723be2a13a2")

    def test_issue_225(self):
        script = tools.compile("OP_RETURN 'foobar'")
        tx_out = TxOut(1, script)
        address = tx_out.bitcoin_address(netcode="XTN")
        self.assertEqual(address, "(nulldata 666f6f626172)")
        address = tx_out.bitcoin_address(netcode="BTC")
        self.assertEqual(address, "(nulldata 666f6f626172)")


if __name__ == "__main__":
    unittest.main()
