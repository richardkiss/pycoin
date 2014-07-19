#!/usr/bin/env python

import io
import unittest

from pycoin.key import Key
from pycoin.serialize import h2b
from pycoin.tx import Tx, TxIn, TxOut, SIGHASH_ALL, tx_utils
from pycoin.tx.TxOut import standard_tx_out_script

from pycoin.tx.pay_to import ScriptMultisig, ScriptPayToPublicKey
from pycoin.tx.pay_to import address_for_pay_to_script, build_hash160_lookup, build_p2sh_lookup
from pycoin.tx.pay_to import script_obj_from_address, script_obj_from_script

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
                solution = st.solve(hash160_lookup=hl, sign_value=sv, signature_type=SIGHASH_ALL)
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
                solution = st.solve(hash160_lookup=hl, sign_value=sv, signature_type=SIGHASH_ALL)
                sc = st.script()
                st = script_obj_from_script(sc)
                self.assertEqual(st.address(), addr)

    def test_sign(self):
        sv = 33143560198659167577410026742586567991638126035902913554051654024377193788946
        tx_out_script = b'v\xa9\x14\x91\xb2K\xf9\xf5(\x852\x96\n\xc6\x87\xab\xb05\x12{\x1d(\xa5\x88\xac'
        st = script_obj_from_script(tx_out_script)
        hl = build_hash160_lookup([1])
        solution = st.solve(hash160_lookup=hl, sign_value=sv, signature_type=SIGHASH_ALL)
        self.assertEqual(solution, b'G0D\x02 ^=\xf5\xb5[\xe6!@\x04,"\x0b\x1f\xdf\x10\\\xc8Q\x13\xafV*!\\\x1f\xc5\xb5\xc5"\xd1\xb3\xd3\x02 8\xc9YK\x15o\xae\xd7\xf3|0\x07z\xff\xbfj\xcfB\xbf\x17\xb1\xe69\xa1\xfc\xc6\xc5\x1ag\xab\xa2\x16\x01A\x04y\xbef~\xf9\xdc\xbb\xacU\xa0b\x95\xce\x87\x0b\x07\x02\x9b\xfc\xdb-\xce(\xd9Y\xf2\x81[\x16\xf8\x17\x98H:\xdaw&\xa3\xc4e]\xa4\xfb\xfc\x0e\x11\x08\xa8\xfd\x17\xb4H\xa6\x85T\x19\x9cG\xd0\x8f\xfb\x10\xd4\xb8')

    def test_validate_multisig(self):
        # this is a transaction in the block chain
        # the unspents are included too, so it can be validated
        f = io.BytesIO(h2b("01000000025718fb915fb8b3a802bb699ddf04dd91261ef6715f5f2820a2b1b9b7e38b4f27000000004a004830450221008c2107ed4e026ab4319a591e8d9ec37719cdea053951c660566e3a3399428af502202ecd823d5f74a77cc2159d8af2d3ea5d36a702fef9a7edaaf562aef22ac35da401ffffffff038f52231b994efb980382e4d804efeadaee13cfe01abe0d969038ccb45ec17000000000490047304402200487cd787fde9b337ab87f9fe54b9fd46d5d1692aa58e97147a4fe757f6f944202203cbcfb9c0fc4e3c453938bbea9e5ae64030cf7a97fafaf460ea2cb54ed5651b501ffffffff0100093d00000000001976a9144dc39248253538b93d3a0eb122d16882b998145888ac0000000002000000000000004751210351efb6e91a31221652105d032a2508275f374cea63939ad72f1b1e02f477da782100f2b7816db49d55d24df7bdffdbc1e203b424e8cd39f5651ab938e5e4a193569e52ae404b4c00000000004751210351efb6e91a31221652105d032a2508275f374cea63939ad72f1b1e02f477da7821004f0331742bbc917ba2056a3b8a857ea47ec088dd10475ea311302112c9d24a7152ae"))
        tx = Tx.parse(f)
        tx.parse_unspents(f)
        self.assertEqual(tx.id(), "70c4e749f2b8b907875d1483ae43e8a6790b0c8397bbb33682e3602617f9a77a")
        self.assertEqual(tx.bad_signature_count(), 0)

    def test_recognize_multisig(self):
        h = '010000000139c92b102879eb95f14e7344e4dd7d481e1238b1bfb1fa0f735068d2927b231400000000910047304402208fc06d216ebb4b6a3a3e0f906e1512c372fa8a9c2a92505d04e9b451ea7acd0c0220764303bb7e514ddd77855949d941c934e9cbda8e3c3827bfdb5777477e73885b014730440220569ec6d2e81625dd18c73920e0079cdb4c1d67d3d7616759eb0c18cf566b3d3402201c60318f0a62e3ba85ca0f158d4dfe63c0779269eb6765b6fc939fc51e7a8ea901ffffffff0140787d01000000001976a914641ad5051edd97029a003fe9efb29359fcee409d88ac0000000040787d0100000000c952410496ec45f878b62c46c4be8e336dff7cc58df9b502178cc240eb3d31b1266f69f5767071aa3e017d1b82a0bb28dab5e27d4d8e9725b3e68ed5f8a2d45c730621e34104cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4410461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af53ae'
        f = io.BytesIO(h2b(h))
        tx = Tx.parse(f)
        tx.parse_unspents(f)
        self.assertEqual(tx.id(), "10c61e258e0a2b19b245a96a2d0a1538fe81cd4ecd547e0a3df7ed6fd3761ada")
        the_script = tx.unspents[0].script
        s = script_obj_from_script(tx.unspents[0].script)
        self.assertEqual(s.script(), the_script)

    def multisig_N_of_M(self, N, M, unsigned_id, signed_id):
        keys = [Key(secret_exponent=i) for i in range(1, M+2)]
        tx_in = TxIn.coinbase_tx_in(script=b'')
        script = ScriptMultisig(n=N, sec_keys=[key.sec() for key in keys[:M]]).script()
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
        self.multisig_N_of_M(1, 2, unsigned_id, signed_id)

    def test_create_multisig_2_of_3(self):
        unsigned_id = "6bc5614a41c7c4aa828f5a4314fff23e5e49b1137e5d31e9716eb58f6fb198ff"
        signed_id = "c521962fe9d0e5efb7d0966759c57e7ee2595ce8e05cb342b19265a8722420dd"
        self.multisig_N_of_M(2, 3, unsigned_id, signed_id)

    def test_multisig_one_at_a_time(self):
        N = 3
        M = 3
        keys = [Key(secret_exponent=i) for i in range(1, M+2)]
        tx_in = TxIn.coinbase_tx_in(script=b'')
        script = ScriptMultisig(n=N, sec_keys=[key.sec() for key in keys[:M]]).script()
        tx_out = TxOut(1000000, script)
        tx1 = Tx(version=1, txs_in=[tx_in], txs_out=[tx_out])
        tx2 = tx_utils.create_tx(tx1.tx_outs_as_spendable(), [keys[-1].address()])
        ids = ["403e5bfc59e097bb197bf77a692d158dd3a4f7affb4a1fa41072dafe7bec7058",
               "5931d9995e83721243dca24772d7012afcd4378996a8b953c458175f15a544db",
               "9bb4421088190bbbb5b42a9eaa9baed7ec7574a407c25f71992ba56ca43d9c44",
               "03a1dc2a63f93a5cf5a7cb668658eb3fc2eda88c06dc287b85ba3e6aff751771"]
        for i in range(1, M+1):
            self.assertEqual(tx2.bad_signature_count(), 1)
            self.assertEqual(tx2.id(), ids[i-1])
            hash160_lookup = build_hash160_lookup(key.secret_exponent() for key in keys[i-1:i])
            tx2.sign(hash160_lookup=hash160_lookup)
            self.assertEqual(tx2.id(), ids[i])
        self.assertEqual(tx2.bad_signature_count(), 0)

    def test_sign_pay_to_script_multisig(self):
        N, M = 3, 3
        keys = [Key(secret_exponent=i) for i in range(1, M+2)]
        tx_in = TxIn.coinbase_tx_in(script=b'')
        underlying_script = ScriptMultisig(n=N, sec_keys=[key.sec() for key in keys[:M]]).script()
        address = address_for_pay_to_script(underlying_script)
        self.assertEqual(address, "39qEwuwyb2cAX38MFtrNzvq3KV9hSNov3q")
        script = standard_tx_out_script(address)
        tx_out = TxOut(1000000, script)
        tx1 = Tx(version=1, txs_in=[tx_in], txs_out=[tx_out])
        tx2 = tx_utils.create_tx(tx1.tx_outs_as_spendable(), [address])
        hash160_lookup = build_hash160_lookup(key.secret_exponent() for key in keys[:M])
        p2sh_lookup = build_p2sh_lookup([underlying_script])
        tx2.sign(hash160_lookup=hash160_lookup, p2sh_lookup=p2sh_lookup)
        self.assertEqual(tx2.bad_signature_count(), 0)

    def test_weird_tx(self):
        # this is from tx 12a8d1d62d12307eac6e62f2f14d7e826604e53c320a154593845aa7c8e59fbf
        st = script_obj_from_script(b'Q')
        self.assertNotEqual(st, None)

if __name__ == "__main__":
    unittest.main()
