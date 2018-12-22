import io
import unittest

from pycoin.encoding.hexbytes import h2b
from pycoin.symbols.btc import network


Tx = network.tx


class PayToTest(unittest.TestCase):

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
        script = tx.unspents[0].script
        multisig_info = network.contract.info_for_script(script)
        del multisig_info["type"]
        s = network.contract.for_multisig(**multisig_info)
        self.assertEqual(s, script)

    def test_nulldata(self):
        OP_RETURN = network.script.compile("OP_RETURN")
        for sample in [b'test', b'me', b'a', b'39qEwuwyb2cAX38MFtrNzvq3KV9hSNov3q', b'', b'0'*80]:
            sample_script = OP_RETURN + sample
            sc = network.contract.for_nulldata(sample)
            info = network.contract.info_for_script(sc)
            self.assertEqual(info.get("data"), sample)
            self.assertEqual(sc, sample_script)
            out = Tx.TxOut(1, sc)
            # ensure we can create a tx
            Tx(0, [], [out])
            # convert between asm and back to ensure no bugs with compilation
            # BRAIN DAMAGE: this doesn't work yet
            # self.assertEqual(sc, network.script.compile(network.script.disassemble(sc)))

    def test_nulldata_push(self):
        OP_RETURN = network.script.compile("OP_RETURN")
        for sample in [b'test', b'me', b'a', b'39qEwuwyb2cAX38MFtrNzvq3KV9hSNov3q', b'', b'0'*80]:
            sample_push = network.script.compile_push_data_list([sample])
            sample_script = OP_RETURN + sample_push
            sc = network.contract.for_nulldata_push(sample)
            info = network.contract.info_for_script(sc)
            self.assertEqual(info.get("data"), sample_push)
            self.assertEqual(sc, sample_script)
            out = Tx.TxOut(1, sc)
            # ensure we can create a tx
            Tx(0, [], [out])
            # convert between asm and back to ensure no bugs with compilation
            self.assertEqual(sc, network.script.compile(network.script.disassemble(sc)))


if __name__ == "__main__":
    unittest.main()
