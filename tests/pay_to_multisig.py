#!/usr/bin/env python

import io
import itertools
import copy
import unittest
from pycoin.cmds.tx import DEFAULT_VERSION
from pycoin.key import Key
from pycoin.serialize import h2b
from pycoin.tx import Tx, TxIn, TxOut, SIGHASH_ALL, tx_utils
from pycoin.tx.Spendable import Spendable
from pycoin.tx.tx_utils import LazySecretExponentDB
from pycoin.tx.pay_to import ScriptMultisig, ScriptPayToPublicKey, ScriptNulldata
from pycoin.tx.pay_to import build_hash160_lookup
from pycoin.tx.pay_to import script_obj_from_address, script_obj_from_script
from pycoin.tx.script import tools
from pycoin.ui import standard_tx_out_script


class ScriptTypesTest(unittest.TestCase):
    def multisig_M_of_N_individually(self, M, N):
        keys = [Key(secret_exponent=i) for i in range(1, N+2)]
        tx_in = TxIn.coinbase_tx_in(script=b'')
        script = ScriptMultisig(n=M, sec_keys=[key.sec() for key in keys[:N]]).script()
        tx_out = TxOut(1000000, script)
        tx1 = Tx(version=1, txs_in=[tx_in], txs_out=[tx_out])
        for partial_key_list in itertools.permutations(keys[:N], M):
            tx2 = tx_utils.create_tx(tx1.tx_outs_as_spendable(), [keys[-1].address()])
            for key in partial_key_list:
                self.assertEqual(tx2.bad_signature_count(), 1)
                hash160_lookup = build_hash160_lookup([key.secret_exponent()])
                tx2.sign(hash160_lookup=hash160_lookup)
            self.assertEqual(tx2.bad_signature_count(), 0)

    def test_multisig_one_at_a_time(self):
        for N in range(1, 4):
            for M in range(1, N+1):
                self.multisig_M_of_N_individually(M, N)

if __name__ == "__main__":
    unittest.main()
