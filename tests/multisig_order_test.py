#!/usr/bin/env python
#-*-mode: python; encoding: utf-8-*-

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
    with_statement,
)

#---- Imports ------------------------------------------------------------

from unittest import (
    TestCase,
    main,
)
from pycoin.encoding import from_bytes_32
from pycoin.key import Key
from pycoin.scripts.tx import DEFAULT_VERSION as TX_VERSION
from pycoin.tx import (
    SIGHASH_ALL,
    Spendable,
    Tx,
    TxIn,
    TxOut,
)
from pycoin.tx.pay_to import (
    ScriptMultisig,
    script_obj_from_address,
    build_hash160_lookup,
)
from pycoin.tx.script.tools import (
    compile as compile_script,
    opcode_list,
)

#---- Constants ----------------------------------------------------------

__all__ = ()

ONE = b'\1' * 32
TWO = b'\2' * 32
ALL_LOOKUP = {}
KE = Key.from_text('cToFsZvLt5LB9QbNDfVbVKw3M7zTL3FeFmcLCX6BR2rMpYGAbRFc')
KE_LOOKUP = build_hash160_lookup(( _k.secret_exponent() for _k in ( KE, ) ))
ALL_LOOKUP.update(KE_LOOKUP)
K1 = Key.from_text('cN7Pece8WaJNxRFRhw6xkfGvqpNwsdDsNJ8XD2fzRRMa18RmjycD')
K1_LOOKUP = build_hash160_lookup(( _k.secret_exponent() for _k in ( K1, ) ))
ALL_LOOKUP.update(K1_LOOKUP)
K2 = Key.from_text('cRrdMjuanRUuVC1nGqK3YzqyeL3yVrtNjW4x4wrt6cS1b7DekgdE')
K2_LOOKUP = build_hash160_lookup(( _k.secret_exponent() for _k in ( K2, ) ))
ALL_LOOKUP.update(K2_LOOKUP)
PAY_TO_K1_SCRIPT_OBJ = script_obj_from_address(K1.address())
PAY_TO_K2_SCRIPT_OBJ = script_obj_from_address(K2.address())

ESCROW_UNSPENTS = (
    Spendable(115010000, PAY_TO_K1_SCRIPT_OBJ.script(), ONE, 1),
    Spendable(115010000, PAY_TO_K2_SCRIPT_OBJ.script(), TWO, 2),
)

ESCROW_TXS_IN = (
    TxIn(ESCROW_UNSPENTS[0].tx_hash, ESCROW_UNSPENTS[0].tx_out_index, PAY_TO_K1_SCRIPT_OBJ.solve(hash160_lookup=K1_LOOKUP, sign_value=from_bytes_32(ONE), signature_type=SIGHASH_ALL)),
    TxIn(ESCROW_UNSPENTS[1].tx_hash, ESCROW_UNSPENTS[1].tx_out_index, PAY_TO_K2_SCRIPT_OBJ.solve(hash160_lookup=K2_LOOKUP, sign_value=from_bytes_32(TWO), signature_type=SIGHASH_ALL)),
)

TX_VALIDATES_WITH_SIGS_OUT_OF_ORDER_MSG = 'signatures appear out of order but they still validate'

#---- Classes ------------------------------------------------------------

#=========================================================================
class PartialSignTest(TestCase):
    """
    Signing MULTISIG transactions out of order should either fail
    validation (or possibly raise an exception), or produce the same
    result as signing in the correct order. This is because signatures in
    the reverse order won't validate. From
    http://tinyurl.com/op-checkmultisig:

        Because public keys are not checked again if they fail any
        signature comparison, signatures must be placed in the signature
        script using the same order as their corresponding public keys
        were placed in the pubkey script or redeem script. See the
        OP_CHECKMULTISIG warning below for more details.
    """

    #---- Public hook methods --------------------------------------------

    #=====================================================================
    def test_partial_sign_2_of_2(self):
        unsigned_disburse_tx = self._fake_unsigned_disburse_tx(2, K1, K2)
        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, K1_LOOKUP, K2_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx, out_of_order_tx)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)

    #=====================================================================
    def test_partial_sign_2_of_3(self):
        unsigned_disburse_tx = self._fake_unsigned_disburse_tx(2, KE, K1, K2)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, KE_LOOKUP, K1_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx, out_of_order_tx)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, KE_LOOKUP, K2_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx, out_of_order_tx)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, K1_LOOKUP, K2_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx, out_of_order_tx)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)

        # Sign all with any of KE, K1, and K2
        disburse_unspents = unsigned_disburse_tx.unspents
        disburse_tx_copy = Tx.tx_from_hex(unsigned_disburse_tx.as_hex())
        disburse_tx_copy.set_unspents(disburse_unspents)
        self.assertFalse(disburse_tx_copy.is_signature_ok(0))
        disburse_tx_copy.sign(ALL_LOOKUP)
        self.assertTrue(disburse_tx_copy.is_signature_ok(0))

    #=====================================================================
    def test_partial_sign_3_of_3(self):
        unsigned_disburse_tx = self._fake_unsigned_disburse_tx(3, KE, K1, K2)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, KE_LOOKUP, K1_LOOKUP, K2_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx, out_of_order_tx)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, K2_LOOKUP, KE_LOOKUP, K1_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx, out_of_order_tx)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, K1_LOOKUP, K2_LOOKUP, KE_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx, out_of_order_tx)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)

        # Sign all with any of KE, K1, and K2
        disburse_unspents = unsigned_disburse_tx.unspents
        disburse_tx_copy = Tx.tx_from_hex(unsigned_disburse_tx.as_hex())
        disburse_tx_copy.set_unspents(disburse_unspents)
        self.assertFalse(disburse_tx_copy.is_signature_ok(0))
        disburse_tx_copy.sign(ALL_LOOKUP)
        self.assertTrue(disburse_tx_copy.is_signature_ok(0))

    #=====================================================================
    def test_partial_sign_weird_2_of_4(self):
        unsigned_disburse_tx = self._fake_unsigned_disburse_tx(2, KE, K1, K2, KE)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, KE_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, K1_LOOKUP, K2_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx, out_of_order_tx)

        in_order_tx1, out_of_order_tx1 = self._sign_out_of_order(unsigned_disburse_tx, K1_LOOKUP, KE_LOOKUP)
        in_order_tx2, out_of_order_tx2 = self._sign_out_of_order(unsigned_disburse_tx, KE_LOOKUP, K1_LOOKUP)
        self.assertEqual(in_order_tx1.txs_in[0].script, out_of_order_tx2.txs_in[0].script)
        self.assertEqual(in_order_tx2.txs_in[0].script, out_of_order_tx1.txs_in[0].script)

        in_order_tx1, out_of_order_tx1 = self._sign_out_of_order(unsigned_disburse_tx, K2_LOOKUP, KE_LOOKUP)
        in_order_tx2, out_of_order_tx2 = self._sign_out_of_order(unsigned_disburse_tx, KE_LOOKUP, K2_LOOKUP)
        self.assertEqual(in_order_tx1.txs_in[0].script, out_of_order_tx2.txs_in[0].script)
        self.assertEqual(in_order_tx2.txs_in[0].script, out_of_order_tx1.txs_in[0].script)

    #=====================================================================
    def test_partial_sign_weird_3_of_4(self):
        unsigned_disburse_tx = self._fake_unsigned_disburse_tx(3, KE, K1, K2, KE)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, KE_LOOKUP, K1_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx, out_of_order_tx)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, KE_LOOKUP, K2_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx, out_of_order_tx)

        in_order_tx1, out_of_order_tx1 = self._sign_out_of_order(unsigned_disburse_tx, K1_LOOKUP, K2_LOOKUP, KE_LOOKUP)
        in_order_tx2, out_of_order_tx2 = self._sign_out_of_order(unsigned_disburse_tx, KE_LOOKUP, K2_LOOKUP, K1_LOOKUP)
        self.assertEqual(in_order_tx1.txs_in[0].script, out_of_order_tx2.txs_in[0].script)
        self.assertEqual(in_order_tx2.txs_in[0].script, out_of_order_tx1.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx1, out_of_order_tx2)

        in_order_tx1, out_of_order_tx1 = self._sign_out_of_order(unsigned_disburse_tx, K2_LOOKUP, K1_LOOKUP, KE_LOOKUP)
        in_order_tx2, out_of_order_tx2 = self._sign_out_of_order(unsigned_disburse_tx, KE_LOOKUP, K1_LOOKUP, K2_LOOKUP)
        self.assertEqual(in_order_tx1.txs_in[0].script, out_of_order_tx2.txs_in[0].script)
        self.assertEqual(in_order_tx2.txs_in[0].script, out_of_order_tx1.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx1, out_of_order_tx2)

    #=====================================================================
    def test_partial_sign_weird_4_of_4(self):
        unsigned_disburse_tx = self._fake_unsigned_disburse_tx(4, KE, K1, K2, KE)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, KE_LOOKUP, K1_LOOKUP, K2_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx, out_of_order_tx)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, K1_LOOKUP, K2_LOOKUP, KE_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx, out_of_order_tx)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, K2_LOOKUP, KE_LOOKUP, K1_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx, out_of_order_tx)

    #=====================================================================
    def test_partial_sign_weird_3_of_5(self):
        unsigned_disburse_tx = self._fake_unsigned_disburse_tx(3, K2, K1, KE, K1, K2)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, K2_LOOKUP, K1_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, K2_LOOKUP, KE_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx, out_of_order_tx)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, K1_LOOKUP, KE_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx, out_of_order_tx)

    #=====================================================================
    def test_partial_sign_weird_6_of_6(self):
        unsigned_disburse_tx = self._fake_unsigned_disburse_tx(6, KE, K1, K2, KE, K1, K2)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, KE_LOOKUP, K1_LOOKUP, K2_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx, out_of_order_tx)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, K2_LOOKUP, KE_LOOKUP, K1_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx, out_of_order_tx)

        in_order_tx, out_of_order_tx = self._sign_out_of_order(unsigned_disburse_tx, K1_LOOKUP, K2_LOOKUP, KE_LOOKUP)
        self.assertEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)
        self._screw_up_signature_order_then_fix_it(in_order_tx, out_of_order_tx)

    #---- Private methods ------------------------------------------------

    #=====================================================================
    def _fake_unsigned_disburse_tx(self, m, *keys):
        # Fake an escrow transaction
        escrow_multisig_script_obj = ScriptMultisig(m, [ k.sec() for k in keys ])

        escrow_txs_out = (
            TxOut(210010000, escrow_multisig_script_obj.script()),
            TxOut(10000000, PAY_TO_K1_SCRIPT_OBJ.script()),
            TxOut(10000000, PAY_TO_K2_SCRIPT_OBJ.script()),
        )

        escrow_tx = Tx(TX_VERSION, ESCROW_TXS_IN, escrow_txs_out, unspents=ESCROW_UNSPENTS)
        escrow_tx_hash = escrow_tx.hash()

        # Create an unsigned disbursement transaction
        escrow_tx_out_idx = 0
        disburse_unspents = escrow_tx.tx_outs_as_spendable()[escrow_tx_out_idx:escrow_tx_out_idx + 1]

        disburse_txs_in = (
            TxIn(escrow_tx_hash, escrow_tx_out_idx, escrow_multisig_script_obj.solve(hash160_lookup={}, signature_type=SIGHASH_ALL)),
        )

        disburse_txs_out = (
            TxOut(110000000, PAY_TO_K1_SCRIPT_OBJ.script()),
            TxOut(100000000, PAY_TO_K2_SCRIPT_OBJ.script()),
        )

        unsigned_disburse_tx = Tx(TX_VERSION, disburse_txs_in, disburse_txs_out, unspents=disburse_unspents)

        return unsigned_disburse_tx

    #=====================================================================
    def _screw_up_signature_order_then_fix_it(self, in_order_tx, out_of_order_tx):
        # Swap the last two signatures
        opcodes = opcode_list(out_of_order_tx.txs_in[0].script)
        opcodes[-1], opcodes[-2] = opcodes[-2], opcodes[-1]
        out_of_order_tx.txs_in[0].script = compile_script(' '.join(opcodes))
        self.assertFalse(out_of_order_tx.is_signature_ok(0))
        self.assertNotEqual(in_order_tx.txs_in[0].script, out_of_order_tx.txs_in[0].script)

        # Fix it (it already has all the signatures it needs, they're just
        # in the wrong order)
        out_of_order_tx.sign({})
        self.assertTrue(out_of_order_tx.is_signature_ok(0))

    #=====================================================================
    def _sign_one_key_at_a_time(self, unsigned_disburse_tx, *lookups):
        disburse_tx_copy = Tx.tx_from_hex(unsigned_disburse_tx.as_hex())
        disburse_tx_copy.set_unspents(unsigned_disburse_tx.unspents)
        self.assertFalse(disburse_tx_copy.is_signature_ok(0))

        for lookup in lookups:
            disburse_tx_copy.sign(lookup)

        return disburse_tx_copy

    #=====================================================================
    def _sign_in_order(self, unsigned_disburse_tx, *lookups):
        signed_disburse_tx = self._sign_one_key_at_a_time(unsigned_disburse_tx, *lookups)
        self.assertTrue(signed_disburse_tx.is_signature_ok(0))

        return signed_disburse_tx

    #=====================================================================
    def _sign_out_of_order(self, unsigned_disburse_tx, *lookups):
        disburse_in_order_tx = self._sign_in_order(unsigned_disburse_tx, *lookups)
        disburse_out_of_order_tx = self._sign_one_key_at_a_time(unsigned_disburse_tx, *reversed(lookups)) # pylint: disable=star-args
        self.assertTrue(disburse_out_of_order_tx.is_signature_ok(0))

        return disburse_in_order_tx, disburse_out_of_order_tx

#---- Initialization -----------------------------------------------------

if __name__ == '__main__':
    import logging
    import cProfile as profile
    import unittest
    logging.basicConfig(level=logging.CRITICAL + 1)
    suite = unittest.TestLoader().discover('.')
    def runtests():
        unittest.TextTestRunner().run(suite)
    s = profile.run('runtests()', 'profile_results.original')
    main()
