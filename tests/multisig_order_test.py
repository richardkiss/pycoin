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
class ParitalSignTest(TestCase):
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
        self._sign_out_of_order(unsigned_disburse_tx, K1_LOOKUP, K2_LOOKUP)

    #=====================================================================
    def test_partial_sign_2_of_3(self):
        unsigned_disburse_tx = self._fake_unsigned_disburse_tx(2, KE, K1, K2)
        disburse_unspents = unsigned_disburse_tx.unspents

        # Sign all with any of KE, K1, and K2
        disburse_tx_copy = Tx.tx_from_hex(unsigned_disburse_tx.as_hex())
        disburse_tx_copy.set_unspents(disburse_unspents)
        self.assertFalse(disburse_tx_copy.is_signature_ok(0))
        disburse_tx_copy.sign(ALL_LOOKUP)
        self.assertTrue(disburse_tx_copy.is_signature_ok(0))

        # Sign out of order with various pairs
        self._sign_out_of_order(unsigned_disburse_tx, KE_LOOKUP, K1_LOOKUP)
        self._sign_out_of_order(unsigned_disburse_tx, KE_LOOKUP, K2_LOOKUP)
        self._sign_out_of_order(unsigned_disburse_tx, K1_LOOKUP, K2_LOOKUP)

    #=====================================================================
    def test_partial_sign_specific_transactions(self):
        # pylint: disable=pointless-string-statement
        key = Key.from_text('cUQV5ChTDSVqvPxu39Fzvdfw4FhaS417SdKHbG59Kq7bGB9BqPfk')
        hash160_lookup = build_hash160_lookup(( k.secret_exponent() for k in ( key, ) ))

        escrow_tx1 = Tx.tx_from_hex('010000000245b681a697a3cf8a9be4af56182b383a4a45c6ca92f43b4846a520beee94968900000000490047304402200aec5aae8d2e8116cc933cb27d9f3a2094ab1904ceb3e8c20eb11d207c16e11e02206c0d496c625f48036d6f2c8e60bb3817b2e60aab4f3b0da3d61c8139f88a0e4701ffffffff9f47c29599ea8d452e6d3e267cacfc232904301842a332d0765df5de4a32b24c00000000490047304402202c8acaaf8b674ae47a93661c5dc81f56e72e0da59a40710cfbe7e5e09c487f4d02202f29e89eee22bdc2ba121dc26bea1dd55af7f4119c58a6f9389844ecc8f733ff01ffffffff039aa4a0000000000069522103fe4e6231d614d159741df8371fa3b31ab93b3d28a7495cdaa0cd63a2097015c72103dd97fd4f2dd61dd0510fa43acd83231e9b9cadb321fdd0fec97096249eabd2522103dd97fd4f2dd61dd0510fa43acd83231e9b9cadb321fdd0fec97096249eabd25253aece010400000000001976a9147ae117a1ae026769482bf896ea266671bb7e8d8d88acce010400000000001976a9147ae117a1ae026769482bf896ea266671bb7e8d8d88ac00000000')
        partial_disburse_tx1 = Tx.tx_from_hex('0100000001e9a392c95b88f8b65d66a5d104de1c8ba8599c38a79e15d01775b5796b34a44c000000009300483045022100ca2c7414f1b3aa62c70f715eea8824d780ddfe87ceb8981c4a96f02a08006ea702200409efff354e2571d5d2dce8c60c8ec1cbe4e11b3c47cc05f568c79f496a07c101483045022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414002207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a001ffffffff030ae70700000000001976a91467c62abb4b00de59f45d5ac06d1ca9490920148c88ace5eb3e00000000001976a9147ae117a1ae026769482bf896ea266671bb7e8d8d88ac9baa5900000000001976a9147ae117a1ae026769482bf896ea266671bb7e8d8d88ac00000000')
        escrow_tx1_out_idx = 0
        partial_disburse_tx1.set_unspents(escrow_tx1.tx_outs_as_spendable()[escrow_tx1_out_idx:escrow_tx1_out_idx + 1])

        # bitcoind can complete this transaction ...
        """
        % bitcoin-cli -testnet signrawtransaction 0100000001e9a392c95b88f8b65d66a5d104de1c8ba8599c38a79e15d01775b5796b34a44c000000004b00483045022100ca2c7414f1b3aa62c70f715eea8824d780ddfe87ceb8981c4a96f02a08006ea702200409efff354e2571d5d2dce8c60c8ec1cbe4e11b3c47cc05f568c79f496a07c10100ffffffff030ae70700000000001976a91467c62abb4b00de59f45d5ac06d1ca9490920148c88ace5eb3e00000000001976a9147ae117a1ae026769482bf896ea266671bb7e8d8d88ac9baa5900000000001976a9147ae117a1ae026769482bf896ea266671bb7e8d8d88ac00000000 '[]' '["cUQV5ChTDSVqvPxu39Fzvdfw4FhaS417SdKHbG59Kq7bGB9BqPfk"]' ALL
        {
            "hex" : "0100000001e9a392c95b88f8b65d66a5d104de1c8ba8599c38a79e15d01775b5796b34a44c000000009300483045022100ca2c7414f1b3aa62c70f715eea8824d780ddfe87ceb8981c4a96f02a08006ea702200409efff354e2571d5d2dce8c60c8ec1cbe4e11b3c47cc05f568c79f496a07c1014830450221008dfe5036313be8f57c320a32cfc01489bf2ac81d3d2696b411c96f44ff385f1a02206c4bbb4f5b9c67d53cb765a98f9a8f281493e655508e51ea86c2ec5d7f444e5f01ffffffff030ae70700000000001976a91467c62abb4b00de59f45d5ac06d1ca9490920148c88ace5eb3e00000000001976a9147ae117a1ae026769482bf896ea266671bb7e8d8d88ac9baa5900000000001976a9147ae117a1ae026769482bf896ea266671bb7e8d8d88ac00000000",
            "complete" : true
        }
        """

        # ... can pycoin?
        partial_disburse_tx1.sign(hash160_lookup)
        self.assertTrue(partial_disburse_tx1.is_signature_ok(0))

        escrow_tx2 = Tx.tx_from_hex('010000000295989fa4578e8004790813dc5feaaf8edfdde1da3d3267dcc0703d59564d48e5000000004900473044022017df76061e0529bec90abd4c35ed177b8528ed6cf636df5beff9013fffdee816022076a8ab1c2866e7478f1ffae66949ff1ef4659f19743a22b37cc10b6e5452a00501ffffffffd585df72afedad0f2408d79880d411d3f5820973896e37c63485f0d20c3b3915000000004a004830450221009be18163101230eb171dc5e00efeac515f4b559517afd34f0c86879409b6ac16022017dccbd2ebdd0ca92eee4b30527aec1e1bd304185db138196e00d3d10c38bbea01ffffffff039aa4a0000000000069522103fe4e6231d614d159741df8371fa3b31ab93b3d28a7495cdaa0cd63a2097015c72103dd97fd4f2dd61dd0510fa43acd83231e9b9cadb321fdd0fec97096249eabd2522103540be1c323e54ad38f45a12d42d409fb798fab71551559d2feabf2ac473aeffc53aece010400000000001976a9147ae117a1ae026769482bf896ea266671bb7e8d8d88acce010400000000001976a9144a62edd0a379c76e4fcbf7d00d0debf055c0979088ac00000000')
        partial_disburse_tx2 = Tx.tx_from_hex('01000000018a9ca5b80315cdb0026e11a8db533fa07b59877f292b684268b6efd3f0f67841000000009200473044022062af66e008b01a8ca17f632fbc2a0b705b70308f708318d94f4eafffa902e64b02203260c060b43fb8fa28ce7dff3687b8ec7dfb5c247fd547328ad09055687a284f01483045022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414002207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a001ffffffff030ae70700000000001976a914f89873b36ea31cfbf4d2081db73147078460c61188ace5eb3e00000000001976a9147ae117a1ae026769482bf896ea266671bb7e8d8d88ac9baa5900000000001976a9144a62edd0a379c76e4fcbf7d00d0debf055c0979088ac00000000')
        escrow_tx2_out_idx = 0
        partial_disburse_tx2.set_unspents(escrow_tx2.tx_outs_as_spendable()[escrow_tx2_out_idx:escrow_tx2_out_idx + 1])

        # bitcoind can complete this transaction
        """
        % bitcoin-cli -testnet signrawtransaction 01000000018a9ca5b80315cdb0026e11a8db533fa07b59877f292b684268b6efd3f0f67841000000009200473044022062af66e008b01a8ca17f632fbc2a0b705b70308f708318d94f4eafffa902e64b02203260c060b43fb8fa28ce7dff3687b8ec7dfb5c247fd547328ad09055687a284f01483045022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414002207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a001ffffffff030ae70700000000001976a914f89873b36ea31cfbf4d2081db73147078460c61188ace5eb3e00000000001976a9147ae117a1ae026769482bf896ea266671bb7e8d8d88ac9baa5900000000001976a9144a62edd0a379c76e4fcbf7d00d0debf055c0979088ac00000000 '[]' '["cUQV5ChTDSVqvPxu39Fzvdfw4FhaS417SdKHbG59Kq7bGB9BqPfk"]' ALL
        {
            "hex" : "01000000018a9ca5b80315cdb0026e11a8db533fa07b59877f292b684268b6efd3f0f67841000000009200473044022062af66e008b01a8ca17f632fbc2a0b705b70308f708318d94f4eafffa902e64b02203260c060b43fb8fa28ce7dff3687b8ec7dfb5c247fd547328ad09055687a284f01483045022100cd2bd2b0cb56c516e7ee4d4c6575d07f97e23192053d13077e42bfc4df84414d02206258a12dd2568602391a6424a3566e376abf2b11195dc856930e49fc96aabadc01ffffffff030ae70700000000001976a914f89873b36ea31cfbf4d2081db73147078460c61188ace5eb3e00000000001976a9147ae117a1ae026769482bf896ea266671bb7e8d8d88ac9baa5900000000001976a9144a62edd0a379c76e4fcbf7d00d0debf055c0979088ac00000000",
            "complete" : true
        }
        """

        # ... can pycoin?
        partial_disburse_tx2.sign(hash160_lookup)
        self.assertTrue(partial_disburse_tx2.is_signature_ok(0))

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
    def _sign_one_key_at_a_time(self, unsigned_disburse_tx, *lookups):
        disburse_tx_copy = Tx.tx_from_hex(unsigned_disburse_tx.as_hex())
        disburse_tx_copy.set_unspents(unsigned_disburse_tx.unspents)

        for lookup in lookups:
            self.assertFalse(disburse_tx_copy.is_signature_ok(0))
            disburse_tx_copy.sign(lookup)

        return disburse_tx_copy

    #=====================================================================
    def _sign_in_order(self, unsigned_disburse_tx, *lookups):
        disburse_tx_signed_copy = self._sign_one_key_at_a_time(unsigned_disburse_tx, *lookups)
        self.assertTrue(disburse_tx_signed_copy.is_signature_ok(0))

        return disburse_tx_signed_copy

    #=====================================================================
    def _sign_out_of_order(self, unsigned_disburse_tx, *lookups):
        disburse_tx_in_order_copy = self._sign_in_order(unsigned_disburse_tx, *lookups)
        reversed_lookups = reversed(lookups)
        disburse_tx_out_of_order_copy = self._sign_one_key_at_a_time(unsigned_disburse_tx, *reversed_lookups) # pylint: disable=star-args
        expected_result = disburse_tx_in_order_copy.txs_in[0].script == disburse_tx_out_of_order_copy.txs_in[0].script \
            or not disburse_tx_out_of_order_copy.is_signature_ok(0)
        self.assertTrue(expected_result, TX_VALIDATES_WITH_SIGS_OUT_OF_ORDER_MSG)

#---- Initialization -----------------------------------------------------

if __name__ == '__main__':
    main()
