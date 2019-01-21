import unittest

from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.encoding.hexbytes import b2h, b2h_rev
from pycoin.intbytes import int2byte
from pycoin.networks.registry import network_for_netcode
from pycoin.satoshi.der import sigdecode_der, sigencode_der


PRIV_KEYS = (
    2330949616242593315303241053456316633827293588958882755297900732239663851861,
    4437411780076344925846479906614060621668407514498402815534040340772719979673,
    14311886404724799688521454580288220586308410691395501373612453626821267193196,
    16404731722033649474165521611800542240555275746052963990137782680023514762282,
    92715304942310420502826004911529506622922082818576946681102234225452853924813,
    103235678552410630318322729483874198805317322052500844759252733409163632402845,
)


def sigcheck(a_key, a_hash_for_sig, a_sig):
    """
    Returns True if a_key was used to generate a_sig from a_hash_for_sig;
    False otherwise.
    """
    r, s = sigdecode_der(a_sig)

    return secp256k1_generator.verify(a_key.public_pair(), a_hash_for_sig, (r, s))


def sigmake(a_key, a_hash_for_sig, a_sig_type):
    """
    Signs a_hash_for_sig with a_key and returns a DER-encoded signature
    with a_sig_type appended.
    """
    order = secp256k1_generator.order()
    r, s = secp256k1_generator.sign(a_key.secret_exponent(), a_hash_for_sig)

    if s + s > order:
        s = order - s

    return sigencode_der(r, s) + int2byte(a_sig_type)


class SighashSingleTest(unittest.TestCase):

    def test_sighash_single(self):
        for netcode in ["BTC", "XTN"]:
            self._test_sighash_single(network_for_netcode(netcode))

    def _test_sighash_single(self, network):
        flags = network.validator.flags

        k0, k1, k2, k3, k4, k5 = [
            network.keys.private(secret_exponent=se, is_compressed=True) for se in PRIV_KEYS]

        # Fake a coinbase transaction
        coinbase_tx = network.tx.coinbase_tx(k0.sec(), 500000000)
        for k in [k1, k2]:
            coinbase_tx.txs_out.append(network.tx.TxOut(
                1000000000, network.script.compile('%s OP_CHECKSIG' % b2h(k.sec()))))

        self.assertEqual('2acbe1006f7168bad538b477f7844e53de3a31ffddfcfc4c6625276dd714155a',
                         b2h_rev(coinbase_tx.hash()))

        # Make the test transaction
        txs_in = [
            network.tx.TxIn(coinbase_tx.hash(), 0),
            network.tx.TxIn(coinbase_tx.hash(), 1),
            network.tx.TxIn(coinbase_tx.hash(), 2),
        ]
        txs_out = [
            network.tx.TxOut(900000000, network.contract.for_address(k3.address())),
            network.tx.TxOut(800000000, network.contract.for_address(k4.address())),
            network.tx.TxOut(800000000, network.contract.for_address(k5.address())),
        ]
        tx = network.tx(1, txs_in, txs_out)
        tx.set_unspents(coinbase_tx.txs_out)

        self.assertEqual('791b98ef0a3ac87584fe273bc65abd89821569fd7c83538ac0625a8ca85ba587', b2h_rev(tx.hash()))

        sig_type = flags.SIGHASH_SINGLE

        solution_checker = network.tx.SolutionChecker(tx)
        sig_hash = solution_checker._signature_hash(coinbase_tx.txs_out[0].script, 0, sig_type)
        self.assertEqual(0xcc52d785a3b4133504d1af9e60cd71ca422609cb41df3a08bbb466b2a98a885e, sig_hash)

        sig = sigmake(k0, sig_hash, sig_type)
        self.assertTrue(sigcheck(k0, sig_hash, sig[:-1]))

        tx.txs_in[0].script = network.script.compile(b2h(sig))
        self.assertTrue(tx.is_solution_ok(0))

        sig_hash = solution_checker._signature_hash(coinbase_tx.txs_out[1].script, 1, sig_type)
        self.assertEqual(0x93bb883d70fccfba9b8aa2028567aca8357937c65af7f6f5ccc6993fd7735fb7, sig_hash)

        sig = sigmake(k1, sig_hash, sig_type)
        self.assertTrue(sigcheck(k1, sig_hash, sig[:-1]))

        tx.txs_in[1].script = network.script.compile(b2h(sig))
        self.assertTrue(tx.is_solution_ok(1))

        sig_hash = solution_checker._signature_hash(coinbase_tx.txs_out[2].script, 2, sig_type)
        self.assertEqual(0x53ef7f67c3541bffcf4e0d06c003c6014e2aa1fb38ff33240b3e1c1f3f8e2a35, sig_hash)

        sig = sigmake(k2, sig_hash, sig_type)
        self.assertTrue(sigcheck(k2, sig_hash, sig[:-1]))

        tx.txs_in[2].script = network.script.compile(b2h(sig))
        self.assertTrue(tx.is_solution_ok(2))

        sig_type = flags.SIGHASH_SINGLE | flags.SIGHASH_ANYONECANPAY

        sig_hash = solution_checker._signature_hash(coinbase_tx.txs_out[0].script, 0, sig_type)
        self.assertEqual(0x2003393d246a7f136692ce7ab819c6eadc54ffea38eb4377ac75d7d461144e75, sig_hash)

        sig = sigmake(k0, sig_hash, sig_type)
        self.assertTrue(sigcheck(k0, sig_hash, sig[:-1]))

        tx.txs_in[0].script = network.script.compile(b2h(sig))
        self.assertTrue(tx.is_solution_ok(0))

        sig_hash = solution_checker._signature_hash(coinbase_tx.txs_out[1].script, 1, sig_type)
        self.assertEqual(0xe3f469ac88e9f35e8eff0bd8ad4ad3bf899c80eb7645947d60860de4a08a35df, sig_hash)

        sig = sigmake(k1, sig_hash, sig_type)
        self.assertTrue(sigcheck(k1, sig_hash, sig[:-1]))

        tx.txs_in[1].script = network.script.compile(b2h(sig))
        self.assertTrue(tx.is_solution_ok(1))

        sig_hash = solution_checker._signature_hash(coinbase_tx.txs_out[2].script, 2, sig_type)
        self.assertEqual(0xbacd7c3ab79cad71807312677c1788ad9565bf3c00ab9a153d206494fb8b7e6a, sig_hash)

        sig = sigmake(k2, sig_hash, sig_type)
        self.assertTrue(sigcheck(k2, sig_hash, sig[:-1]))

        tx.txs_in[2].script = network.script.compile(b2h(sig))
        self.assertTrue(tx.is_solution_ok(2))


if __name__ == "__main__":
    unittest.main()
