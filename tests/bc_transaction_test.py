#! /usr/bin/env python
# coding=utf-8
"""
Test suite for pycoin library: check validity of txs in files
tx_valid.json and tx_invalid.json. Adapted from Bitcoin Core
transaction_tests.cpp test suite.

The MIT License (MIT)

Copyright (c) 2015 by Marek Miller
Copyright (c) 2015 by Richard Kiss
Copyright (c) 2015 by The Bitcoin Core Developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

###############################################################################
# This test takes each transaction in  ./data/tx_valid.json
# and asserts that it is valid.  Similarly, it takes each transaction in
# ./data/tx_invalid.json and tries to show that it is invalid.
# The following transactions still cause problems and will eventually be
# included in json files with an appropriate bug fix.
###############################################################################
# These are valid transactions for which bad_signature_count() > 0:
# (cut out from tx_valid.json)
#
# ["An invalid P2SH Transaction"],
# [[["0000000000000000000000000000000000000000000000000000000000000100", 0, "HASH160 0x14 0x7a052c840ba73af26755de42cf01cc9e0a49fef0 EQUAL"]],
# "010000000100010000000000000000000000000000000000000000000000000000000000000000000009085768617420697320ffffffff010000000000000000015100000000", "NONE"],
#
# ["ddc454a1c0c35c188c98976b17670f69e586d9c0f3593ea879928332f0a069e7, which spends an input that pushes using a PUSHDATA1 that is negative when read as signed"],
#  [[["c5510a5dd97a25f43175af1fe649b707b1df8e1a41489bac33a23087027a2f48", 0, "0x4c 0xae 0x606563686f2022553246736447566b58312b5a536e587574356542793066794778625456415675534a6c376a6a334878416945325364667657734f53474f36633338584d7439435c6e543249584967306a486956304f376e775236644546673d3d22203e20743b206f70656e73736c20656e63202d7061737320706173733a5b314a564d7751432d707269766b65792d6865785d202d64202d6165732d3235362d636263202d61202d696e207460 DROP DUP HASH160 0x14 0xbfd7436b6265aa9de506f8a994f881ff08cc2872 EQUALVERIFY CHECKSIG"]],
#  "0100000001482f7a028730a233ac9b48411a8edfb107b749e61faf7531f4257ad95d0a51c5000000008b483045022100bf0bbae9bde51ad2b222e87fbf67530fbafc25c903519a1e5dcc52a32ff5844e022028c4d9ad49b006dd59974372a54291d5764be541574bb0c4dc208ec51f80b7190141049dd4aad62741dc27d5f267f7b70682eee22e7e9c1923b9c0957bdae0b96374569b460eb8d5b40d972e8c7c0ad441de3d94c4a29864b212d56050acb980b72b2bffffffff0180969800000000001976a914e336d0017a9d28de99d16472f6ca6d5a3a8ebc9988ac00000000", "P2SH"],
#
# ["cc60b1f899ec0a69b7c3f25ddf32c4524096a9c5b01cbd84c6d0312a0c478984, which is a fairly strange transaction which relies on OP_CHECKSIG returning 0 when checking a completely invalid sig of length 0"],
# [[["cbebc4da731e8995fe97f6fadcd731b36ad40e5ecb31e38e904f6e5982fa09f7", 0, "0x2102085c6600657566acc2d6382a47bc3f324008d2aa10940dd7705a48aa2a5a5e33ac7c2103f5d0fb955f95dd6be6115ce85661db412ec6a08abcbfce7da0ba8297c6cc0ec4ac7c5379a820d68df9e32a147cffa36193c6f7c43a1c8c69cda530e1c6db354bfabdcfefaf3c875379a820f531f3041d3136701ea09067c53e7159c8f9b2746a56c3d82966c54bbc553226879a5479827701200122a59a5379827701200122a59a6353798277537982778779679a68"]],
# "0100000001f709fa82596e4f908ee331cb5e0ed46ab331d7dcfaf697fe95891e73dac4ebcb000000008c20ca42095840735e89283fec298e62ac2ddea9b5f34a8cbb7097ad965b87568100201b1b01dc829177da4a14551d2fc96a9db00c6501edfa12f22cd9cefd335c227f483045022100a9df60536df5733dd0de6bc921fab0b3eee6426501b43a228afa2c90072eb5ca02201c78b74266fac7d1db5deff080d8a403743203f109fbcabf6d5a760bf87386d20100ffffffff01c075790000000000232103611f9a45c18f28f06f19076ad571c344c82ce8fcfe34464cf8085217a2d294a6ac00000000", "P2SH"],
#
# ["The following is a tweaked form of 23b397edccd3740a74adb603c9756370fafcde9bcc4483eb271ecad09a94dd63"],
# ["It is an OP_CHECKMULTISIG with an arbitrary extra byte stuffed into the signature at pos length - 2"],
# ["The dummy byte is fine however, so the NULLDUMMY flag should be happy"],
# [[["60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1", 0, "1 0x41 0x04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4 0x41 0x0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af 2 OP_CHECKMULTISIG"]],
# "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba260000000004a0048304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2bab01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000", "P2SH,NULLDUMMY"],
#
# ["The following is a tweaked form of 23b397edccd3740a74adb603c9756370fafcde9bcc4483eb271ecad09a94dd63"],
# ["It is an OP_CHECKMULTISIG with the dummy value set to something other than an empty string"],
# [[["60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1", 0, "1 0x41 0x04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4 0x41 0x0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af 2 OP_CHECKMULTISIG"]],
# "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba260000000004a01ff47304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000", "P2SH"],
#
# ["As above, but using a OP_1"],
# [[["60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1", 0, "1 0x41 0x04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4 0x41 0x0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af 2 OP_CHECKMULTISIG"]],
# "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba26000000000495147304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000", "P2SH"],
#
# ["As above, but using a OP_1NEGATE"],
# [[["60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1", 0, "1 0x41 0x04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4 0x41 0x0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af 2 OP_CHECKMULTISIG"]],
# "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba26000000000494f47304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000", "P2SH"],
#
# ["The following is c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73"],
# ["It is of interest because it contains a 0-sequence as well as a signature of SIGHASH type 0 (which is not a real type)"],
# [[["406b2b06bcd34d3c8733e6b79f7a394c8a431fbf4ff5ac705c93f4076bb77602", 0, "DUP HASH160 0x14 0xdc44b1164188067c3a32d4780f5996fa14a4f2d9 EQUALVERIFY CHECKSIG"]],
# "01000000010276b76b07f4935c70acf54fbf1f438a4c397a9fb7e633873c4dd3bc062b6b40000000008c493046022100d23459d03ed7e9511a47d13292d3430a04627de6235b6e51a40f9cd386f2abe3022100e7d25b080f0bb8d8d5f878bba7d54ad2fda650ea8d158a33ee3cbd11768191fd004104b0e2c879e4daf7b9ab68350228c159766676a14f5815084ba166432aab46198d4cca98fa3e9981d0a90b2effc514b76279476550ba3663fdcaff94c38420e9d5000000000100093d00000000001976a9149a7b0f3b80c6baaeedce0a0842553800f832ba1f88ac00000000", "P2SH"],
#
# ["As above, with the IF block executed"],
# [[["a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944", 0, "IF CODESEPARATOR ENDIF 0x21 0x0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 CHECKSIGVERIFY CODESEPARATOR 1"]],
# "010000000144490eda355be7480f2ec828dcc1b9903793a8008fad8cfe9b0c6b4d2f0355a9000000004a483045022100fa4a74ba9fd59c59f46c3960cf90cbe0d2b743c471d24a3d5d6db6002af5eebb02204d70ec490fd0f7055a7c45f86514336e3a7f03503dacecabb247fc23f15c83510151ffffffff010000000000000000016a00000000", "P2SH"],
#
###############################################################################
# These are invalid transactions that somehow return bad_signature_count() == 0
# (cut out from tx_invalid.json)
#
# ["The following is a tweaked form of 23b397edccd3740a74adb603c9756370fafcde9bcc4483eb271ecad09a94dd63"],
# ["It is an OP_CHECKMULTISIG with the dummy value set to something other than an empty string"],
# [[["60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1", 0, "1 0x41 0x04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4 0x41 0x0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af 2 OP_CHECKMULTISIG"]],
# "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba260000000004a010047304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000", "P2SH,NULLDUMMY"],
#
# ["Inverted versions of tx_valid CODESEPARATOR IF block tests"],
#
# ["CODESEPARATOR in an unexecuted IF block does not change what is hashed"],
# [[["a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944", 0, "IF CODESEPARATOR ENDIF 0x21 0x0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 CHECKSIGVERIFY CODESEPARATOR 1"]],
# "010000000144490eda355be7480f2ec828dcc1b9903793a8008fad8cfe9b0c6b4d2f0355a9000000004a48304502207a6974a77c591fa13dff60cabbb85a0de9e025c09c65a4b2285e47ce8e22f761022100f0efaac9ff8ac36b10721e0aae1fb975c90500b50c56e8a0cc52b0403f0425dd0151ffffffff010000000000000000016a00000000", "P2SH"],
#
# ["As above, with the IF block executed"],
# [[["a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944", 0, "IF CODESEPARATOR ENDIF 0x21 0x0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 CHECKSIGVERIFY CODESEPARATOR 1"]],
# "010000000144490eda355be7480f2ec828dcc1b9903793a8008fad8cfe9b0c6b4d2f0355a9000000004a483045022100fa4a74ba9fd59c59f46c3960cf90cbe0d2b743c471d24a3d5d6db6002af5eebb02204d70ec490fd0f7055a7c45f86514336e3a7f03503dacecabb247fc23f15c83510100ffffffff010000000000000000016a00000000", "P2SH"],
#
###############################################################################

import unittest
import json
import os
import io
import binascii

from pycoin.convention import SATOSHI_PER_COIN
from pycoin.intbytes import bytes_from_int, byte_to_int
from pycoin.tx.Tx import Tx, TxIn
from pycoin.tx.Spendable import Spendable
from pycoin.tx.script.opcodes import OPCODE_TO_INT


TX_VALID_JSON = os.path.dirname(__file__) + '/data/tx_valid.json'
TX_INVALID_JSON = os.path.dirname(__file__) + '/data/tx_invalid.json'

FLAGS = ['NONE', 'P2SH', 'STRICTENC', 'DERSIG', 'LOW_S', 'SIGPUSHONLY',
         'MINIMALDATA', 'NULLDUMMY', 'DISCOURAGE_UPGRADABLE_NOPS', 'CLEANSTACK']


MAX_MONEY = 21000000 * SATOSHI_PER_COIN
MAX_BLOCK_SIZE = 1000000


def compile_script(s):
    """Compile the given script. Returns a bytes object with the compiled script.
    (Taken from tx.script.tools with minor changes."""
    f = io.BytesIO()
    for t in s.split():
        if t in OPCODE_TO_INT:
            f.write(bytes_from_int(OPCODE_TO_INT[t]))
        elif ("OP_%s" % t) in OPCODE_TO_INT:
            f.write(bytes_from_int(OPCODE_TO_INT["OP_%s" % t]))
        else:
            if (t[0], t[-1]) == ('[', ']'):
                t = t[1:-1]
            if len(t) == 1:
                t = "0" + t
            if t[:2] == "0x":
                t = t[2:]
            t = binascii.unhexlify(t.encode("utf8"))
            f.write(t)
    return f.getvalue()


def txs_from_json(path):
    """
    Read tests from ./data/tx_??valid.json
    Format is an array of arrays
    Inner arrays are either [ "comment" ]
    or [[[prevout hash, prevout index, prevout scriptPubKey], [input 2], ...], serializedTransaction, verifyFlags]
    ... where all scripts are stringified scripts.

    verifyFlags is a comma separated list of script verification flags to apply, or "NONE"
    """
    with open(path, 'r') as f:
        for tvec in json.load(f):
            if len(tvec) == 1:
                continue
            assert len(tvec) == 3
            prevouts = tvec[0]
            for prevout in prevouts:
                assert len(prevout) == 3

            tx_hex = tvec[1]

            flags = set()
            for flag in tvec[2].split(','):
                assert flag in FLAGS
                flags.add(flag)
            yield (prevouts, tx_hex, flags)


def check_transaction(tx):
    """
    Basic checks that don't depend on any context.
    Adapted from Bicoin Code: main.cpp
    """
    if not tx.txs_in:
        raise ValidationFailureError("tx.txs_in = []")
    if not tx.txs_out:
        raise ValidationFailureError("tx.txs_out = []")
    # Size limits
    f = io.BytesIO()
    tx.stream(f)
    size = len(f.getvalue())
    if size > MAX_BLOCK_SIZE:
        raise ValidationFailureError("size > MAX_BLOCK_SIZE")
    # Check for negative or overflow output values
    nValueOut = 0
    for txout in tx.txs_out:
        if txout.coin_value < 0 or txout.coin_value > MAX_MONEY:
            raise ValidationFailureError("txout value negative or out of range")
        nValueOut += txout.coin_value
        if nValueOut > MAX_MONEY:
            raise ValidationFailureError("txout total out of range")
    # Check for duplicate inputs
    if [x for x in tx.txs_in if tx.txs_in.count(x) > 1]:
        raise ValidationFailureError("duplicate inputs")
    if(tx.is_coinbase()):
        if len(tx.txs_in[0].script) < 2 or len(tx.txs_in[0].script) > 100:
            raise ValidationFailureError("bad coinbase script size")
    else:
        for txin in tx.txs_in:
            if not txin:
                raise ValidationFailureError("prevout is null")
    return True


class TestTx(unittest.TestCase):

    def test_is_valid(self):
        for (prevouts, tx_hex, flags) in txs_from_json(TX_VALID_JSON):
            try:
                tx = Tx.tx_from_hex(tx_hex)
            except:
                self.fail("Cannot parse tx_hex: " + tx_hex)

            if not check_transaction(tx):
                self.fail("check_transaction(tx) = False for valid tx: " +
                          tx_hex)

            unspents = [Spendable(coin_value=1000000,
                                  script=compile_script(prevout[2]),
                                  tx_hash=prevout[0], tx_out_index=prevout[1])
                        for prevout in prevouts]
            tx.set_unspents(unspents)

            bs = tx.bad_signature_count()
            if bs > 0:
                msg = str(tx_hex) + " bad_signature_count() = " + str(bs)
                self.fail(msg)


    def test_is_invalid(self):
        for (prevouts, tx_hex, flags) in txs_from_json(TX_INVALID_JSON):
            try:
                tx = Tx.tx_from_hex(tx_hex)
                if not check_transaction(tx):
                    continue
                unspents = [Spendable(coin_value=1000000,
                                  script=compile_script(prevout[2]),
                                  tx_hash=prevout[0], tx_out_index=prevout[1])
                        for prevout in prevouts]
                tx.set_unspents(unspents)

                bs = tx.bad_signature_count()
                self.assertEqual(bs, 0)
            except:
                continue

            self.fail("Invalid transaction: " + tx.id() +
                      " appears to be valid.")


if __name__ == '__main__':
    unittest.main()
