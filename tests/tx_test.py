#!/usr/bin/env python

import unittest

from pycoin.serialize import b2h
from pycoin.tx.Tx import Tx

TX_E1A18B843FC420734DEEB68FF6DF041A2585E1A0D7DBF3B82AAB98291A6D9952_HEX = ("0100000001a8f57056b016d7d243fc0fc2a73f9146e7e4c7766ec6033b5ac4cb89c"
"64e19d0000000008a4730440220251acb534ba1b8a269260ad3fa80e075cd150d3ff"
"ba76ad20cd2e8178dee98b702202284f9c7eae3adfcf0857a901cd34f0ea338d5744caab88afad5797be643f7b7"
"014104af8385da9dc85aa153f16341a4015bc95e7ff57876b9bde40bd8450a5723a05c1c89ff2d85230d2e62c0c"
"7690b8272cf85868a0a0fc02f99a5b793f22d5c7092ffffffff02bb5b0700000000001976a9145b78716d137e38"
"6ae2befc4296d938372559f37888acdd3c71000000000017a914c6572ee1c85a1b9ce1921753871bda0b5ce889ac8700000000")

class TxTest(unittest.TestCase):

    def test_tx_api(self):
        tx = Tx.tx_from_hex(TX_E1A18B843FC420734DEEB68FF6DF041A2585E1A0D7DBF3B82AAB98291A6D9952_HEX)
        # this transaction is a pay-to-hash transaction
        self.assertEqual(tx.id(), "e1a18b843fc420734deeb68ff6df041a2585e1a0d7dbf3b82aab98291a6d9952")
        self.assertEqual(tx.txs_out[0].bitcoin_address(), "19LemzJ3XPdUxp113uynqCAivDbXZBdBy3")
        self.assertEqual(tx.txs_out[1].bitcoin_address(), "3KmkA7hvqG2wKkWUGz1BySioUywvcmdPLR")

    def test_blanked_hash(self):
        tx = Tx.tx_from_hex(TX_E1A18B843FC420734DEEB68FF6DF041A2585E1A0D7DBF3B82AAB98291A6D9952_HEX)
        self.assertEqual(tx.id(), "e1a18b843fc420734deeb68ff6df041a2585e1a0d7dbf3b82aab98291a6d9952")
        self.assertEqual(b2h(tx.blanked_hash()), "909579526c4c2c441687c7478d3f96249724d2ff071d2272b44500d6cf70d5d6")
        tx.txs_in[0].script = b"foo"
        self.assertEqual(b2h(tx.blanked_hash()), "909579526c4c2c441687c7478d3f96249724d2ff071d2272b44500d6cf70d5d6")
        tx.txs_out[0].coin_value += 1
        self.assertEqual(b2h(tx.blanked_hash()), "10d4e87f7bf35f2949e7693e7a4a84189aad8631f0b2b0999e88f7261066cbe5")
        tx.txs_in[0].script = b"bar"
        self.assertEqual(b2h(tx.blanked_hash()), "10d4e87f7bf35f2949e7693e7a4a84189aad8631f0b2b0999e88f7261066cbe5")
        tx.txs_in[0].script = b""
        self.assertEqual(b2h(tx.hash()), "10d4e87f7bf35f2949e7693e7a4a84189aad8631f0b2b0999e88f7261066cbe5")
        tx.txs_in[0].script = b"foo"
        self.assertEqual(b2h(tx.hash()), "c91910058722f1c0f52fc5c734939053c9b87882a9c72b609f21632e0bd13751")

if __name__ == "__main__":
    unittest.main()
