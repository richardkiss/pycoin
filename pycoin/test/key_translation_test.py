#!/usr/bin/env python

import unittest

from pycoin.ecdsa import public_pair_for_secret_exponent, generator_secp256k1

from pycoin.encoding import bitcoin_address_to_hash160_sec, is_sec_compressed, public_pair_to_sec, secret_exponent_to_wif, public_pair_to_bitcoin_address, wif_to_tuple_of_secret_exponent_compressed, sec_to_public_pair, public_pair_to_hash160_sec
from pycoin.serialize import h2b

"""
http://sourceforge.net/mailarchive/forum.php?thread_name=CAPg%2BsBhDFCjAn1tRRQhaudtqwsh4vcVbxzm%2BAA2OuFxN71fwUA%40mail.gmail.com&forum_name=bitcoin-development
"""

class BuildTxTest(unittest.TestCase):

    def test_translation(self):
        def do_test(exp_hex, wif, c_wif, public_pair_sec, c_public_pair_sec, address_b58, c_address_b58):
            secret_exponent = int(exp_hex, 16)
            sec = h2b(public_pair_sec)
            c_sec = h2b(c_public_pair_sec)

            self.assertEqual(secret_exponent_to_wif(secret_exponent, compressed=False), wif)
            self.assertEqual(secret_exponent_to_wif(secret_exponent, compressed=True), c_wif)

            exponent, compressed = wif_to_tuple_of_secret_exponent_compressed(wif)
            self.assertEqual(exponent, secret_exponent)
            self.assertFalse(compressed)

            exponent, compressed = wif_to_tuple_of_secret_exponent_compressed(c_wif)
            self.assertEqual(exponent, secret_exponent)
            self.assertTrue(compressed)

            public_pair = public_pair_for_secret_exponent(generator_secp256k1, secret_exponent)

            pk_public_pair = sec_to_public_pair(sec)
            compressed = is_sec_compressed(sec)
            self.assertEqual(pk_public_pair, public_pair)
            self.assertFalse(is_sec_compressed(sec))
            self.assertEqual(public_pair_to_sec(pk_public_pair, compressed=False), sec)

            pk_public_pair = sec_to_public_pair(c_sec)
            compressed = is_sec_compressed(c_sec)
            self.assertEqual(pk_public_pair, public_pair)
            self.assertTrue(compressed)
            self.assertEqual(public_pair_to_sec(pk_public_pair, compressed=True), c_sec)

            bca = public_pair_to_bitcoin_address(pk_public_pair, compressed=True)
            self.assertEqual(bca, c_address_b58)

            self.assertEqual(bitcoin_address_to_hash160_sec(c_address_b58), public_pair_to_hash160_sec(pk_public_pair, compressed=True))

            bca = public_pair_to_bitcoin_address(pk_public_pair, compressed=False)
            self.assertEqual(bca, address_b58)

            self.assertEqual(bitcoin_address_to_hash160_sec(address_b58), public_pair_to_hash160_sec(pk_public_pair, compressed=False))


        do_test("1111111111111111111111111111111111111111111111111111111111111111",
                 "5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC1115WWsh",
                 "KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp",
                 "044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"\
                   "385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1",
                 "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                 "1MsHWS1BnwMc3tLE8G35UXsS58fKipzB7a",
                 "1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9")

        do_test("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "5KVzsHJiUxgvBBgtVS7qBTbbYZpwWM4WQNCCyNSiuFCJzYMxg8H",
                    "L4ezQvyC6QoBhxB4GVs9fAPhUKtbaXYUn8YTqoeXwbevQq4U92vN",
                    "04ed83704c95d829046f1ac27806211132102c34e9ac7ffa1b71110658e5b9d1bd"\
                      "edc416f5cefc1db0625cd0c75de8192d2b592d7e3b00bcfb4a0e860d880fd1fc",
                    "02ed83704c95d829046f1ac27806211132102c34e9ac7ffa1b71110658e5b9d1bd",
                    "1JyMKvPHkrCQd8jQrqTR1rBsAd1VpRhTiE",
                    "1NKRhS7iYUGTaAfaR5z8BueAJesqaTyc4a")

        do_test("47f7616ea6f9b923076625b4488115de1ef1187f760e65f89eb6f4f7ff04b012",
                "5JMys7YfK72cRVTrbwkq5paxU7vgkMypB55KyXEtN5uSnjV7K8Y",
                "KydbzBtk6uc7M6dXwEgTEH2sphZxSPbmDSz6kUUHi4eUpSQuhEbq",
                "042596957532fc37e40486b910802ff45eeaa924548c0e1c080ef804e523ec3ed3"\
                  "ed0a9004acf927666eee18b7f5e8ad72ff100a3bb710a577256fd7ec81eb1cb3",
                "032596957532fc37e40486b910802ff45eeaa924548c0e1c080ef804e523ec3ed3",
                "1PM35qz2uwCDzcUJtiqDSudAaaLrWRw41L",
                "19ck9VKC6KjGxR9LJg4DNMRc45qFrJguvV")

        # in this case, the public_pair y value is less than 256**31, and so has a leading 00 byte.
        # This triggers a bug in the Python 2.7 version of to_bytes_32.
        do_test("ae2aaef5080b6e1704aab382a40a7c9957a40b4790f7df7faa04b14f4db56361",
                "5K8zSJ4zcV3UfkAKCFY5PomL6SRx2pYjaKfnAtMVh6zbhnAuPon",
                "L34GWeLdHcmw81W7JfAAPfQfH1F7u2s4v5QANdfTe1TEAYpjXoLL",
                "04f650fb572d1475950b63f5175c77e8b5ed9035a209d8fb5af5a04d6bc39b7323"\
                  "00186733fcfe3def4ace6feae8b82dd03cc31b7855307d33b0a039170f374962",
                "02f650fb572d1475950b63f5175c77e8b5ed9035a209d8fb5af5a04d6bc39b7323",
                "18fKPR8s1MQeckAsgya1sx6Z3WmFXd8wv8",
                "1DVJQzgnyCahXdoXdJ3tjGA3hrYVgKpvgK")

if __name__ == '__main__':
    unittest.main()

