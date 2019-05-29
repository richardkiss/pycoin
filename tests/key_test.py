import unittest

from pycoin.encoding.hexbytes import h2b
from pycoin.symbols.btc import network


class KeyTest(unittest.TestCase):

    def test_sign_verify(self):
        private_key = network.keys.private(secret_exponent=1)
        h = b"\x16" * 32
        sig = private_key.sign(h)
        self.assertTrue(private_key.verify(h, sig))
        public_key = private_key.public_copy()
        self.assertTrue(public_key.verify(h, sig))

    def test_translation(self):
        def do_test(exp_hex, wif, c_wif, public_pair_sec, c_public_pair_sec, address_b58, c_address_b58):
            secret_exponent = int(exp_hex, 16)
            sec = h2b(public_pair_sec)
            c_sec = h2b(c_public_pair_sec)

            keys_wif = [
                network.keys.private(secret_exponent=secret_exponent),
                network.parse.wif(wif),
                network.parse.wif(c_wif),
            ]

            key_sec = network.keys.public(sec)
            key_sec_c = network.keys.public(c_sec)
            keys_sec = [key_sec, key_sec_c]

            for key in keys_wif:
                self.assertEqual(key.secret_exponent(), secret_exponent)
                self.assertEqual(key.public_copy().secret_exponent(), None)
                repr(key)
                if key.is_compressed():
                    self.assertEqual(key.wif(), c_wif)
                self.assertEqual(key.wif(is_compressed=False), wif)
                self.assertEqual(key.wif(is_compressed=True), c_wif)

            for key in keys_wif + keys_sec:
                if key.is_compressed():
                    self.assertEqual(key.sec(), c_sec)
                self.assertEqual(key.sec(is_compressed=False), sec)
                self.assertEqual(key.sec(is_compressed=True), c_sec)
                if key.is_compressed():
                    self.assertEqual(key.address(), c_address_b58)
                else:
                    self.assertEqual(key.address(), address_b58)
                self.assertEqual(key.address(is_compressed=True), c_address_b58)
                self.assertEqual(key.address(is_compressed=False), address_b58)

            key_pub = network.parse.address(address_b58)

            self.assertEqual(key_pub.address(), address_b58)

        do_test("1111111111111111111111111111111111111111111111111111111111111111",
                "5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC1115WWsh",
                "KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp",
                "044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
                "385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1",
                "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                "1MsHWS1BnwMc3tLE8G35UXsS58fKipzB7a",
                "1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9")

        do_test("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "5KVzsHJiUxgvBBgtVS7qBTbbYZpwWM4WQNCCyNSiuFCJzYMxg8H",
                "L4ezQvyC6QoBhxB4GVs9fAPhUKtbaXYUn8YTqoeXwbevQq4U92vN",
                "04ed83704c95d829046f1ac27806211132102c34e9ac7ffa1b71110658e5b9d1bd"
                "edc416f5cefc1db0625cd0c75de8192d2b592d7e3b00bcfb4a0e860d880fd1fc",
                "02ed83704c95d829046f1ac27806211132102c34e9ac7ffa1b71110658e5b9d1bd",
                "1JyMKvPHkrCQd8jQrqTR1rBsAd1VpRhTiE",
                "1NKRhS7iYUGTaAfaR5z8BueAJesqaTyc4a")

        do_test("47f7616ea6f9b923076625b4488115de1ef1187f760e65f89eb6f4f7ff04b012",
                "5JMys7YfK72cRVTrbwkq5paxU7vgkMypB55KyXEtN5uSnjV7K8Y",
                "KydbzBtk6uc7M6dXwEgTEH2sphZxSPbmDSz6kUUHi4eUpSQuhEbq",
                "042596957532fc37e40486b910802ff45eeaa924548c0e1c080ef804e523ec3ed3"
                "ed0a9004acf927666eee18b7f5e8ad72ff100a3bb710a577256fd7ec81eb1cb3",
                "032596957532fc37e40486b910802ff45eeaa924548c0e1c080ef804e523ec3ed3",
                "1PM35qz2uwCDzcUJtiqDSudAaaLrWRw41L",
                "19ck9VKC6KjGxR9LJg4DNMRc45qFrJguvV")

        # in this case, the public_pair y value is less than 256**31, and so has a leading 00 byte.
        # This triggers a bug in the Python 2.7 version of to_bytes_32.
        do_test("ae2aaef5080b6e1704aab382a40a7c9957a40b4790f7df7faa04b14f4db56361",
                "5K8zSJ4zcV3UfkAKCFY5PomL6SRx2pYjaKfnAtMVh6zbhnAuPon",
                "L34GWeLdHcmw81W7JfAAPfQfH1F7u2s4v5QANdfTe1TEAYpjXoLL",
                "04f650fb572d1475950b63f5175c77e8b5ed9035a209d8fb5af5a04d6bc39b7323"
                "00186733fcfe3def4ace6feae8b82dd03cc31b7855307d33b0a039170f374962",
                "02f650fb572d1475950b63f5175c77e8b5ed9035a209d8fb5af5a04d6bc39b7323",
                "18fKPR8s1MQeckAsgya1sx6Z3WmFXd8wv8",
                "1DVJQzgnyCahXdoXdJ3tjGA3hrYVgKpvgK")


if __name__ == '__main__':
    unittest.main()
