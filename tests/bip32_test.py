#!/usr/bin/env python

import unittest

from pycoin.key import bip32
from pycoin.serialize import h2b

from pycoin.key.BIP32Node import BIP32Node

def Wallet(*args, **kwargs):
    return BIP32Node(*args, **kwargs)
Wallet.from_master_secret = lambda *args, **kwargs: BIP32Node.from_master_secret(*args, **kwargs)
Wallet.from_wallet_key = lambda *args, **kwargs: BIP32Node.from_wallet_key(*args, **kwargs)
bip32.Wallet = Wallet

class Bip0032TestCase(unittest.TestCase):

    def test_vector_1(self):
        master = bip32.Wallet.from_master_secret(h2b("000102030405060708090a0b0c0d0e0f"))
        self.assertEqual(master.wallet_key(as_private=True), "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
        self.assertEqual(master.bitcoin_address(), "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma")
        self.assertEqual(master.wif(), "L52XzL2cMkHxqxBXRyEpnPQZGUs3uKiL3R11XbAdHigRzDozKZeW")

        self.assertEqual(master.wallet_key(), "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")

        m0p = master.subkey(is_hardened=True)
        self.assertEqual(m0p.wallet_key(), "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")
        self.assertEqual(m0p.wallet_key(as_private=True), "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
        self.assertEqual(master.subkey_for_path("0p").wallet_key(), m0p.wallet_key())

        pub_mp0 = master.subkey(is_hardened=True, as_private=False)
        self.assertEqual(pub_mp0.wallet_key(), m0p.wallet_key())
        self.assertEqual(master.subkey_for_path("0p.pub").wallet_key(), pub_mp0.wallet_key())

        m0p1 = m0p.subkey(i=1)
        self.assertEqual(m0p1.wallet_key(), "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")
        self.assertEqual(m0p1.wallet_key(as_private=True), "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs")
        self.assertEqual(master.subkey_for_path("0p/1").wallet_key(), m0p1.wallet_key())

        pub_m0p1 = m0p.subkey(i=1, as_private=False)
        self.assertEqual(pub_m0p1.wallet_key(), m0p1.wallet_key())
        self.assertEqual(master.subkey_for_path("0p/1.pub").wallet_key(), pub_m0p1.wallet_key())

        m0p1_1_2p = m0p1.subkey(i=2, is_hardened=True)
        self.assertEqual(m0p1_1_2p.wallet_key(), "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5")
        self.assertEqual(m0p1_1_2p.wallet_key(as_private=True), "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM")
        self.assertEqual(master.subkey_for_path("0p/1/2p").wallet_key(), m0p1_1_2p.wallet_key())

        pub_m0p1_1_2p = m0p1.subkey(i=2, as_private=False, is_hardened=True)
        self.assertEqual(pub_m0p1_1_2p.wallet_key(), m0p1_1_2p.wallet_key())
        self.assertEqual(master.subkey_for_path("0p/1/2p.pub").wallet_key(), pub_m0p1_1_2p.wallet_key())

        m0p1_1_2p_2 = m0p1_1_2p.subkey(i=2)
        self.assertEqual(m0p1_1_2p_2.wallet_key(), "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV")
        self.assertEqual(m0p1_1_2p_2.wallet_key(as_private=True), "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334")
        self.assertEqual(master.subkey_for_path("0p/1/2p/2").wallet_key(), m0p1_1_2p_2.wallet_key())

        pub_m0p1_1_2p_2 = m0p1_1_2p.subkey(i=2, as_private=False)
        self.assertEqual(pub_m0p1_1_2p_2.wallet_key(), m0p1_1_2p_2.wallet_key())
        self.assertEqual(master.subkey_for_path("0p/1/2p/2.pub").wallet_key(), pub_m0p1_1_2p_2.wallet_key())

        m0p1_1_2p_2_1000000000 = m0p1_1_2p_2.subkey(i=1000000000)
        self.assertEqual(m0p1_1_2p_2_1000000000.wallet_key(), "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")
        self.assertEqual(m0p1_1_2p_2_1000000000.wallet_key(as_private=True), "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76")
        self.assertEqual(master.subkey_for_path("0p/1/2p/2/1000000000").wallet_key(), m0p1_1_2p_2_1000000000.wallet_key())

        pub_m0p1_1_2p_2_1000000000 = m0p1_1_2p_2.subkey(i=1000000000, as_private=False)
        self.assertEqual(pub_m0p1_1_2p_2_1000000000.wallet_key(), m0p1_1_2p_2_1000000000.wallet_key())
        self.assertEqual(master.subkey_for_path("0p/1/2p/2/1000000000.pub").wallet_key(), pub_m0p1_1_2p_2_1000000000.wallet_key())


    def test_vector_2(self):
        master = bip32.Wallet.from_master_secret(h2b("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))
        self.assertEqual(master.wallet_key(as_private=True), "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U")

        self.assertEqual(master.wallet_key(), "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB")

        m0 = master.subkey()
        self.assertEqual(m0.wallet_key(), "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH")
        self.assertEqual(m0.wallet_key(as_private=True), "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt")
        pub_m0 = master.subkey(as_private=False)
        self.assertEqual(pub_m0.wallet_key(), m0.wallet_key())

        m0_2147483647p = m0.subkey(i=2147483647, is_hardened=True)
        self.assertEqual(m0_2147483647p.wallet_key(), "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a")
        self.assertEqual(m0_2147483647p.wallet_key(as_private=True), "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9")
        pub_m0_2147483647p = m0.subkey(i=2147483647, is_hardened=True, as_private=False)
        self.assertEqual(pub_m0_2147483647p.wallet_key(), m0_2147483647p.wallet_key())

        m0_2147483647p_1 = m0_2147483647p.subkey(i=1)
        self.assertEqual(m0_2147483647p_1.wallet_key(), "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon")
        self.assertEqual(m0_2147483647p_1.wallet_key(as_private=True), "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef")
        pub_m0_2147483647p_1 = m0_2147483647p.subkey(i=1, as_private=False)
        self.assertEqual(pub_m0_2147483647p_1.wallet_key(), m0_2147483647p_1.wallet_key())
        pub_m0_2147483647p_1 = pub_m0_2147483647p.subkey(i=1, as_private=False)
        self.assertEqual(pub_m0_2147483647p_1.wallet_key(), m0_2147483647p_1.wallet_key())

        m0_2147483647p_1_2147483646p = m0_2147483647p_1.subkey(i=2147483646, is_hardened=True)
        self.assertEqual(m0_2147483647p_1_2147483646p.wallet_key(), "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL")
        self.assertEqual(m0_2147483647p_1_2147483646p.wallet_key(as_private=True), "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc")
        pub_m0_2147483647p_1_2147483646p = m0_2147483647p_1.subkey(i=2147483646, as_private=False, is_hardened=True)
        self.assertEqual(pub_m0_2147483647p_1_2147483646p.wallet_key(), m0_2147483647p_1_2147483646p.wallet_key())

        m0_2147483647p_1_2147483646p_2 = m0_2147483647p_1_2147483646p.subkey(i=2)
        self.assertEqual(m0_2147483647p_1_2147483646p_2.wif(), "L3WAYNAZPxx1fr7KCz7GN9nD5qMBnNiqEJNJMU1z9MMaannAt4aK")
        self.assertEqual(m0_2147483647p_1_2147483646p_2.wallet_key(), "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt")
        self.assertEqual(m0_2147483647p_1_2147483646p_2.wallet_key(as_private=True), "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j")
        pub_m0_2147483647p_1_2147483646p_2 = m0_2147483647p_1_2147483646p.subkey(i=2, as_private=False)
        self.assertEqual(pub_m0_2147483647p_1_2147483646p_2.wallet_key(), m0_2147483647p_1_2147483646p_2.wallet_key())
        pub_m0_2147483647p_1_2147483646p_2 = pub_m0_2147483647p_1_2147483646p.subkey(i=2, as_private=False)
        self.assertEqual(pub_m0_2147483647p_1_2147483646p_2.wallet_key(), m0_2147483647p_1_2147483646p_2.wallet_key())
        self.assertEqual(master.subkey_for_path("0/2147483647p/1/2147483646p/2").wallet_key(), m0_2147483647p_1_2147483646p_2.wallet_key())
        self.assertEqual(master.subkey_for_path("0/2147483647p/1/2147483646p/2.pub").wallet_key(), pub_m0_2147483647p_1_2147483646p_2.wallet_key())

    def test_testnet(self):
        # WARNING: these values have not been verified independently. TODO: do so
        master = bip32.Wallet.from_master_secret(h2b("000102030405060708090a0b0c0d0e0f"), netcode='XTN')
        self.assertEqual(master.wallet_key(as_private=True), "tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m")
        self.assertEqual(master.bitcoin_address(), "mkHGce7dctSxHgaWSSbmmrRWsZfzz7MxMk")
        self.assertEqual(master.wif(), "cVPXTF2TnozE1PenpP3x9huctiATZmp27T9Ue1d8nqLSExoPwfN5")

    def test_streams(self):
        m0 = bip32.Wallet.from_master_secret("foo bar baz".encode("utf8"))
        pm0 = m0.public_copy()
        self.assertEqual(m0.wallet_key(), pm0.wallet_key())
        m1 = m0.subkey()
        pm1 = pm0.subkey()
        for i in range(4):
            m = m1.subkey(i=i)
            pm = pm1.subkey(i=i)
            self.assertEqual(m.wallet_key(), pm.wallet_key())
            self.assertEqual(m.bitcoin_address(), pm.bitcoin_address())
            m2 = bip32.Wallet.from_wallet_key(m.wallet_key(as_private=True))
            m3 = m2.public_copy()
            self.assertEqual(m.wallet_key(as_private=True), m2.wallet_key(as_private=True))
            self.assertEqual(m.wallet_key(), m3.wallet_key())
            print(m.wallet_key(as_private=True))
            for j in range(2):
                k = m.subkey(i=j)
                k2 = bip32.Wallet.from_wallet_key(k.wallet_key(as_private=True))
                k3 = bip32.Wallet.from_wallet_key(k.wallet_key())
                k4 = k.public_copy()
                self.assertEqual(k.wallet_key(as_private=True), k2.wallet_key(as_private=True))
                self.assertEqual(k.wallet_key(), k2.wallet_key())
                self.assertEqual(k.wallet_key(), k3.wallet_key())
                self.assertEqual(k.wallet_key(), k4.wallet_key())
                print("   %s %s" % (k.bitcoin_address(), k.wif()))

    def test_public_subkey(self):
        my_prv = BIP32Node.from_master_secret(b"foo")
        uag = my_prv.subkey(i=0, is_hardened=True, as_private=True)
        self.assertEqual(None, uag.subkey(i=0, as_private=False).secret_exponent())

if __name__ == '__main__':
    unittest.main()

