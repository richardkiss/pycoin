import unittest

from pycoin.encoding.hexbytes import h2b
from pycoin.symbols.btc import network as BTC
from pycoin.symbols.xtn import network as XTN


class Bip0032TestCase(unittest.TestCase):
    def test_vector_1(self):
        master = BTC.keys.bip32_seed(h2b("000102030405060708090a0b0c0d0e0f"))
        self.assertEqual(
            master.hwif(as_private=True),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPG"
            "JxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
        )
        self.assertEqual(master.address(), "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma")
        self.assertEqual(
            master.wif(), "L52XzL2cMkHxqxBXRyEpnPQZGUs3uKiL3R11XbAdHigRzDozKZeW"
        )

        self.assertEqual(
            master.hwif(),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJo"
            "Cu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        )

        m0p = master.subkey(is_hardened=True)
        self.assertEqual(
            m0p.hwif(),
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1"
            "VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
        )
        self.assertEqual(
            m0p.hwif(as_private=True),
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6K"
            "CesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
        )
        self.assertEqual(master.subkey_for_path("0p").hwif(), m0p.hwif())

        pub_mp0 = master.subkey(is_hardened=True, as_private=False)
        self.assertEqual(pub_mp0.hwif(), m0p.hwif())
        self.assertEqual(master.subkey_for_path("0p.pub").hwif(), pub_mp0.hwif())

        m0p1 = m0p.subkey(i=1)
        self.assertEqual(
            m0p1.hwif(),
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj"
            "7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
        )
        self.assertEqual(
            m0p1.hwif(as_private=True),
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYP"
            "xLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
        )
        self.assertEqual(master.subkey_for_path("0p/1").hwif(), m0p1.hwif())

        pub_m0p1 = m0p.subkey(i=1, as_private=False)
        self.assertEqual(pub_m0p1.hwif(), m0p1.hwif())
        self.assertEqual(master.subkey_for_path("0p/1.pub").hwif(), pub_m0p1.hwif())

        m0p1_1_2p = m0p1.subkey(i=2, is_hardened=True)
        self.assertEqual(
            m0p1_1_2p.hwif(),
            "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dF"
            "DFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
        )
        self.assertEqual(
            m0p1_1_2p.hwif(as_private=True),
            "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3r"
            "yjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
        )
        self.assertEqual(master.subkey_for_path("0p/1/2p").hwif(), m0p1_1_2p.hwif())

        pub_m0p1_1_2p = m0p1.subkey(i=2, as_private=False, is_hardened=True)
        self.assertEqual(pub_m0p1_1_2p.hwif(), m0p1_1_2p.hwif())
        self.assertEqual(
            master.subkey_for_path("0p/1/2p.pub").hwif(), pub_m0p1_1_2p.hwif()
        )

        m0p1_1_2p_2 = m0p1_1_2p.subkey(i=2)
        self.assertEqual(
            m0p1_1_2p_2.hwif(),
            "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6Z"
            "LRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
        )
        self.assertEqual(
            m0p1_1_2p_2.hwif(as_private=True),
            "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f"
            "7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
        )
        self.assertEqual(master.subkey_for_path("0p/1/2p/2").hwif(), m0p1_1_2p_2.hwif())

        pub_m0p1_1_2p_2 = m0p1_1_2p.subkey(i=2, as_private=False)
        self.assertEqual(pub_m0p1_1_2p_2.hwif(), m0p1_1_2p_2.hwif())
        self.assertEqual(
            master.subkey_for_path("0p/1/2p/2.pub").hwif(), pub_m0p1_1_2p_2.hwif()
        )

        m0p1_1_2p_2_1000000000 = m0p1_1_2p_2.subkey(i=1000000000)
        self.assertEqual(
            m0p1_1_2p_2_1000000000.hwif(),
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaF"
            "cxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
        )
        self.assertEqual(
            m0p1_1_2p_2_1000000000.hwif(as_private=True),
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4"
            "WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
        )
        self.assertEqual(
            master.subkey_for_path("0p/1/2p/2/1000000000").hwif(),
            m0p1_1_2p_2_1000000000.hwif(),
        )

        pub_m0p1_1_2p_2_1000000000 = m0p1_1_2p_2.subkey(i=1000000000, as_private=False)
        self.assertEqual(
            pub_m0p1_1_2p_2_1000000000.hwif(), m0p1_1_2p_2_1000000000.hwif()
        )
        self.assertEqual(
            master.subkey_for_path("0p/1/2p/2/1000000000.pub").hwif(),
            pub_m0p1_1_2p_2_1000000000.hwif(),
        )

    def test_vector_2(self):
        master = BTC.keys.bip32_seed(
            h2b(
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c99"
                "9693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
            )
        )
        self.assertEqual(
            master.hwif(as_private=True),
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK"
            "4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
        )

        self.assertEqual(
            master.hwif(),
            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDM"
            "Sgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
        )

        m0 = master.subkey()
        self.assertEqual(
            m0.hwif(),
            "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERf"
            "vrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
        )
        self.assertEqual(
            m0.hwif(as_private=True),
            "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2y"
            "JD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
        )
        pub_m0 = master.subkey(as_private=False)
        self.assertEqual(pub_m0.hwif(), m0.hwif())

        m0_2147483647p = m0.subkey(i=2147483647, is_hardened=True)
        self.assertEqual(
            m0_2147483647p.hwif(),
            "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDB"
            "rQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
        )
        self.assertEqual(
            m0_2147483647p.hwif(as_private=True),
            "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwC"
            "d6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
        )
        pub_m0_2147483647p = m0.subkey(i=2147483647, is_hardened=True, as_private=False)
        self.assertEqual(pub_m0_2147483647p.hwif(), m0_2147483647p.hwif())

        m0_2147483647p_1 = m0_2147483647p.subkey(i=1)
        self.assertEqual(
            m0_2147483647p_1.hwif(),
            "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoN"
            "JxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
        )
        self.assertEqual(
            m0_2147483647p_1.hwif(as_private=True),
            "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9"
            "yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
        )
        pub_m0_2147483647p_1 = m0_2147483647p.subkey(i=1, as_private=False)
        self.assertEqual(pub_m0_2147483647p_1.hwif(), m0_2147483647p_1.hwif())
        pub_m0_2147483647p_1 = pub_m0_2147483647p.subkey(i=1, as_private=False)
        self.assertEqual(pub_m0_2147483647p_1.hwif(), m0_2147483647p_1.hwif())

        m0_2147483647p_1_2147483646p = m0_2147483647p_1.subkey(
            i=2147483646, is_hardened=True
        )
        self.assertEqual(
            m0_2147483647p_1_2147483646p.hwif(),
            "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4ko"
            "xb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
        )
        self.assertEqual(
            m0_2147483647p_1_2147483646p.hwif(as_private=True),
            "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39nj"
            "GVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
        )
        pub_m0_2147483647p_1_2147483646p = m0_2147483647p_1.subkey(
            i=2147483646, as_private=False, is_hardened=True
        )
        self.assertEqual(
            pub_m0_2147483647p_1_2147483646p.hwif(), m0_2147483647p_1_2147483646p.hwif()
        )

        m0_2147483647p_1_2147483646p_2 = m0_2147483647p_1_2147483646p.subkey(i=2)
        self.assertEqual(
            m0_2147483647p_1_2147483646p_2.wif(),
            "L3WAYNAZPxx1fr7KCz7GN9nD5qMBnNiqEJNJMU1z9MMaannAt4aK",
        )
        self.assertEqual(
            m0_2147483647p_1_2147483646p_2.hwif(),
            "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGs"
            "ApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
        )
        self.assertEqual(
            m0_2147483647p_1_2147483646p_2.hwif(as_private=True),
            "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq3"
            "8EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
        )
        pub_m0_2147483647p_1_2147483646p_2 = m0_2147483647p_1_2147483646p.subkey(
            i=2, as_private=False
        )
        self.assertEqual(
            pub_m0_2147483647p_1_2147483646p_2.hwif(),
            m0_2147483647p_1_2147483646p_2.hwif(),
        )
        pub_m0_2147483647p_1_2147483646p_2 = pub_m0_2147483647p_1_2147483646p.subkey(
            i=2, as_private=False
        )
        self.assertEqual(
            pub_m0_2147483647p_1_2147483646p_2.hwif(),
            m0_2147483647p_1_2147483646p_2.hwif(),
        )
        self.assertEqual(
            master.subkey_for_path("0/2147483647p/1/2147483646p/2").hwif(),
            m0_2147483647p_1_2147483646p_2.hwif(),
        )
        self.assertEqual(
            master.subkey_for_path("0/2147483647p/1/2147483646p/2.pub").hwif(),
            pub_m0_2147483647p_1_2147483646p_2.hwif(),
        )

    def test_testnet(self):
        # WARNING: these values have not been verified independently. TODO: do so
        master = XTN.keys.bip32_seed(h2b("000102030405060708090a0b0c0d0e0f"))
        self.assertEqual(
            master.hwif(as_private=True),
            "tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5kh"
            "qjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m",
        )
        self.assertEqual(master.address(), "mkHGce7dctSxHgaWSSbmmrRWsZfzz7MxMk")
        self.assertEqual(
            master.wif(), "cVPXTF2TnozE1PenpP3x9huctiATZmp27T9Ue1d8nqLSExoPwfN5"
        )

    def test_streams(self):
        m0 = BTC.keys.bip32_seed(b"foo bar baz")
        pm0 = m0.public_copy()
        self.assertEqual(m0.hwif(), pm0.hwif())
        m1 = m0.subkey()
        pm1 = pm0.subkey()
        for i in range(4):
            m = m1.subkey(i=i)
            pm = pm1.subkey(i=i)
            self.assertEqual(m.hwif(), pm.hwif())
            self.assertEqual(m.address(), pm.address())
            m2 = BTC.parse.secret(m.hwif(as_private=True))
            m3 = m2.public_copy()
            self.assertEqual(m.hwif(as_private=True), m2.hwif(as_private=True))
            self.assertEqual(m.hwif(), m3.hwif())
            print(m.hwif(as_private=True))
            for j in range(2):
                k = m.subkey(i=j)
                k2 = BTC.parse.secret(k.hwif(as_private=True))
                k3 = BTC.parse.secret(k.hwif())
                k4 = k.public_copy()
                self.assertEqual(k.hwif(as_private=True), k2.hwif(as_private=True))
                self.assertEqual(k.hwif(), k2.hwif())
                self.assertEqual(k.hwif(), k3.hwif())
                self.assertEqual(k.hwif(), k4.hwif())
                print("   %s %s" % (k.address(), k.wif()))

    def test_public_subkey(self):
        my_prv = BTC.keys.bip32_seed(b"foo")
        uag = my_prv.subkey(i=0, is_hardened=True, as_private=True)
        self.assertEqual(None, uag.subkey(i=0, as_private=False).secret_exponent())

        with self.assertRaises(ValueError) as cm:
            my_prv.subkey(i=-1)

        err = cm.exception
        self.assertEqual(err.args, ("i can't be negative",))

        for p in ("-1", "0/-1", "0H/-1"):
            with self.assertRaises(ValueError) as cm:
                my_prv.subkey_for_path(p)

            err = cm.exception
            self.assertEqual(err.args, ("i can't be negative",))

        self.assertRaises(ValueError, list, my_prv.subkeys("-1"))
        self.assertRaises(ValueError, list, my_prv.subkeys("-1-0"))

    def test_repr(self):
        key = XTN.keys.private(secret_exponent=273)
        wallet = XTN.keys.bip32_seed(bytes(key.wif().encode("utf8")))

        address = wallet.address()
        pub_k = XTN.parse.address(address)
        self.assertEqual(repr(pub_k), "<myb5gZNXePNf2E2ksrjnHRFCwyuvt7oEay>")

        wif = wallet.wif()
        priv_k = XTN.parse.secret(wif)
        self.assertEqual(
            repr(priv_k),
            "private_for <XTNSEC:03ad094b1dc9fdce5d3648ca359b4e210a89d049532fdd39d9ccdd8ca393ac82f4>",
        )

    # BIP32 test vector 5: every one of these must be rejected.
    # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    INVALID_KEYS = [
        (
            "pubkey version / prvkey mismatch",
            "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D"
            "2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",
        ),
        (
            "prvkey version / pubkey mismatch",
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4"
            "H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH",
        ),
        (
            "invalid pubkey prefix 04",
            "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSu"
            "jt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",
        ),
        (
            "invalid prvkey prefix 04",
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83B"
            "HtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ",
        ),
        (
            "invalid pubkey prefix 01",
            "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctd"
            "iCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4",
        ),
        (
            "invalid prvkey prefix 01",
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2Uu"
            "GCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J",
        ),
        (
            "zero depth with non-zero parent fingerprint (prv)",
            "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4"
            "ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv",
        ),
        (
            "zero depth with non-zero parent fingerprint (pub)",
            "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGEN"
            "hYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ",
        ),
        (
            "zero depth with non-zero index (prv)",
            "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9N"
            "mZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN",
        ),
        (
            "zero depth with non-zero index (pub)",
            "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7g"
            "ucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8",
        ),
        (
            "unknown extended key version (1)",
            "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayA"
            "mfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
        ),
        (
            "unknown extended key version (2)",
            "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXk"
            "TiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
        ),
        (
            "private key 0 not in 1..n-1",
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdU"
            "ayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx",
        ),
        (
            "private key n not in 1..n-1",
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2Uu"
            "GCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G",
        ),
        (
            "invalid pubkey 0200000000000000000000000000000000000000000000000000000000000007",
            "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4"
            "PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY",
        ),
        (
            "invalid checksum",
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPG"
            "JxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL",
        ),
    ]

    @staticmethod
    def _rejected(parse, hwif):
        """pycoin rejects a bad key either by returning None or by raising."""
        try:
            return parse(hwif) is None
        except ValueError:
            return True

    def test_vector_5_invalid_keys(self):
        """Every BIP32 test vector 5 key must be rejected, not parsed."""
        for description, hwif in self.INVALID_KEYS:
            for name in ("bip32_prv", "bip32_pub"):
                self.assertTrue(
                    self._rejected(getattr(BTC.parse, name), hwif),
                    "%s: accepted by parse.%s" % (description, name),
                )
            self.assertTrue(
                self._rejected(BTC.parse, hwif),
                "%s: accepted by parse()" % description,
            )

    def test_bip32_fuzzer_findings(self):
        """Malformed keys found by differential fuzzing against Bitcoin Core."""
        # zero depth with a non-zero child index
        self.assertTrue(
            self._rejected(
                BTC.parse.bip32_prv,
                "xprv9s21ZrQMAtJo7CW4HK4GvxFgsNRcoEyP4PE8oGjs6TLWzwgo1mfNKbhsgo6UbDM"
                "DeopTS2uLBTAaTNfpgAhSeExw76dVnqbH7qjTjQzY2R8",
            )
        )
        # public version prefix carrying private key data
        self.assertTrue(
            self._rejected(
                XTN.parse.bip32_pub,
                "tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLNGbhd2"
                "pq7ZtDiPYTfJ7iBenLjh2unfjahXkTz5HcayoN9Mrarm",
            )
        )

    def test_valid_keys_still_parse(self):
        """The version/depth checks must not reject well-formed keys."""
        master = BTC.keys.bip32_seed(h2b("000102030405060708090a0b0c0d0e0f"))
        for hwif in (master.hwif(as_private=True), master.hwif()):
            self.assertIsNotNone(BTC.parse(hwif))
        # a derived key has non-zero depth, fingerprint and index
        child = master.subkey_for_path("0H/1/2H")
        self.assertNotEqual(child._depth, 0)
        for hwif in (child.hwif(as_private=True), child.hwif()):
            self.assertIsNotNone(BTC.parse(hwif))


if __name__ == "__main__":
    unittest.main()
