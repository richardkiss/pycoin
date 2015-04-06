#!/usr/bin/env python

import unittest

from pycoin.ecdsa.ellipticcurve import Point, NoSuchPointError
from pycoin.ecdsa.secp256k1 import generator_secp256k1
from pycoin.encoding import hash160_sec_to_bitcoin_address
from pycoin.key import Key
from pycoin.key.BIP32Node import BIP32Node
from pycoin.key.Key import InvalidPublicPairError, InvalidSecretExponentError
from pycoin.key.validate import is_address_valid, is_wif_valid, is_public_bip32_valid, is_private_bip32_valid
from pycoin.networks import pay_to_script_prefix_for_netcode, NETWORK_NAMES


def change_prefix(address, new_prefix):
    return hash160_sec_to_bitcoin_address(Key.from_text(address).hash160(), address_prefix=new_prefix)


PAY_TO_HASH_ADDRESSES = ["1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
                        "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP", "1LagHJk2FyCV2VzrNHVqg3gYG4TSYwDV4m",
                        "1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb", "1NZUP3JAc9JkmbvmoTv7nVgZGtyJjirKV1"]

PAY_TO_SCRIPT_PREFIX = pay_to_script_prefix_for_netcode("BTC")

PAY_TO_SCRIPT_ADDRESSES = [change_prefix(t, PAY_TO_SCRIPT_PREFIX) for t in PAY_TO_HASH_ADDRESSES]


class KeyUtilsTest(unittest.TestCase):

    def test_address_valid_btc(self):
        for address in PAY_TO_HASH_ADDRESSES:
            self.assertEqual(is_address_valid(address), "BTC")
            a = address[:-1] + chr(ord(address[-1])+1)
            self.assertEqual(is_address_valid(a), None)

        for address in PAY_TO_HASH_ADDRESSES:
            self.assertEqual(is_address_valid(address, allowable_types=["pay_to_script"]), None)
            self.assertEqual(is_address_valid(address, allowable_types=["address"]), "BTC")

        for address in PAY_TO_SCRIPT_ADDRESSES:
            self.assertEqual(address[0], "3")
            self.assertEqual(is_address_valid(address, allowable_types=["pay_to_script"]), "BTC")
            self.assertEqual(is_address_valid(address, allowable_types=["address"]), None)


    def test_is_wif_valid(self):
        WIFS = ["KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
                "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf",
                "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74NMTptX4",
                "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAvUcVfH"]

        for wif in WIFS:
            self.assertEqual(is_wif_valid(wif), "BTC")
            a = wif[:-1] + chr(ord(wif[-1])+1)
            self.assertEqual(is_wif_valid(a), None)

        for netcode in NETWORK_NAMES:
            for se in range(1, 10):
                key = Key(secret_exponent=se, netcode=netcode)
                for tv in [True, False]:
                    wif = key.wif(use_uncompressed=tv)
                    self.assertEqual(is_wif_valid(wif, allowable_netcodes=[netcode]), netcode)
                    a = wif[:-1] + chr(ord(wif[-1])+1)
                    self.assertEqual(is_wif_valid(a, allowable_netcodes=[netcode]), None)


    def test_is_public_private_bip32_valid(self):
        WALLET_KEYS = ["foo", "1", "2", "3", "4", "5"]

        # not all networks support BIP32 yet
        for netcode in "BTC XTN DOGE".split():
            for wk in WALLET_KEYS:
                wallet = BIP32Node.from_master_secret(wk.encode("utf8"), netcode=netcode)
                text = wallet.wallet_key(as_private=True)
                self.assertEqual(is_private_bip32_valid(text, allowable_netcodes=NETWORK_NAMES), netcode)
                self.assertEqual(is_public_bip32_valid(text, allowable_netcodes=NETWORK_NAMES), None)
                a = text[:-1] + chr(ord(text[-1])+1)
                self.assertEqual(is_private_bip32_valid(a, allowable_netcodes=NETWORK_NAMES), None)
                self.assertEqual(is_public_bip32_valid(a, allowable_netcodes=NETWORK_NAMES), None)
                text = wallet.wallet_key(as_private=False)
                self.assertEqual(is_private_bip32_valid(text, allowable_netcodes=NETWORK_NAMES), None)
                self.assertEqual(is_public_bip32_valid(text, allowable_netcodes=NETWORK_NAMES), netcode)
                a = text[:-1] + chr(ord(text[-1])+1)
                self.assertEqual(is_private_bip32_valid(a, allowable_netcodes=NETWORK_NAMES), None)
                self.assertEqual(is_public_bip32_valid(a, allowable_netcodes=NETWORK_NAMES), None)


    def test_key_limits(self):
        nc = 'BTC'
        cc = b'000102030405060708090a0b0c0d0e0f'
        order = generator_secp256k1.order()

        for k in -1, 0, order, order + 1:
            self.assertRaises(InvalidSecretExponentError, Key, secret_exponent=k)
            self.assertRaises(InvalidSecretExponentError, BIP32Node, nc, cc, secret_exponent=k)

        for i in range(1, 512):
            Key(secret_exponent=i)
            BIP32Node(nc, cc, secret_exponent=i)


    def test_points(self):
        secp256k1_curve = generator_secp256k1.curve()
        # From <https://crypto.stackexchange.com/questions/784/are-there-any-secp256k1-ecdsa-test-examples-available>
        test_points = []
        k = 1
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        test_points.append((k, x, y))
        k = 2
        x = 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
        y = 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A
        test_points.append((k, x, y))
        k = 3
        x = 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9
        y = 0x388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672
        test_points.append((k, x, y))
        k = 4
        x = 0xE493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13
        y = 0x51ED993EA0D455B75642E2098EA51448D967AE33BFBDFE40CFE97BDC47739922
        test_points.append((k, x, y))
        k = 5
        x = 0x2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4
        y = 0xD8AC222636E5E3D6D4DBA9DDA6C9C426F788271BAB0D6840DCA87D3AA6AC62D6
        test_points.append((k, x, y))
        k = 6
        x = 0xFFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556
        y = 0xAE12777AACFBB620F3BE96017F45C560DE80F0F6518FE4A03C870C36B075F297
        test_points.append((k, x, y))
        k = 7
        x = 0x5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC
        y = 0x6AEBCA40BA255960A3178D6D861A54DBA813D0B813FDE7B5A5082628087264DA
        test_points.append((k, x, y))
        k = 8
        x = 0x2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01
        y = 0x5C4DA8A741539949293D082A132D13B4C2E213D6BA5B7617B5DA2CB76CBDE904
        test_points.append((k, x, y))
        k = 9
        x = 0xACD484E2F0C7F65309AD178A9F559ABDE09796974C57E714C35F110DFC27CCBE
        y = 0xCC338921B0A7D9FD64380971763B61E9ADD888A4375F8E0F05CC262AC64F9C37
        test_points.append((k, x, y))
        k = 10
        x = 0xA0434D9E47F3C86235477C7B1AE6AE5D3442D49B1943C2B752A68E2A47E247C7
        y = 0x893ABA425419BC27A3B6C7E693A24C696F794C2ED877A1593CBEE53B037368D7
        test_points.append((k, x, y))
        k = 11
        x = 0x774AE7F858A9411E5EF4246B70C65AAC5649980BE5C17891BBEC17895DA008CB
        y = 0xD984A032EB6B5E190243DD56D7B7B365372DB1E2DFF9D6A8301D74C9C953C61B
        test_points.append((k, x, y))
        k = 12
        x = 0xD01115D548E7561B15C38F004D734633687CF4419620095BC5B0F47070AFE85A
        y = 0xA9F34FFDC815E0D7A8B64537E17BD81579238C5DD9A86D526B051B13F4062327
        test_points.append((k, x, y))
        k = 13
        x = 0xF28773C2D975288BC7D1D205C3748651B075FBC6610E58CDDEEDDF8F19405AA8
        y = 0x0AB0902E8D880A89758212EB65CDAF473A1A06DA521FA91F29B5CB52DB03ED81
        test_points.append((k, x, y))
        k = 14
        x = 0x499FDF9E895E719CFD64E67F07D38E3226AA7B63678949E6E49B241A60E823E4
        y = 0xCAC2F6C4B54E855190F044E4A7B3D464464279C27A3F95BCC65F40D403A13F5B
        test_points.append((k, x, y))
        k = 15
        x = 0xD7924D4F7D43EA965A465AE3095FF41131E5946F3C85F79E44ADBCF8E27E080E
        y = 0x581E2872A86C72A683842EC228CC6DEFEA40AF2BD896D3A5C504DC9FF6A26B58
        test_points.append((k, x, y))
        k = 16
        x = 0xE60FCE93B59E9EC53011AABC21C23E97B2A31369B87A5AE9C44EE89E2A6DEC0A
        y = 0xF7E3507399E595929DB99F34F57937101296891E44D23F0BE1F32CCE69616821
        test_points.append((k, x, y))
        k = 17
        x = 0xDEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34
        y = 0x4211AB0694635168E997B0EAD2A93DAECED1F4A04A95C0F6CFB199F69E56EB77
        test_points.append((k, x, y))
        k = 18
        x = 0x5601570CB47F238D2B0286DB4A990FA0F3BA28D1A319F5E7CF55C2A2444DA7CC
        y = 0xC136C1DC0CBEB930E9E298043589351D81D8E0BC736AE2A1F5192E5E8B061D58
        test_points.append((k, x, y))
        k = 19
        x = 0x2B4EA0A797A443D293EF5CFF444F4979F06ACFEBD7E86D277475656138385B6C
        y = 0x85E89BC037945D93B343083B5A1C86131A01F60C50269763B570C854E5C09B7A
        test_points.append((k, x, y))
        k = 20
        x = 0x4CE119C96E2FA357200B559B2F7DD5A5F02D5290AFF74B03F3E471B273211C97
        y = 0x12BA26DCB10EC1625DA61FA10A844C676162948271D96967450288EE9233DC3A
        test_points.append((k, x, y))
        k = 112233445566778899
        x = 0xA90CC3D3F3E146DAADFC74CA1372207CB4B725AE708CEF713A98EDD73D99EF29
        y = 0x5A79D6B289610C68BC3B47F3D72F9788A26A06868B4D8E433E1E2AD76FB7DC76
        test_points.append((k, x, y))
        k = 112233445566778899112233445566778899
        x = 0xE5A2636BCFD412EBF36EC45B19BFB68A1BC5F8632E678132B885F7DF99C5E9B3
        y = 0x736C1CE161AE27B405CAFD2A7520370153C2C861AC51D6C1D5985D9606B45F39
        test_points.append((k, x, y))
        k = 28948022309329048855892746252171976963209391069768726095651290785379540373584
        x = 0xA6B594B38FB3E77C6EDF78161FADE2041F4E09FD8497DB776E546C41567FEB3C
        y = 0x71444009192228730CD8237A490FEBA2AFE3D27D7CC1136BC97E439D13330D55
        test_points.append((k, x, y))
        k = 57896044618658097711785492504343953926418782139537452191302581570759080747168
        x = 0x00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63
        y = 0x3F3979BF72AE8202983DC989AEC7F2FF2ED91BDD69CE02FC0700CA100E59DDF3
        test_points.append((k, x, y))
        k = 86844066927987146567678238756515930889628173209306178286953872356138621120752
        x = 0xE24CE4BEEE294AA6350FAA67512B99D388693AE4E7F53D19882A6EA169FC1CE1
        y = 0x8B71E83545FC2B5872589F99D948C03108D36797C4DE363EBD3FF6A9E1A95B10
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494317
        x = 0x4CE119C96E2FA357200B559B2F7DD5A5F02D5290AFF74B03F3E471B273211C97
        y = 0xED45D9234EF13E9DA259E05EF57BB3989E9D6B7D8E269698BAFD77106DCC1FF5
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494318
        x = 0x2B4EA0A797A443D293EF5CFF444F4979F06ACFEBD7E86D277475656138385B6C
        y = 0x7A17643FC86BA26C4CBCF7C4A5E379ECE5FE09F3AFD9689C4A8F37AA1A3F60B5
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494319
        x = 0x5601570CB47F238D2B0286DB4A990FA0F3BA28D1A319F5E7CF55C2A2444DA7CC
        y = 0x3EC93E23F34146CF161D67FBCA76CAE27E271F438C951D5E0AE6D1A074F9DED7
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494320
        x = 0xDEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34
        y = 0xBDEE54F96B9CAE9716684F152D56C251312E0B5FB56A3F09304E660861A910B8
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494321
        x = 0xE60FCE93B59E9EC53011AABC21C23E97B2A31369B87A5AE9C44EE89E2A6DEC0A
        y = 0x081CAF8C661A6A6D624660CB0A86C8EFED6976E1BB2DC0F41E0CD330969E940E
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494322
        x = 0xD7924D4F7D43EA965A465AE3095FF41131E5946F3C85F79E44ADBCF8E27E080E
        y = 0xA7E1D78D57938D597C7BD13DD733921015BF50D427692C5A3AFB235F095D90D7
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494323
        x = 0x499FDF9E895E719CFD64E67F07D38E3226AA7B63678949E6E49B241A60E823E4
        y = 0x353D093B4AB17AAE6F0FBB1B584C2B9BB9BD863D85C06A4339A0BF2AFC5EBCD4
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494324
        x = 0xF28773C2D975288BC7D1D205C3748651B075FBC6610E58CDDEEDDF8F19405AA8
        y = 0xF54F6FD17277F5768A7DED149A3250B8C5E5F925ADE056E0D64A34AC24FC0EAE
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494325
        x = 0xD01115D548E7561B15C38F004D734633687CF4419620095BC5B0F47070AFE85A
        y = 0x560CB00237EA1F285749BAC81E8427EA86DC73A2265792AD94FAE4EB0BF9D908
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494326
        x = 0x774AE7F858A9411E5EF4246B70C65AAC5649980BE5C17891BBEC17895DA008CB
        y = 0x267B5FCD1494A1E6FDBC22A928484C9AC8D24E1D20062957CFE28B3536AC3614
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494327
        x = 0xA0434D9E47F3C86235477C7B1AE6AE5D3442D49B1943C2B752A68E2A47E247C7
        y = 0x76C545BDABE643D85C4938196C5DB3969086B3D127885EA6C3411AC3FC8C9358
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494328
        x = 0xACD484E2F0C7F65309AD178A9F559ABDE09796974C57E714C35F110DFC27CCBE
        y = 0x33CC76DE4F5826029BC7F68E89C49E165227775BC8A071F0FA33D9D439B05FF8
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494329
        x = 0x2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01
        y = 0xA3B25758BEAC66B6D6C2F7D5ECD2EC4B3D1DEC2945A489E84A25D3479342132B
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494330
        x = 0x5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC
        y = 0x951435BF45DAA69F5CE8729279E5AB2457EC2F47EC02184A5AF7D9D6F78D9755
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494331
        x = 0xFFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556
        y = 0x51ED8885530449DF0C4169FE80BA3A9F217F0F09AE701B5FC378F3C84F8A0998
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494332
        x = 0x2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4
        y = 0x2753DDD9C91A1C292B24562259363BD90877D8E454F297BF235782C459539959
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494333
        x = 0xE493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13
        y = 0xAE1266C15F2BAA48A9BD1DF6715AEBB7269851CC404201BF30168422B88C630D
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494334
        x = 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9
        y = 0xC77084F09CD217EBF01CC819D5C80CA99AFF5666CB3DDCE4934602897B4715BD
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494335
        x = 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
        y = 0xE51E970159C23CC65C3A7BE6B99315110809CD9ACD992F1EDC9BCE55AF301705
        test_points.append((k, x, y))
        k = 115792089237316195423570985008687907852837564279074904382605163141518161494336
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        y = 0xB7C52588D95C3B9AA25B0403F1EEF75702E84BB7597AABE663B82F6F04EF2777
        test_points.append((k, x, y))
        k = 0xaa5e28d6a97a2479a65527f7290311a3624d4cc0fa1578598ee3c2613bf99522
        x = 0x34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6
        y = 0x0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232
        test_points.append((k, x, y))
        k = 0x7e2b897b8cebc6361663ad410835639826d590f393d90a9538881735256dfae3
        x = 0xd74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575
        y = 0x131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d
        test_points.append((k, x, y))
        k = 0x6461e6df0fe7dfd05329f41bf771b86578143d4dd1f7866fb4ca7e97c5fa945d
        x = 0xe8aecc370aedd953483719a116711963ce201ac3eb21d3f3257bb48668c6a72f
        y = 0xc25caf2f0eba1ddb2f0f3f47866299ef907867b7d27e95b3873bf98397b24ee1
        test_points.append((k, x, y))
        k = 0x376a3a2cdcd12581efff13ee4ad44c4044b8a0524c42422a7e1e181e4deeccec
        x = 0x14890e61fcd4b0bd92e5b36c81372ca6fed471ef3aa60a3e415ee4fe987daba1
        y = 0x297b858d9f752ab42d3bca67ee0eb6dcd1c2b7b0dbe23397e66adc272263f982
        test_points.append((k, x, y))
        k = 0x1b22644a7be026548810c378d0b2994eefa6d2b9881803cb02ceff865287d1b9
        x = 0xf73c65ead01c5126f28f442d087689bfa08e12763e0cec1d35b01751fd735ed3
        y = 0xf449a8376906482a84ed01479bd18882b919c140d638307f0c0934ba12590bde
        test_points.append((k, x, y))

        for k, x, y in test_points:
            p = Point(secp256k1_curve, x, y)
            self.assertTrue(secp256k1_curve.contains_point(p.x(), p.y()))
            K = Key(public_pair=(x, y))
            k = Key(secret_exponent=k)
            self.assertEqual(K.public_pair(), k.public_pair())

        x = y = 0
        self.assertRaises(NoSuchPointError, Point, secp256k1_curve, x, y)
        self.assertRaises(InvalidPublicPairError, Key, public_pair=(0, 0))


    def test_repr(self):
        key = Key(secret_exponent=273, netcode='XTN')

        address = key.address()
        pub_k = Key.from_text(address)
        self.assertEqual(repr(pub_k),  '<mhDVBkZBWLtJkpbszdjZRkH1o5RZxMwxca>')

        wif = key.wif()
        priv_k = Key.from_text(wif)
        self.assertEqual(repr(priv_k), 'private_for <0264e1b1969f9102977691a40431b0b672055dcf31163897d996434420e6c95dc9>')


if __name__ == '__main__':
    unittest.main()
