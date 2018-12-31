import unittest

from pycoin.encoding.bytes32 import to_bytes_32
from pycoin.encoding.hash import double_sha256
from pycoin.encoding.hexbytes import b2h, b2h_rev, h2b
from pycoin.symbols.btc import network


# BRAIN DAMAGE
Tx = network.tx
TxOut = network.tx.TxOut

SIGHASH_ALL = network.validator.flags.SIGHASH_ALL
SIGHASH_SINGLE = network.validator.flags.SIGHASH_SINGLE
SIGHASH_NONE = network.validator.flags.SIGHASH_NONE
SIGHASH_ANYONECANPAY = network.validator.flags.SIGHASH_ANYONECANPAY


class SegwitTest(unittest.TestCase):

    def check_unsigned(self, tx):
        for idx, txs_in in enumerate(tx.txs_in):
            self.assertFalse(tx.is_solution_ok(idx))

    def check_signed(self, tx):
        for idx, txs_in in enumerate(tx.txs_in):
            self.assertTrue(tx.is_solution_ok(idx))

    def unsigned_copy(self, tx):
        tx = Tx.from_hex(tx.as_hex())
        for tx_in in tx.txs_in:
            tx_in.script = b''
            tx_in.witness = []
        return tx

    def check_tx_can_be_signed(self, tx_u, tx_s, private_keys=[], p2sh_values=[]):
        tx_u_prime = self.unsigned_copy(tx_s)
        tx_s_hex = tx_s.as_hex()
        tx_u_prime.set_unspents(tx_s.unspents)
        p2sh_lookup = network.tx.solve.build_p2sh_lookup([h2b(x) for x in p2sh_values])
        hash160_lookup = network.tx.solve.build_hash160_lookup(private_keys)
        tx_u_prime.sign(hash160_lookup=hash160_lookup, p2sh_lookup=p2sh_lookup)
        self.check_signed(tx_u_prime)
        tx_hex = tx_u_prime.as_hex()
        self.assertEqual(tx_hex, tx_s_hex)

    def test_segwit_ui(self):
        # p2wpkh
        address = 'bc1qqyykvamqq62n64t8gw09uw0cdgxjwwlw7mypam'
        s = network.contract.for_address(address)
        afs_address = network.address.for_script(s)
        self.assertEqual(address, afs_address)

    def test_segwit_create_tx(self):
        key1 = network.keys.private(1)
        coin_value = 5000000
        script = network.contract.for_p2pkh_wit(key1.hash160())
        tx_hash = b'\ee' * 32
        tx_out_index = 0
        spendable = Tx.Spendable(coin_value, script, tx_hash, tx_out_index)
        key2 = network.keys.private(2)
        tx = network.tx_utils.create_tx([spendable], [(key2.address(), coin_value)])
        self.check_unsigned(tx)
        network.tx_utils.sign_tx(tx, [key1.wif()])
        self.check_signed(tx)
        self.assertEqual(len(tx.txs_in[0].witness), 2)

        s1 = network.contract.for_p2pkh(key1.hash160())
        address = network.address.for_p2s_wit(s1)
        spendable.script = network.contract.for_address(address)
        tx = network.tx_utils.create_tx([spendable], [(key2.address(), coin_value)])
        self.check_unsigned(tx)
        network.tx_utils.sign_tx(tx, [key1.wif()], p2sh_lookup=network.tx.solve.build_p2sh_lookup([s1]))
        self.check_signed(tx)

    def test_issue_224(self):
        RAWTX = (
            "010000000002145fea0b000000001976a9144838d8b3588c4c7ba7c1d06f866e9b3739"
            "c6303788ac0000000000000000346a32544553540000000a0000000000000001000000"
            "0005f5e1000000000000000000000000000bebc2000032000000000000271000000000"
        )
        Tx.from_hex(RAWTX)

    def check_bip143_tx(
            self, tx_u_hex, tx_s_hex, txs_out_value_scripthex_pair, tx_in_count, tx_out_count, version, lock_time):
        tx_u = Tx.from_hex(tx_u_hex)
        tx_s = Tx.from_hex(tx_s_hex)
        txs_out = [
            TxOut(int(coin_value * 1e8), h2b(script_hex)) for coin_value, script_hex in txs_out_value_scripthex_pair
        ]
        for tx in (tx_u, tx_s):
            self.assertEqual(len(tx.txs_in), tx_in_count)
            self.assertEqual(len(tx.txs_out), tx_out_count)
            self.assertEqual(tx.version, version)
            self.assertEqual(tx.lock_time, lock_time)
            tx.set_unspents(txs_out)
        self.check_unsigned(tx_u)
        self.check_signed(tx_s)
        tx_hex = tx_u.as_hex()
        self.assertEqual(tx_hex, tx_u_hex)
        tx_hex = tx_s.as_hex()
        self.assertEqual(tx_hex, tx_s_hex)
        tx_u_prime = self.unsigned_copy(tx_s)
        tx_hex = tx_u_prime.as_hex()
        self.assertEqual(tx_hex, tx_u_hex)
        self.assertEqual(b2h_rev(double_sha256(h2b(tx_s_hex))), tx_s.w_id())
        self.assertEqual(b2h_rev(double_sha256(h2b(tx_u_hex))), tx_u.w_id())
        self.assertEqual(b2h_rev(double_sha256(h2b(tx_u_hex))), tx_u.id())
        return tx_u, tx_s

    # these examples are from BIP 143 at
    # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki

    def test_bip143_tx_1(self):
        tx_u1, tx_s1 = self.check_bip143_tx(
            "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad"
            "969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9"
            "b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df3"
            "78db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e"
            "4dbe6a21b2d50ce2f0167faa815988ac11000000",
            "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4"
            "e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3beb"
            "f337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede9"
            "44ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b"
            "309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a914"
            "8280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143b"
            "de42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7"
            "d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c45183315"
            "61406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368d"
            "a1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000",
            [
                (6.25, "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac"),
                (6, "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1")
            ],
            2,
            2,
            1,
            17
        )

        sc = tx_s1.SolutionChecker(tx_s1)
        self.assertEqual(b2h(sc._hash_prevouts(SIGHASH_ALL)),
                         "96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37")
        self.assertEqual(b2h(sc._hash_sequence(SIGHASH_ALL)),
                         "52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b")
        self.assertEqual(b2h(sc._hash_outputs(SIGHASH_ALL, 0)),
                         "863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5")

        script = network.contract.for_p2pkh(tx_s1.unspents[1].script[2:])
        self.assertEqual(
            b2h(sc._segwit_signature_preimage(script=script, tx_in_idx=1, hash_type=SIGHASH_ALL)),
            "0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd"
            "3752b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3bef51"
            "e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000019"
            "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffff"
            "ffff863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e511"
            "00000001000000")

        self.assertEqual(b2h(to_bytes_32(sc._signature_for_hash_type_segwit(script, 1, 1))),
                         "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670")
        self.check_tx_can_be_signed(tx_u1, tx_s1, [
            0xbbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866,
            0x619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9
        ])

    def test_bip143_tx_2(self):
        tx_u2, tx_s2 = self.check_bip143_tx(
            "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a"
            "54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45"
            "bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad"
            "0402e8bd8ad6d77c88ac92040000",
            "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3c"
            "eb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffff"
            "ff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388"
            "ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac"
            "02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d1"
            "2d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe"
            "9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2"
            "687392040000",
            [(10, "a9144733f37cf4db86fbc2efed2500b4f4e49f31202387")],
            1,
            2,
            1,
            1170
        )
        self.check_tx_can_be_signed(
            tx_u2, tx_s2, [0xeb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf],
            ["001479091972186c449eb1ded22b78e40d009bdf0089"])

    def test_bip143_tx_3(self):
        tx_u3, tx_s3 = self.check_bip143_tx(
            "0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216"
            "b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47"
            "c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f814"
            "5e5acadf23f751864167f32e0963f788ac00000000",
            "01000000000102fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b"
            "9216b36e000000004847304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6"
            "c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367"
            "096bc02ee5e435b67da201ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac"
            "6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a3"
            "0741f8145e5acadf23f751864167f32e0963f788ac000347304402200de66acf452778"
            "9bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd3471"
            "71cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503473044022027dc95ad6b"
            "740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6"
            "a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e27034721026dccc749ad"
            "c2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626a"
            "ebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac00000000",
            [
                (1.5625, "21036d5c20fa14fb2f635474c1dc4ef5909d4568e5569b79fc94d3448486e14685f8ac"),
                (49, "00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0")
            ],
            2,
            1,
            1,
            0
        )

    def test_bip143_tx_4(self):
        tx_u4, tx_s4 = self.check_bip143_tx(
            "0100000002e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcf"
            "c0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35"
            "ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626"
            "ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531"
            "e1ec47f35916de8e259237294d1e88ac00000000",
            "01000000000102e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba"
            "7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e7"
            "7c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b23"
            "1626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd"
            "4531e1ec47f35916de8e259237294d1e88ac02483045022100f6a10b8604e6dc910194"
            "b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325"
            "be245c5b508ff0339bf1794078e20bfe0babc7ffe683270063ab68210392972e2eb617"
            "b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac0247304402200325"
            "21802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2"
            "188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83275163ab68"
            "210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac"
            "00000000",
            [
                (0.16777215, "0020ba468eea561b26301e4cf69fa34bde4ad60c81e70f059f045ca9a79931004a4d"),
                (0.16777215, "0020d9bbfbe56af7c4b7f960a70d7ea107156913d9e5a26b0a71429df5e097ca6537"),
            ],
            2,
            2,
            1,
            0
        )

    def test_bip143_tx_5(self):
        tx_u5, tx_s5 = self.check_bip143_tx(
            "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787"
            "b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631"
            "e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84"
            "c138dbbd3c3ee41588ac00000000",
            "0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca2"
            "9787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1b"
            "b8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc"
            "0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e"
            "6e84c138dbbd3c3ee41588ac080047304402206ac44d672dac41f9b00e28f4df20c52e"
            "eb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e"
            "4f98acaa594810388cf7409a1870ce01473044022068c7946a43232757cbdf9176f009"
            "a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62"
            "e027f64eefa2695578cc6432cdabce271502473044022059ebf56d98010a932cf8ecfe"
            "c54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a8913"
            "9c9fe7e499259875357e20fcbb15571c76795403483045022100fbefd94bd0a488d50b"
            "79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265"
            "f5a942e96213afae16d83321c8b31bb342142a14d16381483045022100a5263ea0553b"
            "a89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5"
            "d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08824730440220525406a1"
            "482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a"
            "34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae"
            "49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28"
            "bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703"
            "413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb8"
            "33092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94b"
            "a04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2"
            "f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000",
            [(9.87654321, "a9149993a429037b5d912407a71c252019287b8d27a587")],
            1,
            2,
            1,
            0
        )

        tx_u5prime = self.unsigned_copy(tx_s5)
        tx_s_hex = tx_s5.as_hex()
        tx_u5prime.set_unspents(tx_s5.unspents)

        ss = ["56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3"
              "2103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21"
              "034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a2103"
              "3400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6"
              "d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b6"
              "61b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae",
              "0020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54"]
        p2sh_lookup = network.tx.solve.build_p2sh_lookup([h2b(x) for x in ss])
        for se, sighash_type in [
            (0x730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6, SIGHASH_ALL),
            (0x11fa3d25a17cbc22b29c44a484ba552b5a53149d106d3d853e22fdd05a2d8bb3, SIGHASH_NONE),
            (0x77bf4141a87d55bdd7f3cd0bdccf6e9e642935fec45f2f30047be7b799120661, SIGHASH_SINGLE),
            (0x14af36970f5025ea3e8b5542c0f8ebe7763e674838d08808896b63c3351ffe49, SIGHASH_ANYONECANPAY | SIGHASH_ALL),
            (0xfe9a95c19eef81dde2b95c1284ef39be497d128e2aa46916fb02d552485e0323, SIGHASH_ANYONECANPAY | SIGHASH_NONE),
            (0x428a7aee9f0c2af0cd19af3cf1c78149951ea528726989b2e83e4778d2c3f890, SIGHASH_ANYONECANPAY | SIGHASH_SINGLE),
        ]:
            tx_u5prime.sign(hash_type=sighash_type, hash160_lookup=network.tx.solve.build_hash160_lookup(
                [se]), p2sh_lookup=p2sh_lookup)

        self.check_signed(tx_u5prime)
        tx_hex = tx_u5prime.as_hex()
        self.assertEqual(tx_hex, tx_s_hex)

        sc = tx_s5.SolutionChecker(tx_s5)
        self.assertEqual(b2h(sc._hash_prevouts(SIGHASH_ALL)),
                         "74afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0")
        self.assertEqual(b2h(sc._hash_sequence(SIGHASH_ALL)),
                         "3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044")
        self.assertEqual(b2h(sc._hash_outputs(SIGHASH_ALL, 0)),
                         "bc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc")
        self.assertEqual(b2h(sc._hash_outputs(SIGHASH_SINGLE, 0)),
                         "9efe0c13a6b16c14a41b04ebe6a63f419bdacb2f8705b494a43063ca3cd4f708")
        script = tx_s5.txs_in[0].witness[-1]
        self.assertEqual(
            b2h(sc._segwit_signature_preimage(script=script, tx_in_idx=0, hash_type=SIGHASH_ALL)),
            "0100000074afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aa"
            "a03bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e706650443664"
            "1869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf"
            "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3"
            "2103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21"
            "034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a2103"
            "3400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6"
            "d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b6"
            "61b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de"
            "3a00000000ffffffffbc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fd"
            "bb8eb90307cc0000000001000000")

        self.assertEqual(
            b2h(sc._segwit_signature_preimage(script=script, tx_in_idx=0, hash_type=SIGHASH_NONE)),
            "0100000074afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aa"
            "a000000000000000000000000000000000000000000000000000000000000000003664"
            "1869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf"
            "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3"
            "2103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21"
            "034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a2103"
            "3400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6"
            "d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b6"
            "61b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de"
            "3a00000000ffffffff0000000000000000000000000000000000000000000000000000"
            "0000000000000000000002000000")

        self.assertEqual(
            b2h(sc._segwit_signature_preimage(script=script, tx_in_idx=0, hash_type=SIGHASH_SINGLE)),
            "0100000074afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aa"
            "a000000000000000000000000000000000000000000000000000000000000000003664"
            "1869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf"
            "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3"
            "2103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21"
            "034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a2103"
            "3400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6"
            "d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b6"
            "61b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de"
            "3a00000000ffffffff9efe0c13a6b16c14a41b04ebe6a63f419bdacb2f8705b494a430"
            "63ca3cd4f7080000000003000000")

        self.assertEqual(
            b2h(sc._segwit_signature_preimage(
                script=script, tx_in_idx=0, hash_type=SIGHASH_ALL | SIGHASH_ANYONECANPAY)),
            "0100000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000003664"
            "1869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf"
            "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3"
            "2103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21"
            "034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a2103"
            "3400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6"
            "d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b6"
            "61b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de"
            "3a00000000ffffffffbc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fd"
            "bb8eb90307cc0000000081000000")

        self.assertEqual(
            b2h(sc._segwit_signature_preimage(
                script=script, tx_in_idx=0, hash_type=SIGHASH_NONE | SIGHASH_ANYONECANPAY)),
            "0100000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000003664"
            "1869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf"
            "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3"
            "2103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21"
            "034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a2103"
            "3400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6"
            "d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b6"
            "61b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de"
            "3a00000000ffffffff0000000000000000000000000000000000000000000000000000"
            "0000000000000000000082000000")

        self.assertEqual(
            b2h(sc._segwit_signature_preimage(
                script=script, tx_in_idx=0, hash_type=SIGHASH_SINGLE | SIGHASH_ANYONECANPAY)),
            "0100000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000003664"
            "1869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf"
            "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3"
            "2103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21"
            "034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a2103"
            "3400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6"
            "d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b6"
            "61b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de"
            "3a00000000ffffffff9efe0c13a6b16c14a41b04ebe6a63f419bdacb2f8705b494a430"
            "63ca3cd4f7080000000083000000")

        tx = Tx.from_hex("010000000169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1ac83"
                         "87f14c1d000000ffffffff0101000000000000000000000000")
        tx.set_witness(0, [h2b(x) for x in [
            "30450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dc"
            "c9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c5"
            "3e01",
            "02a9781d66b61fb5a7ef00ac5ad5bc6ffc78be7b44a566e3c87870e1079368df4c",
            "ad4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d8915"
            "56dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae6"
            "26c53e01"
        ]])
        tx = Tx.from_hex(
            "0100000000010169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1"
            "ac8387f14c1d000000ffffffff01010000000000000000034830450220487fb382c497"
            "4de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f8"
            "45d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e012102a9781d66b61f"
            "b5a7ef00ac5ad5bc6ffc78be7b44a566e3c87870e1079368df4c4aad4830450220487f"
            "b382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf9"
            "5feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0100000000")
        tx_hex = tx.as_hex()
        print(tx)
        print(tx_hex)
        tx = Tx.from_hex(
            "010000000169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1ac83"
            "87f14c1d000000ffffffff0101000000000000000000000000")
        self.assertEqual(
            tx_hex,
            "0100000000010169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1"
            "ac8387f14c1d000000ffffffff01010000000000000000034830450220487fb382c497"
            "4de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f8"
            "45d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e012102a9781d66b61f"
            "b5a7ef00ac5ad5bc6ffc78be7b44a566e3c87870e1079368df4c4aad4830450220487f"
            "b382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf9"
            "5feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0100000000")

    def test_bip143_tx_6(self):
        tx_u6, tx_s6 = self.check_bip143_tx(
            "010000000169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1ac83"
            "87f14c1d000000ffffffff0101000000000000000000000000",
            "0100000000010169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1"
            "ac8387f14c1d000000ffffffff01010000000000000000034830450220487fb382c497"
            "4de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f8"
            "45d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e012102a9781d66b61f"
            "b5a7ef00ac5ad5bc6ffc78be7b44a566e3c87870e1079368df4c4aad4830450220487f"
            "b382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf9"
            "5feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0100000000",
            [(0.002, "00209e1be07558ea5cc8e02ed1d80c0911048afad949affa36d5c3951e3159dbea19")],
            1,
            1,
            1,
            0
        )

    def test_bip143_tx_7(self):
        tx_u7, tx_s7 = self.check_bip143_tx(
            "01000000019275cb8d4a485ce95741c013f7c0d28722160008021bb469a11982d47a66"
            "28964c1d000000ffffffff0101000000000000000000000000",
            "010000000001019275cb8d4a485ce95741c013f7c0d28722160008021bb469a11982d4"
            "7a6628964c1d000000ffffffff0101000000000000000007004830450220487fb382c4"
            "974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48"
            "f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0148304502205286"
            "f726690b2e9b0207f0345711e63fa7012045b9eb0f19c2458ce1db90cf43022100e89f"
            "17f86abc5b149eba4115d4f128bcf45d77fb3ecdd34f594091340c0395960101022102"
            "966f109c54e85d3aee8321301136cedeb9fc710fdef58a9de8a73942f8e567c021034f"
            "fc99dd9a79dd3cb31e2ab3e0b09e0e67db41ac068c625cd1f491576016c84e9552af48"
            "30450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dc"
            "c9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c5"
            "3e0148304502205286f726690b2e9b0207f0345711e63fa7012045b9eb0f19c2458ce1"
            "db90cf43022100e89f17f86abc5b149eba4115d4f128bcf45d77fb3ecdd34f59409134"
            "0c039596017500000000",
            [(0.002, "00209b66c15b4e0b4eb49fa877982cafded24859fe5b0e2dbfbe4f0df1de7743fd52")],
            1,
            1,
            1,
            0
        )
        print(tx_s7.txs_in[0])
