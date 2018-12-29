import binascii
import unittest

from pycoin.encoding.hexbytes import h2b
from pycoin.symbols.btc import network


class ValidationTest(unittest.TestCase):

    def setUp(self):
        self._key = network.keys.private(1)

    def test_validate_multisig_tx(self):
        # this is a transaction in the block chain
        # the unspents are included too, so it can be validated
        TX_HEX = (
            "01000000025718fb915fb8b3a802bb699ddf04dd91261ef6715f5f2820a2b1b9b7e38b"
            "4f27000000004a004830450221008c2107ed4e026ab4319a591e8d9ec37719cdea0539"
            "51c660566e3a3399428af502202ecd823d5f74a77cc2159d8af2d3ea5d36a702fef9a7"
            "edaaf562aef22ac35da401ffffffff038f52231b994efb980382e4d804efeadaee13cf"
            "e01abe0d969038ccb45ec17000000000490047304402200487cd787fde9b337ab87f9f"
            "e54b9fd46d5d1692aa58e97147a4fe757f6f944202203cbcfb9c0fc4e3c453938bbea9"
            "e5ae64030cf7a97fafaf460ea2cb54ed5651b501ffffffff0100093d00000000001976"
            "a9144dc39248253538b93d3a0eb122d16882b998145888ac0000000002000000000000"
            "004751210351efb6e91a31221652105d032a2508275f374cea63939ad72f1b1e02f477"
            "da782100f2b7816db49d55d24df7bdffdbc1e203b424e8cd39f5651ab938e5e4a19356"
            "9e52ae404b4c00000000004751210351efb6e91a31221652105d032a2508275f374cea"
            "63939ad72f1b1e02f477da7821004f0331742bbc917ba2056a3b8a857ea47ec088dd10"
            "475ea311302112c9d24a7152ae")
        tx = network.tx.from_hex(TX_HEX)
        self.assertEqual(tx.id(), "70c4e749f2b8b907875d1483ae43e8a6790b0c8397bbb33682e3602617f9a77a")
        self.assertEqual(tx.bad_solution_count(), 0)

    def test_validate_block_data(self):
        # block 80971
        block_80971_id = '00000000001126456C67A1F5F0FF0268F53B4F22E0531DC70C7B69746AF69DAC'.lower()
        block_80971_data = h2b(
            "01000000950A1631FB9FAC411DFB173487B9E18018B7C6F7147E78C062584100000000"
            "00A881352F97F14BF191B54915AE124E051B8FE6C3922C5082B34EAD503000FC34D891"
            "974CED66471B4016850A04010000000100000000000000000000000000000000000000"
            "00000000000000000000000000FFFFFFFF0804ED66471B02C301FFFFFFFF0100F2052A"
            "01000000434104CB6B6B4EADC96C7D08B21B29D0ADA5F29F9378978CABDB602B8B65DA"
            "08C8A93CAAB46F5ABD59889BAC704925942DD77A2116D10E0274CAD944C71D3D1A6705"
            "70AC0000000001000000018C55ED829F16A4E43902940D3D33005264606D5F7D555B5F"
            "67EE4C033390C2EB010000008A47304402202D1BF606648EDCDB124C1254930852D991"
            "88E1231715031CBEAEA80CCFD2B39A02201FA9D6EE7A1763580E342474FC1AEF59B046"
            "8F98479953437F525063E25675DE014104A01F763CFBF5E518C628939158AF3DC0CAAC"
            "35C4BA7BC1CE8B7E634E8CDC44E15F0296B250282BD649BAA8398D199F2424FCDCD88D"
            "3A9ED186E4FD3CB9BF57CFFFFFFFFF02404B4C00000000001976A9148156FF75BEF24B"
            "35ACCE3C05289A2411E1B0E57988AC00AA38DF010000001976A914BC7E692A5FFE95A5"
            "96712F5ED83393B3002E452E88AC0000000001000000019C97AFDF6C9A31FFA86D71EA"
            "79A079001E2B59EE408FD418498219400639AC0A010000008B4830450220363CFFAE09"
            "599397B21E6D8A8073FB1DFBE06B6ACDD0F2F7D3FEA86CA9C3F605022100FA255A6ED2"
            "3FD825C759EF1A885A31CAD0989606CA8A3A16657D50FE3CEF5828014104FF444BAC08"
            "308B9EC97F56A652AD8866E0BA804DA97868909999566CB377F4A2C8F1000E83B49686"
            "8F3A282E1A34DF78565B65C15C3FA21A0763FD81A3DFBBB6FFFFFFFF02C05EECDE0100"
            "00001976A914588554E6CC64E7343D77117DA7E01357A6111B7988AC404B4C00000000"
            "001976A914CA6EB218592F289999F13916EE32829AD587DBC588AC0000000001000000"
            "01BEF5C9225CB9FE3DEF929423FA36AAD9980B9D6F8F3070001ACF3A5FB389A69F0000"
            "00004A493046022100FB23B1E2F2FB8B96E04D220D385346290A9349F89BBBC5C225D5"
            "A56D931F8A8E022100F298EB28294B90C1BAF319DAB713E7CA721AAADD8FCC15F849DE"
            "7B0A6CF5412101FFFFFFFF0100F2052A010000001976A9146DDEA8071439951115469D"
            "0D2E2B80ECBCDD48DB88AC00000000")

        # block 80974
        block_80974_id = '0000000000089F7910F6755C10EA2795EC368A29B435D80770AD78493A6FECF1'.lower()
        block_80974_data = h2b(
            "010000007480150B299A16BBCE5CCDB1D1BBC65CFC5893B01E6619107C552000000000"
            "007900A2B203D24C69710AB6A94BEB937E1B1ADD64C2327E268D8C3E5F8B41DBED8796"
            "974CED66471B204C324703010000000100000000000000000000000000000000000000"
            "00000000000000000000000000FFFFFFFF0804ED66471B024001FFFFFFFF0100F2052A"
            "010000004341045FEE68BAB9915C4EDCA4C680420ED28BBC369ED84D48AC178E1F5F7E"
            "EAC455BBE270DABA06802145854B5E29F0A7F816E2DF906E0FE4F6D5B4C9B92940E4F0"
            "EDAC000000000100000001F7B30415D1A7BF6DB91CB2A272767C6799D721A4178AA328"
            "E0D77C199CB3B57F010000008A4730440220556F61B84F16E637836D2E74B8CB784DE4"
            "0C28FE3EF93CCB7406504EE9C7CAA5022043BD4749D4F3F7F831AC696748AD8D8E79AE"
            "B4A1C539E742AA3256910FC88E170141049A414D94345712893A828DE57B4C2054E2F5"
            "96CDCA9D0B4451BA1CA5F8847830B9BE6E196450E6ABB21C540EA31BE310271AA00A49"
            "ED0BA930743D1ED465BAD0FFFFFFFF0200E1F505000000001976A914529A63393D63E9"
            "80ACE6FA885C5A89E4F27AA08988ACC0ADA41A000000001976A9145D17976537F30886"
            "5ED533CCCFDD76558CA3C8F088AC00000000010000000165148D894D3922EF5FFDA962"
            "BE26016635C933D470C8B0AB7618E869E3F70E3C000000008B48304502207F5779EBF4"
            "834FEAEFF4D250898324EB5C0833B16D7AF4C1CB0F66F50FCF6E85022100B78A65377F"
            "D018281E77285EFC31E5B9BA7CB7E20E015CF6B7FA3E4A466DD195014104072AD79E0A"
            "A38C05FA33DD185F84C17F611E58A8658CE996D8B04395B99C7BE36529CAB7606900A0"
            "CD5A7AEBC6B233EA8E0FE60943054C63620E05E5B85F0426FFFFFFFF02404B4C000000"
            "00001976A914D4CAA8447532CA8EE4C80A1AE1D230A01E22BFDB88AC8013A0DE010000"
            "001976A9149661A79AE1F6D487AF3420C13E649D6DF3747FC288AC00000000")

        block_80971 = network.block.from_bin(block_80971_data)
        self.assertEqual(block_80971.id(), block_80971_id)
        block_80974 = network.block.from_bin(block_80974_data)
        self.assertEqual(block_80974.id(), block_80974_id)

        tx_db = {tx.hash(): tx for tx in block_80971.txs}

        tx_to_validate = block_80974.txs[2]
        self.assertEqual("OP_DUP OP_HASH160 [d4caa8447532ca8ee4c80a1ae1d230a01e22bfdb] OP_EQUALVERIFY OP_CHECKSIG",
                         network.script.disassemble(tx_to_validate.txs_out[0].script))
        self.assertEqual(tx_to_validate.id(), "7c4f5385050c18aa8df2ba50da566bbab68635999cc99b75124863da1594195b")

        tx_to_validate.unspents_from_db(tx_db)
        self.assertEqual(tx_to_validate.bad_solution_count(), 0)

        # now, let's corrupt the Tx and see what happens
        tx_out = tx_to_validate.txs_out[1]

        disassembly = network.script.disassemble(tx_out.script)
        tx_out.script = network.script.compile(disassembly)

        self.assertEqual(tx_to_validate.bad_solution_count(), 0)

        disassembly = disassembly.replace("9661a79ae1f6d487af3420c13e649d6df3747fc2",
                                          "9661a79ae1f6d487af3420c13e649d6df3747fc3")

        tx_out.script = network.script.compile(disassembly)

        self.assertEqual(tx_to_validate.bad_solution_count(), 1)
        self.assertFalse(tx_to_validate.is_solution_ok(0))

    def test_validate_two_inputs(self):
        def tx_from_b64(h):
            d = binascii.a2b_base64(h.encode("utf8"))
            return network.tx.from_bin(d)
        # tx_0 = c9989d984c97128b03b9f118481c631c584f7aa42b578dbea6194148701b053d
        # This is the one we're going to validate. It has inputs from
        #  tx_1 = b52201c2741d410b70688335afebba0d58f8675fa9b6c8c54becb0d7c0a75983
        # and tx_2 = 72151f65db1d8594df90778639a4c0c17c1e303af01de0d04af8fac13854bbfd
        TX_0_HEX = (
            "AQAAAAKDWafA17DsS8XItqlfZ/hYDbrrrzWDaHALQR10wgEitQAAAACLSDBFAiAnyvQ1P7"
            "b8+84JbBUbE1Xtgrd0KNpD4eyVTNU/burbtgIhAOS8T1TrhXkGXQTGbLSEJy5uvZMGEzOj"
            "ITxO+DrykiPlAUEE3yJcIB5OCpaDjrop+N3bm8h9PKw8bF/YB4v3yD+VeQf4fXdUZ9hJJS"
            "nFeJ+QeJrC7q3Y23QSYeYbW/AfA3D5G//////9u1Q4wfr4StDgHfA6MB58wcCkOYZ3kN+U"
            "hR3bZR8VcgAAAACLSDBFAiAN6ZQr+9HTgmF57EsPyXIhQ6J5M4lgwlj/tJTShZ+toQIhAL"
            "0U1i9yiCEm75uCEp8uRaySqS7P4x7A+L2Vr5kS+7ANAUEEkSqVI6gw1scM0GuJWgMh4jpW"
            "KJA0yOl03uQaV/jHURn+HswOIORzvsG9qQY1/9BZgDPaMuI5U5JlyA3WkhLxgf////8Ctk"
            "SUzxAAAAAZdqkULXTu3lp2t/wMSuvqbifOSj9/kvmIrAAoa+4AAAAAGXapFF3ySpVdjz9V"
            "8fRKvzDqXQRcmowSiKwAAAAA")
        TX_1_HEX = (
            "AQAAAAEL3YmFDcZpf4SH7uN1IBmMoBd4OhmTp4EAQ8A0ZQ3tiwAAAACKRzBEAiA4Fkl8lk"
            "JSeLtWHsp1j0h7y0KKFmqxhDR0CK0HnmZWBQIgDSTDenor3zbNqTs+FApeDl8DKCz1xGQC"
            "JQN0/sp00VABQQQzSNc33wdDXA/F9y9/hAR88q6Se6vRCHEC7dYgbIp1pgxqGzrWXQroGk"
            "QLhnAbn/fDhUoVbCgM/UHXYmjXlhdO/////wI3HGlfEQAAABl2qRRM+dhUVUjeAlb0jEsH"
            "JrFClGGSZ4isMAYVCgAAAAAZdqkUgnSLXoYTeOKFFRdtLYxWcGZ2Ht2IrAAAAAA=")
        TX_2_HEX = (
            "AQAAAAFDjBbw61AYUWMx+3moZ2vb9dvLKydOSFIwcfBTjG0QSgEAAACKRzBEAiA5WWKhR4"
            "8OI60ZDCXnOru/FH6NvuTGhRLggjbpJB2dhgIgKp0FFL0ClSCxxqGjYneDinvgROGSw6Dt"
            "Vtvflrhaom8BQQR50YjAg1e5qRkP4ER29ec5jKfzk3DHJhS7Si0sEbvNIJMfjjbZfZWtJi"
            "15wHZhuHh4e3G6SWMdJLHH5pgbseFh/////wLPE5deAAAAABl2qRSmRdbMvv5fEbgFD1Yk"
            "taBU9zQTW4iswJ7mBQAAAAAZdqkU4E5+Is4tr+8bPU6ELYHSvz/Ng0eIrAAAAAA=")
        tx_0 = tx_from_b64(TX_0_HEX)
        self.assertEqual(tx_0.id(), "c9989d984c97128b03b9f118481c631c584f7aa42b578dbea6194148701b053d")
        tx_1 = tx_from_b64(TX_1_HEX)
        self.assertEqual(tx_1.id(), "b52201c2741d410b70688335afebba0d58f8675fa9b6c8c54becb0d7c0a75983")
        tx_2 = tx_from_b64(TX_2_HEX)
        self.assertEqual(tx_2.id(), "72151f65db1d8594df90778639a4c0c17c1e303af01de0d04af8fac13854bbfd")

        TX_DB = {tx.hash(): tx for tx in [tx_0, tx_1, tx_2]}

        tx_to_validate = tx_0
        self.assertEqual("OP_DUP OP_HASH160 [2d74eede5a76b7fc0c4aebea6e27ce4a3f7f92f9] OP_EQUALVERIFY OP_CHECKSIG",
                         network.script.disassemble(tx_to_validate.txs_out[0].script))
        self.assertEqual(tx_to_validate.id(), "c9989d984c97128b03b9f118481c631c584f7aa42b578dbea6194148701b053d")

        tx_to_validate.unspents_from_db(TX_DB)
        self.assertEqual(tx_to_validate.bad_solution_count(), 0)

        # now let's mess with signatures
        disassembly = network.script.disassemble(tx_to_validate.txs_in[0].script)
        tx_to_validate.txs_in[0].script = network.script.compile(disassembly)
        self.assertEqual(tx_to_validate.bad_solution_count(), 0)
        disassembly = disassembly.replace("353fb6fcfbce09", "353fb6fcfbce19")
        tx_to_validate.txs_in[0].script = network.script.compile(disassembly)
        self.assertEqual(tx_to_validate.bad_solution_count(), 1)
        self.assertFalse(tx_to_validate.is_solution_ok(0))

        tx_to_validate = tx_from_b64(TX_0_HEX)
        tx_to_validate.unspents_from_db(TX_DB)
        self.assertEqual(tx_to_validate.bad_solution_count(), 0)
        disassembly = network.script.disassemble(tx_to_validate.txs_in[1].script)
        disassembly = disassembly.replace("960c258ffb494d2859f", "960d258ffb494d2859f")
        tx_to_validate.txs_in[1].script = network.script.compile(disassembly)
        self.assertEqual(tx_to_validate.bad_solution_count(), 1)
        self.assertFalse(tx_to_validate.is_solution_ok(1))

        # futz with signature on tx_1
        tx_to_validate = tx_from_b64(TX_0_HEX)
        original_tx_hash = tx_1.hash()
        disassembly = network.script.disassemble(tx_1.txs_out[0].script)
        disassembly = disassembly.replace("4cf9d8545548de0256f48c4b0726b14294619267",
                                          "4cf9d8545548de1256f48c4b0726b14294619267")
        tx_1.txs_out[0].script = network.script.compile(disassembly)
        TX_DB[original_tx_hash] = tx_1
        tx_to_validate.unspents_from_db(TX_DB, ignore_missing=True)
        self.assertEqual(tx_to_validate.bad_solution_count(), 1)
        self.assertFalse(tx_to_validate.is_solution_ok(0))

        # fix it up again
        TX_DB[original_tx_hash] = tx_from_b64(TX_1_HEX)
        tx_to_validate.unspents_from_db(TX_DB)
        self.assertEqual(tx_to_validate.bad_solution_count(), 0)

        # futz with signature on tx_2
        tx_to_validate = tx_from_b64(TX_0_HEX)
        original_tx_hash = tx_2.hash()
        disassembly = network.script.disassemble(tx_2.txs_out[0].script)
        disassembly = disassembly.replace("a645d6ccbefe5f11b8050f5624b5a054f734135b",
                                          "a665d6ccbefe5f11b8050f5624b5a054f734135b")
        tx_2.txs_out[0].script = network.script.compile(disassembly)
        TX_DB[original_tx_hash] = tx_2
        tx_to_validate.unspents_from_db(TX_DB, ignore_missing=True)
        self.assertEqual(tx_to_validate.bad_solution_count(), 1)
        self.assertFalse(tx_to_validate.is_solution_ok(1))

        # fix it up again
        TX_DB[original_tx_hash] = tx_from_b64(TX_2_HEX)
        tx_to_validate.unspents_from_db(TX_DB)
        self.assertEqual(tx_to_validate.bad_solution_count(), 0)

    def _make_tx(self, input_script, other_scripts=[]):
        cv = int(50*1e8)

        key = self._key
        sec = key.sec()
        wif = key.wif()
        address = key.address()
        p2sh_lookup = network.tx.solve.build_p2sh_lookup(other_scripts)

        coinbase_tx = network.tx.coinbase_tx(public_key_sec=sec, coin_value=cv)
        coinbase_tx.txs_out[0].script = input_script
        spendable = coinbase_tx.tx_outs_as_spendable()[0]
        payables = [(address, cv)]
        tx = network.tx_utils.create_signed_tx(
            spendables=[spendable], payables=payables, wifs=[wif], p2sh_lookup=p2sh_lookup)
        tx.unspents = [spendable]
        print(tx.as_hex(include_unspents=True))
        return tx

    def test_validate_p2pkh(self):
        us_1 = network.contract.for_p2pkh(self._key.hash160())
        tx = self._make_tx(us_1)
        tx.check_solution(0)

    def test_validate_p2s_of_p2pkh(self):
        us_1 = network.contract.for_p2pkh(self._key.hash160())
        us_2 = network.contract.for_p2s(us_1)
        tx = self._make_tx(us_2, [us_1])
        tx.check_solution(0)

    def test_validate_p2pkh_wit(self):
        us_1 = network.contract.for_p2pkh_wit(self._key.hash160())
        tx = self._make_tx(us_1)
        tx.check_solution(0)

    def test_validate_p2s_wit_of_p2pkh(self):
        us_1 = network.contract.for_p2pkh_wit(self._key.hash160())
        us_2 = network.contract.for_p2s(us_1)
        tx = self._make_tx(us_2, [us_1])
        self.assertEqual(tx.id(), "1e5d967a3778bfa4e0d90f35f59530e8033a36bd7fd1d9e617c504054b89bd3a")
        tx.check_solution(0)

    def test_validate_p2s_of_p2s_wit_of_p2pkh(self):
        us_1 = network.contract.for_p2pkh(self._key.hash160())
        us_2 = network.contract.for_p2s_wit(us_1)
        us_3 = network.contract.for_p2s(us_2)
        tx = self._make_tx(us_3, [us_1, us_2])
        self.assertEqual(tx.id(), "54a518b82b464744951531270c1bcec133c515fcdbe9d70c6141e067a62ff640")
        tx.check_solution(0)


if __name__ == "__main__":
    unittest.main()
