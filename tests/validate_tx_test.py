#!/usr/bin/env python

import binascii
import io
import unittest

from pycoin.block import Block
from pycoin.serialize import h2b
from pycoin.tx import Tx, ValidationFailureError
from pycoin.tx.script import tools


class ValidatingTest(unittest.TestCase):
    def test_validate(self):
        # block 80971
        block_80971_cs = h2b('00000000001126456C67A1F5F0FF0268F53B4F22E0531DC70C7B69746AF69DAC')
        block_80971_data = h2b('01000000950A1631FB9FAC411DFB173487B9E18018B7C6F7147E78C06258410000000000A881352F97F14B'\
        'F191B54915AE124E051B8FE6C3922C5082B34EAD503000FC34D891974CED66471B4016850A040100'\
        '0000010000000000000000000000000000000000000000000000000000000000000000FFFFFFFF080'\
        '4ED66471B02C301FFFFFFFF0100F2052A01000000434104CB6B6B4EADC96C7D08B21B29D0ADA5F29F937'\
        '8978CABDB602B8B65DA08C8A93CAAB46F5ABD59889BAC704925942DD77A2116D10E0274CAD944C71D3D1A'\
        '670570AC0000000001000000018C55ED829F16A4E43902940D3D33005264606D5F7D555B5F67EE4C033390'\
        'C2EB010000008A47304402202D1BF606648EDCDB124C1254930852D99188E1231715031CBEAEA80CCFD2B39A'\
        '02201FA9D6EE7A1763580E342474FC1AEF59B0468F98479953437F525063E25675DE014104A01F763CFBF5E518'\
        'C628939158AF3DC0CAAC35C4BA7BC1CE8B7E634E8CDC44E15F0296B250282BD649BAA8398D199F2424FCDCD88'\
        'D3A9ED186E4FD3CB9BF57CFFFFFFFFF02404B4C00000000001976A9148156FF75BEF24B35ACCE3C05289A241'\
        '1E1B0E57988AC00AA38DF010000001976A914BC7E692A5FFE95A596712F5ED83393B3002E452E88AC000000'\
        '0001000000019C97AFDF6C9A31FFA86D71EA79A079001E2B59EE408FD418498219400639AC0A010000008B4'\
        '830450220363CFFAE09599397B21E6D8A8073FB1DFBE06B6ACDD0F2F7D3FEA86CA9C3F605022100FA255A6ED'\
        '23FD825C759EF1A885A31CAD0989606CA8A3A16657D50FE3CEF5828014104FF444BAC08308B9EC97F56A652A'\
        'D8866E0BA804DA97868909999566CB377F4A2C8F1000E83B496868F3A282E1A34DF78565B65C15C3FA21A076'\
        '3FD81A3DFBBB6FFFFFFFF02C05EECDE010000001976A914588554E6CC64E7343D77117DA7E01357A6111B798'\
        '8AC404B4C00000000001976A914CA6EB218592F289999F13916EE32829AD587DBC588AC00000000010000000'\
        '1BEF5C9225CB9FE3DEF929423FA36AAD9980B9D6F8F3070001ACF3A5FB389A69F000000004A493046022100F'\
        'B23B1E2F2FB8B96E04D220D385346290A9349F89BBBC5C225D5A56D931F8A8E022100F298EB28294B90C1BAF'\
        '319DAB713E7CA721AAADD8FCC15F849DE7B0A6CF5412101FFFFFFFF0100F2052A010000001976A9146DDEA80'\
        '71439951115469D0D2E2B80ECBCDD48DB88AC00000000');

        # block 80974
        block_80974_cs = h2b('0000000000089F7910F6755C10EA2795EC368A29B435D80770AD78493A6FECF1')
        block_80974_data = h2b('010000007480150B299A16BBCE5CCDB1D1BBC65CFC5893B01E6619107C55200000000000790'\
        '0A2B203D24C69710AB6A94BEB937E1B1ADD64C2327E268D8C3E5F8B41DBED8796974CED66471B204C3247030'\
        '1000000010000000000000000000000000000000000000000000000000000000000000000FFFFFFFF0804ED6'\
        '6471B024001FFFFFFFF0100F2052A010000004341045FEE68BAB9915C4EDCA4C680420ED28BBC369ED84D48A'\
        'C178E1F5F7EEAC455BBE270DABA06802145854B5E29F0A7F816E2DF906E0FE4F6D5B4C9B92940E4F0EDAC000'\
        '000000100000001F7B30415D1A7BF6DB91CB2A272767C6799D721A4178AA328E0D77C199CB3B57F010000008'\
        'A4730440220556F61B84F16E637836D2E74B8CB784DE40C28FE3EF93CCB7406504EE9C7CAA5022043BD4749D'\
        '4F3F7F831AC696748AD8D8E79AEB4A1C539E742AA3256910FC88E170141049A414D94345712893A828DE57B4C'\
        '2054E2F596CDCA9D0B4451BA1CA5F8847830B9BE6E196450E6ABB21C540EA31BE310271AA00A49ED0BA930743'\
        'D1ED465BAD0FFFFFFFF0200E1F505000000001976A914529A63393D63E980ACE6FA885C5A89E4F27AA08988AC'\
        'C0ADA41A000000001976A9145D17976537F308865ED533CCCFDD76558CA3C8F088AC000000000100000001651'\
        '48D894D3922EF5FFDA962BE26016635C933D470C8B0AB7618E869E3F70E3C000000008B48304502207F5779EB'\
        'F4834FEAEFF4D250898324EB5C0833B16D7AF4C1CB0F66F50FCF6E85022100B78A65377FD018281E77285EFC3'\
        '1E5B9BA7CB7E20E015CF6B7FA3E4A466DD195014104072AD79E0AA38C05FA33DD185F84C17F611E58A8658CE'\
        '996D8B04395B99C7BE36529CAB7606900A0CD5A7AEBC6B233EA8E0FE60943054C63620E05E5B85F0426FFFFF'\
        'FFF02404B4C00000000001976A914D4CAA8447532CA8EE4C80A1AE1D230A01E22BFDB88AC8013A0DE0100000'\
        '01976A9149661A79AE1F6D487AF3420C13E649D6DF3747FC288AC00000000')

        block_80971 = Block.parse(io.BytesIO(block_80971_data))
        block_80974 = Block.parse(io.BytesIO(block_80974_data))

        tx_db = { tx.hash(): tx for tx in block_80971.txs }

        tx_to_validate = block_80974.txs[2]
        self.assertEqual("OP_DUP OP_HASH160 d4caa8447532ca8ee4c80a1ae1d230a01e22bfdb OP_EQUALVERIFY OP_CHECKSIG",
            tools.disassemble(tx_to_validate.txs_out[0].script))
        self.assertEqual(tx_to_validate.id(), "7c4f5385050c18aa8df2ba50da566bbab68635999cc99b75124863da1594195b")

        tx_to_validate.unspents_from_db(tx_db)
        self.assertEqual(tx_to_validate.bad_signature_count(), 0)

        # now, let's corrupt the Tx and see what happens
        tx_out = tx_to_validate.txs_out[1]

        disassembly = tools.disassemble(tx_out.script)
        tx_out.script = tools.compile(disassembly)

        self.assertEqual(tx_to_validate.bad_signature_count(), 0)

        disassembly = disassembly.replace("9661a79ae1f6d487af3420c13e649d6df3747fc2", "9661a79ae1f6d487af3420c13e649d6df3747fc3")

        tx_out.script = tools.compile(disassembly)

        self.assertEqual(tx_to_validate.bad_signature_count(), 1)
        self.assertFalse(tx_to_validate.is_signature_ok(0))

    def test_validate_two_inputs(self):
        def tx_from_b64(h):
            f = io.BytesIO(binascii.a2b_base64(h.encode("utf8")))
            return Tx.parse(f)
        # c9989d984c97128b03b9f118481c631c584f7aa42b578dbea6194148701b053d
        # This is the one we're going to validate. It has inputs from
        #  tx_1 = b52201c2741d410b70688335afebba0d58f8675fa9b6c8c54becb0d7c0a75983
        # and tx_2 = 72151f65db1d8594df90778639a4c0c17c1e303af01de0d04af8fac13854bbfd
        #
        TX_0_HEX = """
AQAAAAKDWafA17DsS8XItqlfZ/hYDbrrrzWDaHALQR10wgEitQAAAACLSDBFAiAnyvQ1P7b8
+84JbBUbE1Xtgrd0KNpD4eyVTNU/burbtgIhAOS8T1TrhXkGXQTGbLSEJy5uvZMGEzOjITxO
+DrykiPlAUEE3yJcIB5OCpaDjrop+N3bm8h9PKw8bF/YB4v3yD+VeQf4fXdUZ9hJJSnFeJ+Q
eJrC7q3Y23QSYeYbW/AfA3D5G//////9u1Q4wfr4StDgHfA6MB58wcCkOYZ3kN+UhR3bZR8V
cgAAAACLSDBFAiAN6ZQr+9HTgmF57EsPyXIhQ6J5M4lgwlj/tJTShZ+toQIhAL0U1i9yiCEm
75uCEp8uRaySqS7P4x7A+L2Vr5kS+7ANAUEEkSqVI6gw1scM0GuJWgMh4jpWKJA0yOl03uQa
V/jHURn+HswOIORzvsG9qQY1/9BZgDPaMuI5U5JlyA3WkhLxgf////8CtkSUzxAAAAAZdqkU
LXTu3lp2t/wMSuvqbifOSj9/kvmIrAAoa+4AAAAAGXapFF3ySpVdjz9V8fRKvzDqXQRcmowS
iKwAAAAA"""
        TX_1_HEX = """AQAAAAEL3YmFDcZpf4SH7uN1IBmMoBd4OhmTp4EAQ8A0ZQ3tiwAAAACKRzBEAiA4Fkl8lkJS
eLtWHsp1j0h7y0KKFmqxhDR0CK0HnmZWBQIgDSTDenor3zbNqTs+FApeDl8DKCz1xGQCJQN0
/sp00VABQQQzSNc33wdDXA/F9y9/hAR88q6Se6vRCHEC7dYgbIp1pgxqGzrWXQroGkQLhnAb
n/fDhUoVbCgM/UHXYmjXlhdO/////wI3HGlfEQAAABl2qRRM+dhUVUjeAlb0jEsHJrFClGGS
Z4isMAYVCgAAAAAZdqkUgnSLXoYTeOKFFRdtLYxWcGZ2Ht2IrAAAAAA=
"""
        TX_2_HEX = """AQAAAAFDjBbw61AYUWMx+3moZ2vb9dvLKydOSFIwcfBTjG0QSgEAAACKRzBEAiA5WWKhR48O
I60ZDCXnOru/FH6NvuTGhRLggjbpJB2dhgIgKp0FFL0ClSCxxqGjYneDinvgROGSw6DtVtvf
lrhaom8BQQR50YjAg1e5qRkP4ER29ec5jKfzk3DHJhS7Si0sEbvNIJMfjjbZfZWtJi15wHZh
uHh4e3G6SWMdJLHH5pgbseFh/////wLPE5deAAAAABl2qRSmRdbMvv5fEbgFD1YktaBU9zQT
W4iswJ7mBQAAAAAZdqkU4E5+Is4tr+8bPU6ELYHSvz/Ng0eIrAAAAAA=
"""
        tx_0 = tx_from_b64(TX_0_HEX)
        self.assertEqual(tx_0.id(), "c9989d984c97128b03b9f118481c631c584f7aa42b578dbea6194148701b053d")
        tx_1 = tx_from_b64(TX_1_HEX)
        self.assertEqual(tx_1.id(), "b52201c2741d410b70688335afebba0d58f8675fa9b6c8c54becb0d7c0a75983")
        tx_2 = tx_from_b64(TX_2_HEX)
        self.assertEqual(tx_2.id(), "72151f65db1d8594df90778639a4c0c17c1e303af01de0d04af8fac13854bbfd")

        TX_DB = { tx.hash(): tx for tx in [tx_0, tx_1, tx_2] }

        tx_to_validate = tx_0
        self.assertEqual("OP_DUP OP_HASH160 2d74eede5a76b7fc0c4aebea6e27ce4a3f7f92f9 OP_EQUALVERIFY OP_CHECKSIG",
            tools.disassemble(tx_to_validate.txs_out[0].script))
        self.assertEqual(tx_to_validate.id(), "c9989d984c97128b03b9f118481c631c584f7aa42b578dbea6194148701b053d")

        tx_to_validate.unspents_from_db(TX_DB)
        self.assertEqual(tx_to_validate.bad_signature_count(), 0)

        # now let's mess with signatures
        disassembly = tools.disassemble(tx_to_validate.txs_in[0].script)
        tx_to_validate.txs_in[0].script = tools.compile(disassembly)
        self.assertEqual(tx_to_validate.bad_signature_count(), 0)
        disassembly = disassembly.replace("353fb6fcfbce09", "353fb6fcfbce19")
        tx_to_validate.txs_in[0].script = tools.compile(disassembly)
        self.assertEqual(tx_to_validate.bad_signature_count(), 1)
        self.assertFalse(tx_to_validate.is_signature_ok(0))

        tx_to_validate = tx_from_b64(TX_0_HEX)
        tx_to_validate.unspents_from_db(TX_DB)
        self.assertEqual(tx_to_validate.bad_signature_count(), 0)
        disassembly = tools.disassemble(tx_to_validate.txs_in[1].script)
        disassembly = disassembly.replace("960c258ffb494d2859f", "960d258ffb494d2859f")
        tx_to_validate.txs_in[1].script = tools.compile(disassembly)
        self.assertEqual(tx_to_validate.bad_signature_count(), 1)
        self.assertFalse(tx_to_validate.is_signature_ok(1))

        # futz with signature on tx_1
        tx_to_validate = tx_from_b64(TX_0_HEX)
        original_tx_hash = tx_1.hash()
        disassembly = tools.disassemble(tx_1.txs_out[0].script)
        disassembly = disassembly.replace("4cf9d8545548de0256f48c4b0726b14294619267", "4cf9d8545548de1256f48c4b0726b14294619267")
        tx_1.txs_out[0].script = tools.compile(disassembly)
        TX_DB[original_tx_hash] = tx_1
        tx_to_validate.unspents_from_db(TX_DB, ignore_missing=True)
        self.assertEqual(tx_to_validate.bad_signature_count(), 1)
        self.assertFalse(tx_to_validate.is_signature_ok(0, ))

        # fix it up again
        TX_DB[original_tx_hash] = tx_from_b64(TX_1_HEX)
        tx_to_validate.unspents_from_db(TX_DB)
        self.assertEqual(tx_to_validate.bad_signature_count(), 0)

        # futz with signature on tx_2
        tx_to_validate = tx_from_b64(TX_0_HEX)
        original_tx_hash = tx_2.hash()
        disassembly = tools.disassemble(tx_2.txs_out[0].script)
        disassembly = disassembly.replace("a645d6ccbefe5f11b8050f5624b5a054f734135b", "a665d6ccbefe5f11b8050f5624b5a054f734135b")
        tx_2.txs_out[0].script = tools.compile(disassembly)
        TX_DB[original_tx_hash] = tx_2
        tx_to_validate.unspents_from_db(TX_DB, ignore_missing=True)
        self.assertEqual(tx_to_validate.bad_signature_count(), 1)
        self.assertFalse(tx_to_validate.is_signature_ok(1))

        # fix it up again
        TX_DB[original_tx_hash] = tx_from_b64(TX_2_HEX)
        tx_to_validate.unspents_from_db(TX_DB)
        self.assertEqual(tx_to_validate.bad_signature_count(), 0)

if __name__ == "__main__":
    unittest.main()
