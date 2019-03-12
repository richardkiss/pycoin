import io
import unittest

from pycoin.encoding.hexbytes import h2b
from pycoin.symbols.btc import network


Block = network.block
Tx = network.tx
flags = network.validator.flags

# block 80971
block_80971_cs = h2b('00000000001126456C67A1F5F0FF0268F53B4F22E0531DC70C7B69746AF69DAC')
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

block_80971 = Block.parse(io.BytesIO(block_80971_data))

COINBASE_PUB_KEY_FROM_80971 = h2b(
    "04cb6b6b4eadc96c7d08b21b29d0ada5f29f9378978cabdb602b8b65da08c8a93caab46"
    "f5abd59889bac704925942dd77a2116d10e0274cad944c71d3d1a670570")
COINBASE_BYTES_FROM_80971 = h2b("04ed66471b02c301")


def standard_tx(coins_from, coins_to):
    txs_in = []
    unspents = []
    for h, idx, tx_out in coins_from:
        txs_in.append(Tx.TxIn(h, idx))
        unspents.append(tx_out)

    txs_out = []
    for coin_value, address in coins_to:
        txs_out.append(Tx.TxOut(coin_value, network.contract.for_address(address)))

    version, lock_time = 1, 0
    tx = Tx(version, txs_in, txs_out, lock_time)
    tx.set_unspents(unspents)
    return tx


class BuildTxTest(unittest.TestCase):

    def test_signature_hash(self):
        compressed = False
        exponent_2 = int("137f3276686959c82b454eea6eefc9ab1b9e45bd4636fb9320262e114e321da1", 16)
        address_2 = network.keys.private(exponent_2, is_compressed=compressed).address()
        key = network.parse.wif("5JMys7YfK72cRVTrbwkq5paxU7vgkMypB55KyXEtN5uSnjV7K8Y")
        exponent = key.secret_exponent()

        public_key_sec = network.keys.private(exponent, is_compressed=compressed).sec()

        the_coinbase_tx = Tx.coinbase_tx(public_key_sec, int(50 * 1e8), COINBASE_BYTES_FROM_80971)
        coins_from = [(the_coinbase_tx.hash(), 0, the_coinbase_tx.txs_out[0])]
        coins_to = [(int(50 * 1e8), address_2)]
        unsigned_coinbase_spend_tx = standard_tx(coins_from, coins_to)

        tx_out_script_to_check = the_coinbase_tx.txs_out[0].script
        idx = 0
        solution_checker = Tx.SolutionChecker(unsigned_coinbase_spend_tx)
        actual_hash = solution_checker._signature_hash(tx_out_script_to_check, idx, hash_type=flags.SIGHASH_ALL)
        self.assertEqual(actual_hash, 29819170155392455064899446505816569230970401928540834591675173488544269166940)

    def test_standard_tx_out(self):
        coin_value = 10
        recipient_address = '1BcJRKjiwYQ3f37FQSpTYM7AfnXurMjezu'
        tx_out = standard_tx([], [(coin_value, recipient_address)]).txs_out[0]
        s = str(tx_out)
        self.assertEqual(
            s,
            'TxOut<0.00010 mbtc "OP_DUP OP_HASH160 [745e5b81fd30ca1e90311b012badabaa4411ae1a]'
            ' OP_EQUALVERIFY OP_CHECKSIG">')

    def test_coinbase_tx(self):
        tx = Tx.coinbase_tx(COINBASE_PUB_KEY_FROM_80971, int(50 * 1e8), COINBASE_BYTES_FROM_80971)
        s = io.BytesIO()
        tx.stream(s)
        tx1 = s.getvalue()
        s = io.BytesIO()
        block_80971.txs[0].stream(s)
        tx2 = s.getvalue()
        self.assertEqual(tx1, tx2)

    def test_tx_out_address(self):
        tx = Tx.coinbase_tx(COINBASE_PUB_KEY_FROM_80971, int(50 * 1e8), COINBASE_BYTES_FROM_80971)
        address = network.address.for_script(tx.txs_out[0].puzzle_script())
        self.assertEqual(address, '1DmapcnrJNGeJB13fv9ngRFX1iRvR4zamn')

    def test_build_spends(self):
        # first, here is the tx database
        TX_DB = {}

        # create a coinbase Tx where we know the public & private key

        key = network.parse.wif("5JMys7YfK72cRVTrbwkq5paxU7vgkMypB55KyXEtN5uSnjV7K8Y")
        exponent = key.secret_exponent()
        compressed = False

        public_key_sec = network.keys.private(exponent, is_compressed=compressed).sec()

        the_coinbase_tx = Tx.coinbase_tx(public_key_sec, int(50 * 1e8), COINBASE_BYTES_FROM_80971)
        TX_DB[the_coinbase_tx.hash()] = the_coinbase_tx

        # now create a Tx that spends the coinbase

        compressed = False

        exponent_2 = int("137f3276686959c82b454eea6eefc9ab1b9e45bd4636fb9320262e114e321da1", 16)
        address_2 = network.keys.private(exponent_2, is_compressed=compressed).address()

        self.assertEqual("12WivmEn8AUth6x6U8HuJuXHaJzDw3gHNZ", address_2)

        coins_from = [(the_coinbase_tx.hash(), 0, the_coinbase_tx.txs_out[0])]
        coins_to = [(int(50 * 1e8), address_2)]
        unsigned_coinbase_spend_tx = standard_tx(coins_from, coins_to)
        solver = network.tx.solve.build_hash160_lookup([exponent])

        coinbase_spend_tx = unsigned_coinbase_spend_tx.sign(solver)

        TX_DB[coinbase_spend_tx.hash()] = coinbase_spend_tx

        # now try to respend from priv_key_2 to priv_key_3

        compressed = True

        exponent_3 = int("f8d39b8ecd0e1b6fee5a340519f239097569d7a403a50bb14fb2f04eff8db0ff", 16)
        address_3 = network.keys.private(exponent_3, is_compressed=compressed).address()

        self.assertEqual("13zzEHPCH2WUZJzANymow3ZrxcZ8iFBrY5", address_3)

        coins_from = [(coinbase_spend_tx.hash(), 0, coinbase_spend_tx.txs_out[0])]
        unsigned_spend_tx = standard_tx(coins_from, [(int(50 * 1e8), address_3)])
        solver.update(network.tx.solve.build_hash160_lookup([exponent_2]))
        spend_tx = unsigned_spend_tx.sign(solver)

        # now check that it validates
        self.assertEqual(spend_tx.bad_solution_count(), 0)


if __name__ == '__main__':
    unittest.main()
