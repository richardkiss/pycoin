
import threading
import unittest

from pycoin.encoding.hexbytes import h2b_rev
from pycoin.services import providers
from pycoin.services.blockchain_info import BlockchainInfoProvider
from pycoin.services.blockcypher import BlockcypherProvider
from pycoin.services.blockexplorer import BlockExplorerProvider
from pycoin.services.chain_so import ChainSoProvider
from pycoin.services.insight import InsightProvider


BLOCK_0_HASH = h2b_rev("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
BLOCK_1_HASH = h2b_rev("00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048")


tx_id_for_net = {
    "BTC": ["b958e4a3ccd5bc8fe0ff6fafd635199313e347b88a8102040c05dd123f32a4f3",
            "d1ef46055a84fd02ee82580d691064780def18614d98646371c3448ca20019ac",
            "69916297f7adde13457b8244e2d704966097e9519ec8fd6f2e7af8c2a60f70f2",
            "c586389e5e4b3acb9d6c8be1c19ae8ab2795397633176f5a6442a261bbdefc3a"],
    "XTN": ["4586e67ee5adcdbc97ed3d2a026ee8703df2ed3553854c186c216e90cd761b69"],
    "DOGE": ["ed7df4e7506ac8447b6983c8ad79da1af86cddda0ff012f7db83e664f61ef6cf"],
    "XDT": ["19dd5c3423e606b5b5dd30b070688bdf9af27fa736e8f3aeb2b68d92a50e67ef"],
}


class ServicesTest(unittest.TestCase):
    def test_env(self):
        CS = "blockchain.info blockexplorer.com chain.so insight:https://hostname/url"
        provider_list = providers.providers_for_config_string(CS, "BTC")
        self.assertEqual(len(provider_list), len(CS.split()))

    def test_thread_provider(self):
        p_list_1 = providers.providers_for_config_string("blockchain.info", "BTC")
        p_list_2 = providers.providers_for_config_string("blockexplorer.com", "BTC")
        providers.set_default_providers_for_netcode("BTC", p_list_1)
        self.assertEqual(providers.get_default_providers_for_netcode("BTC"), p_list_1)
        # use a dictionary so it can be mutable in the subthread
        d = {"is_ok": False}

        def subthread():
            providers.set_default_providers_for_netcode("BTC", [])
            self.assertEqual(providers.get_default_providers_for_netcode("BTC"), [])
            providers.set_default_providers_for_netcode("BTC", p_list_2)
            self.assertEqual(providers.get_default_providers_for_netcode("BTC"), p_list_2)
            d["is_ok"] = True
        t = threading.Thread(target=subthread)
        t.start()
        t.join()
        self.assertTrue(d["is_ok"])
        self.assertEqual(providers.get_default_providers_for_netcode("BTC"), p_list_1)

    def check_provider_tx_for_tx_hash(self, p, networks):
        for net in networks:
            b = p(net)
            for tx_id in tx_id_for_net[net]:
                tx = b.tx_for_tx_hash(h2b_rev(tx_id))
                self.assertEqual(tx.id(), tx_id)

    def test_BitcoindProvider(self):
        # not sure what to do here, as there is no open bitcoind provider I know of
        pass

    def test_BlockchainInfo(self):
        self.check_provider_tx_for_tx_hash(BlockchainInfoProvider, ["BTC"])

    @unittest.skip("this test is not working for some reason")
    def test_BlockCypherProvider(self):
        self.check_provider_tx_for_tx_hash(BlockcypherProvider, ["BTC", "XTN"])

    @unittest.skip("this test is not working for some reason")
    def test_BlockExplorerProvider(self):
        self.check_provider_tx_for_tx_hash(BlockExplorerProvider, ["BTC"])

    @unittest.skip("this test is causing problems in travis-ci because chain_so thinks it's a DOS attack")
    def test_ChainSoProvider(self):
        self.check_provider_tx_for_tx_hash(ChainSoProvider, ["BTC", "XTN", "DOGE", "XDT"])

    def test_InsightProvider(self):
        provider = InsightProvider("http://insight.bitpay.com/api/")
        self.check_provider_tx_for_tx_hash(lambda x: provider, ["BTC"])
        provider.get_blockchain_tip()
        h = provider.get_blockheader(BLOCK_1_HASH)
        assert h.previous_block_hash == BLOCK_0_HASH
        height = provider.get_block_height(BLOCK_1_HASH)
        assert height == 1


def main():
    unittest.main()


if __name__ == "__main__":
    main()
