#!/usr/bin/env python

import threading
import unittest

from pycoin.services import providers

class ServicesTest(unittest.TestCase):
    def test_env(self):
        CS = "blockchain.info blockexplorer.com blockr.io chain.so insight:https://hostname/url bitcoinrpc://user:passwd@hostname:8334"
        provider_list = providers.providers_for_config_string(CS, "BTC")
        self.assertEqual(len(provider_list), len(CS.split()))

    def test_thread_provider(self):
        p_list_1 = providers.providers_for_config_string("blockchain.info", "BTC")
        p_list_2 = providers.providers_for_config_string("blockexplorer.com", "BTC")
        providers.set_default_providers_for_netcode("BTC", p_list_1)
        self.assertEqual(providers.get_default_providers_for_netcode("BTC"), p_list_1)
        l = { "is_ok": False }
        def subthread():
            providers.set_default_providers_for_netcode("BTC", [])
            self.assertEqual(providers.get_default_providers_for_netcode("BTC"), [])
            providers.set_default_providers_for_netcode("BTC", p_list_2)
            self.assertEqual(providers.get_default_providers_for_netcode("BTC"), p_list_2)
            l["is_ok"] = True
        t = threading.Thread(target=subthread)
        t.start()
        t.join()
        self.assertTrue(l["is_ok"])
        self.assertEqual(providers.get_default_providers_for_netcode("BTC"), p_list_1)


def main():
    unittest.main()

if __name__ == "__main__":
    main()
