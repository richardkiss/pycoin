import unittest

from pycoin.cmds import ku
from pycoin.networks.registry import network_for_netcode

from .ToolTest import ToolTest


def make_tests_for_netcode(netcode):

    network = network_for_netcode(netcode)

    class KuTest(ToolTest):

        @classmethod
        def setUpClass(cls):
            cls.parser = ku.create_parser()
            cls.tool_name = "ku"

        def test_ku_create(self):
            output = self.launch_tool("ku create -w -n %s" % netcode).split("\n")
            bip32 = network.parse.bip32_prv(output[0])
            bip32_as_text = bip32.hwif(as_private=True)
            self.assertEqual(output[0], bip32_as_text)

    return KuTest


for netcode in ["BTC", "LTC", "BCH", "DOGE", "XTN"]:
    exec("%sTests = make_tests_for_netcode('%s')" % (netcode, netcode))


def main():
    unittest.main()


if __name__ == "__main__":
    main()
