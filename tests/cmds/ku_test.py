import unittest

from pycoin.cmds import ku
from pycoin.coins.bitcoin.networks import BitcoinMainnet

from .ToolTest import ToolTest


# BRAIN DAMAGE
Key = BitcoinMainnet.ui._key_class


class KuTest(ToolTest):

    @classmethod
    def setUpClass(cls):
        cls.parser = ku.create_parser()
        cls.tool_name = "ku"

    def test_ku_create(self):
        output = self.launch_tool("ku create -w").split("\n")
        bip32 = BitcoinMainnet.ui.parse(output[0])
        bip32_as_text = bip32.hwif(as_private=True)
        self.assertEqual(output[0], bip32_as_text)


def main():
    unittest.main()


if __name__ == "__main__":
    main()
