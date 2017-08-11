import unittest
import os
import sys
import tempfile

from pycoin.cmds import fetch_unspent, cache_tx

from .ToolTest import ToolTest, DEFAULT_ENV


class FetchUnspentTest(ToolTest):

    tool_name = "fetch_unspent"
    parser = fetch_unspent.create_parser()

    def invoke_tool(self, args):
        fetch_unspent.fetch_unspent(self.parser.parse_args(args[1:]))

    def test_fetch_unspent(self):
        self.launch_tool("fetch_unspent.py 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T")


class CacheTxTest(ToolTest):

    tool_name = "cache_tx"
    parser = cache_tx.create_parser()

    def invoke_tool(self, args):
        cache_tx.cache_tx(self.parser.parse_args(args[1:]), self.parser)

    def test_cache_tx(self):
        the_dir = self.set_cache_dir()
        tx_id = "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
        self.launch_tool("cache_tx.py %s" % tx_id)
        self.assertTrue(os.path.exists(os.path.join(the_dir, "txs", "%s_tx.bin" % tx_id)))


def main():
    unittest.main()

if __name__ == "__main__":
    main()
