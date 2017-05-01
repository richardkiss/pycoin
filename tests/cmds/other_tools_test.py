#!/usr/bin/env python

import unittest
import os
import sys
import tempfile

from .ToolTest import ToolTest, DEFAULT_ENV


class OtherToolsTest(ToolTest):

    def test_fetch_unspent(self):
        self.launch_tool("fetch_unspent.py 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T")

    def test_cache_tx(self):
        env = self.set_cache_dir()
        the_dir = env["PYCOIN_CACHE_DIR"]
        env.update(DEFAULT_ENV)
        tx_id = "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
        self.launch_tool("cache_tx.py %s" % tx_id, env=env)
        self.assertTrue(os.path.exists(os.path.join(the_dir, "txs", "%s_tx.bin" % tx_id)))


def main():
    unittest.main()

if __name__ == "__main__":
    main()
