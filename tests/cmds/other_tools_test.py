import unittest
import os
import sys
import tempfile

from pycoin.cmds import fetch_unspent

from .ToolTest import ToolTest, DEFAULT_ENV


class FetchUnspentTest(ToolTest):

    tool_name = "fetch_unspent"
    parser = fetch_unspent.create_parser()

    def invoke_tool(self, args):
        fetch_unspent.fetch_unspent(self.parser.parse_args(args[1:]))

    def test_fetch_unspent(self):
        self.launch_tool("fetch_unspent.py 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T")


def main():
    unittest.main()

if __name__ == "__main__":
    main()
