#!/usr/bin/env python

import unittest
import os
import tempfile

class ScriptsTest(unittest.TestCase):

    def launch_tool(self, tool):
        script_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
        cwd = os.getcwd()
        os.chdir(script_dir)
        r = os.system(tool)
        os.chdir(cwd)
        assert r == 0

    def test_simple_tools(self):
        tf1 = tempfile.NamedTemporaryFile()
        tf2 = tempfile.NamedTemporaryFile()
        self.launch_tool("./simple_create_tx.py 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T %s" % tf1.name)
        self.launch_tool("./simple_sign_tx.py %s %s KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn" % (tf1.name, tf2.name))
        self.launch_tool("./dump_tx.py %s %s" % (tf1.name, tf2.name))

    def test_fetch_unspent(self):
        self.launch_tool("./fetch_unspent.py 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T")

    def test_bd(self):
        self.launch_tool("./bd.py 1")
        self.launch_tool("./bd.py 2")

    def test_genwallet(self):
        self.launch_tool("./genwallet.py -g")


def main():
    unittest.main()

if __name__ == "__main__":
    main()
