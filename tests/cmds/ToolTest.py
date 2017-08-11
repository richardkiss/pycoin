import io
import os
import sys
import tempfile
import unittest

DEFAULT_ENV = {
    "PYCOIN_BTC_PROVIDERS": "blockr.io blockchain.info blockexplorer.com",
    "PATH": os.environ.get("PATH")
}


class ToolTest(unittest.TestCase):

    def invoke_tool(self, args):
        raise NotImplemented

    def launch_tool(self, cmd_line=None, args=None):
        if args is None:
            args = cmd_line.split()
        # capture io
        f = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = f

        self.invoke_tool(args)

        sys.stdout = old_stdout
        output = f.getvalue()
        return output

    def set_cache_dir(self):
        temp_dir = tempfile.mkdtemp()
        os.environ["PYCOIN_CACHE_DIR"] = temp_dir
        return temp_dir
