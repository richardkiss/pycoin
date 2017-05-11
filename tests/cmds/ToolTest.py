
import os
import subprocess
import sys
import tempfile
import unittest

DEFAULT_ENV = {
    "PYCOIN_BTC_PROVIDERS": "blockr.io blockchain.info blockexplorer.com",
    "PATH": os.environ.get("PATH")
}


class ToolTest(unittest.TestCase):

    def get_tempdir(self):
        return tempfile.mkdtemp()

    def launch_tool(self, cmd_line=None, args=None, env=DEFAULT_ENV):
        python_path = sys.executable
        script_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "pycoin", "cmds"))
        if args is None:
            args = cmd_line.split()
        script_path = os.path.join(script_dir, args[0])
        output = subprocess.check_output([python_path, script_path] + args[1:], env=env)
        return output.decode("utf8")

    def set_cache_dir(self):
        temp_dir = tempfile.mkdtemp()
        return {"PYCOIN_CACHE_DIR": temp_dir}
