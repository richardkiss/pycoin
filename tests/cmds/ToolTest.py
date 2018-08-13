import os
import shlex
import sys
import tempfile
import unittest

try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO

from pycoin.cmds import block, ku, msg, tx, coinc


DEFAULT_ENV = {
    "PYCOIN_BTC_PROVIDERS": "blockchain.info blockexplorer.com",
    "PATH": os.environ.get("PATH")
}


TOOL_LOOKUP = {
    "tx": (tx.create_parser(), tx.tx),
    "ku": (ku.create_parser(), ku.ku),
    "msg": (msg.create_parser(), msg.msg),
    "block": (block.create_parser(), block.block),
    "coinc": (coinc.create_parser(), coinc.coinc),
}


class ToolTest(unittest.TestCase):

    def invoke_tool(self, args):
        tool_name = args[0]
        parser, main = TOOL_LOOKUP[tool_name]
        return main(parser.parse_args(args[1:]), parser)

    def launch_tool(self, cmd_line=None, args=None, env=None):
        if args is None:
            args = shlex.split(cmd_line)

        new_environ = dict(env or {})
        new_environ.update(DEFAULT_ENV)

        # capture io
        new_stdout = StringIO()
        old_stdout = sys.stdout
        old_environ = os.environ

        os.environ = new_environ
        sys.stdout = new_stdout

        self.invoke_tool(args)

        sys.stdout = old_stdout
        os.environ = old_environ
        output = new_stdout.getvalue()
        return output

    def set_cache_dir(self):
        temp_dir = tempfile.mkdtemp()
        return temp_dir
