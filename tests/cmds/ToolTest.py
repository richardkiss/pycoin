import io
import os
import sys
import tempfile
import unittest

from pycoin.cmds import ku, tx


DEFAULT_ENV = {
    "PYCOIN_BTC_PROVIDERS": "blockr.io blockchain.info blockexplorer.com",
    "PATH": os.environ.get("PATH")
}


TOOL_LOOKUP = {
    "tx" : (tx.create_parser(), tx.tx),
    "ku" : (ku.create_parser(), lambda args, parser: ku.ku(args))
}



class ToolTest(unittest.TestCase):

    def invoke_tool(self, args):
        tool_name = args[0]
        parser, main = TOOL_LOOKUP[tool_name]
        return main(parser.parse_args(args[1:]), parser)

    def launch_tool(self, cmd_line=None, args=None, env=None):
        if args is None:
            args = cmd_line.split()

        new_environ = dict(env or {})
        new_environ.update(DEFAULT_ENV)

        # capture io
        new_stdout = io.StringIO()
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
