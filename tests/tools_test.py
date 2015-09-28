#!/usr/bin/env python

import unittest

from pycoin.intbytes import int_to_bytes, bytes_from_ints
from pycoin.tx.script.tools import bin_script
from pycoin.tx.script.vm import eval_script


class ToolsTest(unittest.TestCase):

    def test_bin_script(self):

        def test_bytes(as_bytes):
            script = bin_script([as_bytes])
            stack = []
            eval_script(script, None, stack=stack, disallow_long_scripts=False)
            assert len(stack) == 1
            assert stack[0] == as_bytes

        def test_val(n):
            as_bytes = int_to_bytes(n)
            test_bytes(as_bytes)

        for i in range(100):
            test_val(100)
        for i in range(0xfff0, 0x10004):
            test_val(i)
        for i in range(0xfffff0, 0x1000005):
            test_val(i)

        for l in (1, 2, 3, 254, 255, 256, 257, 258, 0xfff9, 0xfffe, 0xffff, 0x10000, 0x10001, 0x10005):
            for v in (1, 2, 3, 4, 15, 16, 17, 18):
                b = bytes_from_ints([v] * l)
                test_bytes(b)

        b = bytes_from_ints([30] * (0x1000000+1))
        for l in (0x1000000-1, 0x1000000, 0x1000000+1):
            test_bytes(b[:l])

if __name__ == "__main__":
    unittest.main()
