#!/usr/bin/env python

import unittest
import os
import subprocess
import sys
import tempfile

from .ToolTest import ToolTest


def get_test_cases():
    TESTS_PATH = os.path.join(os.path.dirname(__file__), "test_cases")
    paths = []
    for dirpath, dirnames, filenames in os.walk(TESTS_PATH):
        for fn in filenames:
            paths.append(os.path.join(dirpath, fn))
    paths.sort()
    l = []
    for p in paths:
        with open(p) as f:
            cmd = f.readline()[:-1]
            expected_output = f.read()[:-1]
            test_name = os.path.relpath(
                p, TESTS_PATH).replace(".", "_").replace("/", "_")
            l.append((test_name, cmd, expected_output))
    return l


class CmdlineTest(ToolTest):
    pass


CACHE_DIR = tempfile.mkdtemp()


def make_f(cmd, expected_output):

    def f(self):
        env = dict(PYCOIN_CACHE_DIR=CACHE_DIR)
        os.chdir(CACHE_DIR)
        actual_output = self.launch_tool(cmd, env=env)
        if actual_output != expected_output:
            print(repr(cmd))
            print(repr(actual_output))
            print(repr(expected_output))
        self.assertEqual(expected_output, actual_output)
    return f


def inject():
    for idx, (name, i, o) in enumerate(get_test_cases()):
        name_of_f = "test_%s" % name
        setattr(CmdlineTest, name_of_f, make_f(i, o))
        print("adding %s" % name_of_f)

inject()


def main():
    unittest.main()

if __name__ == "__main__":
    main()
