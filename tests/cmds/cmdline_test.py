import unittest
import os
import tempfile

from .ToolTest import ToolTest


# If the REPAIR_FAILURES environment variable is set, any tests failing due to wrong
# output will be corrected. Be sure to do a "git diff" to validate that you're
# getting changes you expect.

REPAIR_FAILURES = os.getenv("REPAIR_FAILURES", 0)


def get_test_cases():
    TESTS_PATH = os.path.join(os.path.dirname(__file__), "test_cases")
    paths = []
    for dirpath, dirnames, filenames in os.walk(TESTS_PATH):
        for fn in filenames:
            if fn.endswith(".txt") and fn[0] != '.':
                paths.append(os.path.join(dirpath, fn))
    paths.sort()
    test_cases = []
    for p in paths:
        with open(p) as f:
            # allow "#" comments at the beginning of the file
            comments = []
            while 1:
                cmd = f.readline()
                if cmd[0] != '#':
                    break
                comments.append(cmd)
            expected_output = f.read()
            test_name = os.path.relpath(
                p, TESTS_PATH).replace(".", "_").replace("/", "_")
            test_cases.append((test_name, cmd, expected_output, comments, p))
    return test_cases


class CmdlineTest(ToolTest):
    pass


def make_f(cmd, expected_output, comments, path):

    def f(self):
        CACHE_DIR = tempfile.mkdtemp()
        old_environ = dict(os.environ)
        new_environ = dict(PYCOIN_CACHE_DIR=CACHE_DIR)
        for k in "PATH PYCOIN_BTC_PROVIDERS".split():
            new_environ[k] = os.environ.get(k, "")
        os.environ = new_environ
        os.chdir(CACHE_DIR)
        for c in cmd.split(";"):
            actual_output = self.launch_tool(c)
        if actual_output != expected_output:
            print(cmd)
            print(actual_output)
            print(expected_output)
            if REPAIR_FAILURES:
                f = open(path, "w")
                f.write(''.join(comments))
                f.write(cmd)
                f.write(actual_output)
                f.close()
        os.environ = old_environ
        self.assertEqual(expected_output, actual_output)
    return f


def inject():
    for idx, (name, i, o, comments, path) in enumerate(get_test_cases()):
        name_of_f = "test_%s" % name
        setattr(CmdlineTest, name_of_f, make_f(i, o, comments, path))
        print("adding %s" % name_of_f)


inject()


def main():
    unittest.main()


if __name__ == "__main__":
    main()
