import unittest

from pycoin.coins.bitcoin.SolutionChecker import TxContext
from pycoin.coins.bitcoin.VM import BitcoinVM
from pycoin.encoding.hexbytes import h2b
from pycoin.intbytes import int2byte
from pycoin.satoshi.opcodes import OPCODE_LIST
from pycoin.satoshi.IntStreamer import IntStreamer
from pycoin.symbols.btc import network


class ToolsTest(unittest.TestCase):

    def test_compile_push_data_list(self):

        def test_bytes(as_bytes):
            script = network.script.compile_push_data_list([as_bytes])
            # this is a pretty horrible hack to test the vm with long scripts. But it works
            tx_context = TxContext()
            tx_context.signature_for_hash_type_f = None
            tx_context.flags = 0
            tx_context.traceback_f = None
            vm = BitcoinVM(script, tx_context, tx_context.signature_for_hash_type_f, flags=0)
            vm.MAX_SCRIPT_LENGTH = int(1e9)
            vm.MAX_BLOB_LENGTH = int(1e9)
            stack = vm.eval_script()
            assert len(stack) == 1
            assert stack[0] == as_bytes

        def test_val(n):
            as_bytes = IntStreamer.int_to_script_bytes(n)
            test_bytes(as_bytes)

        for i in range(100):
            test_val(100)
        for i in range(0xfff0, 0x10004):
            test_val(i)
        for i in range(0xfffff0, 0x1000005):
            test_val(i)

        for l in (1, 2, 3, 254, 255, 256, 257, 258, 0xfff9, 0xfffe, 0xffff, 0x10000, 0x10001, 0x10005):
            for v in (1, 2, 3, 4, 15, 16, 17, 18):
                b = int2byte(v) * l
                test_bytes(b)

        b = int2byte(30) * (0x1000000+1)
        for l in (0x1000000-1, 0x1000000, 0x1000000+1):
            test_bytes(b[:l])

    def test_compile_decompile(self):
        def check(s):
            b1 = network.script.compile(s)
            s1 = network.script.disassemble(b1)
            b2 = network.script.compile(s1)
            self.assertEqual(s, s1)
            self.assertEqual(b1, b2)

        def build_hex(size, a, b):
            "build some random-looking hex"
            return "[%s]" % "".join("%02x" % (((i+a)*b) & 0xff) for i in range(size))

        check("[ff]")
        check("[ff03]")
        check("[ff030102]")
        check("[55aabbccddeeff112131]")
        long_hex_260 = build_hex(260, 13, 93)
        long_hex_270 = build_hex(270, 11, 47)
        check("%s %s" % (long_hex_260, long_hex_270))
        s = set(x[-1] for x in OPCODE_LIST)
        for opcode, code in OPCODE_LIST:
            # skip reassigned NOPs
            if opcode not in s:
                continue
            if opcode.startswith("OP_PUSHDATA"):
                # these disassemble differently
                continue
            check(opcode)

    def test_tx_7e0114e93f903892b4dff5526a8cab674b2825fd715c4a95f852a1aed634a0f6(self):
        # this tx is from testnet. We add an extra "OP_0" to the end
        # we need to check that the script is being disassembled correctly
        script = h2b(
            "0047304402201f994ca49451bc764fd090f31adb2fa4381b91f967dc05a6f538d4d1ba"
            "aa83cd02206ef3ad06de7890bc4130b4f57401412ca94897ea19b646f794a447237535"
            "1c1f0147304402201f994ca49451bc764fd090f31adb2fa4381b91f967dc05a6f538d4"
            "d1baaa83cd02204655e9eccac412407dfc3e5753a0f2ac605e41c7eb91630dc67137f2"
            "d8081c3a014d0b0152410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d9"
            "59f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d0"
            "8ffb10d4b84104c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b9"
            "5c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe5"
            "2a4104f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
            "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e6724104e4"
            "93dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd1351ed993e"
            "a0d455b75642e2098ea51448d967ae33bfbdfe40cfe97bdc4773992254ae00")

        d1 = network.script.disassemble(script).split()
        self.assertEqual(len(d1), 5)
        self.assertEqual(d1[-1], "OP_0")

    def test_int_to_from_script_bytes(self):
        for i in range(-127, 127):
            self.assertEqual(IntStreamer.int_from_script_bytes(IntStreamer.int_to_script_bytes(i)), i)
        for i in range(-1024, 1024, 16):
            self.assertEqual(IntStreamer.int_from_script_bytes(IntStreamer.int_to_script_bytes(i)), i)
        for i in range(-1024*1024, 1024*1024, 10000):
            self.assertEqual(IntStreamer.int_from_script_bytes(IntStreamer.int_to_script_bytes(i)), i)
        self.assertEqual(IntStreamer.int_to_script_bytes(1), b"\1")
        self.assertEqual(IntStreamer.int_to_script_bytes(127), b"\x7f")
        self.assertEqual(IntStreamer.int_to_script_bytes(128), b"\x80\x00")


if __name__ == "__main__":
    unittest.main()
