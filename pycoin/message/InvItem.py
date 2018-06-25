import functools

from pycoin.encoding.hexbytes import b2h_rev
from pycoin.satoshi.satoshi_struct import parse_struct, stream_struct

ITEM_TYPE_TX = 1
ITEM_TYPE_BLOCK = 2
ITEM_TYPE_MERKLEBLOCK = 3
INV_CMPCT_BLOCK = 4

INV_WITNESS_FLAG = 1 << 30
INV_TYPE_MASK = 0xffffffff >> 2


@functools.total_ordering
class InvItem(object):
    def __init__(self, item_type, data, dont_check=False):
        if not dont_check:
            assert item_type in (ITEM_TYPE_TX, ITEM_TYPE_BLOCK, ITEM_TYPE_MERKLEBLOCK)
        self.item_type = item_type
        assert isinstance(data, bytes)
        assert len(data) == 32
        self.data = data

    def __str__(self):
        INV_TYPES = ["?", "Tx", "Block", "Merkle"]
        idx = self.item_type
        if not 0 < idx < 4:
            idx = 0
        return "InvItem %s [%s]" % (INV_TYPES[idx], b2h_rev(self.data))

    def __repr__(self):
        return str(self)

    def __hash__(self):
        return hash((self.item_type, self.data))

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.item_type == other.item_type and self.data == other.data
        return False

    def __lt__(self, other):
        return (self.item_type, self.data) < (other.item_type, other.data)

    def stream(self, f):
        stream_struct("L#", f, self.item_type, self.data)

    @classmethod
    def parse(self, f):
        return self(*parse_struct("L#", f), dont_check=True)
