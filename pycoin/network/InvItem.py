from ..serialize import b2h_rev
from ..serialize.bitcoin_streamer import parse_struct, stream_struct

ITEM_TYPE_TX, ITEM_TYPE_BLOCK = (1, 2)


class InvItem(object):
    def __init__(self, item_type, data):
        self.item_type = item_type
        self.data = data

    def __str__(self):
        INV_TYPES = [None, "Tx", "Block"]
        return "%s [%s]" % (INV_TYPES[self.item_type], b2h_rev(self.data))

    def __repr__(self):
        return str(self)

    def __hash__(self):
        return hash(self.data)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.item_type == other.item_type and self.data == other.data
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def stream(self, f):
        stream_struct("L#", f, self.item_type, self.data)

    @classmethod
    def parse(self, f):
        return self(*parse_struct("L#", f))
