import logging
import platform
import struct
import os

from pycoin.block import Block
from pycoin.blockchain.BlockChain import BlockChain
from pycoin.encoding.hexbytes import h2b


logger = logging.getLogger(__file__)


# f9beb4d9 (big-endian magic)
# 011d (little-endian size)
# (block data)
# f9beb4d9 (big-endian magic)
# (etc)


class Blockfiles(object):
    def __init__(self, base_dir=None, start_info=(0, 0), MAGIC=h2b("f9beb4d9")):
        if base_dir is None:
            base_dir = self.default_base()
        self.base_dir = base_dir
        self._file_index = None
        self._magic = MAGIC
        self.jump_to(start_info)

    def jump_to(self, start_info):
        file_index, offset = start_info
        if self._file_index != file_index:
            self._file_index = file_index
            full_path = self._path_for_file_index()
            self.f = open(full_path, "rb")
        self.f.seek(offset)

    def close(self):
        self.f.close()

    def default_base(self):
        LOOKUP = dict(Darwin="~/Library/Application Support/Bitcoin/", Linux="~/.bitcoin/")
        system = platform.system()
        path = LOOKUP.get(system)
        if path is None:
            raise ValueError("unknown base path for system %s; you should submit a patch!" % system)
        return os.path.expanduser(path)

    def read(self, N):
        d = self.f.read(N)
        if len(d) >= N:
            return d
        if self._next_file():
            d1 = d + self.f.read(N-len(d))
            return d1
        return b""

    def skip(self, offset):
        while 1:
            cur_pos = self.f.tell()
            self.f.seek(offset, 1)
            new_pos = self.f.tell()
            offset += cur_pos - new_pos
            if offset <= 0:
                break
            if not self.next_file():
                break

    def _path_for_file_index(self):
        return os.path.join(self.base_dir, "blocks", "blk%05d.dat" % self._file_index)

    def _next_file(self):
        self._file_index += 1
        full_path = self._path_for_file_index()
        if not os.path.exists(full_path):
            return False
        self.f.close()
        self.f = open(full_path, "r+b")
        return True

    def next_offset(self, current_offset):
        self.jump_to(current_offset)
        magic = self.read(4)
        if magic == b"\0\0\0\0":
            if not self._next_file():
                return None
            magic = self.read(4)
        if len(magic) == 0:
            return None
        if magic != self._magic:
            offset_info = self.offset_info()
            logger.error("bad magic: %s at %s", magic, offset_info)
            raise ValueError("bad magic at %s" % str(offset_info))
        size = struct.unpack("<L", self.read(4))[0]
        block_offset = self.offset_info()
        self.skip(size)
        next_offset = self.offset_info()
        return block_offset, next_offset

    def offset_info(self):
        return self._file_index, self.f.tell()


def locked_blocks_iterator(blockfile, start_info=(0, 0), cached_headers=50, batch_size=50):
    """
    This method loads blocks from disk, skipping any orphan blocks.
    """
    f = blockfile
    current_state = []

    def change_state(bc, ops):
        for op, bh, work in ops:
            if op == 'add':
                current_state.append(bh)
                pass
            else:
                current_state.pop()
    bc = BlockChain()
    bc.add_change_callback(change_state)
    bhs = []
    index = 0
    info_offset = start_info
    while 1:
        v = blockfile.next_offset(info_offset)
        if v is None:
            break
        block_offset, info_offset = v
        f.jump_to(block_offset)
        bh = Block.parse_as_header(f)
        bh.info = block_offset

        bhs.append(bh)
        if len(bhs) > batch_size:
            bc.add_headers(bhs)
            bhs = []
            if len(current_state) > cached_headers:
                for bh in current_state[:cached_headers]:
                    bh.index = index
                    yield bh
                    index += 1
                    bc.lock_to_index(index)
                current_state = current_state[cached_headers:]
