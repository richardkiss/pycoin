import logging
import platform
import struct
import os

from pycoin.block import Block
from pycoin.blockchain.BlockChain import BlockChain
from pycoin.serialize import h2b


logger = logging.getLogger(__file__)


class Blockfiles(object):
    def __init__(self, base_dir=None, start_info=(0, 0)):
        if base_dir is None:
            base_dir = self.default_base()
        self.base_dir = base_dir
        self.jump_to(start_info)

    def jump_to(self, start_info):
        file_index, offset = start_info
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
        if self.next_file():
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

    def offset_info(self):
        return self._file_index, self.f.tell()


def block_info_iterator(start_info=(0, 0), base_dir=None, MAGIC=h2b("f9beb4d9")):
    f = Blockfiles(base_dir, start_info)
    while 1:
        magic = f.read(4)
        if magic == b"\0\0\0\0":
            if not f._next_file():
                break
            magic = f.read(4)
        if len(magic) == 0:
            break
        size = struct.unpack("<L", f.read(4))[0]
        offset_info = f.offset_info()
        f.skip(size)
        if magic != MAGIC:
            logger.error("bad magic: %s at %s", magic, offset_info)
            raise ValueError("bad magic at %s" % str(offset_info))
        yield offset_info


def blockheader_for_offset_info(offset_info, base_dir=None):
    f = Blockfiles(base_dir, offset_info)
    block = Block.parse_as_header(f)
    f.close()
    return block


def locked_blocks_iterator(start_info=(0, 0), cached_headers=50, batch_size=50, base_dir=None,
                           headers_only=False):
    """
    This method loads blocks from disk, skipping any orphan blocks.
    """
    parse_method = Block.parse_as_header if headers_only else Block.parse
    f = Blockfiles(base_dir, start_info)
    for initial_location in block_info_iterator(start_info, base_dir):
        f.jump_to(initial_location)
        parse_method(f)
        break
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
    for info in block_info_iterator(start_info, base_dir):
        bh = blockheader_for_offset_info(info, base_dir)
        bh.info = info
        bhs.append(bh)
        if len(bhs) > batch_size:
            bc.add_headers(bhs)
            bhs = []
            if len(current_state) > cached_headers:
                for bh in current_state[:cached_headers]:
                    f.jump_to(bh.info)
                    block = parse_method(f)
                    yield block
                    index += 1
                    bc.lock_to_index(index)
                current_state = current_state[cached_headers:]
