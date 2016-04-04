import logging
import platform
import struct
import os

from pycoin.block import Block, BlockHeader
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
        self.f = open(full_path, "r+b")
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


def block_info_iterator(start_info, base_dir=None, MAGIC=h2b("f9beb4d9")):
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
    block = BlockHeader.parse(f)
    f.close()
    return block


def locked_blocks_iterator(start_info=(0, 0), cached_headers=50, batch_size=50, base_dir=None,
                           headers_only=False):
    """
    This method loads blocks from disk, skipping any orphan blocks.
    """
    block_class = BlockHeader if headers_only else Block
    f = Blockfiles(base_dir, start_info)
    for initial_location in block_info_iterator(start_info, base_dir):
        f.jump_to(initial_location)
        initial_header = BlockHeader.parse(f)
        break
    index_table = {initial_header.previous_block_hash: (-1, None, None)}
    head_hash = initial_header.previous_block_hash

    max_index = -1
    for info in block_info_iterator(start_info, base_dir):
        bh = blockheader_for_offset_info(info, base_dir)
        t = index_table.get(bh.previous_block_hash)
        if t is None:
            logger.debug("ignoring block with hash %s" % bh.id())
            continue
        (parent_index, info_1, parent_bh) = t
        h = bh.hash()
        index_table[h] = (parent_index + 1, info, bh)
        max_index = max(max_index, parent_index + 1)
        chain_length = max_index - index_table[head_hash][0]
        if chain_length > cached_headers + batch_size:
            last_hash = h
            best_chain = [last_hash]
            while last_hash != head_hash:
                bh = index_table[last_hash][-1]
                if bh is None:
                    break
                last_hash = bh.previous_block_hash
                best_chain.append(last_hash)
            best_chain.reverse()
            for h in best_chain[:cached_headers]:
                (parent_index, info_1, parent_bh) = index_table[h]
                if info_1:
                    f.jump_to(info_1)
                    block = block_class.parse(f)
                    yield block
            index_table = dict((k, index_table.get(k))
                               for k in best_chain[cached_headers:] if k in index_table)
            head_hash = best_chain[cached_headers]
