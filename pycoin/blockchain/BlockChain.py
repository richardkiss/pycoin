import logging
import weakref

from pycoin.encoding.hexbytes import b2h_rev

from .ChainFinder import ChainFinder

logger = logging.getLogger(__name__)
ZERO_HASH = b'\0' * 32


def _update_q(q, ops):
    # first, we meld out complimentary adds and removes
    while len(ops) > 0:
        op = ops[0]
        if op[0] != 'remove':
            break
        last = q.pop()
        if op[1:] != last[1:]:
            q.put_nowait(last)
            break
        ops = ops[1:]
    for op in ops:
        q.put_nowait(op)


class BlockChain(object):
    def __init__(self, parent_hash=ZERO_HASH, unlocked_block_storage={}, did_lock_to_index_f=None):
        self.parent_hash = parent_hash
        self.hash_to_index_lookup = {}
        self.weight_lookup = {}
        self.chain_finder = ChainFinder()
        self.change_callbacks = weakref.WeakSet()
        self._longest_chain_cache = None
        self.did_lock_to_index_f = did_lock_to_index_f
        self.unlocked_block_storage = unlocked_block_storage

        self._locked_chain = []

    def preload_locked_blocks(self, headers_iter):
        self._locked_chain = []
        the_hash = self.parent_hash
        for idx, h in enumerate(headers_iter):
            the_hash = h.hash()
            self._locked_chain.append((the_hash, h.previous_block_hash, h.difficulty))
            self.hash_to_index_lookup[the_hash] = idx
        self.parent_hash = the_hash

    def is_hash_known(self, the_hash):
        return the_hash in self.hash_to_index_lookup

    def length(self):
        return len(self._longest_local_block_chain()) + len(self._locked_chain)

    def locked_length(self):
        return len(self._locked_chain)

    def unlocked_length(self):
        return len(self._longest_local_block_chain())

    def tuple_for_index(self, index):
        if index < 0:
            index = self.length() + index
        size = len(self._locked_chain)
        if index < size:
            return self._locked_chain[index]
        index -= size

        longest_chain = self._longest_local_block_chain()
        the_hash = longest_chain[-index-1]
        parent_hash = self.parent_hash if index <= 0 else self._longest_chain_cache[-index]
        weight = self.weight_lookup.get(the_hash)
        return (the_hash, parent_hash, weight)

    def last_block_hash(self):
        if self.length() == 0:
            return self.parent_hash
        return self.hash_for_index(-1)

    def hash_for_index(self, index):
        return self.tuple_for_index(index)[0]

    def index_for_hash(self, the_hash):
        return self.hash_to_index_lookup.get(the_hash)

    def add_change_callback(self, callback):
        self.change_callbacks.add(callback)

    def lock_to_index(self, index):
        old_length = len(self._locked_chain)
        index -= old_length
        longest_chain = self._longest_local_block_chain()
        if index < 1:
            return
        excluded = set()
        for idx in range(index):
            the_hash = longest_chain[-idx-1]
            parent_hash = self.parent_hash if idx <= 0 else self._longest_chain_cache[-idx]
            weight = self.weight_lookup.get(the_hash)
            item = (the_hash, parent_hash, weight)
            self._locked_chain.append(item)
            excluded.add(the_hash)
        if self.did_lock_to_index_f:
            self.did_lock_to_index_f(self._locked_chain[old_length:old_length+index], old_length)
        old_chain_finder = self.chain_finder
        self.chain_finder = ChainFinder()
        self._longest_chain_cache = None

        def iterate():
            for tree in old_chain_finder.trees_from_bottom.values():
                for c in tree:
                    if c in excluded:
                        break
                    excluded.add(c)
                    if c in old_chain_finder.parent_lookup:
                        yield (c, old_chain_finder.parent_lookup[c])
        self.chain_finder.load_nodes(iterate())
        self.parent_hash = the_hash

    def _longest_local_block_chain(self):
        if self._longest_chain_cache is None:
            max_weight = 0
            longest = []
            for chain in self.chain_finder.all_chains_ending_at(self.parent_hash):
                weight = sum(self.weight_lookup.get(h, 0) for h in chain)
                if weight > max_weight:
                    longest = chain
                    max_weight = weight
            self._longest_chain_cache = longest[:-1]
        return self._longest_chain_cache

    def block_for_hash(self, h):
        return self.unlocked_block_storage.get(h)

    def add_headers(self, header_iter):
        def iterate():
            for header in header_iter:
                h = header.hash()
                self.weight_lookup[h] = header.difficulty
                self.unlocked_block_storage[h] = header
                yield h, header.previous_block_hash

        old_longest_chain = self._longest_local_block_chain()

        self.chain_finder.load_nodes(iterate())

        self._longest_chain_cache = None
        new_longest_chain = self._longest_local_block_chain()

        if old_longest_chain and new_longest_chain:
            old_path, new_path = self.chain_finder.find_ancestral_path(
                old_longest_chain[0],
                new_longest_chain[0]
            )
            old_path = old_path[:-1]
            new_path = new_path[:-1]
        else:
            old_path = old_longest_chain
            new_path = new_longest_chain
        if old_path:
            logger.debug("old_path is %r-%r", old_path[0], old_path[-1])
        if new_path:
            logger.debug("new_path is %r-%r", new_path[0], new_path[-1])
            logger.debug("block chain now has %d elements", self.length())

        # return a list of operations:
        # ("add"/"remove", the_hash, the_index)
        ops = []
        size = len(old_longest_chain) + len(self._locked_chain)
        for idx, h in enumerate(old_path):
            op = ("remove", self.block_for_hash(h), size-idx-1)
            ops.append(op)
            del self.hash_to_index_lookup[h]
        size = len(new_longest_chain) + len(self._locked_chain)
        for idx, h in reversed(list(enumerate(new_path))):
            op = ("add", self.block_for_hash(h), size-idx-1)
            ops.append(op)
            self.hash_to_index_lookup[h] = size-idx-1
        for callback in self.change_callbacks:
            callback(self, ops)

        return ops

    def __repr__(self):
        local_block_chain = self._longest_local_block_chain()
        if local_block_chain:
            finish = b2h_rev(local_block_chain[0])
            start = b2h_rev(local_block_chain[-1])
            longest_chain = "longest chain %s to %s of size %d" % (start, finish, self.unlocked_length())
        else:
            longest_chain = "no unlocked elements"
        return "<BlockChain with %d locked elements and %s>" % (self.locked_length(), longest_chain)
