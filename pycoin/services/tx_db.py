
import os.path

from pycoin.coins.bitcoin.Tx import Tx
from pycoin.encoding.hexbytes import b2h_rev


class TxDb(object):
    """
    This object can be used in many places that expect a dict.
    """
    def __init__(self, lookup_methods=[], read_only_paths=[], writable_cache_path=None):
        self.lookup_methods = lookup_methods
        self.read_only_paths = read_only_paths
        if writable_cache_path:
            self.read_only_paths.append(writable_cache_path)
        self.writable_cache_path = writable_cache_path
        if self.writable_cache_path and not os.path.exists(self.writable_cache_path):
            os.makedirs(self.writable_cache_path)

    def paths_for_hash(self, hash):
        name = b2h_rev(hash)
        for base_dir in self.read_only_paths:
            p = os.path.join(base_dir, "%s_tx.bin" % name)
            if os.path.exists(p):
                yield p

    def put(self, tx):
        name = b2h_rev(tx.hash())
        if self.writable_cache_path:
            try:
                path = os.path.join(self.writable_cache_path, "%s_tx.bin" % name)
                with open(path, "wb") as f:
                    tx.stream(f)
            except IOError:
                pass

    def get(self, key):
        for path in self.paths_for_hash(key):
            try:
                tx = Tx.parse(open(path, "rb"))
                if tx and tx.hash() == key:
                    return tx
            except IOError:
                pass
        for method in self.lookup_methods:
            try:
                tx = method(key)
                if tx and tx.hash() == key:
                    self.put(tx)
                    return tx
            except Exception:
                pass
        return None

    def __getitem__(self, key):
        raise NotImplemented

    def __setitem__(self, key, val):
        if val.hash() != key:
            raise ValueError("bad key %s for %s" % (b2h_rev(key), val))
        self.put(val)
