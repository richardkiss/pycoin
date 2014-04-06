
import os.path

from pycoin.services import blockexplorer, blockr_io
from pycoin.tx.Tx import Tx


class TxDb(object):
    """
    This object can be used in many places that expect a dict.
    """
    def __init__(self, lookup_methods=[], read_only_paths=[], writable_cache_path=""):
        self.lookup_methods = lookup_methods
        self.read_only_paths = read_only_paths + [writable_cache_path]
        self.writable_cache_path = writable_cache_path

    def paths_for_hash(self, hash):
        name = b2h_rev(hash)
        for base_dir in self.read_only_paths:
            p = os.path.join(base_dir, "%s_tx.bin" % name)
            if os.path.exists(p):
                yield p

    def put(self, tx):
        name = b2h_rev(tx.hash())
        path = os.path.join(self.writable_cache_path, "%s_tx.bin" % name)
        with open(path, "wb") as f:
            tx.stream(f)

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


METHOD_LOOKUP = {
    "BLOCKEXPLORER": blockexplorer.get_tx,
    "BLOCKR_IO": blockr_io.get_tx,
    #"BITEASY": biteasy.tx_for_hash,
}


def pycoin_cache_dir():
    return os.getenv("PYCOIN_CACHE_DIR", os.path.expanduser("~/.pycoin_cache"))


def tx_db_from_env():
    methods = os.getenv("PYCOIN_TX_LOOKUP_METHODS", ["BLOCKR_IO", "BLOCKEXPLORER"])
    lookup_methods = [METHOD_LOOKUP.get(m) for m in methods]
    writable_cache_path = os.path.join(pycoin_cache_dir(), "txs")
    read_only_paths = [p for p in os.getenv("PYCOIN_TX_DB_DIRS", "").split(":") if len(p) > 0]
    return TxDb(lookup_methods=lookup_methods, read_only_paths=read_only_paths,
                writable_cache_path=writable_cache_path)
