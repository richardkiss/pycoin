
import os

from pycoin.serialize import b2h_rev
from pycoin.services import blockexplorer
from pycoin.tx.Tx import Tx

METHOD_LOOKUP = {
    "BLOCKEXPLORER" : blockexplorer.fetch_tx
}

def pycoin_cache_dir():
    return os.getenv("PYCOIN_CACHE_DIR", os.path.expanduser("~/.pycoin_cache"))

def tx_cache_dirs():
    main_dir = os.path.join(pycoin_cache_dir(), "txs")
    if not os.path.exists(main_dir):
        os.makedirs(main_dir)
    yield main_dir
    for p in os.getenv("PYCOIN_TX_DB_DIRS", "").split(":"):
        if p:
            yield p

def default_tx_lookup():
    methods = os.getenv("PYCOIN_TX_LOOKUP_METHODS", ["BLOCKEXPLORER"])
    for m in methods:
        f = METHOD_LOOKUP.get(m)
        if f:
            yield f

def _paths_for_hash(hash):
    for base_dir in tx_cache_dirs():
        yield os.path.join(base_dir, "%s_tx.bin" % b2h_rev(hash))

def tx_for_hash(hash):
    for path in _paths_for_hash(hash):
        try:
            tx = Tx.parse(open(path, "rb"))
            if tx and tx.hash() == hash:
                return tx
        except IOError:
            pass
    for method in default_tx_lookup():
        try:
            tx = method(hash)
            if tx and tx.hash() == hash:
                with open(path, "wb") as f:
                    tx.stream(f)
                return tx
        except Exception:
            pass
    return None
